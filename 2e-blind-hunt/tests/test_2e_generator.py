"""Tests for the 2E Blind Hunt generator, its fixtures and the scorer.

Everything runs in temporary directories with a fixed test seed. The real hunt dataset
(2e-blind-hunt/data/) and its sealed key are never touched.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
GENERATOR = REPO / "2e-blind-hunt" / "generate.py"
SCORER = REPO / "scripts" / "score_my_labels.py"
FIXTURES = REPO / "fixtures"
TEST_SEED = 4242

SIGNIN_FIELDS = {
    "TimeGenerated", "UserPrincipalName", "IPAddress", "Location", "AppDisplayName",
    "ResultType", "AuthenticationRequirement", "DeviceDetail", "CorrelationId",
}
AUDIT_FIELDS = {"TimeGenerated", "OperationName", "InitiatedBy", "TargetResources", "CorrelationId"}
RFC5737 = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
MARKER = "verified: callback to number on file"
FORBIDDEN_WORDS = ("takeover", "attacker", "malicious", "lookalike", "look-alike")
FORBIDDEN_IDS = re.compile(r"(?i)(tk|la)\d")


def run_generator(out_dir: Path, *args: str, seed: int = TEST_SEED, labels: bool = True):
    cmd = [sys.executable, str(GENERATOR), "--seed", str(seed), "--out-dir", str(out_dir)]
    if labels:
        cmd += ["--labels-out", str(out_dir / "labels.json")]
    subprocess.run(cmd + list(args), check=True, capture_output=True, text=True)
    return out_dir


def read_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def load_scorer():
    spec = importlib.util.spec_from_file_location("score_my_labels", SCORER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_t(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture(scope="module")
def default_run(tmp_path_factory):
    out = run_generator(tmp_path_factory.mktemp("default_run"))
    signin = read_rows(out / "signin.jsonl")
    audit = read_rows(out / "audit.jsonl")
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    return {"dir": out, "signin": signin, "audit": audit, "labels": labels,
            "by_id": {r["CorrelationId"]: r for r in signin + audit}}


# ---- determinism ---------------------------------------------------------------------


def test_same_seed_twice_gives_identical_bytes(default_run, tmp_path):
    second = run_generator(tmp_path)
    for name in ("signin.jsonl", "audit.jsonl", "labels.json"):  # labels include "generated"
        assert (default_run["dir"] / name).read_bytes() == (second / name).read_bytes(), name


def test_different_seed_gives_different_data(default_run, tmp_path):
    other = run_generator(tmp_path, seed=TEST_SEED + 1)
    assert (default_run["dir"] / "signin.jsonl").read_bytes() != (other / "signin.jsonl").read_bytes()


# ---- shape of the data ---------------------------------------------------------------


def test_row_count_is_within_ten_percent_of_target(default_run):
    total = len(default_run["signin"]) + len(default_run["audit"])
    assert 4500 <= total <= 5500, total


def test_time_span_is_fourteen_days_and_rows_are_sorted(default_run):
    for name in ("signin", "audit"):
        times = [r["TimeGenerated"] for r in default_run[name]]
        assert times == sorted(times), f"{name} is not sorted by TimeGenerated"
    everything = [parse_t(r["TimeGenerated"]) for r in default_run["signin"] + default_run["audit"]]
    span = max(everything) - min(everything)
    assert abs(span - timedelta(days=14)) <= timedelta(days=1), span


def test_every_row_has_exactly_the_agreed_fields(default_run):
    for row in default_run["signin"]:
        assert set(row) == SIGNIN_FIELDS
        assert set(row["Location"]) == {"city", "state", "countryOrRegion"}
        assert set(row["DeviceDetail"]) == {
            "deviceId", "displayName", "operatingSystem", "browser", "trustType"}
        assert row["ResultType"] in {"0", "50126", "500121"}
        assert row["AuthenticationRequirement"] in {
            "singleFactorAuthentication", "multiFactorAuthentication"}
    for row in default_run["audit"]:
        assert set(row) == AUDIT_FIELDS
        assert set(row["InitiatedBy"]) == {"user"}
        assert set(row["InitiatedBy"]["user"]) == {"userPrincipalName", "ipAddress"}
        assert isinstance(row["TargetResources"], list) and row["TargetResources"]
        for target in row["TargetResources"]:
            assert set(target) == {"displayName", "userPrincipalName", "modifiedProperties"}
            assert isinstance(target["modifiedProperties"], list)
    for row in default_run["signin"] + default_run["audit"]:
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", row["TimeGenerated"])
        assert str(uuid.UUID(row["CorrelationId"])) == row["CorrelationId"]
    ids = list(default_run["by_id"])
    assert len(ids) == len(default_run["signin"]) + len(default_run["audit"]), "duplicate ids"


def test_fifty_staff_all_at_the_fictional_domain(default_run):
    upns = set()
    for row in default_run["signin"]:
        upns.add(row["UserPrincipalName"])
    for row in default_run["audit"]:
        upns.add(row["InitiatedBy"]["user"]["userPrincipalName"])
        upns.update(t["userPrincipalName"] for t in row["TargetResources"])
    assert len(upns) == 50
    assert all(re.fullmatch(r"[a-z]+\.[a-z]+@mapleharbour\.example", u) for u in upns)
    raw = (default_run["dir"] / "signin.jsonl").read_text() + (
        default_run["dir"] / "audit.jsonl").read_text()
    for domain in re.findall(r"@([A-Za-z0-9.-]+)", raw):
        assert domain.endswith(".example"), domain


def test_every_ip_is_in_an_rfc5737_documentation_range(default_run):
    ips = {r["IPAddress"] for r in default_run["signin"]}
    ips |= {r["InitiatedBy"]["user"]["ipAddress"] for r in default_run["audit"]}
    assert ips
    for ip in ips:
        assert any(ipaddress.ip_address(ip) in net for net in RFC5737), ip


def test_phone_numbers_use_the_555_01xx_block(default_run):
    raw = (default_run["dir"] / "audit.jsonl").read_text()
    numbers = re.findall(r"\+1 (\d{3})-(\d{3})-(\d{4})", raw)
    assert numbers
    assert all(mid == "555" and last.startswith("01") for _, mid, last in numbers)


# ---- the hidden cases ------------------------------------------------------------------


def test_labels_have_five_takeovers_and_enough_lookalikes(default_run):
    labels = default_run["labels"]
    assert set(labels) == {"seed", "generated", "takeovers", "lookalikes"}
    assert labels["seed"] == TEST_SEED
    # "generated" is the last local day of the window: 2026-09-14 plus 13 days
    assert labels["generated"] == "2026-09-27"
    assert len(labels["takeovers"]) == 5
    assert len(labels["lookalikes"]) >= 8
    assert [t["id"] for t in labels["takeovers"]] == [f"TK{i}" for i in range(1, 6)]
    for case in labels["takeovers"] + labels["lookalikes"]:
        assert set(case) == {"id", "user", "start", "end", "evidence", "summary"}
        assert case["summary"].endswith(".")
        assert parse_t(case["start"]) <= parse_t(case["end"])
        assert case["evidence"]
        for cid in case["evidence"]:
            assert cid in default_run["by_id"], f"{case['id']} evidence {cid} not in data"


def test_takeover_sequences_have_steps_a_to_d(default_run):
    by_id = default_run["by_id"]
    for case in default_run["labels"]["takeovers"]:
        rows = [by_id[c] for c in case["evidence"]]
        assert len(rows) == 4
        a, b, c, d = rows
        assert a["OperationName"] == "Reset password (by admin)"
        assert MARKER not in json.dumps(a)
        assert a["TargetResources"][0]["userPrincipalName"] == case["user"]
        assert b["OperationName"] == "User registered security info"
        assert c["ResultType"] == "0" and c["AuthenticationRequirement"] == "multiFactorAuthentication"
        assert c["UserPrincipalName"] == case["user"]
        privileged = (d.get("OperationName") in ("Add member to role", "Update user")
                      or d.get("AppDisplayName") == "Core Banking Admin")
        assert privileged
        assert parse_t(a["TimeGenerated"]) <= parse_t(b["TimeGenerated"]) <= parse_t(
            c["TimeGenerated"]) <= parse_t(d["TimeGenerated"])
    spans = [parse_t(c["end"]) - parse_t(c["start"]) for c in default_run["labels"]["takeovers"]]
    assert any(s > timedelta(hours=12) for s in spans), "one sequence should span two days"


def test_takeover_sign_in_uses_a_device_ip_and_country_never_seen_for_that_user(default_run):
    by_id = default_run["by_id"]
    for case in default_run["labels"]["takeovers"]:
        c = by_id[case["evidence"][2]]
        others = [r for r in default_run["signin"]
                  if r["UserPrincipalName"] == case["user"] and r["CorrelationId"] not in
                  case["evidence"]]
        assert others
        assert c["DeviceDetail"]["deviceId"] not in {r["DeviceDetail"]["deviceId"] for r in others}
        assert c["IPAddress"] not in {r["IPAddress"] for r in others}
        assert c["Location"]["countryOrRegion"] != "CA"


def test_lookalikes_cover_the_named_kinds_and_the_marker_alone_never_decides(default_run):
    by_id = default_run["by_id"]
    resets_without_marker = 0
    resets_with_marker = 0
    for case in default_run["labels"]["lookalikes"]:
        for cid in case["evidence"]:
            row = by_id[cid]
            if row.get("OperationName") == "Reset password (by admin)":
                if MARKER in json.dumps(row):
                    resets_with_marker += 1
                else:
                    resets_without_marker += 1
    assert resets_with_marker >= 2  # lost phone, reset followed by a known device
    assert resets_without_marker >= 2  # rushed agent: no marker, but only known-device sign-ins
    ops = {by_id[c].get("OperationName") for case in default_run["labels"]["lookalikes"]
           for c in case["evidence"]}
    assert {"Add member to role", "Reset password (self-service)",
            "User registered security info"} <= ops
    # "travelling" and "VPN" cases: a country outside Canada, but a device the user always uses
    foreign_known = 0
    for case in default_run["labels"]["lookalikes"]:
        rows = [by_id[c] for c in case["evidence"] if "UserPrincipalName" in by_id[c]]
        if rows and all(r["Location"]["countryOrRegion"] != "CA" for r in rows):
            elsewhere = {r["DeviceDetail"]["deviceId"] for r in default_run["signin"]
                         if r["UserPrincipalName"] == case["user"]
                         and r["CorrelationId"] not in case["evidence"]}
            if rows[0]["DeviceDetail"]["deviceId"] in elsewhere:
                foreign_known += 1
    assert foreign_known >= 2


# ---- structural no-tells: hidden cases must not differ from normal life in these ways -------


def local(text: str) -> datetime:
    return parse_t(text) - timedelta(hours=4)


def admin_resets(run):
    return [r for r in run["audit"] if r["OperationName"] == "Reset password (by admin)"]


def test_every_admin_reset_is_in_business_hours_after_an_agent_sign_in(default_run):
    resets = admin_resets(default_run)
    assert len(resets) >= 14  # 5 hidden + look-alikes + unlabelled routine resets
    for r in resets:
        when = local(r["TimeGenerated"])
        assert when.weekday() < 5 and 8.5 <= when.hour + when.minute / 60 < 17.5, when
        agent = r["InitiatedBy"]["user"]["userPrincipalName"]
        earlier = [s for s in default_run["signin"]
                   if s["UserPrincipalName"] == agent and s["ResultType"] == "0"
                   and timedelta(0) <= parse_t(r["TimeGenerated"]) - parse_t(s["TimeGenerated"])
                   <= timedelta(minutes=30)]
        assert earlier, f"no agent sign-in in the 30 minutes before the reset at {when}"
        assert r["InitiatedBy"]["user"]["ipAddress"] in {s["IPAddress"] for s in earlier}


def test_every_admin_reset_is_followed_by_a_wrong_password_from_the_known_device(default_run):
    for r in admin_resets(default_run):
        user = r["TargetResources"][0]["userPrincipalName"]
        after = [s for s in default_run["signin"]
                 if s["UserPrincipalName"] == user and s["ResultType"] == "50126"
                 and timedelta(0) < parse_t(s["TimeGenerated"]) - parse_t(r["TimeGenerated"])
                 <= timedelta(minutes=25)]
        assert after


def test_some_resets_are_ordinary_and_unlabelled_with_and_without_the_marker(default_run):
    labelled = {c for case in default_run["labels"]["takeovers"] + default_run["labels"]["lookalikes"]
                for c in case["evidence"]}
    plain = [r for r in admin_resets(default_run) if r["CorrelationId"] not in labelled]
    assert 3 <= len(plain) <= 6
    markers = [MARKER in json.dumps(r) for r in plain]
    assert any(markers) and not all(markers)


def test_takeover_countries_are_also_ordinary_travel_countries(default_run):
    takeover_ids = {c for case in default_run["labels"]["takeovers"] for c in case["evidence"]}
    takeover_countries = {default_run["by_id"][c]["Location"]["countryOrRegion"]
                          for case in default_run["labels"]["takeovers"]
                          for c in case["evidence"] if "Location" in default_run["by_id"][c]}
    other_foreign = {s["Location"]["countryOrRegion"] for s in default_run["signin"]
                     if s["CorrelationId"] not in takeover_ids
                     and s["Location"]["countryOrRegion"] != "CA"}
    assert takeover_countries and takeover_countries <= other_foreign


def test_a_laptop_is_never_in_canada_while_its_user_is_travelling_or_on_a_vpn(default_run):
    takeover_ids = {c for case in default_run["labels"]["takeovers"] for c in case["evidence"]}
    foreign_by_user: dict = {}
    for s in default_run["signin"]:
        if s["CorrelationId"] not in takeover_ids and s["Location"]["countryOrRegion"] != "CA":
            foreign_by_user.setdefault(s["UserPrincipalName"], []).append(s["TimeGenerated"])
    assert len(foreign_by_user) >= 6  # the two labelled cases plus the unlabelled travellers
    for user, times in foreign_by_user.items():
        first, last = min(times), max(times)
        inside_canada = [s for s in default_run["signin"]
                         if s["UserPrincipalName"] == user and first <= s["TimeGenerated"] <= last
                         and s["Location"]["countryOrRegion"] == "CA"
                         and s["CorrelationId"] not in takeover_ids]
        assert not inside_canada, f"{user} signs in from Canada while away"


def test_personal_computers_are_common_among_ordinary_staff(default_run):
    takeover_ids = {c for case in default_run["labels"]["takeovers"] for c in case["evidence"]}
    users = {s["UserPrincipalName"] for s in default_run["signin"]}
    personal = {s["UserPrincipalName"] for s in default_run["signin"]
                if s["CorrelationId"] not in takeover_ids
                and s["DeviceDetail"]["displayName"].startswith("DESKTOP-")}
    assert len(personal) / len(users) >= 0.2


def test_safari_only_runs_on_macos(default_run):
    for s in default_run["signin"]:
        if s["DeviceDetail"]["browser"] == "Safari":
            assert s["DeviceDetail"]["operatingSystem"] == "MacOs"


# ---- 128-bit seeds ------------------------------------------------------------------------

BIG_SEED = 2**127 + 123456789012345678901234567


def test_a_128_bit_seed_runs_and_is_deterministic(tmp_path):
    small = ("--days", "3", "--events", "300", "--takeovers", "2", "--lookalikes", "3")
    first = run_generator(tmp_path / "a", *small, seed=BIG_SEED)
    second = run_generator(tmp_path / "b", *small, seed=BIG_SEED)
    other = run_generator(tmp_path / "c", *small, seed=7)
    for name in ("signin.jsonl", "audit.jsonl", "labels.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes(), name
    assert (first / "signin.jsonl").read_bytes() != (other / "signin.jsonl").read_bytes()
    assert json.loads((first / "labels.json").read_text())["seed"] == BIG_SEED


# ---- properties that must not be takeover-only clues ---------------------------------------


def recovery_mail_users(run):
    """(users whose recovery email was changed in a takeover, users where it was not)."""
    takeover_ids = {c for case in run["labels"]["takeovers"] for c in case["evidence"]}
    hit, ordinary = set(), set()
    for r in run["audit"]:
        for target in r["TargetResources"]:
            if any(m["displayName"] == "OtherMails" for m in target["modifiedProperties"]):
                (hit if r["CorrelationId"] in takeover_ids else ordinary).add(
                    target["userPrincipalName"])
    return hit, ordinary


@pytest.fixture(scope="module")
def several_runs(tmp_path_factory):
    runs = []
    for seed in (1, 99, BIG_SEED, 2**100 + 5):
        out = run_generator(tmp_path_factory.mktemp(f"seed{seed % 1000}"), seed=seed)
        signin, audit = read_rows(out / "signin.jsonl"), read_rows(out / "audit.jsonl")
        labels = json.loads((out / "labels.json").read_text())
        runs.append((seed, {"signin": signin, "audit": audit, "labels": labels}))
    return runs


def test_recovery_email_changes_are_not_a_takeover_only_clue(default_run, several_runs):
    for _, run in [("default", default_run)] + several_runs:
        hit, ordinary = recovery_mail_users(run)
        assert hit, "expected some takeovers to change a recovery email"
        assert len(ordinary) >= max(2, len(hit)), (len(hit), len(ordinary))
        assert not (hit & ordinary)


def test_every_property_name_in_a_takeover_row_also_appears_in_ordinary_rows(
        default_run, several_runs):
    for _, run in [("default", default_run)] + several_runs:
        takeover_ids = {c for case in run["labels"]["takeovers"] for c in case["evidence"]}
        in_takeover, in_ordinary = set(), set()
        for r in run["audit"]:
            names = {m["displayName"] for t in r["TargetResources"]
                     for m in t["modifiedProperties"]}
            (in_takeover if r["CorrelationId"] in takeover_ids else in_ordinary).update(names)
        assert in_takeover and in_takeover <= in_ordinary, in_takeover - in_ordinary


def test_ordinary_recovery_changes_have_no_reset_and_no_new_mfa(default_run):
    takeover_ids = {c for case in default_run["labels"]["takeovers"] for c in case["evidence"]}
    checked = 0
    for r in default_run["audit"]:
        target = r["TargetResources"][0]
        if r["CorrelationId"] in takeover_ids or not any(
                m["displayName"] == "OtherMails" for m in target["modifiedProperties"]):
            continue
        checked += 1
        user = target["userPrincipalName"]
        t = parse_t(r["TimeGenerated"])
        near = [a for a in default_run["audit"]
                if a is not r and a["TargetResources"][0]["userPrincipalName"] == user
                and abs(parse_t(a["TimeGenerated"]) - t) <= timedelta(hours=24)
                and a["OperationName"] in ("Reset password (by admin)",
                                           "User registered security info")]
        assert not near
        earlier = [s for s in default_run["signin"]
                   if s["UserPrincipalName"] == user and s["ResultType"] == "0"
                   and timedelta(0) <= t - parse_t(s["TimeGenerated"]) <= timedelta(days=3)]
        assert earlier
    assert checked > 0


def recovery_timing_features(run):
    """For each recovery-email change: (is takeover, [3 timing features]). The user's own
    sign-ins that belong to a hidden case are left out, as a hunter cannot tell them apart."""
    hidden = {c for case in run["labels"]["takeovers"] + run["labels"]["lookalikes"]
              for c in case["evidence"]}
    takeover_ids = {c for case in run["labels"]["takeovers"] for c in case["evidence"]}
    rows = []
    for r in run["audit"]:
        target = r["TargetResources"][0]
        if not any(m["displayName"] == "OtherMails" for m in target["modifiedProperties"]):
            continue
        t = parse_t(r["TimeGenerated"])
        own = [parse_t(s["TimeGenerated"]) for s in run["signin"]
               if s["UserPrincipalName"] == target["userPrincipalName"]
               and s["CorrelationId"] not in hidden]
        before = [t - x for x in own if x <= t]
        after = [x - t for x in own if x > t]
        rows.append((r["CorrelationId"] in takeover_ids, [
            not before or min(before) > timedelta(minutes=15),  # no sign-in just before
            not after or min(after) > timedelta(minutes=60),  # no sign-in soon after
            local(r["TimeGenerated"]).hour >= 20,  # late evening
        ]))
    return rows


def test_recovery_email_timing_does_not_separate_takeovers_from_ordinary_changes(
        default_run, several_runs):
    rows = []
    for run in [default_run] + [r for _, r in several_runs]:
        rows += recovery_timing_features(run)
    takeover = [f for is_tk, f in rows if is_tk]
    ordinary = [f for is_tk, f in rows if not is_tk]
    assert len(takeover) >= 10 and len(ordinary) >= 20
    for i, name in enumerate(("last sign-in over 15 min before", "no sign-in within 60 min after",
                              "20:00 or later")):
        tk_share = sum(f[i] for f in takeover) / len(takeover)
        ord_share = sum(f[i] for f in ordinary) / len(ordinary)
        if tk_share >= 0.2:
            assert ord_share >= 0.2, f"{name}: takeover {tk_share:.2f}, ordinary {ord_share:.2f}"
        if ord_share >= 0.2:
            assert tk_share > 0, name
    any_tk = sum(any(f) for f in takeover) / len(takeover)
    any_ord = sum(any(f) for f in ordinary) / len(ordinary)
    assert any_ord >= 0.2 and any_ord >= any_tk - 0.3


def test_making_a_correlation_id_does_not_touch_the_random_generator_state():
    spec = importlib.util.spec_from_file_location("generate_2e", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules["generate_2e"] = module  # dataclasses look the module up by name
    spec.loader.exec_module(module)
    gen = module.Generator(7, 3, 300, 2, 3, datetime(2026, 9, 14).date())
    before = gen.rng.getstate()
    ids = [gen.uuid() for _ in range(3)]
    assert gen.rng.getstate() == before
    assert len(set(ids)) == 3 and all(str(uuid.UUID(i)) == i for i in ids)


# ---- no tells --------------------------------------------------------------------------


def assert_no_tells(directory: Path, labels: dict):
    for name in ("signin.jsonl", "audit.jsonl"):
        text = (directory / name).read_text(encoding="utf-8")
        lowered = text.lower()
        for word in FORBIDDEN_WORDS:
            assert word not in lowered, f"{word!r} found in {name}"
        assert not FORBIDDEN_IDS.search(text), f"TK/LA id pattern found in {name}"
        for case in labels["takeovers"] + labels["lookalikes"]:
            assert case["id"] not in text
            assert case["summary"] not in text


def test_no_tells_in_the_default_data(default_run):
    assert_no_tells(default_run["dir"], default_run["labels"])


def test_no_tells_in_the_committed_fixtures():
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    assert_no_tells(FIXTURES, expected)


def test_hidden_events_use_second_level_jitter_like_normal_events(default_run):
    by_id = default_run["by_id"]
    seconds = {parse_t(by_id[c]["TimeGenerated"]).second
               for case in default_run["labels"]["takeovers"] for c in case["evidence"]}
    assert len(seconds) >= 8  # not all rounded to :00


# ---- fixtures --------------------------------------------------------------------------


def test_fixtures_exist_with_the_agreed_answers():
    for name in ("signin.jsonl", "audit.jsonl", "expected.json"):
        assert (FIXTURES / name).is_file(), name
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))
    assert expected["seed"] == 7
    assert len(expected["takeovers"]) == 2
    assert len(expected["lookalikes"]) >= 3
    ids = {r["CorrelationId"] for r in read_rows(FIXTURES / "signin.jsonl")}
    ids |= {r["CorrelationId"] for r in read_rows(FIXTURES / "audit.jsonl")}
    for case in expected["takeovers"] + expected["lookalikes"]:
        assert set(case["evidence"]) <= ids


def test_fixtures_match_what_the_committed_command_generates(tmp_path):
    run_generator(tmp_path, "--days", "3", "--events", "300", "--takeovers", "2",
                  "--lookalikes", "3", seed=7)
    for name in ("signin.jsonl", "audit.jsonl"):
        assert (tmp_path / name).read_bytes() == (FIXTURES / name).read_bytes(), name
    assert (tmp_path / "labels.json").read_bytes() == (FIXTURES / "expected.json").read_bytes()
    total = len(read_rows(tmp_path / "signin.jsonl")) + len(read_rows(tmp_path / "audit.jsonl"))
    assert 270 <= total <= 330


# ---- the scorer ------------------------------------------------------------------------


def run_scorer(labels_path: Path, key_path: Path) -> str:
    done = subprocess.run(
        [sys.executable, str(SCORER), "--labels", str(labels_path), "--key", str(key_path)],
        check=True, capture_output=True, text=True)
    return done.stdout


def test_scoring_the_answers_against_themselves_gives_one_and_one(default_run):
    scorer = load_scorer()
    labels = default_run["labels"]
    result = scorer.score(labels, labels)
    assert result["precision"] == 1.0 and result["recall"] == 1.0
    out = run_scorer(default_run["dir"] / "labels.json", default_run["dir"] / "labels.json")
    assert "precision: 1.0" in out and "recall: 1.0" in out


def test_scoring_the_fixture_answers_against_themselves():
    out = run_scorer(FIXTURES / "expected.json", FIXTURES / "expected.json")
    assert "precision: 1.0" in out and "recall: 1.0" in out


def test_empty_labels_score_zero(default_run, tmp_path):
    empty = tmp_path / "empty-labels.json"
    empty.write_text(json.dumps({"takeovers": []}))
    result = load_scorer().score({"takeovers": []}, default_run["labels"])
    assert result["precision"] == 0.0 and result["recall"] == 0.0
    out = run_scorer(empty, default_run["dir"] / "labels.json")
    assert "precision: 0.0" in out and "recall: 0.0" in out


def test_scorer_accepts_event_ids_or_time_windows(default_run):
    scorer = load_scorer()
    key = default_run["labels"]
    first, second, third = key["takeovers"][:3]
    by_evidence = {"id": "X1", "user": "", "start": "", "end": "", "evidence": first["evidence"][:1]}
    by_window = {"id": "X2", "user": second["user"].upper(), "start": second["start"],
                 "end": second["start"], "evidence": []}
    wrong_user = {"id": "X3", "user": first["user"], "start": third["start"], "end": third["end"],
                  "evidence": []}
    result = scorer.score({"takeovers": [by_evidence, by_window, wrong_user]}, key)
    assert result["matched"] == [("X1", first["id"]), ("X2", second["id"])]
    assert result["precision"] == round(2 / 3, 3)
    assert result["recall"] == 0.4
    assert [m[0] for m in result["missed"]] == ["TK3", "TK4", "TK5"]
    assert result["extra"][0][0] == "X3"


def test_scorer_flags_a_label_that_hits_a_benign_case(default_run):
    scorer = load_scorer()
    benign = default_run["labels"]["lookalikes"][0]
    label = {"id": "X9", "user": benign["user"], "start": benign["start"], "end": benign["end"],
             "evidence": []}
    result = scorer.score({"takeovers": [label]}, default_run["labels"])
    assert result["precision"] == 0.0
    assert result["extra"] == [("X9", benign["user"], benign["id"])]


def test_scorer_output_names_only_ids_and_users(default_run, tmp_path):
    empty = tmp_path / "empty-labels.json"
    empty.write_text(json.dumps({"takeovers": []}))
    out = run_scorer(empty, default_run["dir"] / "labels.json")  # every takeover is "missed"
    key = default_run["labels"]
    for case in key["takeovers"]:
        assert case["id"] in out and case["user"] in out
        assert case["summary"] not in out
        assert not (set(case["evidence"]) & set(out.split()))
        assert case["start"] not in out


def test_untouched_template_entries_do_not_lower_precision(default_run):
    scorer = load_scorer()
    key = default_run["labels"]
    template_entry = {"id": "", "user": "", "start": "", "end": "", "evidence": [], "summary": ""}
    real = dict(key["takeovers"][0])
    only_template = scorer.score({"takeovers": [template_entry]}, key)
    assert only_template["n_labels"] == 0 and only_template["precision"] == 0.0
    mixed = scorer.score({"takeovers": [real, template_entry]}, key)
    assert mixed["n_labels"] == 1 and mixed["precision"] == 1.0 and mixed["recall"] == 0.2
