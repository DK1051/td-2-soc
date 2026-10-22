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
    datetime.strptime(labels["generated"], "%Y-%m-%d")
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
