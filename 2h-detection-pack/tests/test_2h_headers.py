"""2H header checks: no emulator needed, runs in the normal `checks` CI job.

Every detections/<id>.kql must have a detections/<id>.yaml with all required fields, ids must be
unique, expected_hits / expected_quiet must name ids that exist in fixtures/expected.json, every
TODO(verify) must be spelled exactly that way, and scripts/check_kql.py must pass on every query.
"""

import json
import re
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import check_kql

DETECTIONS = REPO / "2h-detection-pack" / "detections"
REQUIRED = [
    "id", "title", "description", "tables", "attack_technique_ids", "al26_010_control",
    "severity", "false_positive_notes", "expected_hits", "expected_quiet",
]
OPTIONAL = {"known_gap"}
KQL_FILES = sorted(DETECTIONS.glob("*.kql"))
YAML_FILES = sorted(DETECTIONS.glob("*.yaml"))


def load_header(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def expected_ids():
    data = json.loads((REPO / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    takeovers = {item["id"] for item in data["takeovers"]}
    lookalikes = {item["id"] for item in data["lookalikes"]}
    return takeovers, lookalikes


def test_at_least_six_detections():
    assert len(KQL_FILES) >= 6


def test_every_kql_has_a_yaml_and_back():
    assert {p.stem for p in KQL_FILES} == {p.stem for p in YAML_FILES}


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda p: p.stem)
def test_header_fields(path):
    header = load_header(path)
    assert isinstance(header, dict)
    missing = [key for key in REQUIRED if key not in header]
    assert not missing, f"{path.name} is missing {missing}"
    assert set(header) <= set(REQUIRED) | OPTIONAL, "unknown field in header"
    assert header["id"] == path.stem and re.fullmatch(r"TD-2H-\d\d", header["id"])
    assert header["severity"] in {"low", "medium", "high"}
    assert header["tables"] and set(header["tables"]) <= {"SigninLogs", "AuditLogs"}
    for key in ("title", "al26_010_control", "false_positive_notes"):
        assert isinstance(header[key], str) and header[key].strip(), key
    sentences = re.findall(r"[.!?](?:\s|$)", header["description"].strip())
    assert len(sentences) == 2, "description must be two plain sentences"
    assert isinstance(header["attack_technique_ids"], list) and header["attack_technique_ids"]
    for entry in header["attack_technique_ids"]:
        assert entry == "TODO(verify)" or re.fullmatch(r"T\d{4}(\.\d{3})?: \S.*", entry), (
            f"{entry!r}: use exactly TODO(verify), or 'T1234: Exact Technique Name'")
    assert isinstance(header["expected_hits"], list) and header["expected_hits"]
    assert isinstance(header["expected_quiet"], list)
    if "known_gap" in header:
        assert isinstance(header["known_gap"], str) and header["known_gap"].strip()


def test_ids_are_unique():
    ids = [load_header(p)["id"] for p in YAML_FILES]
    assert len(ids) == len(set(ids))


def test_expected_ids_exist_in_expected_json():
    takeovers, lookalikes = expected_ids()
    for path in YAML_FILES:
        header = load_header(path)
        assert set(header["expected_hits"]) <= takeovers, f"{path.name}: unknown takeover id"
        assert set(header["expected_quiet"]) <= lookalikes, f"{path.name}: unknown look-alike id"


def test_every_todo_verify_is_spelled_exactly():
    for path in [*YAML_FILES, *KQL_FILES]:
        text = path.read_text(encoding="utf-8")
        for found in re.findall(r"(?i)todo\s*\(?\s*verify\s*\)?", text):
            assert found == "TODO(verify)", f"{path.name}: write TODO(verify), not {found!r}"


@pytest.mark.parametrize("path", KQL_FILES, ids=lambda p: p.stem)
def test_check_kql_passes(path):
    assert check_kql.check_file(path) == []


# --- the checker itself must reject bad queries, otherwise "passes" means nothing -------------

GOOD = "AuditLogs\n| project UserPrincipalName, TimeGenerated\n"


@pytest.mark.parametrize("text, fragment", [
    (GOOD, None),
    (GOOD.replace("project", "project (") , "bracket"),
    (GOOD.replace("AuditLogs", "AuditLogs | where A == 'x"), "quote"),
    (GOOD.replace("AuditLogs", "SecurityEvent"), "SecurityEvent"),
    (GOOD.replace("TimeGenerated", "Other"), "TimeGenerated"),
    ("AuditLogs\n| project UserPrincipalName, TimeGenerated\n| take 5\n", "project"),
    (GOOD + "\n" * 45, "lines"),
])
def test_check_kql_catches_problems(text, fragment):
    problems = check_kql.check_text(text)
    if fragment is None:
        assert problems == []
    else:
        assert any(fragment in problem for problem in problems), problems
