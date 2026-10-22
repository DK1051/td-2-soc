"""Run every detection against the emulator loaded with fixtures/ and check the answers.

For each detection: the users it returns must include the users of its `expected_hits`
(takeovers) and must not include any user of its `expected_quiet` (look-alikes), and every
result row must carry a UserPrincipalName and a TimeGenerated timestamp.
Needs the emulator (see conftest.py); skipped without it unless KUSTO_REQUIRED=1.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import kql_common

pytestmark = pytest.mark.kusto

EXPECTED = json.loads((REPO / "fixtures" / "expected.json").read_text(encoding="utf-8"))
USER_OF = {item["id"]: item["user"].lower() for item in EXPECTED["takeovers"] + EXPECTED["lookalikes"]}


def load_cases(mark_known_gaps=False):
    cases = []
    for path in sorted(kql_common.DETECTIONS_DIR.glob("*.yaml")):
        header = yaml.safe_load(path.read_text(encoding="utf-8"))
        marks = []
        if mark_known_gaps and header.get("known_gap"):
            # strict xfail: the assertions below still run unchanged; the test is expected to
            # fail today and turns into an error the day the gap is closed, so it cannot be forgotten.
            marks.append(pytest.mark.xfail(strict=True, raises=AssertionError, reason="known gap: " + header["id"]))
        cases.append(pytest.param(header, id=header["id"], marks=marks))
    return cases


def run_detection(kusto, header):
    return kql_common.run_query(kusto, (kql_common.DETECTIONS_DIR / f"{header['id']}.kql").read_text())


@pytest.mark.parametrize("header", load_cases(mark_known_gaps=True))
def test_detection_hits_takeovers_and_stays_quiet_on_lookalikes(kusto, header):
    rows = run_detection(kusto, header)
    users = {row["UserPrincipalName"].lower() for row in rows}
    wanted = {USER_OF[i] for i in header["expected_hits"]}
    quiet = {USER_OF[i] for i in header["expected_quiet"]}
    assert wanted <= users, f"{header['id']} missed {sorted(wanted - users)}"
    assert not (users & quiet), f"{header['id']} fired on look-alike(s) {sorted(users & quiet)}"


@pytest.mark.parametrize("header", load_cases())
def test_every_result_row_has_user_and_timestamp(kusto, header):
    rows = run_detection(kusto, header)
    assert rows, f"{header['id']} returned no rows"
    for row in rows:
        assert row.get("UserPrincipalName"), "row without UserPrincipalName"
        assert isinstance(row.get("TimeGenerated"), datetime), "row without a TimeGenerated timestamp"
