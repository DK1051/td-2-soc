"""Run every detection against the emulator loaded with fixtures/ and check the answers.

For each detection, three separate checks:
  * hits:  the users returned include the users of its `expected_hits` (takeovers);
  * quiet: no user of its `expected_quiet` (look-alikes) is returned;
  * shape: every result row carries a UserPrincipalName and a TimeGenerated timestamp.
`expected_noise` look-alikes (documented in the YAML) are allowed: neither required nor forbidden.
Needs the emulator (see conftest.py); skipped without it unless KUSTO_REQUIRED=1.
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import kql_common

pytestmark = pytest.mark.kusto

EXPECTED = json.loads((REPO / "fixtures" / "expected.json").read_text(encoding="utf-8"))
USER_OF = {item["id"]: item["user"].lower()
           for item in EXPECTED["takeovers"] + EXPECTED["lookalikes"]}
HEADERS = [kql_common.read_detection(i) for i in kql_common.detection_ids()]
CASES = [pytest.param(header, query, id=header["id"]) for header, query in HEADERS]


def users_returned(kusto, query):
    return {row["UserPrincipalName"].lower() for row in kql_common.run_query(kusto, query)}


@pytest.mark.parametrize("header, query", CASES)
def test_detection_hits_all_expected_takeovers(kusto, header, query):
    wanted = {USER_OF[i] for i in header["expected_hits"]}
    users = users_returned(kusto, query)
    assert wanted <= users, f"{header['id']} missed {sorted(wanted - users)}"


@pytest.mark.parametrize("header, query", CASES)
def test_detection_stays_quiet_on_expected_lookalikes(kusto, header, query):
    quiet = {USER_OF[i] for i in header["expected_quiet"]}
    users = users_returned(kusto, query)
    assert not (users & quiet), f"{header['id']} fired on look-alike(s) {sorted(users & quiet)}"


@pytest.mark.parametrize("header, query", CASES)
def test_every_result_row_has_user_and_timestamp(kusto, header, query):
    rows = kql_common.run_query(kusto, query)
    if header["expected_hits"]:
        assert rows, f"{header['id']} returned no rows"
    for row in rows:
        assert row.get("UserPrincipalName"), "row without UserPrincipalName"
        assert isinstance(row.get("TimeGenerated"), datetime), "row without TimeGenerated"
