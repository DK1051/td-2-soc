"""Detections on small SYNTHETIC cases the fixtures do not contain, each with a known answer.

The fixtures (fixtures/, left unchanged) have no "Add member to role" event, no takeover whose new
MFA method comes many hours after the reset, no verification note that merely contains the marker
words ("not verified: ..."), no sign-in with an empty device id, no reset campaign (TD-2H-05) and
no reset spread over several modifiedProperties. This file builds those cases in memory, loads them
into a separate database (mapleharbour_synthetic) of the emulator, and checks each detection.
All names are fictional (mapleharbour.example). Needs the emulator; see conftest.py.
"""

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import kql_common

pytestmark = pytest.mark.kusto

DB = "mapleharbour_synthetic"
D = datetime(2026, 10, 1, tzinfo=UTC)  # the "burst day" for TD-2H-05 and the day of most cases
MARKER = "verified: callback to number on file"
OLD_DEVICE, OLD_IP = "dev-old", "203.0.113.50"
NEW_DEVICE, NEW_IP = "dev-new", "198.51.100.1"
RESET, REGISTER, ROLE, UPDATE = (
    "Reset password (by admin)", "User registered security info", "Add member to role",
    "Update user")


def upn(name):
    return f"{name}@mapleharbour.example"


class Builder:
    def __init__(self):
        self.signin_rows, self.audit_rows, self.count = [], [], 0

    def cid(self):
        self.count += 1
        return f"00000000-0000-4000-8000-{self.count:012d}"

    def signin(self, name, when, device, ip, app="Microsoft Teams"):
        self.signin_rows.append({
            "TimeGenerated": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "UserPrincipalName": upn(name),
            "IPAddress": ip, "Location": {"city": "Toronto", "countryOrRegion": "CA"},
            "AppDisplayName": app, "ResultType": "0",
            "AuthenticationRequirement": "multiFactorAuthentication",
            "DeviceDetail": {"deviceId": device, "operatingSystem": "Windows 11"},
            "CorrelationId": self.cid()})

    def audit(self, op, when, by, target, props):
        self.audit_rows.append({
            "TimeGenerated": when.strftime("%Y-%m-%dT%H:%M:%SZ"), "OperationName": op,
            "InitiatedBy": {"user": {"userPrincipalName": upn(by), "ipAddress": "203.0.113.10"}},
            "TargetResources": [{
                "displayName": target, "userPrincipalName": upn(target),
                "modifiedProperties": [
                    {"displayName": n, "oldValue": None, "newValue": v} for n, v in props]}],
            "CorrelationId": self.cid()})

    def person(self, name):
        """A user with one ordinary sign-in the day before (their known device and IP)."""
        self.signin(name, D - timedelta(days=1, hours=-9), OLD_DEVICE, OLD_IP)

    def reset(self, name, when, note_props, agent="agent.one"):
        self.audit(RESET, when, agent, name, note_props)

    def mfa(self, name, when):
        self.audit(REGISTER, when, name, name, [("StrongAuthenticationMethod", "Authenticator app")])


def at(hours):
    return D + timedelta(hours=hours)


def note(text):
    return [("TicketNote", text)]


def build():
    b = Builder()
    # roleadd: reset -> MFA +1h -> new device +10 min -> adds a role member (the branch missing
    # from the fixtures). Expect 02, 03, 04 (score 4), 06.
    b.person("roleadd"); b.reset("roleadd", at(10), note("INC1: reset on request"))
    b.mfa("roleadd", at(11)); b.signin("roleadd", at(11.2), NEW_DEVICE, NEW_IP)
    b.audit(ROLE, at(13), "roleadd", "someone.else", [("Role.DisplayName", "Helpdesk Administrator")])
    # overnight: new MFA method 18 h after the reset, new device 10 min later, Core Banking Admin.
    b.person("overnight"); b.reset("overnight", at(16), note("INC2: reset on request"))
    b.mfa("overnight", at(34)); b.signin("overnight", at(34.2), NEW_DEVICE, NEW_IP)
    b.signin("overnight", at(34.5), NEW_DEVICE, NEW_IP, "Core Banking Admin")
    # notverified: the note contains the marker words but says NOT verified. Expect 06 to fire.
    b.person("notverified"); b.reset("notverified", at(10), note(f"INC3: not {MARKER}"))
    b.mfa("notverified", at(11))
    # verified: a proper note; 06 must stay quiet. Also checked with the marker in a SECOND property.
    b.person("verified"); b.reset("verified", at(10), note(f"INC4: reset; {MARKER}"))
    b.mfa("verified", at(11))
    b.person("twoprops"); b.reset("twoprops", at(10), [("Reason", "forgot"), *note(f"INC5: ok; {MARKER}")])
    b.mfa("twoprops", at(11))
    b.person("twoprops2"); b.reset("twoprops2", at(10), [("Reason", "forgot"), *note("INC6: no marker")])
    b.mfa("twoprops2", at(11))
    # emptydev: verified reset, new MFA, then Core Banking Admin from the known IP with an EMPTY
    # device id. Unknown is not new: 02 quiet, 04 scores 3 (reset, MFA, privileged), no device stage.
    b.person("emptydev"); b.reset("emptydev", at(10), note(f"INC7: reset; {MARKER}"))
    b.mfa("emptydev", at(11)); b.signin("emptydev", at(11.2), "", OLD_IP, "Core Banking Admin")
    # newiponly: same known device, new IP address. A new IP alone must NOT fire 02.
    b.person("newiponly"); b.reset("newiponly", at(10), note(f"INC8: reset; {MARKER}"))
    b.mfa("newiponly", at(11)); b.signin("newiponly", at(11.2), OLD_DEVICE, NEW_IP)
    # TD-2H-05: agent.burst does 1 reset a day for 14 days, then 6 on the burst day, then 2.
    # agent.busy does 5 a day for 30 days (a high usual volume), including 6 on the burst day.
    for i, count in [(day, 1) for day in range(-14, 0)] + [(0, 6), (1, 2)]:
        for n in range(count):
            b.reset(f"burst-{i}-{n}", at(24 * i + 9 + n), note("INC9: reset"), agent="agent.burst")
    for i in range(-28, 2):
        for n in range(6 if i == 0 else 5):
            b.reset(f"busy-{i}-{n}", at(24 * i + 9 + n), note("INC10: reset"), agent="agent.busy")
    return b


@pytest.fixture(scope="module")
def synth(kusto):
    b = build()
    kql_common.load_rows(kusto, b.signin_rows, b.audit_rows, DB)

    def run(detection_id):
        _, query = kql_common.read_detection(detection_id)
        return kql_common.run_query(kusto, query, DB)

    return run


def names(rows):
    return {row["UserPrincipalName"].split("@")[0] for row in rows}


def only(rows, name):
    return [row for row in rows if row["UserPrincipalName"] == upn(name)]


def test_td_2h_02_new_device_only(synth):
    found = names(synth("TD-2H-02"))
    assert {"roleadd", "overnight"} <= found
    # empty device id = unknown; new IP alone is not enough; verified lost-phone-style users
    assert not {"emptydev", "newiponly", "verified", "notverified"} & found


def test_td_2h_03_role_member_added_and_overnight(synth):
    rows = synth("TD-2H-03")
    assert [r["PrivAction"] for r in only(rows, "roleadd")] == ["role member added"]
    assert {r["PrivAction"] for r in only(rows, "overnight")} == {"Core Banking Admin sign-in"}
    assert "notverified" not in names(rows)


def test_td_2h_04_full_chain_scores(synth):
    rows = synth("TD-2H-04")
    by_user = {row["UserPrincipalName"].split("@")[0]: row for row in rows}
    assert by_user["roleadd"]["chain_score"] == 4
    assert by_user["overnight"]["chain_score"] == 4  # MFA 18 hours after the reset
    # the alert time is the LATEST stage: the role-member add at 13:00 for roleadd
    assert by_user["roleadd"]["TimeGenerated"] == at(13)
    assert by_user["overnight"]["TimeGenerated"] == at(34.5)
    # empty device id: no device stage, so reset + MFA + privileged = 3
    assert by_user["emptydev"]["chain_score"] == 3 and by_user["emptydev"]["NewDeviceTime"] is None
    # reset + MFA only (score 2) stays below the alert level of 3
    assert not {"notverified", "verified", "twoprops", "twoprops2", "newiponly"} & set(by_user)


def test_td_2h_06_marker_rules(synth):
    found = names(synth("TD-2H-06"))
    assert {"notverified", "twoprops2", "roleadd", "overnight"} <= found
    # "not verified: ..." does count as unverified (above); a real marker, also in a second
    # property of the reset, counts as verified
    assert not {"verified", "twoprops", "emptydev", "newiponly"} & found


def test_td_2h_05_campaign_volume(synth):
    rows = synth("TD-2H-05")
    burst = [r for r in rows if r["Agent"] == upn("agent.burst")]
    assert len(burst) == 6 and {r["ResetsToday"] for r in burst} == {6}
    assert {r["TimeGenerated"].date() for r in burst} == {D.date()}  # only on the burst day
    # the 2-reset day after the burst and every 1-reset day stay quiet
    # agent.busy (5 a day usually, 6 on the burst day) is quiet once it has 14 days of history
    busy_late = [r for r in rows if r["Agent"] == upn("agent.busy")
                 and r["TimeGenerated"] >= D - timedelta(days=14)]
    assert busy_late == []
