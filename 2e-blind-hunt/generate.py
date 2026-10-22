#!/usr/bin/env python3
"""2E Blind Hunt data generator (plain Python, standard library only, no network, no AI).

Writes fictional Entra-style sign-in and audit events for Maple Harbour Credit Union
(a made-up credit union; every address is under mapleharbour.example). The same --seed
always produces byte-identical files.

Hidden inside the normal traffic are:
  * exactly --takeovers account-takeover sequences (the real thing a SOC analyst must find), and
  * at least --lookalikes benign look-alikes (events that LOOK suspicious but are fine).
The plaintext answer key is written only where --labels-out says. For the real hunt dataset
that key is sealed with openssl straight after generation (see 2e-blind-hunt/README.md).

Design rules (see the README for the plain-English version):
  * Hidden events are built with the same helpers, pools, formats and second-level jitter as
    normal events, and the data never contains words or ids that give the answer away.
  * Every IP address comes from the documentation ranges reserved by RFC 5737
    (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), so none can point at a real machine.
  * Randomness comes only from random.Random(seed); the seed may be any integer, including a
    128-bit one. Correlation ids are derived from the seed with SHA-256 (not uuid4, and not from
    the random generator's own stream, so the public ids reveal nothing about its internal
    state). There is no clock or set-ordering dependence, so output is reproducible.
    The "generated" date in the labels is the last local day of the data window.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path

# --------------------------------------------------------------------------------------
# Constants and pools
# --------------------------------------------------------------------------------------

TENANT_DOMAIN = "mapleharbour.example"
DEFAULT_START = "2026-09-14"  # a Monday; the first local day of the data window
LOCAL_UTC_OFFSET_HOURS = 4  # Toronto in daylight time (UTC-4), fixed for simplicity
VERIFY_MARKER = "verified: callback to number on file"
FAIL_RATE = 0.06  # share of normal sessions that start with one failed attempt
ROUTINE_AUDIT_SHARE = 0.03  # share of the --events target used by routine audit events

# ResultType values used (TODO(verify) each against Microsoft's sign-in error code list).
RESULT_OK = "0"
RESULT_BAD_PASSWORD = "50126"
RESULT_MFA_FAILED = "500121"

REQ_SINGLE = "singleFactorAuthentication"
REQ_MULTI = "multiFactorAuthentication"

# OperationName values (TODO(verify) each exact spelling against Microsoft's audit log docs).
OP_RESET_ADMIN = "Reset password (by admin)"
OP_RESET_SELF = "Reset password (self-service)"
OP_REGISTER = "User registered security info"
OP_ADD_ROLE = "Add member to role"
OP_ADD_GROUP = "Add member to group"
OP_UPDATE_USER = "Update user"
RECOVERY_MAIL_DOMAINS = ["freemail.example", "mailhost.example", "webmail.example"]

FIRST_NAMES = [
    "Amara", "Benoit", "Chantal", "Dmitri", "Elena", "Farid", "Giulia", "Haruto", "Imani",
    "Jasper", "Keiko", "Lucas", "Maya", "Noor", "Owen", "Priya", "Quentin", "Rosa", "Sanjay",
    "Tamsin", "Uma", "Viktor", "Wren", "Xavier", "Yuki", "Zainab", "Arjun", "Beatrix",
    "Callum", "Divya", "Emeka", "Fiona", "Gavin", "Hana", "Isaac", "Jorge", "Katya", "Liam",
    "Mei", "Nikolai",
]
LAST_NAMES = [
    "Abernathy", "Bergeron", "Castellano", "Dubois", "Eriksen", "Fontaine", "Grewal",
    "Hashemi", "Ivanov", "Jovanovic", "Kowalczyk", "Lindqvist", "Macdonald", "Nakamura",
    "Okafor", "Pelletier", "Quesnel", "Rasmussen", "Sandhu", "Tremblay", "Underhill",
    "Vasquez", "Whitcombe", "Xu", "Yilmaz", "Zielinski", "Adeyemi", "Brennan", "Chowdhury",
    "Delacroix", "Fitzgerald", "Guerrero", "Hartmann", "Iyer", "Johansson", "Kaplan",
    "Lavoie", "Moreau", "Novak", "Petrov",
]

# (department, title) for the 50 staff, in a fixed order.
STAFF_PLAN = (
    [("branch", "Branch Manager")] * 3
    + [("branch", "Teller")] * 8
    + [("branch", "Member Service Representative")] * 7
    + [("lending", "Loan Officer")] * 7
    + [("lending", "Underwriter")] * 3
    + [("finance", "Finance Clerk")] * 5
    + [("finance", "Accountant")] * 2
    + [("finance", "Finance Manager")]
    + [("IT", "Systems Administrator")] * 3
    + [("IT", "Network Analyst")] * 2
    + [("IT", "IT Support Specialist")]
    + [("helpdesk", "Helpdesk Analyst")] * 2
    + [("executives", "Chief Executive Officer"), ("executives", "Chief Financial Officer")]
    + [("executives", "Chief Operating Officer"), ("executives", "VP Lending")]
    + [("executives", "Executive Assistant")] * 2
)

# (city, state/province, country) -- the first is also the head-office city.
LOC_TORONTO = ("Toronto", "Ontario", "CA")
LOC_MISSISSAUGA = ("Mississauga", "Ontario", "CA")
LOC_HAMILTON = ("Hamilton", "Ontario", "CA")
BRANCHES = [  # (location, shared office IP)
    (LOC_TORONTO, "203.0.113.11"),
    (LOC_MISSISSAUGA, "203.0.113.12"),
    (LOC_HAMILTON, "203.0.113.13"),
]
HQ_LOC, HQ_IP = LOC_TORONTO, "203.0.113.10"
REMOTE_LOCS = [
    ("Calgary", "Alberta", "CA"),
    ("Halifax", "Nova Scotia", "CA"),
    ("Vancouver", "British Columbia", "CA"),
    ("Winnipeg", "Manitoba", "CA"),
    ("Calgary", "Alberta", "CA"),
]
# One shared pool of places outside Canada. Travellers, VPN users and the hidden sequences all
# draw from the same few places (Generator.foreign_choices), so a country alone decides nothing.
FOREIGN_LOCS = [
    ("Orlando", "Florida", "US"),
    ("Mexico City", "Ciudad de Mexico", "MX"),
    ("London", "England", "GB"),
    ("Phoenix", "Arizona", "US"),
    ("Amsterdam", "North Holland", "NL"),
    ("Chicago", "Illinois", "US"),
    ("Bucharest", "Bucuresti", "RO"),
    ("Lagos", "Lagos", "NG"),
    ("Sao Paulo", "Sao Paulo", "BR"),
    ("Hanoi", "Hanoi", "VN"),
    ("Paris", "Ile-de-France", "FR"),
    ("Singapore", "Singapore", "SG"),
]
N_FOREIGN_CHOICES = 4  # how many of those places are in use in one dataset
PERSONAL_DEVICE_SHARE = 0.3  # share of staff who also sign in from a personal computer

HOME_IP_POOL = [f"203.0.113.{i}" for i in range(100, 200)]
REMOTE_IP_POOL = [f"192.0.2.{i}" for i in range(10, 100)]
FOREIGN_IP_POOL = [f"198.51.100.{i}" for i in range(1, 255)] + [
    f"203.0.113.{i}" for i in range(201, 255)
]

APPS_COMMON = (
    ["Office 365 Exchange Online"] * 4 + ["Microsoft Teams"] * 3 + ["SharePoint Online"] * 2
)
APPS_BY_DEPT = {
    "branch": ["Branch Teller Portal"] * 3,
    "lending": ["Loan Origination System"] * 3,
    "finance": ["General Ledger"] * 3,
    "IT": ["Azure Portal"] * 2 + ["Microsoft Entra admin center"] * 2,
    "helpdesk": ["ServiceDesk Portal"] * 3 + ["Microsoft Entra admin center"],
    "executives": ["Board Reports"] * 2,
}
CORE_APP = "Core Banking Admin"
CORE_DEPTS = ("finance", "IT", "executives")
ENTRA_ADMIN_APP = "Microsoft Entra admin center"

OS_POOL = ["Windows 11"] * 5 + ["Windows 10"] * 2 + ["MacOs"]
BROWSER_POOL = ["Edge"] * 4 + ["Chrome"] * 3 + ["Firefox"]
PERSONAL_OS_POOL = ["Windows 11", "Windows 10", "MacOs"]
PERSONAL_BROWSER_POOL = ["Chrome", "Firefox", "Edge"]  # Safari is added for MacOs only
TRUST_MANAGED = ["Hybrid Azure AD joined", "Azure AD joined"]
TRUST_PERSONAL = ["Azure AD registered", ""]

GROUPS = [
    "Branch Staff", "Lending Team", "Finance Team", "All Staff", "VPN Users", "Loan Reviewers",
]
ROLES = [
    "Helpdesk Administrator", "Global Reader", "Security Reader", "User Administrator",
    "Groups Administrator", "Authentication Administrator",
]
JOB_TITLES = ["Senior Teller", "Loan Officer II", "Accountant II", "Team Lead", "Analyst"]
NOTE_BASES = [
    "INC{n}: password reset on request",
    "INC{n}: caller locked out, reset completed",
    "INC{n}: user waiting on the phone, reset done",
    "INC{n}: reset per phone request",
]
MFA_METHODS = ["Microsoft Authenticator app", "SMS to +1 416-555-01{xx}", "Phone call to +1 416-555-01{xx}"]


@dataclass
class Device:
    device_id: str
    name: str
    os: str
    browser: str
    trust: str

    def detail(self) -> dict:
        return {
            "deviceId": self.device_id,
            "displayName": self.name,
            "operatingSystem": self.os,
            "browser": self.browser,
            "trustType": self.trust,
        }


@dataclass
class Person:
    upn: str
    display: str
    first: str
    dept: str
    title: str
    loc: tuple
    office_ip: str
    home_ip: str
    remote: bool
    laptop: Device
    mobile: Device | None
    personal: Device | None
    apps: list
    volume: float
    active_from: datetime | None = None
    away: list = field(default_factory=list)  # (start, end, location, ip): travelling or on VPN

    @property
    def privileged(self) -> bool:
        return self.title == "Systems Administrator"


@dataclass
class Case:
    """One hidden record (a takeover sequence or a benign look-alike) and its events."""

    user: Person
    summary: str
    events: list = field(default_factory=list)  # (time, correlation id)

    def label(self, case_id: str) -> dict:
        ordered = sorted(self.events)
        return {
            "id": case_id,
            "user": self.user.upn,
            "start": fmt(ordered[0][0]),
            "end": fmt(ordered[-1][0]),
            "evidence": [cid for _, cid in ordered],
            "summary": self.summary,
        }


def fmt(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------------------
# The generator
# --------------------------------------------------------------------------------------


class Generator:
    def __init__(self, seed, days, events, takeovers, lookalikes, start):
        self.rng = random.Random(seed)
        self.seed = seed
        self.days = days
        self.events = events
        self.n_takeovers = takeovers
        self.n_lookalikes = lookalikes
        self.start = start
        # t0 = local midnight of day 0, written in UTC (naive datetimes; "Z" added on output)
        self.t0 = datetime(start.year, start.month, start.day) + timedelta(
            hours=LOCAL_UTC_OFFSET_HOURS
        )
        self.t_end = self.t0 + timedelta(days=days)
        self.signin_rows: list = []
        self.audit_rows: list = []
        self.used_device_names: set = set()
        self.people: list = []
        self.helpdesk: list = []
        self.sysadmins: list = []
        self.free_pool: list = []
        self.takeover_cases: list = []
        self.lookalike_cases: list = []
        self.foreign_choices: list = []
        self.uuid_counter = 0

    # ---- small helpers -------------------------------------------------------------

    def uuid(self) -> str:
        self.uuid_counter += 1
        digest = hashlib.sha256(f"2e-id:{self.seed}:{self.uuid_counter}".encode()).digest()
        return str(uuid.UUID(bytes=digest[:16], version=4))

    def pick(self, seq):
        return seq[self.rng.randrange(len(seq))]

    def minutes(self, lo, hi) -> timedelta:
        """A random duration between lo and hi minutes with second-level jitter."""
        return timedelta(seconds=self.rng.randrange(int(lo * 60), int(hi * 60)))

    def local_time(self, day, minute) -> datetime:
        return self.t0 + timedelta(days=day, minutes=minute, seconds=self.rng.randrange(60))

    def is_weekday(self, day) -> bool:
        return (self.start + timedelta(days=day)).weekday() < 5

    def local_of(self, t) -> datetime:
        return t - timedelta(hours=LOCAL_UTC_OFFSET_HOURS)

    # ---- people ----------------------------------------------------------------------

    def make_device(self, kind: str, first: str = "") -> Device:
        rng = self.rng
        if kind == "laptop":
            while True:
                name = f"MHCU-LT-{rng.randrange(1000, 9999)}"
                if name not in self.used_device_names:
                    break
            self.used_device_names.add(name)
            return Device(self.uuid(), name, self.pick(OS_POOL), self.pick(BROWSER_POOL),
                          self.pick(TRUST_MANAGED))
        if kind == "mobile":
            if rng.random() < 0.55:
                return Device(self.uuid(), f"{first}-iPhone", "iOS", "Mobile Safari",
                              "Azure AD registered")
            return Device(self.uuid(), f"{first}-Android", "Android", "Chrome Mobile",
                          "Azure AD registered")
        # "personal": a home computer, also used for the devices unknown to the staff member
        letters = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"
        while True:
            name = "DESKTOP-" + "".join(self.pick(letters) for _ in range(7))
            if not re.search(r"(?i)(tk|la)\d", name):  # keep the no-tells rule trivially true
                break
        os_name = self.pick(PERSONAL_OS_POOL)
        browsers = PERSONAL_BROWSER_POOL + (["Safari"] if os_name == "MacOs" else [])
        return Device(self.uuid(), name, os_name, self.pick(browsers), self.pick(TRUST_PERSONAL))

    def build_people(self) -> None:
        rng = self.rng
        seen = set()
        names = []
        for _ in STAFF_PLAN:
            while True:
                first, last = self.pick(FIRST_NAMES), self.pick(LAST_NAMES)
                upn = f"{first}.{last}@{TENANT_DOMAIN}".lower()
                if upn not in seen:
                    seen.add(upn)
                    names.append((first, last, upn))
                    break
        remote_candidates = [
            i for i, (dept, title) in enumerate(STAFF_PLAN)
            if title in ("Loan Officer", "Finance Clerk", "Accountant")
        ]
        remote_idx = rng.sample(remote_candidates, len(REMOTE_LOCS))
        remote_by_idx = dict(zip(sorted(remote_idx), REMOTE_LOCS, strict=True))
        gta_homes = rng.sample(HOME_IP_POOL, len(STAFF_PLAN))
        remote_homes = rng.sample(REMOTE_IP_POOL, len(REMOTE_LOCS))
        personal_idx = set(rng.sample(range(len(STAFF_PLAN)),
                                      round(PERSONAL_DEVICE_SHARE * len(STAFF_PLAN))))
        branch_count = 0
        remote_count = 0
        for i, (dept, title) in enumerate(STAFF_PLAN):
            first, last, upn = names[i]
            if i in remote_by_idx:
                loc, office_ip, home_ip, remote = (
                    remote_by_idx[i], remote_homes[remote_count], remote_homes[remote_count], True,
                )
                remote_count += 1
            elif dept == "branch":
                loc, office_ip = BRANCHES[branch_count % len(BRANCHES)]
                home_ip, remote = gta_homes[i], False
                branch_count += 1
            else:
                loc, office_ip, home_ip, remote = HQ_LOC, HQ_IP, gta_homes[i], False
            apps = list(APPS_COMMON) + list(APPS_BY_DEPT[dept])
            if dept in CORE_DEPTS:
                apps.append(CORE_APP)
            volume = 0.8 + rng.random() * 0.4
            volume *= {"helpdesk": 1.3, "IT": 1.2, "executives": 0.7}.get(dept, 1.0)
            person = Person(
                upn=upn, display=f"{first} {last}", first=first, dept=dept, title=title,
                loc=loc, office_ip=office_ip, home_ip=home_ip, remote=remote,
                laptop=self.make_device("laptop"),
                mobile=self.make_device("mobile", first) if rng.random() < 0.5 else None,
                personal=self.make_device("personal") if i in personal_idx else None,
                apps=apps, volume=volume,
            )
            self.people.append(person)
        self.helpdesk = [p for p in self.people if p.dept == "helpdesk"]
        self.sysadmins = [p for p in self.people if p.privileged]
        self.free_pool = list(self.people)
        rng.shuffle(self.free_pool)

    def take_user(self, predicate) -> Person:
        """Take a not-yet-used person matching predicate (falls back to any unused non-helpdesk)."""
        for fallback in (predicate, lambda p: p.dept != "helpdesk"):
            for i, p in enumerate(self.free_pool):
                if fallback(p):
                    return self.free_pool.pop(i)
        raise SystemExit("not enough staff for that many separate cases; lower the case counts")

    # ---- row builders ----------------------------------------------------------------

    def signin(self, t, p, dev, ip, loc, app, result=RESULT_OK, req=REQ_MULTI) -> str:
        cid = self.uuid()
        self.signin_rows.append({
            "TimeGenerated": fmt(t),
            "UserPrincipalName": p.upn,
            "IPAddress": ip,
            "Location": {"city": loc[0], "state": loc[1], "countryOrRegion": loc[2]},
            "AppDisplayName": app,
            "ResultType": result,
            "AuthenticationRequirement": req,
            "DeviceDetail": dev.detail(),
            "CorrelationId": cid,
        })
        return cid

    def audit(self, t, op, by: Person, by_ip, target: Person, props) -> str:
        cid = self.uuid()
        self.audit_rows.append({
            "TimeGenerated": fmt(t),
            "OperationName": op,
            "InitiatedBy": {"user": {"userPrincipalName": by.upn, "ipAddress": by_ip}},
            "TargetResources": [{
                "displayName": target.display,
                "userPrincipalName": target.upn,
                "modifiedProperties": [
                    {"displayName": n, "oldValue": o, "newValue": v} for n, o, v in props
                ],
            }],
            "CorrelationId": cid,
        })
        return cid

    def note(self, verified: bool) -> str:
        text = self.pick(NOTE_BASES).format(n=self.rng.randrange(10000, 99999))
        return f"{text}; {VERIFY_MARKER}" if verified else text

    def mfa_method(self) -> str:
        return self.pick(MFA_METHODS).format(xx=f"{self.rng.randrange(100):02d}")

    def reset_by_helpdesk(self, t, victim: Person, verified: bool) -> str:
        """An admin password reset. Every reset, hidden or not, is built the same way: inside the
        agent's working day, from the agent's usual address, after a normal agent sign-in, and
        followed by the user trying the old password once or twice."""
        agent = self.pick(self.helpdesk)
        self.known_signin(t - self.minutes(3, 20), agent)
        ip = self.usual_context(agent, t)[1]
        cid = self.audit(t, OP_RESET_ADMIN, agent, ip, victim,
                         [("TicketNote", None, self.note(verified))])
        for _ in range(self.rng.randrange(1, 3)):
            tf = t + self.minutes(1, 25)
            dev, uip, uloc = self.usual_context(victim, tf)
            self.signin(tf, victim, dev, uip, uloc, self.pick(victim.apps),
                        RESULT_BAD_PASSWORD, REQ_SINGLE)
        return cid

    def recovery_mail(self, p: Person) -> str:
        domain = self.pick(RECOVERY_MAIL_DOMAINS)
        return f"{p.first}.{self.rng.randrange(100, 999)}@{domain}".lower()

    def register_mfa(self, t, p: Person, ip) -> str:
        return self.audit(t, OP_REGISTER, p, ip, p, [("StrongAuthenticationMethod", None,
                                                       self.mfa_method())])

    def usual_context(self, p: Person, t):
        """Where and how this person normally signs in at time t (known device, usual IP)."""
        away = self.away_at(p, t)
        if away:
            return p.laptop, away[1], away[0]
        local = self.local_of(t)
        at_work = local.weekday() < 5 and 8 <= local.hour < 18
        ip = p.office_ip if (at_work or p.remote) else p.home_ip
        return p.laptop, ip, p.loc

    @staticmethod
    def away_at(p: Person, t):
        """(location, ip) if p is travelling or on a VPN at time t, else None."""
        for start, end, loc, ip in p.away:
            if start <= t <= end:
                return loc, ip
        return None

    def away_spell(self, p: Person, t, span, loc, ip, n_events) -> list:
        """Mark p as away from t to t+span (every sign-in then comes from loc/ip) and write
        n_events explicit sign-ins from the usual laptop inside that window."""
        p.away.append((t, t + span, loc, ip))
        events = []
        for offset in sorted(self.rng.randrange(0, int(span.total_seconds()))
                             for _ in range(n_events)):
            ts = t + timedelta(seconds=offset)
            events.append((ts, self.signin(ts, p, p.laptop, ip, loc, self.pick(p.apps))))
        return events

    def known_signin(self, t, p: Person, req=REQ_MULTI) -> str:
        dev, ip, loc = self.usual_context(p, t)
        return self.signin(t, p, dev, ip, loc, self.pick(p.apps), req=req)

    # ---- placing hidden events in time ---------------------------------------------

    def place(self, span: timedelta, hours, weekday) -> datetime:
        """Pick a start time (local hour range) so that start + span fits in the window.

        weekday: True = weekdays only, False = weekends only, None = any day.
        """
        lo, hi = int(hours[0] * 60), int(hours[1] * 60)
        for attempt in range(400):
            day = self.rng.randrange(self.days)
            if attempt < 300 and weekday is not None and self.is_weekday(day) != weekday:
                continue
            t = self.local_time(day, self.rng.randrange(lo, hi))
            if t + span < self.t_end - timedelta(minutes=5):
                return t
        raise SystemExit("cannot fit the hidden events in the requested window; use more --days")

    # ---- hidden takeover sequences -------------------------------------------------

    def unfamiliar_context(self, victim: Person):
        """A device, address and place never seen for this person. Same pools as travellers."""
        loc = self.pick(self.foreign_choices)
        if self.rng.random() < 0.4:
            dev = self.make_device("mobile", victim.first)
        else:
            dev = self.make_device("personal")
        return dev, self.pick(FOREIGN_IP_POOL), loc

    def build_takeover(self, index: int) -> Case:
        # Every reset happens inside the helpdesk agent's working day (weekday, 09:00-16:30), so the
        # hour of a sequence varies through the later steps (b) to (d) instead.
        templates = [
            {"pick": lambda p: p.title == "Finance Clerk", "hours": (9.5, 15),
             "gap_b": (12, 40), "gap_c": (5, 25), "gap_d": (40, 120), "step_d": "app"},
            {"pick": lambda p: p.title == "Executive Assistant", "hours": (15, 16.5),
             "gap_b": (150, 330), "gap_c": (5, 20), "gap_d": (25, 90), "step_d": "recovery"},
            {"pick": lambda p: p.privileged, "hours": (9, 11),
             "gap_b": (20, 50), "gap_c": (2, 10), "gap_d": (10, 40), "step_d": "role"},
            # this one spans two days: the new MFA method is registered the next morning
            {"pick": lambda p: p.dept == "lending", "hours": (15.5, 16.5),
             "gap_b": (16 * 60, 21 * 60), "gap_c": (10, 40), "gap_d": (90, 240),
             "step_d": "recovery"},
            {"pick": lambda p: p.dept == "executives" and p.title != "Executive Assistant",
             "hours": (14, 16), "gap_b": (300, 480), "gap_c": (5, 15), "gap_d": (20, 60),
             "step_d": "app"},
        ]
        tpl = templates[index % len(templates)]
        victim = self.take_user(tpl["pick"])
        dev, ip, loc = self.unfamiliar_context(victim)
        gap_b = self.minutes(*tpl["gap_b"])
        gap_c = self.minutes(*tpl["gap_c"])
        gap_d = self.minutes(*tpl["gap_d"])
        t_a = self.place(gap_b + gap_c + gap_d, tpl["hours"], True)
        t_b, t_c = t_a + gap_b, t_a + gap_b + gap_c
        t_d = t_c + gap_d
        case = Case(victim, "")
        case.events.append((t_a, self.reset_by_helpdesk(t_a, victim, verified=False)))
        case.events.append((t_b, self.register_mfa(t_b, victim, ip)))
        case.events.append((t_c, self.signin(t_c, victim, dev, ip, loc, self.pick(victim.apps))))
        kind = tpl["step_d"]
        if kind == "role":
            other = self.pick([p for p in self.people if p is not victim])
            cid = self.audit(t_d, OP_ADD_ROLE, victim, ip, other,
                             [("Role.DisplayName", None, self.pick(ROLES))])
            tail = "added another account to an administrator role"
        elif kind == "recovery":
            cid = self.audit(t_d, OP_UPDATE_USER, victim, ip, victim,
                             [("OtherMails", None, self.recovery_mail(victim))])
            tail = "changed the account's recovery email address to an outside mailbox"
        else:
            cid = self.signin(t_d, victim, dev, ip, loc, CORE_APP)
            tail = "signed in to the Core Banking Admin app"
        case.events.append((t_d, cid))
        case.summary = (
            f"{victim.display} ({victim.title}) had their password reset by the helpdesk with no "
            "callback-verification note, a new MFA method was registered, and the account then "
            f"signed in from a device, IP address and country never seen for them and "
            f"{tail}."
        )
        return case

    # ---- benign look-alikes ----------------------------------------------------------

    def build_lookalike(self, index: int) -> Case:
        kinds = [
            self.la_lost_phone, self.la_rushed_reset, self.la_travelling, self.la_new_hire,
            self.la_role_change, self.la_self_service_reset, self.la_phone_upgrade,
            self.la_vpn, self.la_reset_known_device, self.la_rushed_reset, self.la_rushed_reset,
        ]
        return kinds[index % len(kinds)]()

    def la_lost_phone(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        b, c = self.minutes(10, 45), self.minutes(5, 30)
        t = self.place(b + c + timedelta(minutes=1), (9, 16), True)
        case = Case(p, (
            f"{p.display} lost their phone; the helpdesk reset the password after a callback to "
            "the number on file (written in the ticket), the new MFA method was registered, "
            "and the next sign-in came from their usual laptop at their usual place."))
        case.events.append((t, self.reset_by_helpdesk(t, p, verified=True)))
        _, ip, _ = self.usual_context(p, t + b)
        case.events.append((t + b, self.register_mfa(t + b, p, ip)))
        case.events.append((t + b + c, self.known_signin(t + b + c, p)))
        return case

    def la_rushed_reset(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        gap = self.minutes(3, 30)
        t = self.place(gap + timedelta(hours=1), (9, 16), True)
        case = Case(p, (
            f"A busy helpdesk agent reset the password for {p.display} without the callback "
            "note, but only sign-ins from their known laptop and usual place followed and no new "
            "MFA method was added."))
        case.events.append((t, self.reset_by_helpdesk(t, p, verified=False)))
        t1 = t + gap
        case.events.append((t1, self.known_signin(t1, p)))
        if self.rng.random() < 0.6:
            t2 = t1 + self.minutes(20, 90)
            case.events.append((t2, self.known_signin(t2, p)))
        return case

    def la_travelling(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        loc, ip = self.pick(self.foreign_choices), self.pick(FOREIGN_IP_POOL)
        span = timedelta(days=2)
        t = self.place(span, (8, 12), True)
        case = Case(p, (
            f"{p.display} was travelling: sign-ins came from a new country but only from devices "
            "they had used before, with no password reset and no new MFA method."))
        case.events += self.away_spell(p, t, span, loc, ip, self.rng.randrange(3, 5))
        return case

    def la_new_hire(self) -> Case:
        p = self.take_user(lambda q: q.dept in ("branch", "lending", "finance"))
        return self.new_hire_case(p)

    def new_hire_case(self, p: Person) -> Case:
        gap_first, gap_reg = self.minutes(0, 20), self.minutes(5, 35)
        t = self.place(gap_first + gap_reg + timedelta(minutes=1), (8.5, 10), True)
        p.active_from = t
        case = Case(p, (
            f"{p.display} is a new hire: the first sign-ins from a not-yet-seen laptop and the "
            "first MFA registration are normal onboarding, with no password reset."))
        t1 = t + gap_first
        cid1 = self.signin(t1, p, p.laptop, p.office_ip, p.loc, "Microsoft 365 portal",
                           req=REQ_SINGLE)
        t2 = t1 + gap_reg
        cid2 = self.register_mfa(t2, p, p.office_ip)
        case.events += [(t1, cid1), (t2, cid2)]
        return case

    def la_role_change(self) -> Case:
        admin = self.pick(self.sysadmins)
        target = self.take_user(lambda q: q.dept in ("IT", "helpdesk"))
        gap = self.minutes(1, 10)
        t = self.place(gap + timedelta(minutes=1), (9, 16), True)
        case = Case(target, (
            f"A scheduled role change: IT admin {admin.display} added {target.display} to a "
            "role during business hours from the office network, after a normal admin sign-in."))
        case.events.append((t, self.signin(t, admin, admin.laptop, admin.office_ip, admin.loc,
                                           ENTRA_ADMIN_APP)))
        t2 = t + gap
        case.events.append((t2, self.audit(t2, OP_ADD_ROLE, admin, admin.office_ip, target,
                                           [("Role.DisplayName", None, self.pick(ROLES))])))
        return case

    def la_self_service_reset(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        gap = self.minutes(1, 6)
        t = self.place(gap + timedelta(minutes=1), (6.5, 9), True)
        case = Case(p, (
            f"{p.display} reset their own password with self-service reset from their usual "
            "place and then signed in from their usual laptop."))
        _, ip, _ = self.usual_context(p, t)
        case.events.append((t, self.audit(t, OP_RESET_SELF, p, ip, p,
                                          [("Method", None, "mobile app code")])))
        case.events.append((t + gap, self.known_signin(t + gap, p)))
        return case

    def la_phone_upgrade(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        gap = self.minutes(5, 25)
        t = self.place(gap + timedelta(minutes=1), (9, 16), True)
        case = Case(p, (
            f"{p.display} registered a new MFA method after upgrading their phone, from their "
            "usual IP address, and then signed in from their usual laptop."))
        _, ip, _ = self.usual_context(p, t)
        case.events.append((t, self.register_mfa(t, p, ip)))
        case.events.append((t + gap, self.known_signin(t + gap, p)))
        return case

    def la_vpn(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        loc, ip = self.pick(self.foreign_choices), self.pick(FOREIGN_IP_POOL)
        span = timedelta(hours=4)
        t = self.place(span, (9, 13), True)
        case = Case(p, (
            f"{p.display} used a VPN, so the sign-in place changed country, but every sign-in "
            "came from a device they had used before, with no reset and no new MFA method."))
        case.events += self.away_spell(p, t, span, loc, ip, 3)
        return case

    def la_reset_known_device(self) -> Case:
        p = self.take_user(lambda q: q.dept != "helpdesk")
        gap = self.minutes(5, 40)
        t = self.place(gap + timedelta(minutes=1), (9, 16), True)
        case = Case(p, (
            f"The helpdesk reset {p.display}'s password after a callback to the number on file "
            "(written in the ticket); the only sign-in afterwards was from their usual laptop."))
        case.events.append((t, self.reset_by_helpdesk(t, p, verified=True)))
        case.events.append((t + gap, self.known_signin(t + gap, p)))
        return case

    # ---- normal life -----------------------------------------------------------------

    def sample_minute(self, weekday: bool) -> int:
        rng = self.rng
        if not weekday:
            return rng.randrange(9 * 60, 21 * 60)
        u = rng.random()
        if u < 0.82:
            return int(rng.triangular(8 * 60, 17.5 * 60, 11.5 * 60))
        if u < 0.95:
            return rng.randrange(18 * 60, 22 * 60 + 30)
        return rng.randrange(6 * 60, 8 * 60)

    def session(self, p: Person, day: int) -> None:
        rng = self.rng
        weekday = self.is_weekday(day)
        t = None
        for _ in range(20):
            t = self.local_time(day, self.sample_minute(weekday))
            if p.active_from is None or t >= p.active_from:
                break
        else:
            return
        local = self.local_of(t)
        at_work = weekday and 8 <= local.hour < 18
        ip = p.office_ip if (at_work or p.remote) else p.home_ip
        loc = p.loc
        away = self.away_at(p, t)
        if away:  # travelling or on a VPN: everything comes from the away place
            loc, ip = away
        r = rng.random()
        if p.personal and r < 0.15:
            dev = p.personal
        elif p.mobile and r < 0.4:
            dev = p.mobile
        else:
            dev = p.laptop
        app = self.pick(p.apps)
        if ip == p.office_ip and dev is p.laptop and not p.remote and not away:
            req = REQ_SINGLE if rng.random() < 0.6 else REQ_MULTI
        else:
            req = REQ_SINGLE if rng.random() < 0.25 else REQ_MULTI
        if rng.random() < FAIL_RATE:
            if rng.random() < 0.85:
                self.signin(t, p, dev, ip, loc, app, RESULT_BAD_PASSWORD, REQ_SINGLE)
                t_ok = t + self.minutes(0.25, 1.5)
            else:
                self.signin(t, p, dev, ip, loc, app, RESULT_MFA_FAILED, REQ_MULTI)
                t_ok = t + self.minutes(0.5, 2)
            self.signin(t_ok, p, dev, ip, loc, app, RESULT_OK, req)
        else:
            self.signin(t, p, dev, ip, loc, app, RESULT_OK, req)

    def normal_signins(self, sessions_target: float) -> None:
        weights = []
        for p in self.people:
            for day in range(self.days):
                w = (1.0 if self.is_weekday(day) else 0.1) * p.volume
                if p.dept in ("helpdesk", "IT") and not self.is_weekday(day):
                    w *= 2
                if p.active_from is not None:
                    day_end = self.t0 + timedelta(days=day + 1)
                    day_start = self.t0 + timedelta(days=day)
                    if p.active_from >= day_end:
                        w = 0.0
                    elif p.active_from > day_start:
                        w *= 0.5
                weights.append((p, day, w))
        total = sum(w for _, _, w in weights)
        scale = sessions_target / total
        for p, day, w in weights:
            n = int(scale * w + self.rng.random())  # stochastic rounding keeps the total close
            for _ in range(n):
                self.session(p, day)

    def routine_audits(self, count: int) -> None:
        rng = self.rng
        for _ in range(count):
            u = rng.random()
            if u < 0.55:
                admin = self.pick(self.sysadmins)
                t = self.place(timedelta(minutes=1), (9, 16.5), True)
                target = self.pick(self.people)
                self.audit(t, OP_ADD_GROUP, admin, admin.office_ip, target,
                           [("Group.DisplayName", None, self.pick(GROUPS))])
            elif u < 0.85:
                admin = self.pick(self.sysadmins)
                t = self.place(timedelta(minutes=1), (9, 16.5), True)
                target = self.pick(self.people)
                if rng.random() < 0.5:
                    prop = ("JobTitle", None, self.pick(JOB_TITLES))
                else:
                    prop = ("MobilePhone", None, f"+1 416-555-01{rng.randrange(100):02d}")
                self.audit(t, OP_UPDATE_USER, admin, admin.office_ip, target, [prop])
            else:
                p = self.pick([q for q in self.people if q.active_from is None])
                t = self.place(timedelta(minutes=1), (6.5, 21), None)
                _, ip, _ = self.usual_context(p, t)
                self.audit(t, OP_RESET_SELF, p, ip, p, [("Method", None, "mobile app code")])

    def routine_resets(self, count: int) -> None:
        """Ordinary helpdesk resets (some with the callback note, some without) that are not
        part of any labelled case: only known-device sign-ins follow, no new MFA method."""
        for i in range(count):
            p = self.take_user(lambda q: q.dept != "helpdesk")
            t = self.place(timedelta(hours=1), (9, 16.5), True)
            self.reset_by_helpdesk(t, p, verified=(i % 2 == 0))
            for _ in range(self.rng.randrange(1, 3)):
                ts = t + self.minutes(5, 50)
                self.known_signin(ts, p)

    def routine_recovery_changes(self, count: int) -> None:
        """Ordinary changes of a recovery email address (the same property a hidden sequence
        changes): half self-service by the user from their usual place, half done by the
        helpdesk during the working day. Each follows a normal sign-in from a known device and
        involves no password reset and no new MFA method."""
        for i in range(count):
            p = self.take_user(lambda q: q.dept != "helpdesk")
            if i % 2 == 0:
                t = self.place(timedelta(hours=1), (8, 20), None)
                self.known_signin(t - self.minutes(2, 15), p)
                ip = self.usual_context(p, t)[1]
                mail = self.recovery_mail(p)
                self.audit(t, OP_UPDATE_USER, p, ip, p, [("OtherMails", None, mail)])
            else:
                t = self.place(timedelta(hours=1), (9, 16.5), True)
                agent = self.pick(self.helpdesk)
                self.known_signin(t - self.minutes(3, 20), agent)
                self.known_signin(t - self.minutes(2, 15), p)
                ip = self.usual_context(agent, t)[1]
                mail = self.recovery_mail(p)
                self.audit(t, OP_UPDATE_USER, agent, ip, p, [("OtherMails", None, mail)])
            self.known_signin(t + self.minutes(5, 60), p)

    def routine_away(self) -> None:
        """Unlabelled travellers and VPN users, one per place in use, so that every place the
        hidden sequences use is also an ordinary place for ordinary people."""
        for i, loc in enumerate(self.foreign_choices):
            p = self.take_user(lambda q: q.dept != "helpdesk")
            ip = self.pick(FOREIGN_IP_POOL)
            if i % 2 == 0:
                span = timedelta(days=min(2, self.days - 1))
                t = self.place(span, (8, 12), True)
            else:
                span = timedelta(hours=4)
                t = self.place(span, (9, 13), True)
            self.away_spell(p, t, span, loc, ip, 2)

    # ---- driver ------------------------------------------------------------------------

    def run(self) -> dict:
        self.build_people()
        self.foreign_choices = self.rng.sample(FOREIGN_LOCS, N_FOREIGN_CHOICES)
        takeover_labels, lookalike_labels = [], []
        for i in range(self.n_takeovers):
            self.takeover_cases.append(self.build_takeover(i))
        # at least 11 look-alikes whenever 8 or more are asked for, so that all eight named
        # kinds and two or three rushed-agent cases are present
        n_la = self.n_lookalikes if self.n_lookalikes < 8 else max(self.n_lookalikes, 11)
        for i in range(n_la):
            self.lookalike_cases.append(self.build_lookalike(i))
        for _ in range(self.days // 7):  # routine new hires: normal, unlabelled onboarding
            p = self.take_user(lambda q: q.dept in ("branch", "lending", "finance"))
            self.new_hire_case(p)
        self.routine_resets(min(6, max(1, self.days // 3)))
        self.routine_away()
        self.routine_recovery_changes(max(2, self.days // 3 + 1))
        hidden_rows = len(self.signin_rows) + len(self.audit_rows)
        n_audit = round(self.events * ROUTINE_AUDIT_SHARE)
        remaining = self.events - hidden_rows - n_audit
        if remaining <= 0:
            raise SystemExit("--events is too small for the requested hidden cases")
        self.normal_signins(remaining / (1 + FAIL_RATE))
        self.routine_audits(n_audit)
        for i, case in enumerate(self.takeover_cases, 1):
            takeover_labels.append(case.label(f"TK{i}"))
        for i, case in enumerate(self.lookalike_cases, 1):
            lookalike_labels.append(case.label(f"LA{i}"))
        return {
            "seed": self.seed,
            "generated": (self.start + timedelta(days=self.days - 1)).isoformat(),  # last local day
            "takeovers": takeover_labels,
            "lookalikes": lookalike_labels,
        }


def write_jsonl(path: Path, rows: list) -> None:
    rows = sorted(rows, key=lambda r: (r["TimeGenerated"], r["CorrelationId"]))
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(json.dumps(row, separators=(",", ":")) + "\n" for row in rows)


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Generate the fictional 2E Blind Hunt data.")
    ap.add_argument("--seed", type=int, required=True, help="same seed, same output")
    ap.add_argument("--out-dir", required=True, help="writes signin.jsonl and audit.jsonl here")
    ap.add_argument("--labels-out", help="plaintext answer key; written only where asked")
    ap.add_argument("--days", type=int, default=14)
    ap.add_argument("--events", type=int, default=5000, help="target total rows")
    ap.add_argument("--takeovers", type=int, default=5)
    ap.add_argument("--lookalikes", type=int, default=8)
    ap.add_argument("--start", default=DEFAULT_START,
                    help="first local day, YYYY-MM-DD (default %(default)s, a Monday)")
    args = ap.parse_args(argv)
    if args.days < 2 or args.events < 100 or args.takeovers < 0 or args.lookalikes < 0:
        ap.error("need --days >= 2, --events >= 100 and non-negative case counts")
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    gen = Generator(args.seed, args.days, args.events, args.takeovers, args.lookalikes,
                    date.fromisoformat(args.start))
    labels = gen.run()
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "signin.jsonl", gen.signin_rows)
    write_jsonl(out / "audit.jsonl", gen.audit_rows)
    if args.labels_out:
        with open(args.labels_out, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(labels, handle, indent=2)
            handle.write("\n")
    print(f"wrote {len(gen.signin_rows)} sign-in rows and {len(gen.audit_rows)} audit rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
