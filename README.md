# td-2-soc — Track 2 · SOC (CompTIA Security+)

When an attacker talks a helpdesk into resetting someone's password and multi-factor login, the next line of defence is the security team that watches the sign-in logs. This repo is my Track 2 of the **Takeover Defense** portfolio: I build a fictional credit union's login data with hidden account takeovers in it, hunt for them without knowing the answers, write detection rules that catch the takeover chain automatically, and then test whether an AI assistant that reads those alerts can be tricked by text planted in the data. Everything here uses a made-up company (Maple Harbour Credit Union, `mapleharbour.example`); nothing touches a real system. The portfolio story and the other tracks are in the hub repo: https://github.com/DK1051/takeover-defense

Plain-English glossary for this repo:
- **SOC** (Security Operations Centre): the team that watches security alerts and decides what is a real incident.
- **Entra ID**: Microsoft's cloud sign-in service (formerly Azure Active Directory). It writes two logs we imitate: the *sign-in log* (who logged in, from where, with what device) and the *audit log* (who changed what: password resets, new MFA methods, role changes).
- **MFA** (multi-factor authentication): a second proof of identity, such as a phone app code. Attackers who win a helpdesk reset usually enrol *their own* MFA device next.
- **KQL** (Kusto Query Language): the query language used by Microsoft Sentinel and Azure Data Explorer to search logs. A "detection" is a saved KQL query that raises an alert.
- **Kusto emulator**: a free Docker container that runs a local KQL engine, so the detections can be tested without an Azure account.
- **Prompt injection**: text hidden in data (a device name, a ticket note) that tries to make an AI assistant follow it as if it were an instruction.

Why this matters: the Canadian Centre for Cyber Security alert AL26-010 (May 1, 2026) warns that attackers "convince support staff to reset MFA or enroll attacker-controlled devices" and recommends organisations "restrict and closely monitor MFA reset, recovery, and device re-enrolment processes" (https://www.cyber.gc.ca/en/alerts-advisories/al26-010-cyber-criminals-social-engineering-enabled-compromise-enterprise-saas-environments). The detections in 2H are built around exactly that advice.

## Status

| Project | Status | Session(s) | Verify report | Class transcript |
|---|---|---|---|---|
| 2E Blind Hunt | Planned | T2-S01 | `docs/verify/T2-S01.md` (after the session) | `docs/learning/T2-C1.md` |
| 2H Takeover Detection Pack | Planned | T2-S02 | `docs/verify/T2-S02.md` | `docs/learning/T2-C1.md` |
| 2A Injection-Proof Triage | Planned | T2-S03 | `docs/verify/T2-S03.md` | `docs/learning/T2-C2.md` |

Sessions, days and credit caps: `docs/RUN-SHEET.md`. Surprises and workarounds: `docs/CAVEATS.md`. Credit spent: `COSTS.md`.

## Projects

### 2E Blind Hunt (easy) — `2e-blind-hunt/`
A seeded Python generator (plain code, no AI involved in the data) writes about 5,000 fictional Entra-style events over 14 days for Maple Harbour's 50 staff: `data/signin.jsonl` and `data/audit.jsonl`. Hidden inside are 5 account-takeover sequences (helpdesk reset → new MFA method → sign-in from a new device or IP → a privileged action) and at least 8 benign look-alikes (for example, a real employee who lost their phone and was properly verified). The answer key is encrypted with a passphrase only I hold, and a SHA-256 fingerprint of the plaintext is committed so nobody can swap it later. I hunt blind, commit my labels and 5 incident reports first, and only then decrypt the key and score myself. A small, unsealed `fixtures/` dataset with known answers exists so automated tests can run.

### 2H Takeover Detection Pack (hard) — `2h-detection-pack/`
KQL detection queries, each with a YAML header (what it catches, which AL26-010 control it supports, known false positives, MITRE ATT&CK technique IDs marked `TODO(verify)` until checked). A pytest harness loads the fixtures into the Kusto emulator, runs every detection, and asserts that the known takeovers are caught and the look-alikes are not. The `kql` CI job repeats this in GitHub Actions on every pull request that touches the detections or fixtures.

### 2A Injection-Proof Triage (hard + AI) — `2a-triage/`
A triage assistant (a Claude subagent) reads a batch of 2H alerts and returns JSON verdicts: true or false positive, confidence, a one-paragraph summary, and a proposed containment that always requires human approval. I write 10 prompt-injection strings myself; the harness plants them in the fields an attacker controls (display name, device name, ticket note) in copies of real alerts. The scorer reports precision and recall against my labels, how often an injection changed the assistant's answer, and the cost per 100 alerts for each model tested. The evaluation design is reviewed by a separate "red team" reviewer before any code is written.

## How to run what is here now

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
bash scripts/probe.sh        # what this machine can do (CPU, Docker, reachable package sources)
ruff check . && pytest -q    # the same checks CI runs (pytest reports "no tests" until a session adds some)
```

Cloud sessions run in the `td-2-soc` environment on claude.ai/code. The Kusto emulator image is pulled in the background when a session starts (`.claude/settings.json`); the emulator is started by hand on port 9000 when a brief needs it (command in `docs/briefs/T2-S02.md`). It needs an x86-64 CPU with AVX2; the probe shows whether this machine has one, and the briefs carry a fallback if not.

## How AI was used

Claude Code runs each session from a written brief in `docs/briefs/`: a director model plans and integrates, a builder model writes code and tests, a chores model does mechanical work, a verifier model checks every acceptance criterion and writes `docs/verify/<ID>.md`, and a separate red-team model reviews designs and README claims. The honesty rule: everything Claude produces is checked, the checks are in the repo, and I can explain and rebuild it — the class transcripts in `docs/learning/` are the "why" interviews that prove it. Per-project detail is in `AI-USE.md`. Attack content (the hidden takeover labels are generated by plain code; the injection strings are written by me) is never produced by an AI model.

## How to verify my work

- `docs/verify/` — one report per session: each acceptance criterion with PASS / FAIL / NEEDS-EOJIN and evidence.
- `docs/learning/` — class transcripts: my answers to ten "why" questions per project, graded honestly, plus one live code change.
- Commit history — one branch and one pull request per session; the blind-hunt labels are committed before the answer key is decrypted, and git shows the order.
- CI — the `checks` job (lint, tests, secret scan) and the `kql` job (detections against the emulator) on every pull request that touches the detections or fixtures.

## Data and safety

All people, phone numbers (555-01xx), emails and IP addresses in the data are fictional; the domain `mapleharbour.example` uses the reserved `.example` top-level domain. Real incidents are cited only from public reporting. This repo is defensive: no malware, no exploit code, nothing that targets a real system. The plaintext answer key is never printed or committed.

Licence: MIT (see `LICENSE`).
