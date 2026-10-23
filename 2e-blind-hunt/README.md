# 2E Blind Hunt: find the account takeovers hidden in two weeks of sign-in logs

**Status: the hunt dataset is generated and the answer key is sealed (2026-10-23).** `data/` holds 4,804 sign-in rows and 184 audit rows over 14 days, plus the encrypted answer key. Only Eojin holds the passphrase and the seed. Hunt first, commit `my-labels.json` and the five reports, and only then decrypt.

## What this project is (plain English)

A credit union's security team (a "SOC", security operations centre) watches sign-in logs for signs that a criminal has taken over a staff member's account. This project builds a practice hunt:

- A Python program (`generate.py`) writes about 5,000 made-up log events covering 14 days for a made-up bank, **Maple Harbour Credit Union**, with 50 made-up staff at `mapleharbour.example`. Nothing is real: no real person, company, phone number or network address appears. Every IP address comes from the three ranges that the internet standard RFC 5737 reserves for documentation (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), so none can point at a real machine.
- Hidden in the normal traffic are **5 account takeovers** and **at least 8 harmless look-alikes** (events that look suspicious but are fine, such as a user travelling or a helpdesk reset done properly). The takeover pattern is: the helpdesk resets a password without the "verified: callback to number on file" note, a new multi-factor authentication (MFA) method is added, someone signs in from a device, address and country never seen for that user, and then does something privileged. The look-alikes are there so that no single clue decides a case; for example, a rushed helpdesk agent who skips the callback note is *not* automatically a takeover.
- The answer key (which events are the real takeovers) is encrypted, so the hunter (Eojin) cannot see it while hunting. The merge order of two pull requests proves the hunt was blind (see "The rule" below).

Terms: **Entra** is Microsoft's cloud sign-in service. **Seeded** means the same random seed always gives the same output. The **answer key** is the list of which events are the hidden takeovers. **MFA** is the second proof of identity (a phone app, a text message) on top of a password. **jq** is a small command-line tool for reading JSON.

## The data

Two files of JSON Lines (one JSON object per line), sorted by `TimeGenerated`:

- `signin.jsonl`: one row per sign-in attempt.
- `audit.jsonl`: one row per administrative change (password resets, MFA registration, role changes).

The data **imitates a small part of Entra's sign-in and audit log shape. It does not claim to match Microsoft's real schema.** Every name, number and spelling below that I have not checked against Microsoft's documentation is marked `TODO(verify)`.

**Sign-in fields**

| Field | Meaning in this data |
|---|---|
| `TimeGenerated` | ISO 8601 time in UTC with a `Z` suffix, to the second |
| `UserPrincipalName` | `first.last@mapleharbour.example` |
| `IPAddress` | an RFC 5737 documentation address |
| `Location` | object with `city`, `state`, `countryOrRegion` (real Entra logs use different location fields: `TODO(verify)` the exact shape) |
| `AppDisplayName` | the application signed in to, e.g. `Core Banking Admin` (a made-up app) or `Microsoft Teams` (`TODO(verify)` the exact display names of the Microsoft ones) |
| `ResultType` | `"0"` is success. Failures use a small fixed set: `"50126"` (wrong password) and `"500121"` (MFA step failed). `TODO(verify)` each code and its meaning against Microsoft's sign-in error code list |
| `AuthenticationRequirement` | `singleFactorAuthentication` or `multiFactorAuthentication` (`TODO(verify)` the exact values) |
| `DeviceDetail` | object with `deviceId`, `displayName`, `operatingSystem`, `browser`, `trustType`. The values for `operatingSystem` (e.g. `MacOs`), `browser` (names only, no versions) and `trustType` (`Hybrid Azure AD joined`, `Azure AD joined`, `Azure AD registered`, or empty) are `TODO(verify)` |
| `CorrelationId` | a UUID, unique per row, used as the event id |

**Audit fields**

| Field | Meaning in this data |
|---|---|
| `TimeGenerated`, `CorrelationId` | as above |
| `OperationName` | one of `Reset password (by admin)`, `Reset password (self-service)`, `User registered security info`, `Add member to role`, `Add member to group`, `Update user`. **All six spellings are `TODO(verify)`** against Microsoft's audit log documentation |
| `InitiatedBy` | `{"user": {"userPrincipalName": ..., "ipAddress": ...}}`: who did it, from where (`TODO(verify)` the real shape) |
| `TargetResources` | list of `{displayName, userPrincipalName, modifiedProperties}`; `modifiedProperties` is a list of `{displayName, oldValue, newValue}`. The property names used (`TicketNote`, `StrongAuthenticationMethod`, `Role.DisplayName`, `Group.DisplayName`, `OtherMails`, `JobTitle`, `MobilePhone`, `Method`) are invented for this exercise or unchecked: `TODO(verify)`. In particular, a helpdesk ticket note is not a standard Entra field |

How the data is built (so you know what is realistic and what is not):

- **Normal life first.** Each person signs in several times per working day (from the office or, outside working hours, from home), with some evenings and weekends. About 6% of sign-in sessions begin with one failed attempt (a wrong password, or a failed MFA step) followed by a success. Routine audit events (an IT admin adds someone to a group or updates a job title or phone number, self-service password resets, MFA registration for new hires) make up about 3% of the rows. A few ordinary helpdesk resets (some with the callback note, some without) are not part of any hidden case, and a few ordinary people are travelling or on a VPN, so listing resets or foreign countries does not hand you the answers. Some ordinary accounts also change their recovery email address (by themselves or through the helpdesk), the same property a hidden sequence changes. About 30% of staff also sign in from a personal computer. Phone numbers in the data are `555-01xx` numbers.
- **The window.** The default window starts Monday 14 September 2026 (local time). Local time is treated as a fixed UTC-4 (Toronto daylight time) for simplicity, so `--start` dates after the clocks change on 1 November 2026 are slightly off.
- **Resets look the same everywhere.** Every admin password reset (hidden or not) happens during the helpdesk agent's working day, from the agent's usual address, a few minutes after a normal agent sign-in, and is followed by one or two wrong-password attempts from the user's known device. Places outside Canada come from one small shared set, so the country alone decides nothing.
- **No tells.** Hidden events are built by the same code, from the same pools of devices, applications, ticket notes and addresses, with the same second-level jitter as normal events. The data files never contain the words `takeover`, `attacker`, `malicious`, `lookalike` or `look-alike`, or the case ids (`TK` or `LA` followed by a digit). A test checks this.
- **Deterministic.** Same seed and same options give byte-identical files. Event ids are derived from the seed (with SHA-256), not from the clock, and any whole-number seed works, including a 128-bit one. The `generated` date in the answer key is the last local day of the data window (14 days from 2026-09-14 gives 2026-09-27), so the key is reproducible too.

## What is hidden (counts only)

- 5 account takeovers. Each is a sequence of four events: (a) a helpdesk password reset with no callback-verification note, (b) the account registers a new MFA method, (c) a successful MFA sign-in from a device, address and country never seen for that user, (d) a privileged action (adding a member to a role, signing in to `Core Banking Admin`, or changing the account's recovery email).
- At least 8 harmless look-alikes.
- The key records, for each case, the user, the start and end time, the list of event ids (`CorrelationId`s) and a one-sentence reason. That list is never printed or committed in plain text for the real dataset.

## How to hunt

Use whatever tool you like on `data/signin.jsonl` and `data/audit.jsonl`:

```bash
# how many rows, and what kinds of administrative events exist
wc -l 2e-blind-hunt/data/signin.jsonl 2e-blind-hunt/data/audit.jsonl
jq -r ".OperationName" 2e-blind-hunt/data/audit.jsonl | sort | uniq -c | sort -rn

# everything one person did, in time order (both files)
jq -c 'select(.UserPrincipalName == "first.last@mapleharbour.example")' 2e-blind-hunt/data/signin.jsonl
```

```python
import json
rows = [json.loads(line) for line in open("2e-blind-hunt/data/signin.jsonl")]
print(len(rows), rows[0]["TimeGenerated"], rows[-1]["TimeGenerated"])
```

A spreadsheet works too: import each file as JSON Lines through Power Query or Python. KQL (Kusto Query Language, Microsoft's query language for logs) on the Kusto emulator comes after session T2-S02: `TODO(T2-S02): add the KQL loading and query instructions once the emulator harness exists.`

Write each finding as a labelled takeover in `my-labels.json` (copy `my-labels.template.json`) and as an incident report in `reports/INC-01.md` to `reports/INC-05.md` (copy `incident-report-template.md`). A label is `{"id", "user", "start", "end", "evidence", "summary"}`; `evidence` is a list of event ids (`CorrelationId` values) and may be left empty if you use time windows. **Write `start` and `end` in UTC with a trailing `Z`** (like `2026-09-17T16:09:01Z`), exactly as `TimeGenerated` is written: Toronto local time is 4 hours behind UTC in September, so a local time copied by mistake would shift your window by 4 hours. A time without a zone is read as UTC. An untouched copy of the template entry (empty user, no evidence) is ignored by the scorer.

## The rule: commit your answers BEFORE decrypting

Commit `my-labels.json` and the 5 reports in one pull request and **merge it before you decrypt anything**. The merge order is the proof that the hunt was blind. Only then unseal and score yourself, and put the reconciled list (`labels-final.json`) in a second pull request opened after the first is merged. Never commit the decrypted key, the passphrase or the seed.

## Unseal and score (after the first pull request is merged)

Do this in Azure Cloud Shell (portal, then the Cloud Shell icon, then Bash, then "No storage account required"). It already has `openssl`, `sha256sum`, `git` and Python. First run `git clone https://github.com/DK1051/td-2-soc && cd td-2-soc`. On a Mac, `brew install openssl@3` and use `$(brew --prefix openssl@3)/bin/openssl` and `shasum -a 256` in place of `openssl` and `sha256sum`; on Windows use Git Bash from Git for Windows.

```bash
openssl enc -d -aes-256-cbc -pbkdf2 -in 2e-blind-hunt/data/answer-key.enc -out /tmp/key.json -pass pass:'<PASSPHRASE from your password manager>'
sha256sum /tmp/key.json   # must equal 2e-blind-hunt/data/answer-key.sha256
python scripts/score_my_labels.py --labels 2e-blind-hunt/my-labels.json --key /tmp/key.json
```

`<PASSPHRASE from your password manager>` is a placeholder: never commit it with a real value. Delete `/tmp/key.json` afterwards.

### How the scorer matches

`scripts/score_my_labels.py` counts one of your labels as a hit on a key takeover when either:

1. **Event ids:** your `evidence` list shares at least one `CorrelationId` with the key takeover's evidence, or
2. **Time window:** it has the same `UserPrincipalName` and your `[start, end]` overlaps the key's `[start, end]`.

Event ids are checked first, then time windows. Each key takeover can be hit once. Precision is hits divided by the number of labels you gave; recall is hits divided by the number of real takeovers. No labels at all scores 0.0 for both. The time-window rule is a planning choice; the event-id rule is accepted too so that labels written either way can be scored. The scorer prints only ids and users (for the ones you missed), plus the id of a benign case when one of your extra labels overlaps it.

## What the two hash files prove

- `data/dataset.sha256` holds the SHA-256 fingerprints of `signin.jsonl` and `audit.jsonl` taken when the key was sealed. If you recompute them and they match, the data you hunted in is the data the key belongs to, and nobody changed it afterwards.
- `data/answer-key.sha256` holds the fingerprint of the *decrypted* key. After you decrypt, the fingerprint of your result must equal it. That proves the passphrase was right and the key was not altered. It does not reveal the key.

(Both files were created when the dataset was sealed on 2026-10-23; see Status.)

## My blind-hunt score

`TODO(Eojin): paste the precision and recall printed by scripts/score_my_labels.py here after unsealing.`

## Generating data yourself

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python 2e-blind-hunt/generate.py --seed 123 --out-dir /tmp/practice --labels-out /tmp/practice-labels.json
```

Options: `--seed` and `--out-dir` are required; `--labels-out` (the plaintext key, written only where you say), `--days` (14), `--events` (5000, a target for the total rows), `--takeovers` (5), `--lookalikes` (8) and `--start` (the first local day, default 2026-09-14) are optional. Asking for 8 or more look-alikes produces at least 11, so that every kind below appears.

The small test dataset in `../fixtures/` was made with:

```bash
python 2e-blind-hunt/generate.py --seed 7 --days 3 --events 300 --takeovers 2 --lookalikes 3 --out-dir fixtures --labels-out fixtures/expected.json
```

Its answer file is committed in plain text on purpose: it is for automated tests, not for the hunt.

Run the tests with `ruff check .` and `pytest -q` from the repo root.

## What Claude did and what Eojin did

- **Claude (AI) built:** the generator, the scorer, the tests, the templates, the fixtures and this README. The data itself is produced by ordinary seeded Python code. There is no AI in the data, so the same seed always gives the same answer.
- **Eojin decided (2026-10-22):** the hidden seed for the real dataset is a random 128-bit number instead of a number below one billion; and the data contains ordinary, unlabelled recovery-email changes (self-service and through the helpdesk) so that changing a recovery email is not, by itself, a sign of a takeover.
- **Eojin does (not done yet):** keep the passphrase and seed in his password manager when the real dataset is sealed; hunt in the data with his own methods; write `my-labels.json` and the 5 incident reports; merge them before unsealing; score himself; write `labels-final.json`.

## Limits

- The data is synthetic and only imitates a subset of Entra's log schema; the enumerations and operation names are unchecked (`TODO(verify)`). Do not treat this as a faithful copy of Microsoft's logs.
- There is no real geolocation: a "country" is just a label attached to an address from a documentation range.
- In a takeover, the new MFA method is registered (event b) before the matching successful sign-in (event c) is logged. A real tenant would log a sign-in first. The order follows the exercise design.
- Browser and device names are plain labels without version numbers; operating-system and trust-type strings are examples.
- The seed for the real dataset is a random 128-bit number (`secrets.randbits(128)` in the brief's step 8; Eojin's decision), so trying every seed against the public generator and the public `answer-key.sha256` is not practical. Event ids are derived from the seed with SHA-256, so the public ids do not reveal the random generator's internal state either. The seal is still a self-honesty device for a practice exercise, not a security product: whoever holds the passphrase and seed, or the decrypted key, can read the answers.
