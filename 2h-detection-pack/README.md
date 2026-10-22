# 2H detection pack: takeover detections for Microsoft Entra logs

## What this folder does (plain English)

A **takeover** here means an attacker gets into a bank employee's or customer's account by abusing the helpdesk password-reset process. The chain this pack looks for has four steps:

1. The attacker convinces a helpdesk agent to reset the user's password (an **admin password reset**).
2. The attacker registers their own **MFA method** (multi-factor authentication: a second proof of identity, such as an app code or a phone). MFA methods are the extra ways an account can prove who it is.
3. The attacker signs in from a **device** they have never used before.
4. The attacker does something privileged, such as adding someone to an admin role, changing the recovery email, or opening a banking admin app.

Each detection is a **KQL** query. KQL (Kusto Query Language) is the read-only query language that Microsoft Sentinel and Azure Data Explorer use to search log tables. A detection returns the rows in the logs that match one pattern from the chain above. Each detection has a **YAML header**, a short plain-text block at the top of its metadata file that says what the detection catches, its severity, and which AL26-010 control it supports. AL26-010 is the recommendation reference this project maps each detection to; its source document and exact wording are `TODO(verify)`.

The logs come from **Microsoft Entra ID** (Microsoft's cloud identity service, formerly Azure AD), in two tables: `SigninLogs` (who signed in, from which device and IP) and `AuditLogs` (changes made, such as password resets and MFA registrations).

Because nothing here touches a real bank, the test data is a set of **fixtures**: small, fixed sample files (`fixtures/signin.jsonl`, `fixtures/audit.jsonl`, `fixtures/expected.json`) with fictional Maple Harbour Credit Union users. They were made by the 2E data generator (`2e-blind-hunt/generate.py`). `fixtures/expected.json` names the two known takeovers, **TK1** and **TK2**, and three **look-alikes**, **LA1** to **LA3**. A look-alike is a normal-looking event that resembles a takeover on the surface but is not one. A good detection finds TK1 and TK2 and stays quiet about LA1 to LA3.

The harness is the test code that proves this. It loads the fixtures into the **Kusto emulator**, which is Microsoft's query engine packaged as a free Docker container so it can run on your own PC, then runs every detection and checks the results.

**Status:** nothing in this folder has been run against a real Microsoft 365 or Entra tenant, or against real Entra logs. See Limits.

## The detections

Each row is copied from the matching `detections/<id>.yaml` file by a script, so the text here matches the headers.

| id | What it catches | AL26-010 control (as written in the YAML) | Severity | False-positive notes | ATT&CK ids |
| --- | --- | --- | --- | --- | --- |
| TD-2H-01 | Finds users whose password was reset by an administrator and who then registered a new multi-factor authentication (MFA) method within 24 hours. This is the first two steps of the helpdesk-reset takeover chain, so it is a broad early warning rather than a verdict. | restrict and closely monitor MFA reset, recovery, and device re-enrolment processes | low | This is a deliberately broad early-warning rule, so it is noisy by design. A genuine lost-phone case (LA1: Katya Hashemi, reset after a callback, new MFA method 20 minutes later) returns a row, because a verified reset followed by a new MFA method looks identical to a takeover on these two signals alone. TD-2H-02, TD-2H-04 and TD-2H-06 do the separating (new device, full chain, missing callback note). LA2 and LA3 have no new MFA method, so they stay quiet. | TODO(verify) |
| TD-2H-02 | Finds a successful sign-in within 24 hours after a user registered a new MFA method, where the sign-in came from a device id (not empty) that the user did not use in the previous 14 days. An attacker who has just added their own MFA method and then signs in from their own machine looks exactly like this. | restrict and closely monitor MFA reset, recovery, and device re-enrolment processes | high | A new device is required: a new IP address alone does not alert (it is shown as evidence only), and a sign-in with an empty device id is treated as unknown, not new. An attacker who reuses a device id the user already used would slip past this rule; TD-2H-04 and TD-2H-06 still cover the chain. Travel (LA3: Uma Jovanovic, new country, known devices) stays quiet because no MFA method was added, and a lost-phone case (LA1) stays quiet because the next sign-in came from the usual laptop. A person who registers a new MFA method and then really signs in from a new laptop will trigger it. The fixtures hold only 3 days, so a device can look new simply because it has not appeared yet. | TODO(verify) |
| TD-2H-03 | Finds users whose password was reset by an administrator and who then added someone to an administrator role, changed the account's recovery email address, or signed in to the Core Banking Admin app within 48 hours. These are the actions an attacker takes first to keep control or to reach money systems. | restrict and closely monitor MFA reset, recovery, and device re-enrolment processes | high | Someone whose job includes Core Banking Admin will trigger it when they sign in normally after a routine reset, and one account can produce several rows (every later sign-in in the window). Look-alikes LA1 to LA3 have no privileged action after their reset, so they stay quiet. The 48 hour window is a planning value. | TODO(verify) |
| TD-2H-04 | Joins the four steps of the takeover chain for each reset user (reset, new MFA method within 24 hours, first-ever sign-in from a device within 24 hours after that, privileged action within 48 hours of the reset) and returns a chain_score counting the stages hit. It alerts when the score is 3 or more, and shows the time of each stage. | restrict and closely monitor MFA reset, recovery, and device re-enrolment processes | high | A lost-phone case with a callback (LA1) reaches a score of 2 (reset and new MFA) and stays below the alert level of 3. A user who really does get a new laptop right after a reset and then uses Core Banking Admin would score 4 and need a human to check the ticket. Windows (24 h, 24 h, 48 h) and the alert level are planning values; "new device" means the first sign-in from that device id anywhere in the loaded data, so on short data a normal first sign-in can count as new. | TODO(verify) |
| TD-2H-05 | Counts admin password resets per helpdesk account per UTC day and alerts when a day has at least 3 resets and more than that account's own average for the previous 14 days plus 2. This is a campaign-volume rule, not a per-takeover rule: a burst of resets from one account can be the start of an attacker campaign or of a compromised helpdesk account. | restrict and closely monitor MFA reset, recovery, and device re-enrolment processes | medium | The limit (more than the account's own 14-day daily average plus 2, and at least 3 that day) is a planning value, not a measured one. A genuinely busy day, such as an office-wide password expiry, would trigger it, but an agent whose usual volume is high does not (the average rises with it). Until a data set holds 14 days of history for an agent (the first week or more), its normal days can look like bursts. It returns one row per reset in the burst, so benign resets in the same burst appear too. The generator that made the fixtures has no campaigns, so this rule is tested on synthetic data (test_2h_detections_synthetic.py); on the fixtures it happens to return three resets by one agent on 15 September, which is not required and not relied on. | TODO(verify) |
| TD-2H-06 | Finds users who registered a new MFA method within 24 hours after an admin password reset whose ticket note does not contain the text 'verified: callback to number on file'. That text records that the helpdesk called the user back on a number already on file, which is the out-of-band check that stops a stranger on the phone from getting a reset. | "out-of-band verification" (the AL26-010 control name as written in the T2-S02 brief; TODO(verify) the exact wording against the alert text) | high | A lost-phone case where the agent did the callback and wrote the marker (LA1) stays quiet. A genuine reset where the agent forgot to write the marker and the user then added a new MFA method would trigger it, which is a process failure worth reviewing anyway. A reset without the marker and without a new MFA method (LA2) stays quiet. The marker is matched case-insensitively and only as a whole semicolon-separated part of a note value, so a note saying "not verified: callback to number on file" does not count as verified; every changed property of the reset is checked, not only the first. | TODO(verify) |

- **TK** means a known takeover in `fixtures/expected.json`. **LA** means a look-alike in the same file.
- **ATT&CK** is MITRE ATT&CK, a public catalogue of attacker techniques with numbered IDs. None of the IDs here has been checked against the official catalogue, so every one is marked `TODO(verify)`. No technique name is quoted.

### Notes on specific rows

- **TD-2H-01 (low severity, early warning).** The YAML field `expected_noise` lists LA1 (a verified lost-phone reset, followed by a new MFA method). On these two signals alone, that case looks the same as a takeover, so the rule is allowed to return it. It is not required to return it and not forbidden from returning it. Eojin chose to keep TD-2H-01 as a low-severity early warning rather than remove it. TD-2H-02, TD-2H-04 and TD-2H-06 are the rules that separate LA1 from the takeovers.
- **TD-2H-02 (new device required).** The rule needs a sign-in from a device ID that is not empty and that the user has not used in the previous 14 days. A new IP address alone does not count; the IP is shown only as evidence. A sign-in with an empty device ID counts as unknown, not new. This is Eojin's choice.
- **TD-2H-05 (campaign-volume rule, tested on synthetic data).** Its YAML field `tested_by` is `synthetic`. The fixture generator produces no campaigns, so this rule is tested on a small synthetic table in `tests/test_2h_detections_synthetic.py`, not on the fixtures. Its `expected_hits` is empty, so nothing in the fixture check depends on it. The rule has a cold-start limit: its 14-day average needs 14 days of history for each helpdesk account, so until an account has that much history, its normal days can look like bursts. The YAML also records that on the fixtures it happens to return three resets by one agent on 15 September. That is not required and not relied on.

## How the harness works

The harness is the pytest test code in `tests/` plus two scripts in `scripts/`. **pytest** is the Python test runner; `pytest -q` runs the tests and prints a short summary.

1. **Create a database.** The harness creates a fresh database named `mapleharbour` in the emulator. A database is a named container for tables. The exact create command, and whether the `volatile` option (data kept only in memory) is accepted, are `TODO(verify)` against the emulator documentation. If the command fails, the harness uses the persistent form with paths under `/kustodata`.
2. **Create the tables.** `SigninLogs` and `AuditLogs` get one column per field in the fixture files. Object-shaped fields are typed `dynamic` (flexible, JSON-like data). `TimeGenerated` is typed `datetime`.
3. **Ingest the rows.** Rows are sent in batches of at most 100 with a control command that appends them to the table (`.set-or-append` with an inline `datatable`, or `.ingest inline` as the alternative).
4. **Row-count check.** The number of rows in each table must equal the number of lines in its fixture file. If not, the tests stop before any detection runs, so a half-loaded table cannot produce a false pass.
5. **Run each detection.** Each `.kql` file is sent to the emulator and its result rows are returned.
6. **Assert.** For each detection, the users returned must include every user in its `expected_hits`, and must include none of the users in its `expected_quiet`. Every result row must also carry a `UserPrincipalName` (the user's sign-in name) and a timestamp.
7. **Synthetic tests for what the fixtures lack.** The fixtures have no role-add events, no overnight takeover and no campaign. Those cases are covered by `tests/test_2h_detections_synthetic.py`, which builds its own small test table with hand-written rows.

Two checks need no emulator. `tests/test_2h_headers.py` checks every YAML header: required fields, unique IDs, that `expected_hits` and `expected_quiet` name IDs that exist in `fixtures/expected.json`, and that every `TODO(verify)` is spelled exactly that way. `scripts/check_kql.py` (in the repo-root `scripts/` folder) checks each `.kql` file: balanced brackets and quotes, that each table name is `SigninLogs` or `AuditLogs`, and that each file ends by selecting at least `UserPrincipalName` and a timestamp column.

`scripts/run_detections.py` is a separate tool. It loads the fixture (or other) data into a fresh database, runs every detection, and writes one alert per result row as a JSON line. Each alert has `alert_id`, `detection_id`, `title`, `severity`, `UserPrincipalName`, `TimeGenerated`, `evidence` (the row's fields) and `source_correlation_ids`.

## How to run it locally

**You need:** Docker; an x86-64 processor with AVX2 (the Kusto emulator does not run on ARM chips); Python 3.12 or newer. AVX2 is a set of processor instructions that the emulator requires.

1. **Start Docker.** Check with `docker info`. If it fails, start the Docker engine (on Linux, `sudo systemctl start docker`; on Windows or macOS, open Docker Desktop).
2. **Start the emulator** (pinned to a digest, which is an exact fingerprint of one image version, so it cannot silently change):

   ```bash
   docker run -d --name kusto -e ACCEPT_EULA=Y -m 4G -p 9000:8080 mcr.microsoft.com/azuredataexplorer/kustainer-linux@sha256:7479dc8efa4b3c15bc1a245b418464e88b5328cf6e4781881d73fe4f79d03eb1
   ```

   Port 9000 on your PC leads to port 8080 inside the container. Port 8080 is taken by Keycloak in the other tracks, which is why 9000 is used. To wait until it answers:

   ```bash
   for i in $(seq 1 36); do code=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' -d '{"csl":".show cluster"}' http://localhost:9000/v1/rest/mgmt); [ "$code" = "200" ] && echo ready && break; sleep 5; done
   ```

   If the container exits, run `docker logs kusto` to read the error.
3. **Set up Python** (once). From the repo root: `python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt`. Do not install these packages system-wide.
4. **Environment variables.**
   - `KUSTO_URL` is the emulator address. It defaults to `http://localhost:9000`.
   - `KUSTO_REQUIRED=1` turns a missing emulator into a failure. Without it, the emulator tests are skipped when the emulator is unreachable, so a plain test run still passes on a machine without Docker.
5. **Run the tests.**

   ```bash
   KUSTO_REQUIRED=1 pytest -q 2h-detection-pack/tests
   ```

6. **Run the detections over the fixtures and write the alerts.**

   ```bash
   python scripts/run_detections.py --url http://localhost:9000 --data fixtures --out /tmp/alerts-fixtures.jsonl
   ```

   On Windows, use any writable path for `--out`; `/tmp` is a Linux folder. The script refuses to read `2e-blind-hunt/data` until `2e-blind-hunt/my-labels.json` exists. That folder holds Eojin's blind hunt, which is separate from this pack. The guard is there so the hunt data is never loaded by accident.

7. **Stop or restart the emulator** with `docker stop kusto` and `docker start kusto`. Remove it with `docker rm -f kusto`.

## How CI runs it

The workflow file is `.github/workflows/ci.yml`. It has three jobs that matter here:

- **`checks`** is the required job. It runs the static tests (the header checks and the KQL checks), and it does not start the emulator. A missing emulator therefore cannot break `checks`.
- **`kql`** runs the emulator tests against the emulator. The emulator runs as a **service container**, which is a helper container that GitHub Actions starts next to the job. It uses the same digest as the local command above. The job runs only when `kql-paths` says so.
- **`kql-paths`** is a tiny job that compares the pull request's base commit and head commit. It sets `kql` to run only when files under `2h-detection-pack/` or `fixtures/` change. A pull request that changes only `scripts/run_detections.py` will not run `kql`; touch a file under `2h-detection-pack/` in that case.

Running `kql` separately from `checks` means a slow image download or a failed emulator start shows up as a red `kql` job, not as a broken `checks` job. The full-data run is guarded: `kql` runs the detections over `2e-blind-hunt/data` only after `2e-blind-hunt/my-labels.json` exists, the same rule the script uses. Until then it runs only on the fixtures.

## What Claude did, and what Eojin did

**Claude** wrote the six `.kql` detections and their `.yaml` headers, the test harness and the two scripts, and this README, all from Eojin's brief (`docs/briefs/T2-S02.md`). The README table is generated from the YAML files, so the values match the headers.

**Eojin** made the design choices:
- TD-2H-01 stays as a low-severity early warning, even though a verified lost-phone reset can return it.
- TD-2H-02 needs a device ID that the user has never used. A new IP address alone does not count.
- TD-2H-05 is tested on synthetic data, because the fixtures have no campaigns.

His blind hunt on `2e-blind-hunt/data` continues separately. Nothing in this pack reads that data.

## Limits

- **The fixtures are small, fictional and synthetic.** They cover three days of fictional Maple Harbour Credit Union sign-ins and admin actions. They contain no role-add events, no overnight takeover and no campaign. Those cases are covered only by the synthetic tests.
- **Thresholds and time windows are planning values, not measured ones.** These include the 24-hour, 48-hour and 14-day windows, the chain-score alert level of 3, and TD-2H-05's "average plus 2" and "at least 3 resets".
- **Field names match the 2E data generator.** The Entra `OperationName` strings the detections match are also the generator's. The real Entra strings are `TODO(verify)`, so a real tenant could use different names and the detections would miss them.
- **Nothing here has run against a real tenant or real Entra logs.** A passing test on these fixtures shows that the queries behave as written on this data. It does not show that they catch real takeovers.
- **ATT&CK IDs are `TODO(verify)`.** The AL26-010 wording is copied from the YAML; its source is `TODO(verify)`.
- **The emulator path needs an x86-64 processor with AVX2.** On other machines, the `kql` CI job is the only place these data tests run.
- **Some rules are known to be noisy by design.** TD-2H-01 is one; the notes above say which look-alikes can trigger each rule and why.

## Results

Run in the cloud session on 2026-10-22, against the pinned Kusto emulator, on the fixtures and the synthetic test rows only (never on the blind-hunt data):

- `ruff check .` → `All checks passed!`
- `KUSTO_REQUIRED=1 pytest -q 2h-detection-pack/tests` → `67 passed`
- `python scripts/run_detections.py --url http://localhost:9000 --data fixtures --out /tmp/alerts-fixtures.jsonl` → `wrote 16 alert(s)` (at least the 10 the fixtures' `expected_hits` require)

The full check, including the emulator-stopped proofs, is in `docs/verify/T2-S02.md`. The CI `kql` job result is on the pull request.
