# What Claude did vs what Eojin did

Honesty rule for this repo: every file Claude produces is checked by the `verifier` subagent against the session brief (reports in `docs/verify/`), and Eojin can explain and rebuild the work (class transcripts in `docs/learning/`). Filled in at each `wrap`.

## 2E Blind Hunt

Claude (models used)
- T2-S01 director (Opus 5.5): probe and its plain-English notes, caveats, run sheet, PR. On 2026-10-23, with Eojin present, ran step 8 exactly as the brief's subshell (fresh 128-bit seed, AES-256 passphrase shown once), checked his stored passphrase (MATCH), committed only the five sealed data files.
- T2-S01 `builder` (Sonnet 5.5): `generate.py` (standard library, seeded), `score_my_labels.py`, 31 tests, the seed-7 fixtures and their plain answer sheet, the templates and the 2E README.
- T2-S01 `verifier` (Opus 5.5): mid-review (instead of redteam, because the files contain synthetic takeover sequences) and final check, `docs/verify/T2-S01.md`.

Eojin
- Was present for step 8: stored the passphrase and seed in his password manager and typed the passphrase back (MATCH). To do: hunt blind, write `my-labels.json` and five incident reports, merge them, and only then decrypt and score.

## 2H Takeover Detection Pack

Claude (models used)
- T2-S02 director (Opus 5.5): pinned the emulator image by digest, started the Docker engine and the emulator, asked Eojin the design choices, logged caveats, opened the PR.
- T2-S02 `builder` (Sonnet 5.5): six KQL detections with YAML headers, the header and static KQL checks, the Kusto test harness (fixtures and a synthetic test database), `run_detections.py` with the blind-hunt guard.
- T2-S02 `chores` (Haiku 5.5): the 2H README table and sections; YAML validation.
- T2-S02 `verifier` (Opus 5.5): mid-review (instead of redteam, because these are detection rules) and final check, `docs/verify/T2-S02.md`.

Eojin
- Decided: TD-2H-01 low-severity early warning, TD-2H-02 needs a new device, TD-2H-05 synthetic test. Kept his blind hunt separate (no detection ran on the hunt data). Still to do: record the credit balance; commit `my-labels.json` and the five reports before T2-C1.

## 2A Injection-Proof Triage

Claude (models used)
- (to be filled at wrap)

Eojin
- (to be filled at wrap)
