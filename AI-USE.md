# What Claude did vs what Eojin did

Honesty rule for this repo: every file Claude produces is checked by the `verifier` subagent against the session brief (reports in `docs/verify/`), and Eojin can explain and rebuild the work (class transcripts in `docs/learning/`). Filled in at each `wrap`.

## 2E Blind Hunt

Claude (models used)
- T2-S01 director (Opus 5.5): probe and its plain-English notes, caveats, run sheet, PR. Step 8 (real dataset + sealed key) not run — Eojin was not present.
- T2-S01 `builder` (Sonnet 5.5): `generate.py` (standard library, seeded), `score_my_labels.py`, 31 tests, the seed-7 fixtures and their plain answer sheet, the templates and the 2E README.
- T2-S01 `verifier` (Opus 5.5): mid-review (instead of redteam, because the files contain synthetic takeover sequences) and final check, `docs/verify/T2-S01.md`.

Eojin
- To do: be present for step 8 to store the passphrase and seed; then hunt blind, write `my-labels.json` and five incident reports, merge them, and only then decrypt and score.

## 2H Takeover Detection Pack

Claude (models used)
- (to be filled at wrap)

Eojin
- (to be filled at wrap)

## 2A Injection-Proof Triage

Claude (models used)
- (to be filled at wrap)

Eojin
- (to be filled at wrap)
