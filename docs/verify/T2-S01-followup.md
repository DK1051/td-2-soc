# Verify — T2-S01 follow-up (Eojin's decisions after D0)

Branch `claude/friendly-heisenberg-seafff` (commit `bdbf44d`) compared with `origin/main` (`0bdcc19`). PR: https://github.com/DK1051/td-2-soc/pull/2.
Checked by the `verifier` (Opus 5.5) on 2026-10-22. The verifier also did the mid-review, because this PR changes synthetic takeover data (CLAUDE.md sends that to the verifier, not `redteam`). The verifier wrote only this file.

Decisions under review:
1. Step 8's hidden seed is now 128 bits (`secrets.randbits(128)`). The builder also changed every id (CorrelationId and deviceId) from raw generator output to SHA-256 of (seed, counter).
2. Recovery-email changes (`OtherMails`) are no longer takeover-only: unlabelled benign changes were added, with guard tests.

## 1. Review findings (whole diff, also acting as mid-review)

Files changed: `2e-blind-hunt/generate.py`, `2e-blind-hunt/tests/test_2e_generator.py`, `2e-blind-hunt/README.md`, `docs/briefs/T2-S01.md`, `docs/CAVEATS.md` and the regenerated `fixtures/`. There are no `redteam` comments to check, because the verifier is the mid-reviewer for this PR.

**F1 (MEDIUM, in scope, cheap fix): the benign recovery-email changes add a new timing tell.** A "tell" is a pattern that gives away the answer without the intended hunting skill. `routine_recovery_changes` always:
- puts a sign-in by the user 2 to 15 minutes before the change (`known_signin(t - self.minutes(2, 15), p)`, also in the helpdesk variant);
- puts another sign-in 5 to 60 minutes after it;
- schedules self-service changes only between 08:00 and 20:00 local time.

The takeover step (d) follows its template gap instead (25–90 min or 90–240 min after the attacker's sign-in), and one template often lands after 20:00. The verifier measured this over 30 random 128-bit test seeds (from `random.Random(20261022)`, not the real seed): 150 benign and 60 takeover `OtherMails` rows.

| Pattern on an `OtherMails` row | takeover | benign |
|---|---|---|
| user's last own sign-in was more than 15 min before the change | 51/60 | 0/150 |
| no own sign-in within 60 min after the change | 40/60 | 0/150 |
| local time at or after 20:00, or before 08:00 | 25/60 | 0/150 |
| any of the three above | 56/60 | 0/150 |
| initiator IP seen at most twice for that user (the intended clue) | 60/60 | 0/150 |

The intended clue (an address never seen for the user) still separates the rows perfectly, so the hunt is not easier overall. But the clock alone now isolates about 93% of recovery-email takeovers with no false positives, without looking at addresses or devices. That is the kind of artefact the README's "No tells" rule rules out.
Cheap fix (builder): draw the benign gap before the change from the takeover's range (for example `minutes(2, 240)`), allow self-service changes later in the evening (for example hours `(8, 23)`), and make the follow-up sign-in optional or much later. Then widen `test_ordinary_recovery_changes_have_no_reset_and_no_new_mfa`, which currently requires a sign-in within 30 minutes before the change and so locks the artefact in. Also add a guard test that compares these timing patterns between takeover and benign `OtherMails` rows.

**F2 (LOW): reverting the id change would be caught only by the fixture byte-compare.** Mutation check (a deliberate small break to see whether any test notices): the verifier put back `uuid.UUID(int=self.rng.getrandbits(128), version=4)` in a scratch copy. Only `test_fixtures_match_what_the_committed_command_generates` failed, and regenerating the fixtures would hide that. Suggested guard: check that `Generator.uuid()` does not change `rng.getstate()`, or that the ids for seed 7 equal SHA-256 of `2e-id:7:<n>`.

**F3 (LOW): one new test passes without checking anything on `main`.** `test_ordinary_recovery_changes_have_no_reset_and_no_new_mfa` loops over benign `OtherMails` rows. On `main` there are none, so it passes there. Add `assert checked > 0`. The other two guard tests do fail on `main` (see section 2).

**F4 (LOW, docs):**
- README "What Claude did and what Eojin did" does not record Eojin's two decisions (128-bit seed, benign recovery changes). Only the Limits section and CAVEATS do.
- `docs/RUN-SHEET.md` is not touched by this PR. Its T2-S01 line still says "step 8 waits for Eojin", which is still true, so this is only a note for `wrap`.
- CAVEATS wording, "so the 128-bit seed cannot be recovered from the public ids": the real risk with raw ids was rebuilding the generator's *state* (Python's Mersenne Twister can be rebuilt from about 624 consecutive 32-bit outputs) and then replaying it, not recovering the seed itself. The README wording ("do not reveal the random generator's internal state") is the accurate one.

**Decision 1, correctness (code checks):**
- Deterministic: the same seed and options give byte-identical files. Tests `test_same_seed_twice_gives_identical_bytes` and `test_a_128_bit_seed_runs_and_is_deterministic` pass, and the seed-7 fixtures regenerate identically (section 3).
- v4 shape: all 584 ids in the fixtures (CorrelationIds and deviceIds) match `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` and parse as `uuid.UUID(...).version == 4` with the RFC 4122 variant. All CorrelationIds are unique.
- Derivation: every fixture id equals `uuid.UUID(bytes=sha256(f"2e-id:7:{n}")[:16], version=4)` for some counter `n`. The verifier rebuilt them independently.
- No other raw full-width generator output: `getrandbits`/`randbits` no longer appear in any code (only in README text). deviceIds also go through `self.uuid()`. Rows are sorted by (time, CorrelationId), and the CorrelationId is a hash, so the order of rows does not reveal the order in which events were generated.
- Residual risk (verifier judgement): other fields still contain *truncated* generator outputs at unknown positions in its stream (device-name digits, seconds jitter, ticket numbers, recovery-mail digits), and many draws are rejected and never shown. The verifier knows of no practical way to rebuild the generator state from these. The README claim is limited to ids, so it is accurate.
- A 128-bit seed works through `argparse type=int` and `random.Random(int)`, and is stored in the sealed labels only.

**Decision 2, other new tells checked:**
- Format: the same `recovery_mail()` builds both kinds, using `first.NNN@{freemail|mailhost|webmail}.example`. Domain counts: takeover 21/18/21, benign 54/51/45. Every value has one property and `oldValue` null. No difference.
- Who starts the change: takeovers are always self-initiated. Benign changes are 90/150 self-initiated and 60/150 by a helpdesk agent. A helpdesk-initiated change is always benign. That points away from a takeover, so it is not a shortcut to the answers.
- Sort order: no positional tell (see above).
- Weekends: benign 20/150, takeover 2/60. No strong difference.
- Small realism slip (LOW): a self-service change just after 08:00 can come from the office IP 2 to 15 minutes after a home sign-in, because `usual_context` switches at 08:00 (seen once at seed 4242). It makes the benign row look odder, not the takeover.

**Secrets, real data, unsafe patterns:** none found (section 4).

## 2. Regression (nothing broken)

| | `ruff check .` | `pytest -q` |
|---|---|---|
| `origin/main` (clean worktree `/tmp/t2f-main`, since removed) | `All checks passed!` | `31 passed in 1.06s` |
| this branch | `All checks passed!` | `35 passed in 2.25s` |

Python 3.13.16 and ruff 0.17.1 from the repo `.venv`. The branch collects all 31 test names from `main` plus 4 new ones. Nothing that passed on `main` fails now. **PASS**

Guard tests against `main`'s generator (the branch test file copied into the `main` worktree, then restored): `2 failed, 33 passed`:
- `test_recovery_email_changes_are_not_a_takeover_only_clue` → `AssertionError: (2, 0)`
- `test_every_property_name_in_a_takeover_row_also_appears_in_ordinary_rows` → `AssertionError: {'OtherMails'}`

So both guards are meaningful. `test_ordinary_recovery_changes_...` passes on `main` without checking anything (F3).

## 3. Checks requested for this follow-up

| Check | Result | Evidence |
|---|---|---|
| D1 seed is 128-bit in step 8; README updated | PASS (code check) | Brief step 8: `SEED="$(python3 -c 'import secrets; print(secrets.randbits(128))')"`; README Limits updated. |
| D1 ids: correct, deterministic, v4, nothing else leaks raw generator output | PASS (code checks + judgement on truncated outputs) | Section 1: 584/584 v4-shaped; all derivable from SHA-256(seed 7, n); no `getrandbits` in code. F2 is a missing guard, not a bug. |
| D2 `OtherMails` no longer takeover-only | PASS (code check) | Seed 4242 analysis (`analyse.py`): `('OtherMails', '-'): 5, ('OtherMails', 'TK'): 2`. Guard tests pass on the branch and fail on `main`. |
| D2 no new tell from the benign events | **FAIL (cheap fix)** | F1: the "last own sign-in more than 15 min before" pattern is 51/60 takeover vs 0/150 benign. |
| Earlier analysis script re-run (seed 4242) | PASS, runs | `rows 4998 generated 2026-09-27`; 14 admin resets (5 TK, 5 LA, 4 unlabelled), all from the agent's usual address; countries VN/US/GB each also used by ordinary (`N`) rows; self-initiated Update user: 3 benign, 2 takeover. |
| Fixtures regenerate byte-identically (brief step 7, seed 7) | PASS (code check) | `signin.jsonl identical`, `audit.jsonl identical`, `expected.json identical`; `takeovers 2 lookalikes 3`; `fixtures/audit.jsonl` holds 3 `OtherMails` rows. |
| AC6-style repo checks | PASS (code checks) | `git ls-files \| grep -iE 'key\.json\|labels\.json'` is empty; `/tmp/key.json` and `2e-blind-hunt/data/` do not exist; `git grep -n -E "pass:[^<\$\"']"` finds only brief or verify text (`docs/briefs/T2-C1.md:16`, `docs/briefs/T2-S01.md:60`, `docs/verify/T2-S01.md:74`); `git grep -n -E '^[A-Za-z0-9+/]{22,24}={0,2}$'` is empty. |
| No-tells word test still holds | PASS (code check) | Included in `35 passed`. The new domains contain no forbidden words. |

## 4. Secrets and fictional data (diff of added lines, 467 lines)

- Words key/token/password/secret/tenant/subscription: only README, CAVEATS and brief text about `secrets.randbits(128)`, plus the existing "Reset password" operation names. No values.
- Long random strings (32 or more characters, not UUIDs): none (only test names and `---` rulers).
- Email domains: `mapleharbour.example` (326), `freemail.example`, `mailhost.example`, `webmail.example`. No real domains and no URLs.
- IP addresses: only 192.0.2.x, 198.51.100.x and 203.0.113.x (RFC 5737 documentation ranges).
- Phones: `+1 416-555-01xx` only.
- `gitleaks` is not installed in this session, so it was not run; CI runs it.

## Verdict

FAIL (one cheap in-scope fix): regression, determinism, id derivation, fixtures, AC6-style checks and secrets all PASS, but the benign recovery-email changes add a timing tell (F1: 56/60 takeover vs 0/150 benign) that the builder should remove by widening the benign timing and the matching test. Without that fix, it needs a caveat.

New caveats: F1, if not fixed. Truncated generator outputs in other fields are a theoretical residual only (judgement); no action is needed.
