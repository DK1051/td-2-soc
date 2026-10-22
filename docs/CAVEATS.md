# Caveats found during execution

One line per surprise (missing tool, limit, wrong assumption, cheaper path), appended during the session it happened in:

`- YYYY-MM-DD <ID> | what happened | impact: this session / <later IDs> / plan | what I did | needs Eojin: yes/no`
- 2026-10-22 T2-S01 | Ran in one cloud session with the hub and the other tracks (Eojin's D0 launch, no plan-approval stop); this session can push only to `claude/friendly-heisenberg-seafff`, not the brief's branch name | impact: this session | used that branch; one PR | needs Eojin: no
- 2026-10-22 T2-S01 | Credit balances not available during the unattended run; the usage menu shows one combined number for all five D0 sessions | impact: this session | placeholders in `COSTS.md`; record the combined number in the hub `COSTS.md` | needs Eojin: yes
- 2026-10-22 T2-S01 | Step 8 (generate the real 2E dataset and seal the answer key) skipped by Eojin's order: he was not present to store the passphrase and seed | impact: this session (AC3, AC6, AC7 open) / T2-S03 (needs the hunt data and Eojin's labels) | built and tested everything else; README says the data is not generated yet | needs Eojin: yes — run step 8 in a session where he is present
- 2026-10-22 T2-S01 | Probe: x86_64 and avx2 4, but `docker: not available` (no Docker engine) | impact: T2-S02 | marked T2-S02 AT RISK; it falls back to data tests in the `kql` CI job | needs Eojin: yes (confirm fallback before D2)
- 2026-10-22 T2-S01 | The background Kusto image pull never ran (`/tmp/kusto-pull.log` missing): this session started in the hub repo, so td-2-soc's SessionStart hook did not fire; the hook also pulls `kustainer-linux:latest`, not a pinned tag | impact: T2-S02 | none now | needs Eojin: yes (pin the image tag)
- 2026-10-22 T2-S01 | Builder flag: step 8's seed is `secrets.randbelow(10**9)` (about 30 bits); with the public generator and public `answer-key.sha256`, a determined person could in principle brute-force the seed and rebuild the key | impact: step 8 | not changed; README states it | needs Eojin: yes (consider a larger seed range, e.g. 10**18, before running step 8)
