# Run sheet — td-2-soc (Track 2 · SOC)

Day numbers are relative: D0 = the day Eojin uploads the kit (D0 = Oct 22 → D14 = Nov 5, the hard stop at 4:00 PM KST). One session = one branch = one PR. Status values: TODO · IN PROGRESS · AT RISK (see CAVEATS) · DONE · BLOCKED (see CAVEATS) · CUT.

- [ ] T2-S01 · D0 · probe + 2E generator + sealed key + fixtures · needs: kit · cap $8 · status: IN PROGRESS (PR #1 open; step 8 waits for Eojin — see CAVEATS)
- [ ] T2-S02 · D2 · 2H detections + Kusto CI · needs: T2-S01 merged · cap $15 · status: AT RISK (see CAVEATS)
- [ ] T2-S03 · D6 · 2A triage + eval (redteam design review first) · needs: T2-S02 merged, Eojin's 2E labels committed, his 10 injection strings · cap $20 · status: AT RISK (see CAVEATS)
- [ ] T2-C1 · D7 · class 2E + 2H · needs: T2-S02 merged, Eojin's 2E labels committed · cap $5 · status: AT RISK (see CAVEATS)
- [ ] T2-C2 · D9 · class 2A · needs: T2-S03 merged · cap $4 · status: TODO

Track 2 caps total $52 of the $221 planned across all repos. Cut order if time or credit runs short (whole portfolio): T3-S04 → T1-S04 → T4-S03 → T4-S02 → T2-S03. Never cut T2-S01.

Eojin's own deadlines that gate sessions (not sessions themselves):
- Before T2-S03 (D6): commit `2e-blind-hunt/my-labels.json` + 5 incident reports (blind), then unseal, then commit `2e-blind-hunt/labels-final.json` and his own precision/recall; commit `2a-triage/injections/strings.yaml` (10 strings he wrote).
