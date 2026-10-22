#!/usr/bin/env python3
"""Score a blind hunt: compare your labelled takeovers with the decrypted answer key.

    python scripts/score_my_labels.py --labels 2e-blind-hunt/my-labels.json --key <decrypted-key.json>

A label of yours counts as a hit when it matches a not-yet-matched takeover in the key by EITHER
  * evidence: it lists at least one CorrelationId that is in the key takeover's evidence, or
  * time window: same UserPrincipalName and the two [start, end] time windows overlap.
Event ids are checked first, then time windows, and each key takeover can be hit only once.

precision = hits / labels you gave        (how many of your labels were real)
recall    = hits / takeovers in the key   (how many of the real ones you found)
With no labels at all, both are reported as 0.0.

Output rule: the key is only ever described by ids (and users of the ones you missed).
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime


def parse_time(text):
    """ISO 8601 text -> aware datetime (UTC if no zone), or None if it cannot be read."""
    if not isinstance(text, str) or not text.strip():
        return None
    try:
        t = datetime.fromisoformat(text.strip())
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=UTC)


def window(item):
    start, end = parse_time(item.get("start")), parse_time(item.get("end"))
    if start and not end:
        end = start
    if end and not start:
        start = end
    if start and end and start > end:
        start, end = end, start
    return start, end


def windows_overlap(a, b) -> bool:
    (a0, a1), (b0, b1) = window(a), window(b)
    if not (a0 and a1 and b0 and b1):
        return False
    return a0 <= b1 and b0 <= a1


def same_user(a, b) -> bool:
    ua, ub = str(a.get("user", "")).strip().lower(), str(b.get("user", "")).strip().lower()
    return bool(ua) and ua == ub


def shares_evidence(a, b) -> bool:
    ea = {str(x).strip().lower() for x in a.get("evidence") or [] if str(x).strip()}
    eb = {str(x).strip().lower() for x in b.get("evidence") or [] if str(x).strip()}
    return bool(ea & eb)


def score(labels: dict, key: dict) -> dict:
    mine = list(labels.get("takeovers") or [])
    truth = list(key.get("takeovers") or [])
    benign = list(key.get("lookalikes") or [])
    matched = []  # (my index, key index)
    used_mine, used_key = set(), set()
    for rule in (shares_evidence, lambda a, b: same_user(a, b) and windows_overlap(a, b)):
        for i, m in enumerate(mine):
            if i in used_mine:
                continue
            for j, k in enumerate(truth):
                if j not in used_key and rule(m, k):
                    matched.append((i, j))
                    used_mine.add(i)
                    used_key.add(j)
                    break
    extra = []
    for i, m in enumerate(mine):
        if i in used_mine:
            continue
        near = next((b.get("id") for b in benign if shares_evidence(m, b)
                     or (same_user(m, b) and windows_overlap(m, b))), None)
        extra.append((m.get("id", "?"), m.get("user", "?"), near))
    hits = len(matched)
    return {
        "precision": round(hits / len(mine), 3) if mine else 0.0,
        "recall": round(hits / len(truth), 3) if truth else 0.0,
        "matched": [(mine[i].get("id", "?"), truth[j].get("id", "?")) for i, j in matched],
        "missed": [(k.get("id", "?"), k.get("user", "?"))
                   for j, k in enumerate(truth) if j not in used_key],
        "extra": extra,
        "n_labels": len(mine),
        "n_key": len(truth),
    }


def load(path: str, what: str) -> dict:
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        sys.exit(f"cannot read {what} file as JSON: {path}")
    if not isinstance(data, dict):
        sys.exit(f"{what} file must be a JSON object with a 'takeovers' list")
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Score blind-hunt labels against the answer key.")
    ap.add_argument("--labels", required=True, help="your my-labels.json")
    ap.add_argument("--key", required=True, help="the decrypted answer key")
    args = ap.parse_args(argv)
    result = score(load(args.labels, "labels"), load(args.key, "key"))
    print(f"labels given: {result['n_labels']}   takeovers in key: {result['n_key']}")
    print(f"precision: {result['precision']}")
    print(f"recall: {result['recall']}")
    print("matched:", ", ".join(f"{a} = {b}" for a, b in result["matched"]) or "none")
    print("missed:", ", ".join(f"{i} ({u})" for i, u in result["missed"]) or "none")
    if result["extra"]:
        print("extra (not takeovers):")
        for label_id, user, near in result["extra"]:
            note = f" - overlaps benign case {near}" if near else ""
            print(f"  {label_id} ({user}){note}")
    else:
        print("extra (not takeovers): none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
