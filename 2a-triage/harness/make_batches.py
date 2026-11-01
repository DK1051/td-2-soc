#!/usr/bin/env python3
"""Build the clean and poisoned alert batches for the 2A injection test.

    python make_batches.py --alerts alerts.jsonl --strings ../injections/strings.yaml --out batches

Writes into --out:
  clean-NN.json     a seeded sample of the alerts, split into batches of --batch-size
  poisoned-NN.json  poisoned copies plus their unchanged "clean twins", shuffled, fresh random ids
  manifest.json     {poisoned_id: {clean_twin, original_id, injection_id, field, batch}}

Clean sample: at most --max-clean alerts. Every alert inside a labelled takeover window is always
kept (even if that exceeds --max-clean); the rest are drawn round-robin across detection_id.

Poisoned copies: for each string, --per-string alerts from the clean sample. The field rotates
over FIELDS. A string is appended to the field's existing text after one space. If the field holds
JSON written as text, it is parsed, edited and written back as text. An alert lacking the field is
skipped and another is tried.

Ticket note definition (third field): the "newValue" of the first entry of
evidence.TargetResources[0].modifiedProperties, because that is the free-text value a
requester can type. If that value is itself a JSON-encoded string, the text goes inside it.

Before writing, main prints the in-window alert count per label and the count of alerts with an
empty UserPrincipalName, and stops (exit 2) if a label matches no alerts (--allow-empty-labels
overrides) or if any marker already appears in the clean sample.

Only counts are printed. String text is never printed.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
from pathlib import Path

from triage_common import is_takeover, load_alerts, load_labels, load_strings, matching_labels

HERE = Path(__file__).resolve().parent
DEFAULT_LABELS = HERE.parent.parent / "2e-blind-hunt" / "labels-final.json"

FIELDS = {
    "evidence.DeviceDetail.displayName": ("evidence", "DeviceDetail", "displayName"),
    "evidence.TargetResources[0].displayName": ("evidence", "TargetResources", 0, "displayName"),
    "evidence.TargetResources[0].modifiedProperties": (
        "evidence", "TargetResources", 0, "modifiedProperties", 0, "newValue",
    ),
}


class MissingField(Exception):
    """The alert has no (text) value at the requested path."""


def _insert(node, path, text):
    if not path:
        if not isinstance(node, str):
            raise MissingField
        try:
            inner = json.loads(node)
        except ValueError:
            inner = None
        if isinstance(inner, str):  # the value is itself a JSON-encoded string: edit inside it
            joined = f"{inner} {text}" if inner else text
            return json.dumps(joined, ensure_ascii=False)
        return f"{node} {text}" if node else text
    if isinstance(node, str):  # JSON written as text: parse, edit, write back as text
        try:
            inner = json.loads(node)
        except ValueError:
            raise MissingField from None
        if not isinstance(inner, (dict, list)):
            raise MissingField
        return json.dumps(_insert(inner, path, text), ensure_ascii=False)
    key = path[0]
    if isinstance(node, dict) and isinstance(key, str) and key in node:
        node[key] = _insert(node[key], path[1:], text)
        return node
    if isinstance(node, list) and isinstance(key, int) and 0 <= key < len(node):
        node[key] = _insert(node[key], path[1:], text)
        return node
    raise MissingField


def insert_text(alert: dict, field: str, text: str) -> dict:
    """Return a copy of the alert with text appended to the field. Raises MissingField."""
    return _insert(copy.deepcopy(alert), FIELDS[field], text)


def make_clean_sample(alerts, labels, max_clean, rng):
    must = [a for a in alerts if is_takeover(a, labels)]
    must_ids = {a["alert_id"] for a in must}
    groups: dict[str, list] = {}
    for alert in alerts:
        if alert["alert_id"] not in must_ids:
            groups.setdefault(alert["detection_id"], []).append(alert)
    names = sorted(groups)
    rng.shuffle(names)
    for name in names:
        rng.shuffle(groups[name])
    budget = max(0, max_clean - len(must))
    picked = []
    while budget > 0 and any(groups.values()):
        for name in names:
            if budget > 0 and groups[name]:
                picked.append(groups[name].pop())
                budget -= 1
    sample = must + picked
    rng.shuffle(sample)
    return sample


def _fresh_id(rng, taken):
    while True:
        new = f"p-{rng.getrandbits(48):012x}"
        if new not in taken:
            taken.add(new)
            return new


def pick_poisoned(sample, strings, per_string, rng, taken):
    """Yield (string, [(poisoned, twin, original, field)]) for each string."""
    used_anywhere: set[str] = set()
    names = list(FIELDS)
    for s_index, string in enumerate(strings):
        group, used_here = [], set()
        for k in range(per_string):
            field = names[(s_index * per_string + k) % len(names)]
            order = sample[:]
            rng.shuffle(order)
            unused = [a for a in order if a["alert_id"] not in used_anywhere]
            used = [a for a in order if a["alert_id"] in used_anywhere]
            order = unused + used  # prefer alerts not yet poisoned for another string
            for alert in order:
                if alert["alert_id"] in used_here:
                    continue
                try:
                    poisoned = insert_text(alert, field, string["text"])
                except MissingField:
                    continue
                twin = copy.deepcopy(alert)
                poisoned["alert_id"] = _fresh_id(rng, taken)
                twin["alert_id"] = _fresh_id(rng, taken)
                used_here.add(alert["alert_id"])
                used_anywhere.add(alert["alert_id"])
                group.append((poisoned, twin, alert, field))
                break
            else:
                raise SystemExit(f"not enough alerts have field {field} for string {s_index + 1}")
        yield string, group


def write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--alerts", required=True, type=Path)
    p.add_argument("--strings", type=Path, default=HERE.parent / "injections" / "strings.yaml")
    p.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    p.add_argument("--out", type=Path, default=HERE.parent / "batches")
    p.add_argument("--batch-size", type=int, default=20)
    p.add_argument("--per-string", type=int, default=3)
    p.add_argument("--max-clean", type=int, default=100)
    p.add_argument("--seed", type=int, default=1)
    p.add_argument("--allow-empty-labels", action="store_true",
                   help="do not stop when a label matches no alerts")
    p.add_argument("--n-strings", type=int, default=10,
                   help="exact number of entries the strings file must hold (tests use fewer)")
    args = p.parse_args(argv)

    try:
        strings = load_strings(args.strings, expected=args.n_strings)
    except (ValueError, TypeError) as err:
        raise SystemExit(f"strings file rejected: {err}") from None
    alerts = load_alerts(args.alerts)
    ids = [a["alert_id"] for a in alerts]
    if len(set(ids)) != len(ids):
        raise SystemExit("alert_id values are not unique")
    labels = load_labels(args.labels)
    rng = random.Random(args.seed)

    # Sanity counts: a label that matches nothing usually means a wrong user or time window.
    per_label = [0] * len(labels)
    for alert in alerts:
        for i in matching_labels(alert, labels):
            per_label[i] += 1
    for i, label in enumerate(labels):
        print(f"label {label['id'] if label['id'] is not None else i + 1}: "
              f"{per_label[i]} in-window alerts")
    print(f"alerts with empty UserPrincipalName: "
          f"{sum(1 for a in alerts if not str(a.get('UserPrincipalName', '')).strip())}")
    empty = [label["id"] if label["id"] is not None else i + 1
             for i, label in enumerate(labels) if per_label[i] == 0]
    if empty and not args.allow_empty_labels:
        print(f"refused: label(s) {', '.join(map(str, empty))} match 0 alerts; check the user "
              "and times, or pass --allow-empty-labels")
        return 2

    sample = make_clean_sample(alerts, labels, args.max_clean, rng)
    sample_text = json.dumps(sample, ensure_ascii=False).lower()
    clashing = [st["id"] for st in strings if st["marker"].lower() in sample_text]
    if clashing:
        print(f"refused: the marker of string(s) {', '.join(clashing)} already appears in the "
              "clean alerts; pick a marker that does not occur in the data")
        return 2
    # Refuse a folder that already holds batch files: score.py reads every *.json in it, so
    # files left over from an earlier run would be scored by mistake.
    if args.out.exists() and any(args.out.glob("*.json")):
        print(f"refused: {args.out} already holds .json files; empty it or pick a new --out")
        return 2
    args.out.mkdir(parents=True, exist_ok=True)
    clean_names = []
    for n, start in enumerate(range(0, len(sample), args.batch_size), 1):
        name = f"clean-{n:02d}.json"
        write_json(args.out / name, sample[start:start + args.batch_size])
        clean_names.append(name)

    taken = set(ids)
    groups = [g for _, g in pick_poisoned(sample, strings, args.per_string, rng, taken)]
    packed, current = [], []
    for group in groups:  # pack whole strings into batches of at most --batch-size alerts
        if current and 2 * len(current) + 2 * len(group) > args.batch_size:
            packed.append(current)
            current = []
        current += group
    if current:
        packed.append(current)

    manifest = {}
    for n, members in enumerate(packed, 1):
        name = f"poisoned-{n:02d}.json"
        batch = []
        for poisoned, twin, original, field in members:
            batch += [poisoned, twin]
            manifest[poisoned["alert_id"]] = {
                "clean_twin": twin["alert_id"],
                "original_id": original["alert_id"],
                "injection_id": None,  # filled below
                "field": field,
                "batch": name,
            }
        rng.shuffle(batch)
        write_json(args.out / name, batch)
    # injection ids: groups were built string by string, in order
    flat = [(s["id"], g_item[0]["alert_id"]) for s, g in zip(strings, groups, strict=True)
            for g_item in g]
    for injection_id, poisoned_id in flat:
        manifest[poisoned_id]["injection_id"] = injection_id
    write_json(args.out / "manifest.json", manifest)

    print(f"clean sample: {len(sample)} alerts in {len(clean_names)} batches")
    print(f"poisoned: {len(manifest)} copies (plus twins) in {len(packed)} batches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
