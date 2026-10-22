#!/usr/bin/env python3
"""Load a folder of sign-in/audit data into the Kusto emulator, run every 2H detection, write alerts.

    python scripts/run_detections.py --url http://localhost:9000 --data fixtures --out alerts.jsonl

<data> must hold signin.jsonl and audit.jsonl. A fresh database is created on every run.
One JSON line is written per result row of a detection:
    {alert_id, detection_id, title, severity, UserPrincipalName, TimeGenerated,
     evidence: {every column of the row}, source_correlation_ids: [CorrelationId values]}
alert_id is a short hash of the detection id, user, time and source ids, so re-running gives the
same ids. Only counts are printed (never user names), because CI logs are public.
Standard library plus azure-kusto-data. The emulator needs no credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import kql_common


def to_json_value(value):
    """Datetimes become 2026-09-15T17:20:40Z text; everything else is already JSON-friendly."""
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, dict):
        return {key: to_json_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [to_json_value(item) for item in value]
    return value


def build_alert(header: dict, row: dict) -> dict:
    evidence = {name: to_json_value(value) for name, value in row.items()}
    # every column whose name ends in CorrelationId holds an id of a log row behind this alert
    sources = sorted({str(value) for name, value in evidence.items()
                      if name.endswith("CorrelationId") and value})
    stamp = evidence["TimeGenerated"]
    digest = hashlib.sha256(
        "|".join([header["id"], evidence["UserPrincipalName"], stamp, *sources]).encode()
    ).hexdigest()[:12]
    return {
        "alert_id": f"{header['id']}-{digest}",
        "detection_id": header["id"],
        "title": header["title"],
        "severity": header["severity"],
        "UserPrincipalName": evidence["UserPrincipalName"],
        "TimeGenerated": stamp,
        "evidence": evidence,
        "source_correlation_ids": sources,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--url", required=True, help="Kusto emulator URL, e.g. http://localhost:9000")
    parser.add_argument("--data", required=True, type=Path, help="folder with signin.jsonl and audit.jsonl")
    parser.add_argument("--out", required=True, type=Path, help="alerts file to write (JSON Lines)")
    args = parser.parse_args(argv)

    client = kql_common.connect(args.url)
    counts = kql_common.load_data(client, args.data)
    print("loaded " + ", ".join(f"{table}={count}" for table, count in counts.items()))

    alerts = []
    for detection_id in kql_common.detection_ids():
        header = yaml.safe_load((kql_common.DETECTIONS_DIR / f"{detection_id}.yaml").read_text())
        rows = kql_common.run_query(
            client, (kql_common.DETECTIONS_DIR / f"{detection_id}.kql").read_text())
        alerts += [build_alert(header, row) for row in rows]
        print(f"{detection_id}: {len(rows)} alert(s)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.writelines(json.dumps(alert, sort_keys=True) + "\n" for alert in alerts)
    print(f"wrote {len(alerts)} alert(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
