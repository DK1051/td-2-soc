"""Shared helpers for the 2H detection pack: load JSONL data into the Kusto emulator and run KQL.

Used by scripts/run_detections.py and by 2h-detection-pack/tests/conftest.py, so the tests and the
alert runner load data in exactly the same way. Python 3.12+, needs azure-kusto-data.

Safety: the emulator is a local, unauthenticated Docker container with no real data in it.
Never point this at a real cluster; no credentials are used or stored anywhere in this file.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml
from azure.kusto.data import KustoClient, KustoConnectionStringBuilder

DATABASE = "mapleharbour"
BATCH_SIZE = 100  # rows per ingestion command (the brief's limit)

REPO_ROOT = Path(__file__).resolve().parent.parent
DETECTIONS_DIR = REPO_ROOT / "2h-detection-pack" / "detections"

# One column per fixture field. "dynamic" columns hold nested JSON objects/arrays.
TABLES = {
    "SigninLogs": [
        ("TimeGenerated", "datetime"), ("UserPrincipalName", "string"), ("IPAddress", "string"),
        ("Location", "dynamic"), ("AppDisplayName", "string"), ("ResultType", "string"),
        ("AuthenticationRequirement", "string"), ("DeviceDetail", "dynamic"),
        ("CorrelationId", "string"),
    ],
    "AuditLogs": [
        ("TimeGenerated", "datetime"), ("OperationName", "string"), ("InitiatedBy", "dynamic"),
        ("TargetResources", "dynamic"), ("CorrelationId", "string"),
    ],
}
# data file name inside a data directory -> table name
DATA_FILES = {"signin.jsonl": "SigninLogs", "audit.jsonl": "AuditLogs"}

_ISO_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def connect(url: str) -> KustoClient:
    """Client for the local emulator (no authentication)."""
    return KustoClient(KustoConnectionStringBuilder.with_no_authentication(url))


def kql_literal(value, kind: str) -> str:
    """Turn one JSON value into a KQL literal for a datatable(...) row."""
    if kind == "datetime":
        if not isinstance(value, str) or not _ISO_UTC.match(value):
            raise ValueError("TimeGenerated must look like 2026-09-14T12:34:44Z")
        return f"datetime({value})"
    if kind == "dynamic":
        return f"dynamic({json.dumps(value, ensure_ascii=False)})"
    if value is None:
        return '""'
    # json.dumps gives a double-quoted string with quotes and backslashes escaped,
    # which is also a valid KQL string literal.
    return json.dumps(str(value), ensure_ascii=False)


def read_rows(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def count_lines(path: Path) -> int:
    with open(path, encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def reset_database(client: KustoClient, database: str = DATABASE) -> None:
    """Drop (if present) and re-create the database and both tables, so every run starts empty."""
    client.execute_mgmt("NetDefaultDB", f".drop database {database} ifexists")
    # TODO(verify): "volatile" (in-memory database) is what the emulator accepted when this
    # harness was written; if a future image refuses it, use the persist form instead.
    client.execute_mgmt("NetDefaultDB", f".create database {database} volatile")
    for table, columns in TABLES.items():
        schema = ", ".join(f"{name}:{kind}" for name, kind in columns)
        client.execute_mgmt(database, f".create table {table} ({schema})")


def ingest(client: KustoClient, table: str, rows: list[dict], database: str = DATABASE) -> None:
    columns = TABLES[table]
    names = {name for name, _ in columns}
    schema = ", ".join(f"{name}:{kind}" for name, kind in columns)
    for start in range(0, len(rows), BATCH_SIZE):
        lines = []
        for row in rows[start:start + BATCH_SIZE]:
            unknown = set(row) - names
            if unknown:
                raise ValueError(f"{table}: unexpected field(s) {sorted(unknown)}")
            lines.append(", ".join(kql_literal(row.get(name), kind) for name, kind in columns))
        body = ",\n".join(lines)
        client.execute_mgmt(database, f".set-or-append {table} <|\ndatatable({schema})[\n{body}\n]")


def table_count(client: KustoClient, table: str, database: str = DATABASE) -> int:
    result = client.execute_query(database, f"{table} | count")
    return int(result.primary_results[0][0]["Count"])


def load_data(client: KustoClient, data_dir: Path, database: str = DATABASE) -> dict[str, int]:
    """Fresh database + tables, ingest signin.jsonl and audit.jsonl, check the row counts.
    Returns {table: row count}. Raises RuntimeError if a count differs from the file."""
    data_dir = Path(data_dir)
    reset_database(client, database)
    counts = {}
    for file_name, table in DATA_FILES.items():
        path = data_dir / file_name
        ingest(client, table, read_rows(path), database)
        expected, actual = count_lines(path), table_count(client, table, database)
        if expected != actual:
            raise RuntimeError(f"{table}: file has {expected} rows but the table has {actual}")
        counts[table] = actual
    return counts


def load_rows(client: KustoClient, signin: list[dict], audit: list[dict], database: str) -> None:
    """Same as load_data but from rows already in memory (used by the synthetic test cases)."""
    reset_database(client, database)
    for table, rows in (("SigninLogs", signin), ("AuditLogs", audit)):
        ingest(client, table, rows, database)
        if table_count(client, table, database) != len(rows):
            raise RuntimeError(f"{table}: row count differs after ingest")


def run_query(client: KustoClient, text: str, database: str = DATABASE) -> list[dict]:
    """Run a KQL query; return the rows as plain dicts."""
    result = client.execute_query(database, text)
    return [row.to_dict() for row in result.primary_results[0]]


def detection_ids() -> list[str]:
    return sorted(path.stem for path in DETECTIONS_DIR.glob("*.kql"))


def read_detection(detection_id: str) -> tuple[dict, str]:
    """(YAML header, KQL text) of one detection."""
    header = yaml.safe_load((DETECTIONS_DIR / f"{detection_id}.yaml").read_text(encoding="utf-8"))
    return header, (DETECTIONS_DIR / f"{detection_id}.kql").read_text(encoding="utf-8")
