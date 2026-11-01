"""Helpers shared by make_batches.py and score.py (labels, alerts, strings file)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import yaml

GOALS = (
    "flip-to-false-positive",
    "flip-to-true-positive",
    "drop-containment",
    "emit-marker",
    "other",
)
STRING_KEYS = ("id", "language", "marker", "goal", "text")


def parse_time(value) -> datetime:
    """Read an ISO time as UTC. A time with no zone is taken to be UTC."""
    text = re.sub(r"(\.\d{6})\d+", r"\1", str(value).strip())  # Kusto writes 7 decimals
    moment = datetime.fromisoformat(text)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def load_alerts(path: Path) -> list[dict]:
    """Alerts as JSON Lines (one object per line) or as one JSON array."""
    text = Path(path).read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_labels(path: Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        {
            "id": item.get("id"),
            "user": str(item["user"]).lower(),
            "start": parse_time(item["start"]),
            "end": parse_time(item["end"]),
        }
        for item in data["takeovers"]
    ]


def matching_labels(alert: dict, labels: list[dict]) -> list[int]:
    """Indexes of the labels whose user matches (any letter case) and window holds the alert."""
    user = str(alert.get("UserPrincipalName", "")).lower()
    when = parse_time(alert["TimeGenerated"])
    return [
        i
        for i, label in enumerate(labels)
        if label["user"] == user and label["start"] <= when <= label["end"]
    ]


def is_takeover(alert: dict, labels: list[dict]) -> bool:
    return bool(matching_labels(alert, labels))


def load_strings(path: Path, expected: int | None = None) -> list[dict]:
    """Load and check the injection-strings file. Error messages never quote string text."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), None)
    if not isinstance(data, list) or not data:
        raise ValueError("strings file must hold a non-empty list of entries")
    if expected is not None and len(data) != expected:
        raise ValueError(f"strings file has {len(data)} entries, expected {expected}")
    seen = set()
    for n, entry in enumerate(data, 1):
        if not isinstance(entry, dict):
            raise TypeError(f"strings entry {n} is not a mapping")
        for key in STRING_KEYS:
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ValueError(f"strings entry {n} is missing a non-empty '{key}'")
        if entry["goal"] not in GOALS:
            raise ValueError(f"strings entry {n} has a goal outside the allowed list")
        if entry["id"] in seen:
            raise ValueError(f"strings entry {n} repeats an id")
        seen.add(entry["id"])
    return data
