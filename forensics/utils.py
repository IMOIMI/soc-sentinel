"""Hashing and timeline utilities for incident triage."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from engines.alert_schema import Alert


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 hash for a file on disk."""

    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(data: Any) -> str:
    """Return a stable SHA-256 hash for JSON-like evidence."""

    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()


def build_timeline(alerts: list[Alert]) -> list[dict[str, Any]]:
    """Flatten alert event evidence into a chronological incident timeline."""

    timeline: list[dict[str, Any]] = []
    for alert in alerts:
        events = alert.raw_event.get("events", [])
        if not events:
            timeline.append(
                {
                    "timestamp": alert.created_at,
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "summary": alert.summary,
                    "event_id": None,
                }
            )
            continue

        for event in events:
            timeline.append(
                {
                    "timestamp": event.get("timestamp", alert.created_at),
                    "alert_id": alert.alert_id,
                    "title": alert.title,
                    "event_id": event.get("event_id"),
                    "event_code": event.get("event_code"),
                    "computer": event.get("computer"),
                    "user": event.get("user"),
                    "message": event.get("message"),
                }
            )

    return sorted(timeline, key=lambda item: item["timestamp"] or "")

