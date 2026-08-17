"""Shared alert schema for all soc-Analyser detection engines.

Both phishing and log-analysis engines should return Alert objects so the API,
dashboard, reports, and incident response playbooks can consume one stable
contract regardless of detection source.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class AlertSource(str, Enum):
    """Engine or telemetry source that produced an alert."""

    PHISHING_EMAIL = "phishing_email"
    LOG_ANALYSIS = "log_analysis"


class AlertSeverity(str, Enum):
    """Analyst-facing severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Lifecycle state for dashboard and incident response workflows."""

    NEW = "new"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    CLOSED = "closed"


@dataclass(frozen=True)
class Indicator:
    """A concrete observable that contributed to the alert."""

    type: str
    value: str
    description: str


@dataclass(frozen=True)
class Evidence:
    """A scored detection signal produced by an engine."""

    name: str
    score: int
    description: str
    location: str = "unknown"


@dataclass
class Alert:
    """Canonical alert object emitted by every soc-Analyser engine."""

    source: AlertSource
    title: str
    severity: AlertSeverity
    score: int
    summary: str
    recommended_actions: list[str]
    mitre_techniques: list[str]
    indicators: list[Indicator]
    evidence: list[Evidence]
    raw_event: dict[str, Any]
    alert_id: str = field(default_factory=lambda: f"alert-{uuid4()}")
    status: AlertStatus = AlertStatus.NEW
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")

        if not self.title.strip():
            raise ValueError("title is required")

        if not self.summary.strip():
            raise ValueError("summary is required")

        if not self.mitre_techniques:
            raise ValueError("mitre_techniques must contain at least one value")

        if not self.recommended_actions:
            raise ValueError("recommended_actions must contain at least one value")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dictionary for API responses and storage."""

        payload = asdict(self)
        payload["source"] = self.source.value
        payload["severity"] = self.severity.value
        payload["status"] = self.status.value
        return payload

