"""Correlated Windows Security/Sysmon log analysis engine."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from engines.alert_schema import Alert, AlertSeverity, AlertSource, Evidence, Indicator
from engines.mitre_mapping import techniques_for_signals


BRUTE_FORCE_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_FAILURES = 5
EXTERNAL_TEST_NETS = ("203.0.113.", "198.51.100.")


@dataclass(frozen=True)
class LogSignal:
    triggered: bool
    weight: float
    reason: str
    indicator: str | None = None
    signal: str = "suspicious_login"


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load schema-accurate synthetic Windows/Sysmon JSON events."""

    return json.loads(Path(path).read_text(encoding="utf-8"))


def analyze_events(events: list[dict[str, Any]]) -> list[Alert]:
    """Analyze raw events and return correlated alerts."""

    sorted_events = sorted(events, key=lambda event: event["timestamp"])
    alerts: list[Alert] = []
    brute_force = _detect_brute_force(sorted_events)
    powershell = _detect_powershell_c2(sorted_events)
    persistence = _detect_scheduled_task_persistence(sorted_events)

    for alert in (brute_force, powershell, persistence):
        if alert is not None:
            alerts.append(alert)

    return alerts


def analyze_log_file(path: str | Path) -> list[Alert]:
    """Load and analyze a JSON event file."""

    return analyze_events(load_events(path))


def _detect_brute_force(events: list[dict[str, Any]]) -> Alert | None:
    failures_by_key: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    successes = [event for event in events if event.get("event_code") == 4624]

    for event in events:
        if event.get("event_code") == 4625:
            key = (event.get("computer", ""), event.get("user", ""), event.get("source_ip", ""))
            failures_by_key[key].append(event)

    for key, failures in failures_by_key.items():
        if len(failures) < BRUTE_FORCE_FAILURES:
            continue

        first_time = _parse_time(failures[0]["timestamp"])
        last_time = _parse_time(failures[-1]["timestamp"])
        if last_time - first_time > BRUTE_FORCE_WINDOW:
            continue

        computer, user, source_ip = key
        matching_success = next(
            (
                success
                for success in successes
                if success.get("computer") == computer
                and success.get("user") == user
                and success.get("source_ip") == source_ip
                and _parse_time(success["timestamp"]) >= last_time
                and _parse_time(success["timestamp"]) - last_time <= BRUTE_FORCE_WINDOW
            ),
            None,
        )
        if not matching_success:
            continue

        correlated = failures + [matching_success]
        signals = [
            LogSignal(
                True,
                45,
                f"{len(failures)} failed logons for {user} from {source_ip} in under five minutes",
                source_ip,
                "brute_force",
            ),
            LogSignal(
                True,
                30,
                "Successful logon followed the failed-logon burst from the same source",
                matching_success["event_id"],
                "valid_accounts",
            ),
        ]
        return _build_alert(
            alert_id="log-bruteforce-compromise",
            title="Compromised account after brute-force burst",
            score=75,
            summary=f"Account {user} on {computer} had repeated failures from {source_ip}, then a successful logon.",
            signals=signals,
            events=correlated,
            severity=AlertSeverity.HIGH,
            recommended_actions=[
                "Disable or reset the affected account",
                "Block the source IP at the perimeter",
                "Review successful logon session activity",
            ],
        )

    return None


def _detect_powershell_c2(events: list[dict[str, Any]]) -> Alert | None:
    process_events = [event for event in events if event.get("event_code") == 1]
    network_events = [event for event in events if event.get("event_code") == 3]

    suspicious_processes = []
    decoded_payloads: dict[str, str] = {}
    for event in process_events:
        image = event.get("image", "").lower()
        command_line = event.get("command_line", "")
        if "powershell.exe" not in image:
            continue

        decoded = decode_powershell_command(command_line)
        decoded_payloads[event["event_id"]] = decoded
        if "-encodedcommand" in command_line.lower() or _contains_credential_theft(decoded):
            suspicious_processes.append(event)

    if not suspicious_processes:
        return None

    c2_events = [
        event
        for event in network_events
        if any(event.get("destination_ip", "").startswith(prefix) for prefix in EXTERNAL_TEST_NETS)
    ]
    recon_events = [
        event
        for event in process_events
        if event.get("image", "").lower().endswith("whoami.exe")
        or "whoami" in event.get("command_line", "").lower()
    ]
    if not c2_events:
        return None

    powershell_event = suspicious_processes[0]
    c2_event = c2_events[0]
    decoded = decoded_payloads[powershell_event["event_id"]]
    correlated = [powershell_event, *recon_events[:1], c2_event]
    signals = [
        LogSignal(
            True,
            35,
            "PowerShell launched with an encoded command",
            powershell_event["event_id"],
            "powershell",
        ),
        LogSignal(
            bool(decoded),
            25,
            f"Decoded payload contains suspicious content: {decoded[:120]}",
            decoded,
            "user_execution",
        ),
        LogSignal(
            True,
            25,
            f"PowerShell made an outbound connection to {c2_event.get('destination_ip')}:{c2_event.get('destination_port')}",
            c2_event.get("destination_ip"),
            "command_and_control",
        ),
    ]
    if recon_events:
        signals.append(
            LogSignal(
                True,
                10,
                "Account discovery command executed after PowerShell launch",
                recon_events[0]["event_id"],
                "account_discovery",
            )
        )

    return _build_alert(
        alert_id="log-powershell-c2",
        title="Encoded PowerShell execution with C2 callback",
        score=95,
        summary="Encoded PowerShell decoded to a credential-theft style payload and made an outbound callback.",
        signals=signals,
        events=correlated,
        severity=AlertSeverity.CRITICAL,
        recommended_actions=[
            "Isolate the host from the network",
            "Collect PowerShell logs and memory artifacts",
            "Block the destination IP and search for the decoded payload",
        ],
    )


def _detect_scheduled_task_persistence(events: list[dict[str, Any]]) -> Alert | None:
    task_events = [event for event in events if event.get("event_code") == 4698]
    process_events = [event for event in events if event.get("event_code") == 1]
    if not task_events:
        return None

    task_event = task_events[0]
    task_name = task_event.get("task_name", "")
    task_content = task_event.get("task_content", "")
    schtasks = [
        event
        for event in process_events
        if event.get("image", "").lower().endswith("schtasks.exe")
        or "schtasks" in event.get("command_line", "").lower()
    ]
    payload_path = _extract_task_command(task_content)
    payload_runs = [
        event
        for event in process_events
        if payload_path and payload_path.lower() in event.get("image", "").lower()
    ]

    suspicious_path = "\\programdata\\" in payload_path.lower() if payload_path else False
    if not (schtasks or payload_runs or suspicious_path):
        return None

    correlated = [task_event, *schtasks[:1], *payload_runs[:1]]
    signals = [
        LogSignal(
            True,
            35,
            f"Scheduled task created: {task_name}",
            task_name,
            "scheduled_task",
        ),
        LogSignal(
            suspicious_path,
            20,
            f"Task points to writable ProgramData payload: {payload_path}",
            payload_path,
            "scheduled_task",
        ),
    ]
    if payload_runs:
        signals.append(
            LogSignal(
                True,
                25,
                "Scheduled task payload executed after creation",
                payload_runs[0]["event_id"],
                "user_execution",
            )
        )

    return _build_alert(
        alert_id="log-scheduled-task-persistence",
        title="Scheduled task persistence with payload execution",
        score=80,
        summary=f"Task {task_name} created persistence and executed {payload_path}.",
        signals=signals,
        events=correlated,
        severity=AlertSeverity.CRITICAL,
        recommended_actions=[
            "Delete the scheduled task",
            "Hash and quarantine the payload",
            "Hunt for matching task names and payload paths across endpoints",
        ],
    )


def decode_powershell_command(command_line: str) -> str:
    """Decode a PowerShell -EncodedCommand payload when present."""

    match = re.search(r"-(?:enc|encodedcommand)\s+([A-Za-z0-9+/=]+)", command_line, re.IGNORECASE)
    if not match:
        return ""

    encoded = match.group(1)
    for encoding in ("utf-16le", "utf-8"):
        try:
            return base64.b64decode(encoded).decode(encoding, errors="replace")
        except Exception:
            continue
    return ""


def _build_alert(
    alert_id: str,
    title: str,
    score: int,
    summary: str,
    signals: list[LogSignal],
    events: list[dict[str, Any]],
    severity: AlertSeverity,
    recommended_actions: list[str],
) -> Alert:
    evidence = [
        Evidence(
            name=_slugify(signal.reason),
            score=int(signal.weight),
            description=signal.reason,
            location=signal.indicator or "event",
        )
        for signal in signals
        if signal.triggered
    ]
    indicators = _indicators_from_events(events, signals)
    event_ids = [event["event_id"] for event in events]

    return Alert(
        alert_id=alert_id,
        source=AlertSource.LOG_ANALYSIS,
        title=title,
        severity=severity,
        score=score,
        summary=summary,
        recommended_actions=recommended_actions,
        mitre_techniques=techniques_for_signals([signal.signal for signal in signals if signal.triggered]),
        indicators=indicators,
        evidence=evidence,
        raw_event={
            "correlated_event_ids": event_ids,
            "event_count": len(events),
            "events": events,
            "event_hash": _hash_events(events),
        },
        created_at=events[0]["timestamp"] if events else None,
    )


def _indicators_from_events(events: list[dict[str, Any]], signals: list[LogSignal]) -> list[Indicator]:
    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(indicator_type: str, value: Any, description: str) -> None:
        if value in (None, ""):
            return
        normalized = str(value)
        key = (indicator_type, normalized)
        if key not in seen:
            indicators.append(Indicator(indicator_type, normalized, description))
            seen.add(key)

    for event in events:
        add("host", event.get("computer"), "Affected host")
        add("user", event.get("user"), "User account")
        add("ip", event.get("source_ip"), "Source IP")
        add("ip", event.get("destination_ip"), "Destination IP")
        add("process", event.get("image"), "Process image")
        add("scheduled_task", event.get("task_name"), "Scheduled task")
    for signal in signals:
        add("signal", signal.indicator, signal.reason)

    return indicators


def _contains_credential_theft(text: str) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in ("mimikatz", "dumpcreds", "sekurlsa", "downloadstring"))


def _extract_task_command(task_content: str) -> str:
    match = re.search(r"<Command>(.*?)</Command>", task_content, re.IGNORECASE)
    return match.group(1) if match else ""


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _hash_events(events: list[dict[str, Any]]) -> str:
    encoded = json.dumps(events, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug[:64] or "log_signal"
