"""MITRE ATT&CK technique helpers shared by detection engines."""

from __future__ import annotations


MITRE_TECHNIQUES = {
    "phishing_link": "T1566.002",
    "phishing_attachment": "T1566.001",
    "valid_accounts": "T1078",
    "user_execution": "T1204",
    "command_and_control": "T1102",
    "suspicious_login": "T1078",
    "brute_force": "T1110",
    "exfiltration": "T1041",
}


def techniques_for_signals(signals: list[str]) -> list[str]:
    """Map engine signal names to a stable, de-duplicated MITRE technique list."""

    techniques: list[str] = []
    for signal in signals:
        technique = MITRE_TECHNIQUES.get(signal)
        if technique and technique not in techniques:
            techniques.append(technique)

    return techniques or ["N/A"]

