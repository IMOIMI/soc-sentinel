import unittest
from pathlib import Path

from engines.log_engine import analyze_log_file, decode_powershell_command, load_events
from forensics.utils import build_timeline, sha256_json


ROOT = Path(__file__).resolve().parents[1]
LOG_SAMPLE = ROOT / "data" / "samples" / "windows" / "security_sysmon_scenario.json"


class LogEngineTest(unittest.TestCase):
    def test_log_engine_correlates_three_alerts(self):
        alerts = analyze_log_file(LOG_SAMPLE)

        self.assertEqual(len(alerts), 3)
        self.assertEqual(
            {alert.alert_id for alert in alerts},
            {
                "log-bruteforce-compromise",
                "log-powershell-c2",
                "log-scheduled-task-persistence",
            },
        )

    def test_powershell_payload_is_decoded(self):
        events = load_events(LOG_SAMPLE)
        command_line = next(event for event in events if event["event_id"] == "evt-007")[
            "command_line"
        ]
        decoded = decode_powershell_command(command_line)

        self.assertIn("Invoke-Mimikatz", decoded)
        self.assertIn("203.0.113.77", decoded)

    def test_forensics_timeline_and_hash_are_stable(self):
        alerts = analyze_log_file(LOG_SAMPLE)
        timeline = build_timeline(alerts)
        evidence_hash = sha256_json(timeline)

        self.assertGreaterEqual(len(timeline), 10)
        self.assertEqual(len(evidence_hash), 64)
        self.assertEqual(timeline, sorted(timeline, key=lambda item: item["timestamp"]))


if __name__ == "__main__":
    unittest.main()

