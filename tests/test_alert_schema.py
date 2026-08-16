import unittest

from engines.alert_schema import (
    Alert,
    AlertSeverity,
    AlertSource,
    Evidence,
    Indicator,
)


class AlertSchemaTest(unittest.TestCase):
    def test_alert_schema_serializes_to_dashboard_contract(self):
        alert = Alert(
            source=AlertSource.PHISHING_EMAIL,
            title="Suspicious login lure",
            severity=AlertSeverity.HIGH,
            score=82,
            summary="Email asks the user to verify credentials through an external link.",
            recommended_actions=["Quarantine message", "Block sender domain"],
            mitre_techniques=["T1566.002"],
            indicators=[
                Indicator(
                    type="url",
                    value="https://login.example.invalid",
                    description="Credential collection landing page",
                )
            ],
            evidence=[
                Evidence(
                    name="credential_language",
                    score=25,
                    description="Message requests account verification.",
                    location="body",
                )
            ],
            raw_event={"sample": "sample-3864.eml"},
        )

        payload = alert.to_dict()

        self.assertEqual(payload["source"], "phishing_email")
        self.assertEqual(payload["severity"], "high")
        self.assertEqual(payload["status"], "new")
        self.assertEqual(payload["mitre_techniques"], ["T1566.002"])
        self.assertEqual(payload["indicators"][0]["type"], "url")

    def test_alert_schema_rejects_invalid_score(self):
        with self.assertRaisesRegex(ValueError, "score must be between 0 and 100"):
            Alert(
                source=AlertSource.LOG_ANALYSIS,
                title="Impossible travel",
                severity=AlertSeverity.MEDIUM,
                score=101,
                summary="Login pattern exceeded the scoring range.",
                recommended_actions=["Review authentication logs"],
                mitre_techniques=["T1078"],
                indicators=[],
                evidence=[],
                raw_event={},
            )


if __name__ == "__main__":
    unittest.main()
