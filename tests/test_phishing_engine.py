import unittest
from pathlib import Path

from engines.phishing_engine import analyze_email, analyze_email_content


ROOT = Path(__file__).resolve().parents[1]


class PhishingEngineTest(unittest.TestCase):
    def test_real_phishing_sample_returns_alert(self):
        alert = analyze_email(ROOT / "data" / "samples" / "phishing" / "sample-1.eml")

        self.assertEqual(alert.raw_event["classification"], "PHISHING")
        self.assertGreaterEqual(alert.score, 20)
        self.assertTrue(alert.evidence)
        self.assertIn("T1566.002", alert.mitre_techniques)

    def test_synthetic_legitimate_samples_have_no_false_positives(self):
        samples = sorted((ROOT / "data" / "samples" / "legitimate").glob("*.eml"))
        results = [analyze_email(sample) for sample in samples]

        self.assertEqual(len(results), 5)
        self.assertTrue(
            all(result.raw_event["classification"] == "SAFE" for result in results)
        )

    def test_raw_email_content_entry_point(self):
        raw_email = b"""From: PayPal Security <security@paypa1-alerts.example>
Return-Path: bounce@relay.example
Reply-To: support@credential-check.example
Subject: Verify your PayPal account immediately
Authentication-Results: company.example; spf=fail smtp.mailfrom=relay.example; dkim=none; dmarc=fail

Your account will be suspended. Verify your login password now:
http://203.0.113.55/paypal/login
"""
        alert = analyze_email_content(raw_email, label="paste-test.eml")

        self.assertEqual(alert.raw_event["classification"], "PHISHING")
        self.assertGreaterEqual(alert.score, 20)
        self.assertEqual(alert.raw_event["path"], "paste-test.eml")


if __name__ == "__main__":
    unittest.main()
