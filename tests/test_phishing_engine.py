import unittest
from pathlib import Path

from engines.phishing_engine import analyze_email


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


if __name__ == "__main__":
    unittest.main()

