import unittest

from apps.dashboard.app import ALERT_CACHE, app


class DashboardTest(unittest.TestCase):
    def test_alert_cache_is_loaded_once(self):
        self.assertEqual(len(ALERT_CACHE), 16)
        self.assertEqual(len({alert.alert_id for alert in ALERT_CACHE}), 16)

    def test_dashboard_routes_render(self):
        client = app.test_client()
        index = client.get("/")
        detail = client.get(f"/alerts/{ALERT_CACHE[0].alert_id}")
        api = client.get("/api/alerts")

        self.assertEqual(index.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(api.status_code, 200)
        self.assertEqual(len(api.get_json()), 16)

    def test_live_analyzer_scores_phishing_and_appends_to_queue(self):
        client = app.test_client()
        before = len(ALERT_CACHE)
        raw_email = """From: PayPal Security <security@paypa1-alerts.example>
Return-Path: bounce@relay.example
Reply-To: support@credential-check.example
Subject: Verify your PayPal account immediately
Authentication-Results: company.example; spf=fail smtp.mailfrom=relay.example; dkim=none; dmarc=fail

Your account will be suspended. Verify your login password now:
http://203.0.113.55/paypal/login
"""

        response = client.post("/analyze", data={"raw_email": raw_email})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"PHISHING", response.data)
        self.assertEqual(len(ALERT_CACHE), before + 1)
        self.assertEqual(ALERT_CACHE[0].raw_event["classification"], "PHISHING")

    def test_live_analyzer_scores_legitimate_email_safe(self):
        client = app.test_client()
        raw_email = """From: IT Support <it-support@company.example>
Subject: Maintenance complete
Authentication-Results: company.example; spf=pass smtp.mailfrom=company.example; dkim=pass; dmarc=pass

The scheduled maintenance finished successfully. No action is required.
"""

        response = client.post("/analyze", data={"raw_email": raw_email})

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SAFE", response.data)
        self.assertEqual(ALERT_CACHE[0].raw_event["classification"], "SAFE")


if __name__ == "__main__":
    unittest.main()
