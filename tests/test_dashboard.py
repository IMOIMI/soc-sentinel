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


if __name__ == "__main__":
    unittest.main()

