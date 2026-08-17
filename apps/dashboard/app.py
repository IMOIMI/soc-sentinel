"""SOC-Sentinel Flask dashboard."""

from __future__ import annotations

import sys
from pathlib import Path

from flask import Flask, abort, jsonify, render_template


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from engines.alert_schema import Alert
from engines.log_engine import analyze_log_file
from engines.phishing_engine import analyze_email


PHISHING_DIR = ROOT / "data" / "samples" / "phishing"
LEGITIMATE_DIR = ROOT / "data" / "samples" / "legitimate"
LOG_SAMPLE = ROOT / "data" / "samples" / "windows" / "security_sysmon_scenario.json"


def load_alert_cache() -> list[Alert]:
    """Load alerts once so IDs stay stable for the life of the app process."""

    alerts: list[Alert] = []
    for sample_dir in (PHISHING_DIR, LEGITIMATE_DIR):
        for sample in sorted(sample_dir.glob("*.eml")):
            alerts.append(analyze_email(sample))

    alerts.extend(analyze_log_file(LOG_SAMPLE))
    return sorted(alerts, key=lambda alert: (alert.severity.value, -alert.score, alert.title))


ALERT_CACHE = load_alert_cache()
ALERT_INDEX = {alert.alert_id: alert for alert in ALERT_CACHE}


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    @app.get("/")
    def index():
        stats = {
            "total": len(ALERT_CACHE),
            "critical": sum(1 for alert in ALERT_CACHE if alert.severity.value == "critical"),
            "high": sum(1 for alert in ALERT_CACHE if alert.severity.value == "high"),
            "log_alerts": sum(1 for alert in ALERT_CACHE if alert.source.value == "log_analysis"),
            "phishing_alerts": sum(
                1 for alert in ALERT_CACHE if alert.source.value == "phishing_email"
            ),
        }
        return render_template("index.html", alerts=ALERT_CACHE, stats=stats)

    @app.get("/alerts/<alert_id>")
    def alert_detail(alert_id: str):
        alert = ALERT_INDEX.get(alert_id)
        if alert is None:
            abort(404)
        return render_template("detail.html", alert=alert)

    @app.get("/api/alerts")
    def api_alerts():
        return jsonify([alert.to_dict() for alert in ALERT_CACHE])

    @app.get("/api/alerts/<alert_id>")
    def api_alert_detail(alert_id: str):
        alert = ALERT_INDEX.get(alert_id)
        if alert is None:
            abort(404)
        return jsonify(alert.to_dict())

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True, port=5001)

