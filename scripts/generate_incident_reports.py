"""Generate markdown and PDF incident response reports for showcase alerts."""

from __future__ import annotations

import sys
from pathlib import Path
from textwrap import wrap

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from engines.log_engine import analyze_log_file
from forensics.utils import build_timeline, sha256_json


LOG_SAMPLE = ROOT / "data" / "samples" / "windows" / "security_sysmon_scenario.json"
REPORT_DIR = ROOT / "data" / "reports"
SHOWCASE_ALERT_IDS = {
    "log-bruteforce-compromise",
    "log-scheduled-task-persistence",
}


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    alerts = [
        alert
        for alert in analyze_log_file(LOG_SAMPLE)
        if alert.alert_id in SHOWCASE_ALERT_IDS
    ]

    for alert in alerts:
        markdown = _render_markdown(alert)
        md_path = REPORT_DIR / f"{alert.alert_id}.md"
        pdf_path = REPORT_DIR / f"{alert.alert_id}.pdf"
        md_path.write_text(markdown, encoding="utf-8")
        _render_pdf(alert, pdf_path)
        print(f"generated {md_path.relative_to(ROOT)}")
        print(f"generated {pdf_path.relative_to(ROOT)}")


def _render_markdown(alert) -> str:
    timeline = build_timeline([alert])
    timeline_hash = sha256_json(timeline)
    lines = [
        f"# Incident Report: {alert.title}",
        "",
        f"- Alert ID: `{alert.alert_id}`",
        f"- Severity: `{alert.severity.value.upper()}`",
        f"- Score: `{alert.score}/100`",
        f"- Source: `{alert.source.value}`",
        f"- Created At: `{alert.created_at}`",
        f"- MITRE Techniques: `{', '.join(alert.mitre_techniques)}`",
        f"- Evidence Hash: `{timeline_hash}`",
        "",
        "## Executive Summary",
        "",
        alert.summary,
        "",
        "## Evidence",
        "",
    ]
    for item in alert.evidence:
        lines.extend(
            [
                f"- **{item.name}** (+{item.score})",
                f"  - Location: `{item.location}`",
                f"  - Reason: {item.description}",
            ]
        )

    lines.extend(["", "## Indicators", ""])
    for indicator in alert.indicators:
        lines.append(f"- `{indicator.type}`: `{indicator.value}` - {indicator.description}")

    lines.extend(["", "## Timeline", ""])
    for item in timeline:
        lines.append(
            f"- `{item['timestamp']}` `{item['event_id']}` event={item.get('event_code')} "
            f"host={item.get('computer')} user={item.get('user')} - {item.get('message')}"
        )

    lines.extend(["", "## Recommended Actions", ""])
    for action in alert.recommended_actions:
        lines.append(f"- {action}")

    lines.append("")
    return "\n".join(lines)


def _render_pdf(alert, path: Path) -> None:
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=LETTER, title=alert.title)
    story = [
        Paragraph(f"Incident Report: {alert.title}", styles["Title"]),
        Spacer(1, 12),
    ]

    summary_rows = [
        ["Alert ID", alert.alert_id],
        ["Severity", alert.severity.value.upper()],
        ["Score", f"{alert.score}/100"],
        ["Source", alert.source.value],
        ["MITRE", ", ".join(alert.mitre_techniques)],
    ]
    summary_table = Table(summary_rows, colWidths=[110, 390])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#9ca3af")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ]
        )
    )
    story.extend([summary_table, Spacer(1, 14)])

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(_pdf_escape(alert.summary), styles["BodyText"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Evidence", styles["Heading2"]))
    for item in alert.evidence:
        text = f"<b>{item.name}</b> (+{item.score}) - {item.description}"
        story.append(Paragraph(_pdf_escape(text), styles["BodyText"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Timeline", styles["Heading2"]))
    for item in build_timeline([alert]):
        line = (
            f"{item['timestamp']} | {item['event_id']} | event={item.get('event_code')} | "
            f"{item.get('message')}"
        )
        story.append(Paragraph(_pdf_escape(_wrap_pdf_line(line)), styles["BodyText"]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Recommended Actions", styles["Heading2"]))
    for action in alert.recommended_actions:
        story.append(Paragraph(f"- {_pdf_escape(action)}", styles["BodyText"]))

    doc.build(story)


def _pdf_escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _wrap_pdf_line(value: str) -> str:
    return "<br/>".join(wrap(value, width=105))


if __name__ == "__main__":
    main()

