from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas
except Exception:
    A4 = None


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _kv(c: canvas.Canvas, x: float, y: float, k: str, v: str, kW: int = 70):
    c.setFont("Helvetica-Bold", 10)
    c.drawString(x, y, k)
    c.setFont("Helvetica", 10)
    c.drawString(x + kW, y, v)


def generate_pdf(out_dir: Path, author: str = "Ulfat Ibadov", sections: List[str] = []) -> Optional[Path]:
    if A4 is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "ShadowLab_Report.pdf"

    score = _read_json(out_dir / "score.json")
    def_sum = _read_json(out_dir / "events_defender.json")
    sys_sum = _read_json(out_dir / "events_sysmon.json")
    incident_bundle = _read_json(out_dir / "incident_bundle.json")

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4

    try:
        logo = ImageReader("static/shadowlab-logo-active.png")
        c.drawImage(logo, 20 * mm, height - 34 * mm, width=18 * mm, height=18 * mm, preserveAspectRatio=True, mask="auto")
        c.setFont("Helvetica-Bold", 18)
        c.drawString(44 * mm, height - 22 * mm, "ShadowLab")
        c.setFont("Helvetica", 11)
        c.drawString(44 * mm, height - 29 * mm, "Created by Ulfat Ibadov")
    except Exception:
        c.setFont("Helvetica-Bold", 18)
        c.drawString(20 * mm, height - 20 * mm, "ShadowLab")
        c.setFont("Helvetica", 11)
        c.drawString(20 * mm, height - 28 * mm, "Created by Ulfat Ibadov")

    c.setFont("Helvetica", 10)
    c.drawString(20 * mm, height - 55 * mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(20 * mm, height - 62 * mm, f"Author: {author}")
    c.drawString(20 * mm, height - 69 * mm, "Scope: Defensive research in owned, isolated lab environments.")

    y = height - 85 * mm
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Executive Summary")
    y -= 7 * mm
    c.setFont("Helvetica", 10)
    summary_lines = [
        f"Likelihood: {score.get('likelihood', 'N/A')}",
        f"Incident Severity: {incident_bundle.get('severity', 'N/A')}",
        f"Telemetry Samples: {incident_bundle.get('telemetry_count', 0)}",
        f"Correlation Story: {incident_bundle.get('correlation_story', 'No correlation story available.')}",
    ]
    for line in summary_lines:
        c.drawString(20 * mm, y, line[:140])
        y -= 5 * mm

    attack_chain = incident_bundle.get("attack_chain", []) or []
    if attack_chain:
        y -= 2 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Attack Chain")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        c.drawString(20 * mm, y, " -> ".join(attack_chain)[:140])
        y -= 7 * mm

    recommendations = incident_bundle.get("recommended_actions", []) or []
    if recommendations:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Recommended Actions")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        for action in recommendations[:8]:
            c.drawString(25 * mm, y, f"- {action[:120]}")
            y -= 5 * mm
            if y < 30 * mm:
                c.showPage()
                y = height - 20 * mm

    if "Detection Score" in sections:
        y -= 3 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Detection Likelihood")
        y -= 6 * mm
        c.setFont("Helvetica", 11)
        c.drawString(20 * mm, y, f"Final Likelihood (0..1): {score.get('likelihood', 'N/A')}")
        y -= 6 * mm
        for key, value in (score.get("parts", {}) or {}).items():
            line = f"- {key}: {value:.3f}" if isinstance(value, (float, int)) else f"- {key}: {value}"
            c.drawString(25 * mm, y, line[:120])
            y -= 5 * mm

    if "Events Summary" in sections:
        y -= 5 * mm
        c.setFont("Helvetica-Bold", 12)
        c.drawString(20 * mm, y, "Event Summaries")
        y -= 6 * mm
        c.setFont("Helvetica", 10)
        c.drawString(20 * mm, y, f"Defender total: {def_sum.get('summary', {}).get('total', 0)}")
        y -= 5 * mm
        for key, value in (def_sum.get("summary", {}).get("by_id", {}) or {}).items():
            c.drawString(25 * mm, y, f"- {key}: {value}")
            y -= 5 * mm
        y -= 2 * mm
        c.drawString(20 * mm, y, f"Sysmon total: {sys_sum.get('summary', {}).get('total', 0)}")
        y -= 5 * mm
        for key, value in (sys_sum.get("summary", {}).get("by_id", {}) or {}).items():
            c.drawString(25 * mm, y, f"- {key}: {value}")
            y -= 5 * mm

    c.setFont("Helvetica-Oblique", 9)
    c.drawString(20 * mm, 15 * mm, "Copyright 2026 Ulfat Ibadov. ShadowLab is for authorized lab research only.")
    c.save()
    return pdf_path


def generate_html(out_dir: Path, author: str = "Ulfat Ibadov") -> Optional[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "ShadowLab_Report.html"
    score = _read_json(out_dir / "score.json")
    incident_bundle = _read_json(out_dir / "incident_bundle.json")
    defender = _read_json(out_dir / "events_defender.json")
    sysmon = _read_json(out_dir / "events_sysmon.json")

    recommendations = "".join(
        f"<li>{html.escape(str(item))}</li>" for item in (incident_bundle.get("recommended_actions") or [])
    )
    findings = "".join(
        "<li><strong>{title}</strong> - {summary}</li>".format(
            title=html.escape(str(item.get("title", "Finding"))),
            summary=html.escape(str(item.get("summary", ""))),
        )
        for item in (incident_bundle.get("findings") or [])
    )

    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ShadowLab Incident Report</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 40px; background:#0b1320; color:#eef4ff; }}
    .card {{ background:#101b2c; border:1px solid #1e385d; border-radius:16px; padding:24px; margin-bottom:24px; }}
    h1,h2 {{ margin-top:0; }}
    .muted {{ color:#94a8c6; }}
    code {{ color:#8ec5ff; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>ShadowLab Incident Report</h1>
    <p class="muted">Generated {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} by {html.escape(author)}</p>
    <p>{html.escape(str(incident_bundle.get('correlation_story', 'No correlation story available.')))}</p>
  </div>
  <div class="card">
    <h2>Executive Summary</h2>
    <p>Likelihood: <strong>{html.escape(str(score.get('likelihood', 'N/A')))}</strong></p>
    <p>Severity: <strong>{html.escape(str(incident_bundle.get('severity', 'N/A')))}</strong></p>
    <p>Attack Chain: <code>{html.escape(' -> '.join(incident_bundle.get('attack_chain', []) or []))}</code></p>
  </div>
  <div class="card">
    <h2>Technical Findings</h2>
    <ul>{findings or '<li>No detailed findings were recorded.</li>'}</ul>
  </div>
  <div class="card">
    <h2>Recommended Actions</h2>
    <ul>{recommendations or '<li>No recommendations were generated.</li>'}</ul>
  </div>
  <div class="card">
    <h2>Event Totals</h2>
    <p>Defender total: {html.escape(str(defender.get('summary', {}).get('total', 0)))}</p>
    <p>Sysmon total: {html.escape(str(sysmon.get('summary', {}).get('total', 0)))}</p>
  </div>
</body>
</html>
"""
    html_path.write_text(page, encoding="utf-8")
    return html_path
