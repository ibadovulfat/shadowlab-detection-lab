from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

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


def _fmt_timestamp(value: Any) -> str:
    try:
        if value in (None, ""):
            return "N/A"
        return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value or "N/A")


def _fmt_float(value: Any, digits: int = 3) -> str:
    try:
        return f"{float(value):.{digits}f}"
    except Exception:
        return str(value or "0")


def _severity_rank(value: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(str(value).lower(), 0)


def _json_excerpt(value: Any, limit: int = 160) -> str:
    if isinstance(value, dict):
        parts = []
        for key, item in list(value.items())[:6]:
            parts.append(f"{key}={item}")
        text = ", ".join(parts)
    elif isinstance(value, list):
        text = ", ".join(str(item) for item in value[:6])
    else:
        text = str(value or "")
    return text[:limit]


def _artifact_inventory(out_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for path in sorted(out_dir.iterdir()) if out_dir.exists() else []:
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        rows.append(
            {
                "name": path.name,
                "type": path.suffix.lower().lstrip(".") or "file",
                "size": f"{size:,} bytes",
            }
        )
    return rows


def _report_model(out_dir: Path) -> dict[str, Any]:
    score = _read_json(out_dir / "score.json")
    defender = _read_json(out_dir / "events_defender.json")
    sysmon = _read_json(out_dir / "events_sysmon.json")
    bundle = _read_json(out_dir / "incident_bundle.json")
    incident = bundle.get("incident", {}) if isinstance(bundle.get("incident"), dict) else {}
    findings = bundle.get("findings") or score.get("rule_findings") or []
    telemetry_preview = bundle.get("telemetry_preview", []) if isinstance(bundle.get("telemetry_preview"), list) else []
    security_events = score.get("security_events", []) if isinstance(score.get("security_events"), list) else []
    return {
        "score": score,
        "defender": defender.get("summary", {}) if isinstance(defender.get("summary"), dict) else {},
        "sysmon": sysmon.get("summary", {}) if isinstance(sysmon.get("summary"), dict) else {},
        "bundle": bundle,
        "incident": incident,
        "findings": findings if isinstance(findings, list) else [],
        "telemetry_preview": telemetry_preview,
        "security_events": security_events,
        "artifacts": _artifact_inventory(out_dir),
    }


def _wrap_text(text: str, limit: int = 105) -> list[str]:
    words = str(text or "").split()
    if not words:
        return [""]
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if len(candidate) <= limit:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _new_page(doc: canvas.Canvas, title: str) -> float:
    doc.showPage()
    width, height = A4
    doc.setFont("Helvetica-Bold", 16)
    doc.drawString(18 * mm, height - 18 * mm, title)
    doc.setFont("Helvetica", 9)
    doc.drawRightString(width - 18 * mm, height - 18 * mm, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return height - 28 * mm


def _ensure_space(doc: canvas.Canvas, y: float, needed_mm: float, title: str) -> float:
    if y < needed_mm * mm:
        return _new_page(doc, title)
    return y


def _draw_heading(doc: canvas.Canvas, y: float, text: str, page_title: str) -> float:
    y = _ensure_space(doc, y, 28, page_title)
    doc.setFont("Helvetica-Bold", 12)
    doc.drawString(18 * mm, y, text)
    return y - 6 * mm


def _draw_paragraph(doc: canvas.Canvas, y: float, text: str, page_title: str, indent_mm: float = 18) -> float:
    for line in _wrap_text(text):
        y = _ensure_space(doc, y, 18, page_title)
        doc.setFont("Helvetica", 9)
        doc.drawString(indent_mm * mm, y, line[:135])
        y -= 4.6 * mm
    return y


def _draw_bullets(doc: canvas.Canvas, y: float, items: Iterable[str], page_title: str) -> float:
    values = list(items)
    if not values:
        return _draw_paragraph(doc, y, "No items recorded.", page_title)
    for item in values:
        for index, line in enumerate(_wrap_text(str(item), limit=98)):
            y = _ensure_space(doc, y, 18, page_title)
            doc.setFont("Helvetica", 9)
            prefix = "- " if index == 0 else "  "
            doc.drawString(22 * mm, y, f"{prefix}{line}"[:135])
            y -= 4.6 * mm
    return y


def _top_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        [item for item in findings if isinstance(item, dict)],
        key=lambda item: (_severity_rank(str(item.get("severity", ""))), float(item.get("score", 0) or 0)),
        reverse=True,
    )
    return ordered[:8]


def _top_security_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = sorted(
        [item for item in events if isinstance(item, dict)],
        key=lambda item: (int(item.get("risk_score", 0) or 0), _severity_rank(str(item.get("severity", "")))),
        reverse=True,
    )
    return ordered[:10]


def _telemetry_snapshot(rows: list[dict[str, Any]]) -> list[str]:
    if not rows:
        return ["No telemetry samples were preserved in the preview set."]
    latest = rows[-1] if isinstance(rows[-1], dict) else {}
    peaks = {
        "cpu_peak": max(float((row or {}).get("cpu", 0) or 0) for row in rows if isinstance(row, dict)),
        "memory_peak": max(float((row or {}).get("mem_percent", 0) or 0) for row in rows if isinstance(row, dict)),
        "tcp_peak": max(float((row or {}).get("tcp_conns", 0) or 0) for row in rows if isinstance(row, dict)),
        "recv_peak": max(float((row or {}).get("bytes_recv_rate", 0) or 0) for row in rows if isinstance(row, dict)),
    }
    return [
        f"Latest sample time: {_fmt_timestamp(latest.get('ts'))}",
        f"Peak CPU observed: {_fmt_float(peaks['cpu_peak'], 1)}%",
        f"Peak memory observed: {_fmt_float(peaks['memory_peak'], 1)}%",
        f"Peak concurrent TCP connections: {_fmt_float(peaks['tcp_peak'], 0)}",
        f"Peak inbound throughput: {_fmt_float(peaks['recv_peak'], 1)} bytes/sec",
        f"Latest remote IP set: {_json_excerpt(latest.get('remote_ips', []), limit=110) or 'None'}",
    ]


def generate_pdf(out_dir: Path, author: str = "Ulfat Ibadov", sections: list[str] | None = None) -> Optional[Path]:
    if A4 is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "ShadowLab_Report.pdf"
    model = _report_model(out_dir)
    bundle = model["bundle"]
    incident = model["incident"]
    score = model["score"]
    findings = _top_findings(model["findings"])
    security_events = _top_security_events(model["security_events"])

    doc = canvas.Canvas(str(pdf_path), pagesize=A4)
    width, height = A4

    try:
        logo = ImageReader("static/shadowlab-logo-active.png")
        doc.drawImage(logo, 18 * mm, height - 34 * mm, width=16 * mm, height=16 * mm, preserveAspectRatio=True, mask="auto")
    except Exception:
        pass

    doc.setFont("Helvetica-Bold", 20)
    doc.drawString(38 * mm, height - 20 * mm, "ShadowLab Incident Report")
    doc.setFont("Helvetica", 10)
    doc.drawString(38 * mm, height - 27 * mm, "Operational report for authorized lab and enterprise response workflows")

    y = height - 42 * mm
    meta = [
        f"Incident ID: {bundle.get('incident_id') or incident.get('incident_id') or 'N/A'}",
        f"Title: {bundle.get('title') or incident.get('title') or 'Behavioral detection incident'}",
        f"Severity: {bundle.get('severity') or incident.get('severity') or 'unknown'}",
        f"Likelihood: {_fmt_float(bundle.get('likelihood', score.get('likelihood', 'N/A')))}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Author: {author}",
    ]
    for item in meta:
        doc.setFont("Helvetica", 9)
        doc.drawString(18 * mm, y, item[:135])
        y -= 4.8 * mm

    y -= 2 * mm
    page_title = "ShadowLab Incident Report"
    y = _draw_heading(doc, y, "Executive Summary", page_title)
    executive_lines = [
        bundle.get("summary") or incident.get("summary") or "Automated incident generated from available telemetry and correlation logic.",
        bundle.get("correlation_story") or score.get("correlation_story") or "No correlation narrative was generated.",
        f"Telemetry samples retained: {bundle.get('telemetry_count', len(model['telemetry_preview']))}",
        f"Primary ATT&CK coverage: {', '.join(bundle.get('mitre_techniques', []) or score.get('mitre_mapping', []) or ['None'])}",
        f"Attack chain: {' -> '.join(bundle.get('attack_chain', []) or score.get('attack_chain', []) or ['Not mapped'])}",
    ]
    y = _draw_bullets(doc, y, executive_lines, page_title)

    y = _draw_heading(doc, y - 2 * mm, "Analyst Findings", page_title)
    if findings:
        for finding in findings:
            title = f"{finding.get('title', 'Finding')} | severity={finding.get('severity', 'unknown')} | score={_fmt_float(finding.get('score', 0), 2)}"
            y = _draw_paragraph(doc, y, title, page_title)
            y = _draw_paragraph(doc, y, str(finding.get("summary", "No summary provided.")), page_title, indent_mm=22)
            metrics = ((finding.get("evidence") or {}).get("metrics") or {}) if isinstance(finding.get("evidence"), dict) else {}
            if metrics:
                metric_line = "Evidence metrics: " + _json_excerpt(metrics, limit=110)
                y = _draw_paragraph(doc, y, metric_line, page_title, indent_mm=22)
            techniques = finding.get("mitre_techniques") or []
            tactics = finding.get("attack_tactics") or []
            if techniques or tactics:
                y = _draw_paragraph(
                    doc,
                    y,
                    f"ATT&CK: techniques={', '.join(techniques or ['None'])} | tactics={', '.join(tactics or ['None'])}",
                    page_title,
                    indent_mm=22,
                )
            y -= 1 * mm
    else:
        y = _draw_paragraph(doc, y, "No structured rule findings were preserved in the incident bundle.", page_title)

    y = _draw_heading(doc, y - 2 * mm, "Response Guidance", page_title)
    y = _draw_bullets(doc, y, bundle.get("recommended_actions") or ["Review process ancestry, network destinations, and recent operator actions."], page_title)
    y = _draw_bullets(doc, y, bundle.get("notes") or score.get("notes") or [], page_title)

    y = _new_page(doc, page_title)
    y = _draw_heading(doc, y, "Telemetry Snapshot", page_title)
    y = _draw_bullets(doc, y, _telemetry_snapshot(model["telemetry_preview"]), page_title)

    if sections and "Detection Score" in sections:
        y = _draw_heading(doc, y - 2 * mm, "Detection Scoring Breakdown", page_title)
        score_parts = score.get("parts", {}) if isinstance(score.get("parts"), dict) else {}
        score_lines = [f"Final likelihood: {_fmt_float(score.get('likelihood', 0))}"]
        score_lines.extend(f"{key}: {_fmt_float(value)}" for key, value in score_parts.items())
        y = _draw_bullets(doc, y, score_lines, page_title)

    if sections and "Events Summary" in sections:
        defender = model["defender"]
        sysmon = model["sysmon"]
        y = _draw_heading(doc, y - 2 * mm, "Event Source Totals", page_title)
        event_lines = [
            f"Microsoft Defender total events: {defender.get('total', 0)}",
            f"Sysmon total events: {sysmon.get('total', 0)}",
        ]
        event_lines.extend(
            f"Defender event {key}: {value}" for key, value in list((defender.get("by_id") or {}).items())[:6]
        )
        event_lines.extend(
            f"Sysmon event {key}: {value}" for key, value in list((sysmon.get("by_id") or {}).items())[:6]
        )
        y = _draw_bullets(doc, y, event_lines, page_title)

    y = _draw_heading(doc, y - 2 * mm, "Security Event Highlights", page_title)
    if security_events:
        event_lines = []
        for event in security_events:
            details = _json_excerpt(event.get("details", {}), limit=70)
            event_lines.append(
                f"{event.get('source', 'unknown')} | {event.get('title', 'event')} | severity={event.get('severity', 'unknown')} | risk={event.get('risk_score', 0)} | {details}"
            )
        y = _draw_bullets(doc, y, event_lines, page_title)
    else:
        y = _draw_paragraph(doc, y, "No prioritized security events were recorded.", page_title)

    y = _new_page(doc, page_title)
    y = _draw_heading(doc, y, "Artifact Manifest", page_title)
    artifact_lines = [f"{item['name']} | type={item['type']} | size={item['size']}" for item in model["artifacts"][:18]]
    y = _draw_bullets(doc, y, artifact_lines or ["No artifacts were available in shadowlab_out."], page_title)

    y = _draw_heading(doc, y - 2 * mm, "Telemetry Preview", page_title)
    preview_rows = model["telemetry_preview"][-8:] if isinstance(model["telemetry_preview"], list) else []
    preview_lines = []
    for row in preview_rows:
        if not isinstance(row, dict):
            continue
        preview_lines.append(
            f"{_fmt_timestamp(row.get('ts'))} | cpu={_fmt_float(row.get('cpu', 0), 1)}% | mem={_fmt_float(row.get('mem_percent', 0), 1)}% | tcp={_fmt_float(row.get('tcp_conns', 0), 0)} | remote_ips={_json_excerpt(row.get('remote_ips', []), 50)}"
        )
    y = _draw_bullets(doc, y, preview_lines or ["No telemetry preview rows were preserved."], page_title)

    doc.setFont("Helvetica-Oblique", 8)
    doc.drawString(18 * mm, 12 * mm, "ShadowLab is intended for authorized defensive research, testing, and incident response workflows.")
    doc.save()
    return pdf_path


def generate_html(out_dir: Path, author: str = "Ulfat Ibadov") -> Optional[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "ShadowLab_Report.html"
    model = _report_model(out_dir)
    bundle = model["bundle"]
    incident = model["incident"]
    score = model["score"]
    findings = _top_findings(model["findings"])
    security_events = _top_security_events(model["security_events"])
    telemetry_cards = "".join(
        f"<li>{html.escape(item)}</li>" for item in _telemetry_snapshot(model["telemetry_preview"])
    )
    findings_html = "".join(
        (
            "<div class='finding'>"
            f"<h3>{html.escape(str(item.get('title', 'Finding')))}</h3>"
            f"<p><strong>Severity:</strong> {html.escape(str(item.get('severity', 'unknown')))} | "
            f"<strong>Score:</strong> {html.escape(_fmt_float(item.get('score', 0), 2))}</p>"
            f"<p>{html.escape(str(item.get('summary', 'No summary provided.')))}</p>"
            f"<p class='muted'>ATT&CK: {html.escape(', '.join(item.get('mitre_techniques', []) or ['None']))}</p>"
            "</div>"
        )
        for item in findings
    )
    events_html = "".join(
        (
            "<tr>"
            f"<td>{html.escape(str(item.get('source', 'unknown')))}</td>"
            f"<td>{html.escape(str(item.get('title', 'event')))}</td>"
            f"<td>{html.escape(str(item.get('severity', 'unknown')))}</td>"
            f"<td>{html.escape(str(item.get('risk_score', 0)))}</td>"
            f"<td>{html.escape(_json_excerpt(item.get('details', {}), 90))}</td>"
            "</tr>"
        )
        for item in security_events
    )
    artifact_html = "".join(
        (
            "<tr>"
            f"<td>{html.escape(item['name'])}</td>"
            f"<td>{html.escape(item['type'])}</td>"
            f"<td>{html.escape(item['size'])}</td>"
            "</tr>"
        )
        for item in model["artifacts"][:20]
    )
    score_parts = "".join(
        f"<li><strong>{html.escape(str(key))}</strong>: {html.escape(_fmt_float(value))}</li>"
        for key, value in (score.get("parts", {}) or {}).items()
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ShadowLab Incident Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background:#0b1320; color:#eef4ff; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 48px; }}
    .hero {{ background: linear-gradient(135deg,#12243c,#0f1727); border:1px solid #24405f; border-radius: 18px; padding: 28px; margin-bottom: 24px; }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(220px,1fr)); gap:16px; margin-top:18px; }}
    .card {{ background:#101b2c; border:1px solid #1e385d; border-radius:16px; padding:22px; margin-bottom:20px; }}
    .metric {{ background:#0e1725; border:1px solid #22354d; border-radius:12px; padding:14px; }}
    .muted {{ color:#94a8c6; }}
    h1,h2,h3 {{ margin-top:0; }}
    ul {{ margin: 0; padding-left: 20px; }}
    table {{ width:100%; border-collapse: collapse; }}
    th, td {{ border-bottom:1px solid #22354d; padding:10px 8px; text-align:left; vertical-align:top; }}
    .finding {{ background:#0e1725; border:1px solid #22354d; border-radius:12px; padding:14px; margin-bottom:12px; }}
    code {{ color:#8ec5ff; }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>ShadowLab Incident Report</h1>
      <p class="muted">Generated {html.escape(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))} by {html.escape(author)}</p>
      <p>{html.escape(str(bundle.get('correlation_story') or score.get('correlation_story') or incident.get('summary') or 'No correlation story available.'))}</p>
      <div class="grid">
        <div class="metric"><strong>Incident</strong><br>{html.escape(str(bundle.get('incident_id') or incident.get('incident_id') or 'N/A'))}</div>
        <div class="metric"><strong>Severity</strong><br>{html.escape(str(bundle.get('severity') or incident.get('severity') or 'unknown'))}</div>
        <div class="metric"><strong>Likelihood</strong><br>{html.escape(_fmt_float(bundle.get('likelihood', score.get('likelihood', 0))))}</div>
        <div class="metric"><strong>Telemetry Samples</strong><br>{html.escape(str(bundle.get('telemetry_count', len(model['telemetry_preview']))))}</div>
      </div>
    </section>

    <section class="card">
      <h2>Executive Summary</h2>
      <p>{html.escape(str(bundle.get('summary') or incident.get('summary') or 'Automated incident generated from telemetry, event logs, and rule correlation.'))}</p>
      <p><strong>Attack Chain:</strong> <code>{html.escape(' -> '.join(bundle.get('attack_chain', []) or score.get('attack_chain', []) or ['Not mapped']))}</code></p>
      <p><strong>MITRE Techniques:</strong> {html.escape(', '.join(bundle.get('mitre_techniques', []) or score.get('mitre_mapping', []) or ['None']))}</p>
    </section>

    <section class="card">
      <h2>Detection Breakdown</h2>
      <ul>{score_parts or '<li>No score components recorded.</li>'}</ul>
    </section>

    <section class="card">
      <h2>Findings</h2>
      {findings_html or "<p>No detailed findings were recorded.</p>"}
    </section>

    <section class="card">
      <h2>Response Guidance</h2>
      <ul>{"".join(f"<li>{html.escape(str(item))}</li>" for item in (bundle.get("recommended_actions") or ["Review process ancestry, network destinations, and recent operator actions."]))}</ul>
      <h3 style="margin-top:18px;">Analyst Notes</h3>
      <ul>{"".join(f"<li>{html.escape(str(item))}</li>" for item in (bundle.get("notes") or score.get("notes") or ["No analyst notes captured."]))}</ul>
    </section>

    <section class="card">
      <h2>Telemetry Snapshot</h2>
      <ul>{telemetry_cards}</ul>
    </section>

    <section class="card">
      <h2>Security Event Highlights</h2>
      <table>
        <tr><th>Source</th><th>Title</th><th>Severity</th><th>Risk</th><th>Details</th></tr>
        {events_html or "<tr><td colspan='5'>No prioritized security events recorded.</td></tr>"}
      </table>
    </section>

    <section class="card">
      <h2>Artifact Inventory</h2>
      <table>
        <tr><th>Name</th><th>Type</th><th>Size</th></tr>
        {artifact_html or "<tr><td colspan='3'>No artifacts found.</td></tr>"}
      </table>
    </section>
  </main>
</body>
</html>
"""
    html_path.write_text(page, encoding="utf-8")
    return html_path
