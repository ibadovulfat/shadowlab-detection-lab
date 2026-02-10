
from __future__ import annotations
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import json

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
except Exception:
    A4 = None

def _kv(c: canvas.Canvas, x: float, y: float, k: str, v: str, kW: int = 70):
    c.setFont("Helvetica-Bold", 10); c.drawString(x, y, k)
    c.setFont("Helvetica", 10);      c.drawString(x + kW, y, v)

def generate_pdf(out_dir: Path, author: str = "Ulfat Ibadov", sections: List[str] = []) -> Optional[Path]:
    if A4 is None:
        return None
    out_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = out_dir / "ShadowLab_Report.pdf"

    # Load artifacts if present
    score = {}
    def_sum = {}
    sys_sum = {}
    tele_csv = out_dir / "telemetry.csv"
    try:
        score = json.loads((out_dir / "score.json").read_text())
    except Exception:
        pass
    try:
        def_sum = json.loads((out_dir / "events_defender.json").read_text())
    except Exception:
        pass
    try:
        sys_sum = json.loads((out_dir / "events_sysmon.json").read_text())
    except Exception:
        pass

    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    W, H = A4

    # Header banner (if exists)
    try:
        banner = ImageReader("static/shadowlab_banner.png")
        c.drawImage(banner, 10*mm, H-45*mm, width=W-20*mm, height=30*mm, preserveAspectRatio=True, mask='auto')
    except Exception:
        c.setFont("Helvetica-Bold", 18)
        c.drawString(20*mm, H-20*mm, "ShadowLab Defender Web Simulator")
        c.setFont("Helvetica", 11)
        c.drawString(20*mm, H-28*mm, "Created by Ulfat Ibadov")

    # Metadata
    c.setFont("Helvetica", 10)
    c.drawString(20*mm, H-55*mm, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(20*mm, H-62*mm, f"Author: {author}")
    c.drawString(20*mm, H-69*mm, "Scope: Research & Education — No bypass, no exploit")

    y = H-85*mm

    if "Detection Score" in sections:
        # Score
        c.setFont("Helvetica-Bold", 12); c.drawString(20*mm, y, "Detection Likelihood")
        y -= 6*mm
        c.setFont("Helvetica", 11)
        c.drawString(20*mm, y, f"Final Likelihood (0..1): {score.get('likelihood','N/A')}")
        y -= 6*mm
        parts = score.get("parts", {})
        for k, v in parts.items():
            c.drawString(25*mm, y, f"- {k}: {v:.3f}" if isinstance(v,(float,int)) else f"- {k}: {v}")
            y -= 5*mm
        y -= 4*mm

    if "Events Summary" in sections:
        # Defender / Sysmon
        c.setFont("Helvetica-Bold", 12); c.drawString(20*mm, y, "Event Summaries")
        y -= 6*mm
        c.setFont("Helvetica", 10)
        c.drawString(20*mm, y, f"Defender total: {def_sum.get('summary',{}).get('total',0)}")
        y -= 5*mm
        for k, v in (def_sum.get('summary',{}).get('by_id',{}) or {}).items():
            c.drawString(25*mm, y, f"- {k}: {v}"); y -= 5*mm
            if y < 30*mm: c.showPage(); y = H-20*mm
        y -= 2*mm
        c.drawString(20*mm, y, f"Sysmon total: {sys_sum.get('summary',{}).get('total',0)}")
        y -= 5*mm
        for k, v in (sys_sum.get('summary',{}).get('by_id',{}) or {}).items():
            c.drawString(25*mm, y, f"- {k}: {v}"); y -= 5*mm
            if y < 30*mm: c.showPage(); y = H-20*mm
        y -= 4*mm

    # Placeholder for other sections (Telemetry, Threat Intelligence, Process Analysis, Network Graph)
    # These would require more complex integration, possibly generating temporary images/tables.

    # Footer
    c.setFont("Helvetica-Oblique", 9)
    c.drawString(20*mm, 15*mm, "© 2025 Ulfat Ibadov — ShadowLab is for educational research in isolated labs only.")
    c.save()
    return pdf_path
