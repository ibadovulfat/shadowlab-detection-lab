
import pyautogui
import os
import time
from pathlib import Path
import re

class EvidenceCollector:
    def __init__(self):
        self.evidence_dir = Path("evidence_locker")
        self.evidence_dir.mkdir(exist_ok=True)

    def capture_screenshot(self, alert_name="incident"):
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            safe_name = self._safe_alert_name(alert_name)
            filename = f"{timestamp}_{safe_name}.png"
            filepath = (self.evidence_dir / filename).resolve()
            evidence_root = self.evidence_dir.resolve()
            if evidence_root not in filepath.parents:
                raise ValueError("Evidence output path escaped the evidence locker")
            
            # Take screenshot
            sc = pyautogui.screenshot()
            sc.save(filepath)
            
            return str(filepath)
        except Exception as e:
            return f"Error capturing evidence: {e}"

    def list_evidence(self):
        if not self.evidence_dir.exists():
            return []
        
        # Return list of files sorted by time
        files = sorted(self.evidence_dir.glob("*.png"), key=os.path.getmtime, reverse=True)
        return [str(f) for f in files]

    def _safe_alert_name(self, alert_name: str) -> str:
        candidate = str(alert_name or "").strip() or "incident"
        candidate = re.sub(r"[^A-Za-z0-9._ -]", "_", candidate)
        candidate = candidate.replace(" ", "_")
        return candidate[:80] or "incident"
