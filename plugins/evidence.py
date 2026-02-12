
import pyautogui
import os
import time
from pathlib import Path

class EvidenceCollector:
    def __init__(self):
        self.evidence_dir = Path("evidence_locker")
        self.evidence_dir.mkdir(exist_ok=True)

    def capture_screenshot(self, alert_name="incident"):
        try:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{alert_name}.png"
            filepath = self.evidence_dir / filename
            
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
