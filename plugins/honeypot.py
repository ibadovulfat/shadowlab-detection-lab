
import os
import time
import tempfile
from pathlib import Path

class FileHoneypot:
    def __init__(self, filename="passwords.txt"):
        self.filename = filename
        # Default to a safe temp location or user home if needed. 
        # For lab, let's put it in the current directory or a 'honey' subdir.
        self.honey_dir = Path("honey")
        self.honey_dir.mkdir(exist_ok=True)
        self.filepath = self.honey_dir / self.filename
        self.last_access = 0.0
        self.is_active = False

    def deploy(self):
        """Creates the honeyfile with fake content."""
        try:
            with open(self.filepath, 'w') as f:
                f.write("run_date=2023-01-01\nuser=admin\npass=CorrectHorseBatteryStaple\n")
            
            # Set initial access time
            self.last_access = os.path.getatime(self.filepath)
            self.is_active = True
            return True, f"Deployed at {self.filepath}"
        except Exception as e:
            return False, str(e)

    def check(self):
        """Checks if the file has been accessed since deployment/last check."""
        if not self.is_active or not self.filepath.exists():
            return "inactive"

        try:
            current_access = os.path.getatime(self.filepath)
            status = "safe"
            
            # Simple float comparison with small buffer
            if current_access > self.last_access + 1.0: 
                status = "alert"
                self.last_access = current_access # Reset alert base
                
            return status
        except Exception:
            return "error"

    def cleanup(self):
        """Removes the honeyfile."""
        if self.filepath.exists():
            os.remove(self.filepath)
        self.is_active = False
