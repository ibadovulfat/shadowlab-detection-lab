
import os
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class CanaryHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_modified(self, event):
        if not event.is_directory:
            self.callback(event.src_path, "MODIFIED")

    def on_deleted(self, event):
        if not event.is_directory:
            self.callback(event.src_path, "DELETED")

class RansomwareCanary:
    def __init__(self, alert_callback):
        self.canary_dir = Path("canary_files")
        self.observer = None
        self.alert_callback = alert_callback
        self.files = ["quarterly_report.docx", "passwords.xlsx", "backup.zip"]

    def deploy(self):
        """Creates decoy files."""
        self.canary_dir.mkdir(exist_ok=True)
        created = []
        for f in self.files:
            p = self.canary_dir / f
            with open(p, 'w') as fp:
                fp.write("This is a honeypot file. Modification triggers alarm.\n" * 100)
            created.append(str(p))
        
        # Start Watchdog
        self.start_monitoring()
        return created

    def start_monitoring(self):
        event_handler = CanaryHandler(self.handle_event)
        self.observer = Observer()
        self.observer.schedule(event_handler, str(self.canary_dir), recursive=False)
        self.observer.start()

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

    def handle_event(self, path, event_type):
        """Called when filesystem event occurs."""
        # Simple heuristic: Ransomware modifies or deletes files quickly
        msg = f"RANSOMWARE ALERT: Canary file {path} was {event_type}!"
        self.alert_callback(msg)

    def cleanup(self):
        self.stop()
        if self.canary_dir.exists():
            import shutil
            shutil.rmtree(self.canary_dir)
