
import os
import platform
import glob
from pathlib import Path

def get_persistence_items():
    """
    Scans common persistence locations based on the OS.
    Returns a list of dictionaries with detected items.
    """
    system = platform.system()
    results = []

    if system == "Darwin":  # macOS
        # Common macOS persistence locations
        locations = [
            str(Path.home() / "Library/LaunchAgents/*.plist"),
            "/Library/LaunchAgents/*.plist",
            "/Library/LaunchDaemons/*.plist",
            # "/System/Library/LaunchAgents/*.plist", # Too noisy usually
            # "/System/Library/LaunchDaemons/*.plist", # Too noisy usually
        ]

        for loc in locations:
            for plist_path in glob.glob(loc):
                try:
                    # Basic parsing of plist to find 'Program' or 'ProgramArguments' would be better,
                    # but for now we just list the file existence as a persistence mechanism.
                    # We can read the content to show what command is being executed.
                    content_preview = ""
                    with open(plist_path, 'r', encoding='utf-8', errors='ignore') as f:
                        # Read first 500 chars to peek
                        content_preview = f.read(500)
                    
                    # Simple heuristic: Identify if it points to a suspicious binary or path?
                    # For now just reporting it.
                    results.append({
                        "name": os.path.basename(plist_path),
                        "path": plist_path,
                        "type": "LaunchAgent/Daemon",
                        "details": "Autostart Service",
                        "content_preview": content_preview  # useful for UI to show tooltip
                    })
                except Exception as e:
                    results.append({
                        "name": os.path.basename(plist_path),
                        "path": plist_path,
                        "type": "LaunchAgent/Daemon",
                        "details": f"Error reading: {str(e)}",
                        "content_preview": ""
                    })
        
        # Check for Cron (current user)
        # Note: This might not work in all environments depending on permissions/terminal access
        try:
            import subprocess
            cron_out = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT).decode()
            if cron_out and "no crontab" not in cron_out.lower():
                for line in cron_out.splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                         results.append({
                            "name": "User Crontab",
                            "path": "crontab",
                            "type": "Cron Job",
                            "details": line,
                            "content_preview": line
                        })
        except Exception:
            pass # No crontab or permission denied
            
    elif system == "Windows":
        # Placeholder for Windows logic if moved to Windows
        results.append({
            "name": "Windows Persistence Check",
            "path": "N/A",
            "type": "Info",
            "details": "Windows persistence checks not yet fully implemented in this module.",
            "content_preview": ""
        })

    return results
