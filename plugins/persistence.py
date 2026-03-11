
import os
import platform
import glob
import subprocess
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
        results.extend(_windows_run_keys())
        results.extend(_windows_startup_items())
        results.extend(_windows_scheduled_tasks())
        results.extend(_windows_services())

    return results


def remediate_persistence_item(item_type: str, path: str, name: str = "") -> dict:
    system = platform.system()
    if system != "Windows":
        return {"ok": False, "message": "Persistence remediation is currently implemented for Windows only"}

    try:
        if item_type == "Registry Run Key":
            subprocess.check_call(["reg", "delete", path, "/v", name, "/f"], timeout=10)
            return {"ok": True, "message": f"Deleted Run key value {name} from {path}"}
        if item_type == "Scheduled Task":
            subprocess.check_call(["schtasks", "/change", "/tn", path, "/disable"], timeout=15)
            return {"ok": True, "message": f"Disabled scheduled task {path}"}
        if item_type == "Windows Service":
            subprocess.call(["sc", "stop", path], timeout=15)
            subprocess.check_call(["sc", "config", path, "start=", "disabled"], timeout=15)
            return {"ok": True, "message": f"Stopped and disabled service {path}"}
        if item_type == "Startup Folder":
            target = Path(path)
            if target.exists():
                quarantine_dir = Path("shadowlab_quarantine") / "startup_items"
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                destination = quarantine_dir / target.name
                target.replace(destination)
                return {"ok": True, "message": f"Moved startup item to {destination}"}
            return {"ok": False, "message": "Startup item no longer exists"}
        return {"ok": False, "message": f"Unsupported persistence type: {item_type}"}
    except Exception as exc:
        return {"ok": False, "message": str(exc)}


def _windows_run_keys():
    results = []
    keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    for key in keys:
        try:
            output = subprocess.check_output(["reg", "query", key], stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="ignore", timeout=8)
        except Exception:
            continue
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("HKEY_"):
                continue
            parts = line.split(None, 2)
            if len(parts) == 3:
                name, reg_type, value = parts
                results.append({
                    "name": name,
                    "path": key,
                    "type": "Registry Run Key",
                    "details": reg_type,
                    "content_preview": value,
                })
    return results


def _windows_startup_items():
    results = []
    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    for directory in startup_dirs:
        if not directory.exists():
            continue
        for item in directory.iterdir():
            results.append({
                "name": item.name,
                "path": str(item),
                "type": "Startup Folder",
                "details": "Startup shortcut/file",
                "content_preview": str(item),
            })
    return results


def _windows_scheduled_tasks():
    results = []
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "csv", "/v"],
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=20,
        )
    except Exception:
        return results

    import csv
    from io import StringIO

    reader = csv.DictReader(StringIO(output))
    for row in reader:
        task_name = row.get("TaskName") or row.get("Task Name")
        task_to_run = row.get("Task To Run") or row.get("Actions")
        status = row.get("Status", "")
        if task_name:
            results.append({
                "name": task_name,
                "path": task_name,
                "type": "Scheduled Task",
                "details": status,
                "content_preview": task_to_run or "",
            })
    return results


def _windows_services():
    results = []
    try:
        output = subprocess.check_output(
            ["sc", "query", "type=", "service", "state=", "all"],
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=15,
        )
    except Exception:
        return results

    current_name = None
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("SERVICE_NAME:"):
            current_name = line.split(":", 1)[1].strip()
        elif line.startswith("STATE") and current_name:
            results.append({
                "name": current_name,
                "path": current_name,
                "type": "Windows Service",
                "details": line,
                "content_preview": "",
            })
            current_name = None
    return results
