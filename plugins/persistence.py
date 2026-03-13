import glob
import json
import os
import platform
import subprocess
import time
from pathlib import Path


def get_persistence_items():
    system = platform.system()
    results = []

    if system == "Darwin":
        locations = [
            str(Path.home() / "Library/LaunchAgents/*.plist"),
            "/Library/LaunchAgents/*.plist",
            "/Library/LaunchDaemons/*.plist",
        ]
        for loc in locations:
            for plist_path in glob.glob(loc):
                try:
                    with open(plist_path, "r", encoding="utf-8", errors="ignore") as handle:
                        content_preview = handle.read(500)
                    results.append(
                        {
                            "name": os.path.basename(plist_path),
                            "path": plist_path,
                            "type": "LaunchAgent/Daemon",
                            "details": "Autostart Service",
                            "content_preview": content_preview,
                        }
                    )
                except Exception as exc:
                    results.append(
                        {
                            "name": os.path.basename(plist_path),
                            "path": plist_path,
                            "type": "LaunchAgent/Daemon",
                            "details": f"Error reading: {exc}",
                            "content_preview": "",
                        }
                    )
        try:
            cron_out = subprocess.check_output(["crontab", "-l"], stderr=subprocess.STDOUT).decode()
            if cron_out and "no crontab" not in cron_out.lower():
                for line in cron_out.splitlines():
                    if line.strip() and not line.strip().startswith("#"):
                        results.append(
                            {
                                "name": "User Crontab",
                                "path": "crontab",
                                "type": "Cron Job",
                                "details": line,
                                "content_preview": line,
                            }
                        )
        except Exception:
            pass
    elif system == "Windows":
        results.extend(_windows_run_keys())
        results.extend(_windows_startup_items())
        results.extend(_windows_scheduled_tasks())
        results.extend(_windows_services())
        results.extend(_windows_winlogon_entries())

    return results


def get_persistence_items_fast():
    system = platform.system()
    if system != "Windows":
        return get_persistence_items()
    results = []
    results.extend(_windows_run_keys())
    results.extend(_windows_startup_items())
    results.extend(_windows_scheduled_tasks(verbose=False))
    results.extend(_windows_winlogon_entries())
    return results[:150]


def remediate_persistence_item(item_type: str, path: str, name: str = "") -> dict:
    system = platform.system()
    if system != "Windows":
        return {"ok": False, "message": "Persistence remediation is currently implemented for Windows only"}

    remediation_dir = _remediation_dir()
    rollback_data = {}
    backup_path = ""

    try:
        if item_type == "Registry Run Key":
            rollback_data = _query_registry_value(path, name)
            backup_path = str(remediation_dir / f"{_safe_name(name or path)}.json")
            Path(backup_path).write_text(json.dumps(rollback_data, indent=2), encoding="utf-8")
            subprocess.check_call(["reg", "delete", path, "/v", name, "/f"], timeout=10)
            return {
                "ok": True,
                "message": f"Deleted Run key value {name} from {path}",
                "backup_path": backup_path,
                "rollback_data": rollback_data,
            }
        if item_type == "Scheduled Task":
            backup_path = str(remediation_dir / f"{_safe_name(path)}.xml")
            task_xml = _scheduled_task_xml(path)
            Path(backup_path).write_text(task_xml, encoding="utf-16", errors="ignore")
            subprocess.check_call(["schtasks", "/change", "/tn", path, "/disable"], timeout=15)
            return {
                "ok": True,
                "message": f"Disabled scheduled task {path}",
                "backup_path": backup_path,
            }
        if item_type == "Windows Service":
            rollback_data = _service_config(path)
            backup_path = str(remediation_dir / f"{_safe_name(path)}.json")
            Path(backup_path).write_text(json.dumps(rollback_data, indent=2), encoding="utf-8")
            subprocess.call(["sc", "stop", path], timeout=15)
            subprocess.check_call(["sc", "config", path, "start=", "disabled"], timeout=15)
            return {
                "ok": True,
                "message": f"Stopped and disabled service {path}",
                "backup_path": backup_path,
                "rollback_data": rollback_data,
            }
        if item_type == "Startup Folder":
            target = Path(path)
            if target.exists():
                destination = remediation_dir / target.name
                target.replace(destination)
                return {
                    "ok": True,
                    "message": f"Moved startup item to {destination}",
                    "backup_path": str(destination),
                }
            return {"ok": False, "message": "Startup item no longer exists"}
        return {"ok": False, "message": f"Unsupported persistence type: {item_type}"}
    except Exception as exc:
        return {"ok": False, "message": str(exc), "backup_path": backup_path, "rollback_data": rollback_data}


def rollback_persistence_item(item_type: str, path: str, backup_path: str = "", rollback_data=None) -> dict:
    if platform.system() != "Windows":
        return {"ok": False, "message": "Rollback is currently implemented for Windows only"}
    rollback_data = rollback_data or {}
    try:
        if item_type == "Registry Run Key":
            if not rollback_data and backup_path:
                rollback_data = json.loads(Path(backup_path).read_text(encoding="utf-8"))
            subprocess.check_call(
                [
                    "reg",
                    "add",
                    rollback_data["registry_path"],
                    "/v",
                    rollback_data["name"],
                    "/t",
                    rollback_data.get("type", "REG_SZ"),
                    "/d",
                    rollback_data.get("value", ""),
                    "/f",
                ],
                timeout=10,
            )
            return {"ok": True, "message": f"Restored registry persistence {rollback_data['name']}"}
        if item_type == "Scheduled Task":
            subprocess.check_call(["schtasks", "/create", "/tn", path, "/xml", backup_path, "/f"], timeout=20)
            return {"ok": True, "message": f"Restored scheduled task {path}"}
        if item_type == "Windows Service":
            if not rollback_data and backup_path:
                rollback_data = json.loads(Path(backup_path).read_text(encoding="utf-8"))
            start_mode = rollback_data.get("start_mode", "demand")
            subprocess.check_call(["sc", "config", path, "start=", start_mode], timeout=15)
            return {"ok": True, "message": f"Restored service start mode for {path}"}
        if item_type == "Startup Folder":
            source = Path(backup_path)
            target = Path(path)
            if source.exists():
                source.replace(target)
                return {"ok": True, "message": f"Restored startup item to {target}"}
            return {"ok": False, "message": "Backup item not found"}
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
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ]
    for key in keys:
        try:
            output = subprocess.check_output(
                ["reg", "query", key],
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=8,
            )
        except Exception:
            continue
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("HKEY_"):
                continue
            parts = line.split(None, 2)
            if len(parts) == 3:
                name, reg_type, value = parts
                results.append(
                    {
                        "name": name,
                        "path": key,
                        "type": "Registry Run Key",
                        "details": reg_type,
                        "content_preview": value,
                    }
                )
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
            results.append(
                {
                    "name": item.name,
                    "path": str(item),
                    "type": "Startup Folder",
                    "details": "Startup shortcut/file",
                    "content_preview": str(item),
                }
            )
    return results


def _windows_scheduled_tasks(verbose: bool = True):
    results = []
    try:
        output = subprocess.check_output(
            ["schtasks", "/query", "/fo", "csv", *([] if not verbose else ["/v"])],
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10 if not verbose else 20,
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
            results.append(
                {
                    "name": task_name,
                    "path": task_name,
                    "type": "Scheduled Task",
                    "details": status,
                    "content_preview": task_to_run or "",
                }
            )
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
            results.append(
                {
                    "name": current_name,
                    "path": current_name,
                    "type": "Windows Service",
                    "details": line,
                    "content_preview": "",
                }
            )
            current_name = None
    return results


def _windows_winlogon_entries():
    results = []
    keys = [
        (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell"),
        (r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit"),
    ]
    for key, value_name in keys:
        query = _query_registry_value(key, value_name)
        if query:
            results.append(
                {
                    "name": value_name,
                    "path": key,
                    "type": "Registry Run Key",
                    "details": query.get("type", "REG_SZ"),
                    "content_preview": query.get("value", ""),
                }
            )
    return results


def _query_registry_value(path: str, name: str):
    try:
        output = subprocess.check_output(
            ["reg", "query", path, "/v", name],
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10,
        )
    except Exception:
        return {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("HKEY_"):
            continue
        parts = line.split(None, 2)
        if len(parts) == 3:
            reg_name, reg_type, value = parts
            return {"registry_path": path, "name": reg_name, "type": reg_type, "value": value}
    return {}


def _scheduled_task_xml(task_name: str) -> str:
    output = subprocess.check_output(
        ["schtasks", "/query", "/tn", task_name, "/xml"],
        stderr=subprocess.STDOUT,
        timeout=15,
    )
    return output.decode("utf-16", errors="ignore")


def _service_config(service_name: str) -> dict:
    output = subprocess.check_output(
        ["sc", "qc", service_name],
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=15,
    )
    start_mode = "demand"
    for line in output.splitlines():
        if "START_TYPE" in line:
            lowered = line.lower()
            if "auto_start" in lowered:
                start_mode = "auto"
            elif "disabled" in lowered:
                start_mode = "disabled"
            break
    return {"service_name": service_name, "start_mode": start_mode, "raw": output}


def _remediation_dir() -> Path:
    target = Path("shadowlab_out") / "remediation_backups" / time.strftime("%Y%m%d")
    target.mkdir(parents=True, exist_ok=True)
    return target


def _safe_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in value)[:120]
