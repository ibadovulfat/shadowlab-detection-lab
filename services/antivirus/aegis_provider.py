from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .base import AntivirusProvider
from .trust import is_trusted_path, strict_source_trust_enabled, trusted_source_roots


class AegisProvider(AntivirusProvider):
    provider_key = "aegis_core"
    display_name = "Aegis Core"

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.runtime_root = self.base_dir / "shadowlab_out" / "antivirus" / "aegis"
        self.system_rules_path = self.runtime_root / "system_rules"
        self.user_rules_path = self.runtime_root / "user_rules"
        self._ensure_runtime_dirs()
        self._strict_source_trust = strict_source_trust_enabled()
        self._trusted_source_roots = trusted_source_roots(self.base_dir)
        configured_root = os.environ.get("SHADOWLAB_AEGIS_ROOT", "").strip() or os.environ.get("SHADOWLAB_KICOMAV_ROOT", "").strip()
        self.source_root = Path(configured_root).expanduser() if configured_root else None
        if self.source_root is None:
            default_root = Path.home() / "Downloads" / "kicomav-master"
            if default_root.exists():
                self.source_root = default_root
        if self.source_root and not self._trusted_source(self.source_root):
            self.source_root = None
        self.plugins_path = self._resolve_plugins_path()
        self._configure_runtime_env()

    def _ensure_runtime_dirs(self) -> None:
        self.system_rules_path.mkdir(parents=True, exist_ok=True)
        self.user_rules_path.mkdir(parents=True, exist_ok=True)

    def _configure_runtime_env(self) -> None:
        os.environ.setdefault("SYSTEM_RULES_BASE", str(self.system_rules_path))
        os.environ.setdefault("USER_RULES_BASE", str(self.user_rules_path))
        os.environ.setdefault("KICOMAV_SUPPRESS_WARNINGS", "1")

    def _resolve_plugins_path(self) -> Path | None:
        configured_plugins = os.environ.get("SHADOWLAB_AEGIS_PLUGINS", "").strip() or os.environ.get("SHADOWLAB_KICOMAV_PLUGINS", "").strip()
        if configured_plugins:
            path = Path(configured_plugins).expanduser()
            if path.exists() and self._trusted_source(path):
                return path
        if self.source_root:
            candidate = self.source_root / "kicomav" / "plugins"
            if candidate.exists() and self._trusted_source(candidate):
                return candidate
        return None

    def status(self) -> dict[str, Any]:
        try:
            import kicomav  # type: ignore

            version = getattr(kicomav, "__version__", "unknown")
            import_mode = "package"
        except Exception:
            version = ""
            import_mode = "source-bridge" if self.source_root else "package"
        available = bool(self.plugins_path) or self._package_available()
        rule_files = [path for path in self.system_rules_path.rglob("*") if path.is_file()] + [path for path in self.user_rules_path.rglob("*") if path.is_file()]
        latest_rule_update = 0.0
        for path in rule_files:
            try:
                latest_rule_update = max(latest_rule_update, float(path.stat().st_mtime))
            except OSError:
                continue
        return {
            "display_name": self.display_name,
            "available": available,
            "version": version,
            "plugins_path": str(self.plugins_path) if self.plugins_path else "",
            "source_root": str(self.source_root) if self.source_root else "",
            "system_rules_path": str(self.system_rules_path),
            "user_rules_path": str(self.user_rules_path),
            "system_rule_files": len([path for path in self.system_rules_path.rglob("*") if path.is_file()]) if self.system_rules_path.exists() else 0,
            "user_rule_files": len([path for path in self.user_rules_path.rglob("*") if path.is_file()]) if self.user_rules_path.exists() else 0,
            "latest_signature_update": latest_rule_update,
            "mode": "embedded-ruleset" if available else import_mode,
            "strict_source_trust": self._strict_source_trust,
            "trusted_source_roots": [str(item) for item in self._trusted_source_roots],
            "notes": [
                "ShadowLab owns the provider wrapper locally.",
                "Runtime uses an embedded signature adapter with optional plugin bridging.",
            ],
        }

    def _package_available(self) -> bool:
        try:
            import kicomav  # type: ignore  # noqa: F401

            return True
        except Exception:
            return False

    def scan_file(self, path: Path, *, policy: dict[str, Any]) -> dict[str, Any]:
        timeout_seconds = max(10, int(policy.get("scan_timeout_seconds", 90) or 90))
        result_holder: dict[str, Any] = {}
        finished = threading.Event()

        def _worker() -> None:
            result_holder["result"] = self._scan_file_impl(path)
            finished.set()

        worker = threading.Thread(target=_worker, daemon=True, name="shadowlab-aegis-scan")
        worker.start()
        finished.wait(timeout=float(timeout_seconds))
        if not finished.is_set():
            return {
                "status": "error",
                "engine": self.display_name,
                "error": f"Scan timed out after {timeout_seconds} seconds",
                "scan_time_ms": int(timeout_seconds * 1000),
            }
        result = result_holder.get("result")
        if isinstance(result, dict):
            return result
        return {"status": "error", "engine": self.display_name, "error": "Scanner returned no result"}

    def _scan_file_impl(self, path: Path) -> dict[str, Any]:
        self._configure_runtime_env()
        original_sys_path = list(sys.path)
        previous_warning_flag = os.environ.get("KICOMAV_SUPPRESS_WARNINGS")
        os.environ["KICOMAV_SUPPRESS_WARNINGS"] = "1"
        try:
            if self.source_root and str(self.source_root) not in sys.path:
                sys.path.insert(0, str(self.source_root))
            import kicomav  # type: ignore

            started = time.time()
            scanner_kwargs: dict[str, Any] = {}
            if self.plugins_path:
                scanner_kwargs["plugins_path"] = str(self.plugins_path)
            with kicomav.Scanner(**scanner_kwargs) as scanner:
                result = scanner.scan_file(str(path))
            duration_ms = int((time.time() - started) * 1000)
            if getattr(result, "error", None):
                return {
                    "status": "error",
                    "engine": self.display_name,
                    "error": str(result.error),
                    "scan_time_ms": duration_ms,
                }
            return {
                "status": "infected" if bool(getattr(result, "infected", False)) else "clean",
                "engine": self.display_name,
                "malware_name": getattr(result, "malware_name", None),
                "scan_time_ms": duration_ms,
            }
        except Exception as exc:
            return {"status": "error", "engine": self.display_name, "error": str(exc)}
        finally:
            sys.path[:] = original_sys_path
            if previous_warning_flag is None:
                os.environ.pop("KICOMAV_SUPPRESS_WARNINGS", None)
            else:
                os.environ["KICOMAV_SUPPRESS_WARNINGS"] = previous_warning_flag

    def _trusted_source(self, candidate: Path) -> bool:
        if not self._strict_source_trust:
            return True
        return is_trusted_path(candidate, self._trusted_source_roots)
