from __future__ import annotations

import csv
import hashlib
import html
import json
import time
from pathlib import Path

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QBrush, QColor, QDesktopServices
from PySide6.QtWidgets import QListWidgetItem, QTableWidget, QTableWidgetItem

try:
    from _safe_paths import UnsafeArtifactPath, ensure_under_artifact_root
except ImportError:  # pragma: no cover - frozen build / non-sys.path layout
    from desktop._safe_paths import UnsafeArtifactPath, ensure_under_artifact_root


def _format_size(n: int) -> str:
    n = int(n or 0)
    if n < 1024:
        return f"{n} B"
    for unit in ("KB", "MB", "GB"):
        n /= 1024.0
        if n < 1024:
            return f"{n:.1f} {unit}"
    return f"{n:.1f} TB"


def _classify_suffix(suffix: str) -> str:
    """Map a file suffix to the broad type slug we expose as a filter chip."""
    s = (suffix or "").lower().lstrip(".")
    if s in {"json"}:
        return "json"
    if s in {"csv", "tsv"}:
        return "csv"
    if s in {"html", "htm"}:
        return "html"
    if s in {"pdf"}:
        return "pdf"
    if s in {"png", "jpg", "jpeg", "gif", "webp", "bmp"}:
        return "image"
    if s in {"bin", "exe", "dll", "sys"}:
        return "binary"
    return "other"


def _sha256_file(path: Path, *, limit_bytes: int = 16 * 1024 * 1024) -> str:
    """Return the SHA-256 hex digest of `path` (capped to `limit_bytes`).

    Big artifacts get bounded so a 4 GB capture doesn't freeze the UI;
    the cap is high enough that 99% of forensic outputs hash in full.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            remaining = int(limit_bytes)
            while remaining > 0:
                chunk = handle.read(min(65536, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
        return digest.hexdigest()
    except Exception:
        return ""


def _artifact_category(name: str, path: Path) -> tuple[str, str, int]:
    lower_name = name.lower()
    suffix = path.suffix.lower()
    if "antivirus_detection_report" in lower_name:
        return ("Antivirus Detection Report", "antivirus", 0)
    if "antivirus_quarantine_report" in lower_name:
        return ("Antivirus Quarantine Report", "antivirus", 1)
    if "securityops_report" in lower_name:
        return ("Security Ops Report", "security", 2)
    if "shadowlab_report" in lower_name:
        return ("Incident Report", "report", 3)
    if "navigator" in lower_name or "workbench" in lower_name or "mitre" in lower_name:
        return ("ATT&CK Coverage", "intel", 4)
    if "incident_bundle" in lower_name or "bundle" in lower_name:
        return ("Incident Bundle", "bundle", 5)
    if "whids" in lower_name or "ossec" in lower_name:
        return ("Integration Export", "integration", 6)
    if suffix == ".pdf":
        return ("Portable Report", "report", 7)
    if suffix == ".html":
        return ("HTML Report", "report", 8)
    if suffix == ".json":
        return ("Structured Data", "data", 9)
    if suffix == ".csv":
        return ("Telemetry Export", "telemetry", 10)
    return ("Artifact", "artifact", 11)


def _artifact_operator_note(category_key: str) -> str:
    notes = {
        "security": "Use for platform readiness, integrity drift, secrets posture, and deployment evidence.",
        "antivirus": "Use for malware validation, containment handoff, quarantine review, and case escalation evidence.",
        "report": "Best for briefings, handoff, and executive or responder-facing reporting.",
        "intel": "Use to explain ATT&CK mapping, detection coverage, and investigation scope.",
        "bundle": "Use for replay, evidence transfer, or reproducible investigation packaging.",
        "integration": "Use to validate upstream HIDS or manager ingest and response synchronization.",
        "data": "Use for deeper triage, automation replay, or downstream parsing.",
        "telemetry": "Use for analyst review, trend reconstruction, and external spreadsheet work.",
        "artifact": "Use as a supporting forensic output when a richer report is not yet available.",
    }
    return notes.get(category_key, notes["artifact"])


def _read_json_summary(path: Path) -> str:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return "Structured JSON artifact available."
    if isinstance(data, dict):
        status = data.get("status")
        items = data.get("items")
        workspace = data.get("workspace_id")
        summary_bits: list[str] = []
        if status:
            summary_bits.append(f"status={status}")
        if isinstance(items, list):
            summary_bits.append(f"items={len(items)}")
        if workspace:
            summary_bits.append(f"workspace={workspace}")
        interesting_keys = [key for key in ["severity", "risk", "overall_risk", "database", "abuse", "integrity"] if key in data]
        if interesting_keys:
            summary_bits.append("keys=" + ", ".join(interesting_keys))
        return ", ".join(summary_bits) if summary_bits else "Structured JSON artifact available."
    if isinstance(data, list):
        return f"JSON collection with {len(data)} records."
    return "Structured JSON artifact available."


def _read_csv_summary(path: Path) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
            reader = csv.reader(handle)
            rows = list(reader)
    except Exception:
        return "CSV export available."
    if not rows:
        return "CSV export is empty."
    header = ", ".join(rows[0][:6])
    return f"{max(0, len(rows) - 1)} rows | columns: {header}"


def _artifact_summary(name: str, path: Path, category_label: str, category_key: str) -> str:
    suffix = path.suffix.lower()
    if category_key in {"report", "security", "intel"} and suffix in {".html", ".pdf"}:
        return f"{category_label} ready for operator or stakeholder review."
    if suffix == ".json" and path.exists():
        return _read_json_summary(path)
    if suffix == ".csv" and path.exists():
        return _read_csv_summary(path)
    return f"{category_label} stored in artifact locker."


def _build_record(name: str, raw_path: str, *, integrity_map: dict | None = None) -> dict[str, object]:
    path = Path(raw_path)
    category_label, category_key, priority = _artifact_category(name, path)
    exists = path.exists()
    stat = path.stat() if exists else None
    modified = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)) if stat else "missing"
    size = int(stat.st_size) if stat else 0
    type_slug = _classify_suffix(path.suffix)
    # Hash + signature reconciliation against the integrity manifest the
    # API ships through alongside the artifact list. Mismatches surface
    # in the Signature column as `tampered` and recolour the row.
    sha256 = ""
    signature_status = "unsigned"
    expected_sha256 = ""
    if exists:
        sha256 = _sha256_file(path)
        if integrity_map:
            manifest_entry = (integrity_map or {}).get(name) or {}
            expected_sha256 = str(manifest_entry.get("sha256", "") or "").lower()
            if expected_sha256 and sha256:
                signature_status = "valid" if expected_sha256 == sha256 else "tampered"
            elif expected_sha256:
                signature_status = "unverifiable"
    return {
        "name": name,
        "path": str(path),
        "path_obj": path,
        "suffix": path.suffix.lower(),
        "type_slug": type_slug,
        "exists": exists,
        "size": size,
        "size_human": _format_size(size) if exists else "missing",
        "modified": modified,
        "modified_epoch": int(stat.st_mtime) if stat else 0,
        "sha256": sha256,
        "sha256_short": sha256[:12] if sha256 else "",
        "expected_sha256": expected_sha256,
        "signature_status": signature_status,
        "category_label": category_label,
        "category_key": category_key,
        "priority": priority,
        "summary": _artifact_summary(name, path, category_label, category_key) if exists else "Artifact path is registered but the file is currently missing.",
        "operator_note": _artifact_operator_note(category_key),
    }


def _render_overview_html(records: list[dict[str, object]]) -> str:
    category_counts: dict[str, int] = {}
    for record in records:
        label = str(record.get("category_label", "Artifact"))
        category_counts[label] = category_counts.get(label, 0) + 1
    highlights = "".join(
        f"<li><b>{html.escape(label)}</b>: {count}</li>"
        for label, count in sorted(category_counts.items(), key=lambda item: (-item[1], item[0]))
    )
    top_records = "".join(
        "<tr>"
        f"<td>{html.escape(str(record.get('category_label', 'Artifact')))}</td>"
        f"<td>{html.escape(str(record.get('name', '')))}</td>"
        f"<td>{html.escape(str(record.get('summary', '')))}</td>"
        "</tr>"
        for record in records[:8]
    )
    return (
        "<div style='color:#eef4fb;'>"
        "<h3>Artifacts Workspace</h3>"
        f"<p><b>Total artifacts:</b> {len(records)}"
        f"<br><b>Operational reports:</b> {sum(1 for item in records if str(item.get('category_key')) in {'report', 'security', 'intel'})}"
        f"<br><b>Structured exports:</b> {sum(1 for item in records if str(item.get('suffix')) in {'.json', '.csv'})}</p>"
        f"<h4>Inventory Mix</h4><ul>{highlights or '<li>No artifact categories detected.</li>'}</ul>"
        "<h4>Priority Outputs</h4>"
        "<table style='width:100%;border-collapse:collapse;'>"
        "<tr><th align='left'>Category</th><th align='left'>Artifact</th><th align='left'>Summary</th></tr>"
        f"{top_records or '<tr><td colspan=3>No artifacts found.</td></tr>'}"
        "</table>"
        "</div>"
    )


def _render_detail(record: dict[str, object], download_url: str) -> str:
    return (
        f"Artifact: {record['name']}\n"
        f"Category: {record['category_label']}\n"
        f"Summary: {record['summary']}\n"
        f"Operator Note: {record['operator_note']}\n"
        f"Exists: {record['exists']}\n"
        f"Modified: {record['modified']}\n"
        f"Size (bytes): {record['size']}\n"
        f"Local Path: {record['path']}\n"
        f"Download URL: {download_url}"
    )


def _render_text_preview(window, title: str, subtitle: str, body: str) -> None:
    safe_body = html.escape(body[:6000])
    window.art_preview.setHtml(
        "<div style='color:#eef4fb;'>"
        f"<h3>{html.escape(title)}</h3>"
        f"<p style='color:#96a5b8;'>{html.escape(subtitle)}</p>"
        f"<pre style='white-space:pre-wrap;background:#0f1823;border:1px solid #243446;border-radius:8px;padding:12px;'>{safe_body}</pre>"
        "</div>"
    )


def refresh_artifacts(window) -> None:
    # Optional busy lock — provided by the History controller's upgraded
    # build_artifacts_tab. Older callers without one still work.
    busy = getattr(window, "_artifacts_busy", None)
    if busy is not None:
        busy.set_busy(True, "Refreshing artifact locker…")
    try:
        try:
            manifest = window._get("/artifacts").json()
        except Exception as exc:
            window._show_error(window.art_detail, "Failed to load artifacts", exc)
            return
        # A list/null/error-envelope body would make manifest.items()
        # below raise into the Qt event loop (the except above only
        # wraps .json()). The /integrity block right after is already
        # isinstance-guarded — match it.
        if not isinstance(manifest, dict):
            manifest = {}
        # Best-effort pull of the integrity manifest so SHA-256 columns can
        # surface signature status without an extra round-trip per row.
        integrity_map: dict = {}
        try:
            payload = window._get("/integrity", timeout=15).json()
            files = (payload or {}).get("files") if isinstance(payload, dict) else None
            if isinstance(files, dict):
                # Normalise to short basenames so the lookup matches the
                # artifact `name` field exactly.
                for key, meta in files.items():
                    basename = Path(str(key)).name
                    if basename and basename not in integrity_map:
                        integrity_map[basename] = meta or {}
        except Exception:
            integrity_map = {}

        window.artifacts = manifest
        records = [
            _build_record(name, path, integrity_map=integrity_map)
            for name, path in manifest.items()
        ]
        records.sort(key=lambda item: (int(item["priority"]), str(item["name"]).lower()))
        window.artifact_records = records

        table = window.art_list
        # Disable sort + clear placeholders before bulk load so row
        # indices stay stable and the empty-state span doesn't leak.
        try:
            table.setSortingEnabled(False)
            table.clearSpans()
        except AttributeError:
            pass
        if hasattr(table, "setRowCount"):
            table.setRowCount(len(records))
            workspace_id = ""
            try:
                workspace_id = (
                    window.workspace_id.text().strip() if hasattr(window, "workspace_id") else ""
                ) or (getattr(window, "current_auth_context", {}) or {}).get("workspace_id", "default")
            except Exception:
                workspace_id = "default"
            for row, record in enumerate(records):
                cells = [
                    record["name"],
                    record["category_label"],
                    record["size_human"],
                    record["modified"],
                    record["sha256_short"] or "—",
                    record["signature_status"],
                    workspace_id,
                ]
                for col, value in enumerate(cells):
                    item = QTableWidgetItem(str(value))
                    if col == 0:
                        item.setData(Qt.UserRole, str(record["name"]))
                    item.setToolTip(str(record["summary"]))
                    table.setItem(row, col, item)
                # Tone the Signature column so tampered rows jump out.
                sig_item = table.item(row, 5)
                if sig_item is not None:
                    status = record["signature_status"]
                    if status == "valid":
                        sig_item.setForeground(QBrush(QColor("#9ae6b4")))
                    elif status == "tampered":
                        sig_item.setForeground(QBrush(QColor("#feb2b2")))
                    elif status == "unverifiable":
                        sig_item.setForeground(QBrush(QColor("#f6e05e")))
                if not bool(record["exists"]):
                    for c in range(table.columnCount()):
                        cell = table.item(row, c)
                        if cell is not None:
                            cell.setForeground(window._severity_color("high"))
            try:
                table.setSortingEnabled(True)
            except AttributeError:
                pass
        else:
            # Legacy QListWidget callers (e.g. tests holding a fixture)
            # still receive the original list-style population path.
            table.clear()
            for record in records:
                item = QListWidgetItem(f"[{record['category_label']}] {record['name']}")
                item.setData(Qt.UserRole, str(record["name"]))
                item.setToolTip(str(record["summary"]))
                if not bool(record["exists"]):
                    item.setForeground(window._severity_color("high"))
                table.addItem(item)

        if hasattr(window, "metric_art"):
            window.metric_art.setText(f"Artifacts: {len(records)}")
        window.art_detail.setPlainText(json.dumps(manifest, indent=2))
        window.art_preview.setHtml(_render_overview_html(records))
        if hasattr(window, "dash_metrics"):
            window._refresh_dashboard_panels()

        # KPI strip update (only when the upgraded tab actually populated
        # chips - the Artifacts tab dropped the strip entirely so this
        # block becomes a no-op there).
        chips = getattr(window.history_controller, "_artifacts_kpis", None) if hasattr(window, "history_controller") else None
        if chips is None and hasattr(window, "_artifacts_kpis"):
            chips = window._artifacts_kpis
        if isinstance(chips, dict) and chips:
            total = len(records)
            present = [r for r in records if r["exists"]]
            missing = total - len(present)
            total_size = sum(int(r["size"]) for r in present)
            newest = max((int(r["modified_epoch"]) for r in present), default=0)
            oldest = min((int(r["modified_epoch"]) for r in present if int(r["modified_epoch"])), default=0)
            chips["total"].update(str(total), "ok" if total else "neutral", f"{len(present)} present · {missing} missing")
            chips["locker_size"].update(_format_size(total_size), "neutral", "all categories")
            chips["newest"].update(
                time.strftime("%H:%M", time.localtime(newest)) if newest else "—",
                "ok" if newest else "neutral",
                time.strftime("%Y-%m-%d", time.localtime(newest)) if newest else "no captures",
            )
            chips["oldest"].update(
                time.strftime("%H:%M", time.localtime(oldest)) if oldest else "—",
                "neutral",
                time.strftime("%Y-%m-%d", time.localtime(oldest)) if oldest else "no captures",
            )
            chips["missing"].update(
                str(missing),
                "ok" if missing == 0 else ("warn" if missing < 5 else "crit"),
                "registered but on-disk gone" if missing else "all paths resolve",
            )

        # Last refreshed + workspace badge on the controller, if upgraded.
        controller = getattr(window, "history_controller", None)
        if controller is not None:
            if hasattr(controller, "_artifacts_last_refresh"):
                controller._artifacts_last_refresh.setText(
                    f"Last refreshed: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            if hasattr(controller, "_update_artifacts_workspace_badge"):
                controller._update_artifacts_workspace_badge()
            if hasattr(controller, "_apply_artifact_filters"):
                controller._apply_artifact_filters()
    finally:
        if busy is not None:
            busy.set_busy(False)


def render_html_source_preview(window, text: str, title: str) -> None:
    _render_text_preview(
        window,
        title,
        "HTML is shown as escaped source so untrusted markup never executes inside the desktop client.",
        text,
    )


def _selected_record(window) -> dict[str, object] | None:
    table = window.art_list
    # QTableWidget path - the upgraded Artifacts tab puts the artifact
    # name on column 0 with the UserRole payload. Fall back to text in
    # case sorting permuted the cell.
    if hasattr(table, "selectedItems") and hasattr(table, "rowCount") and hasattr(table, "columnCount"):
        try:
            indices = table.selectionModel().selectedRows()
            if indices:
                row = indices[0].row()
                cell = table.item(row, 0)
                selected_name = (cell.data(Qt.UserRole) if cell else None) or (cell.text() if cell else "")
                return next(
                    (rec for rec in getattr(window, "artifact_records", []) if rec.get("name") == selected_name),
                    None,
                )
        except Exception:
            pass
    # Legacy QListWidget path - retained so tests / older callers keep
    # working without rewriting fixtures.
    items = table.selectedItems() if hasattr(table, "selectedItems") else []
    if not items:
        return None
    selected_name = items[0].data(Qt.UserRole) or items[0].text()
    return next((record for record in getattr(window, "artifact_records", []) if record.get("name") == selected_name), None)


def show_selected_artifact(window) -> None:
    record = _selected_record(window)
    if record is None:
        return
    name = str(record["name"])
    artifact_path = Path(str(record["path"]))
    window.art_detail.setPlainText(_render_detail(record, window._url("/artifacts/" + name)))
    suffix = str(record.get("suffix", ""))
    if suffix == ".html" and artifact_path.exists():
        render_html_source_preview(window, artifact_path.read_text(encoding="utf-8", errors="ignore"), name)
    elif suffix == ".json" and artifact_path.exists():
        _render_text_preview(window, name, str(record["summary"]), artifact_path.read_text(encoding="utf-8", errors="ignore"))
    elif suffix == ".csv" and artifact_path.exists():
        _render_text_preview(window, name, str(record["summary"]), artifact_path.read_text(encoding="utf-8", errors="ignore"))
    elif suffix == ".pdf":
        window.art_preview.setHtml(
            "<div style='color:#eef4fb;'>"
            f"<h3>{html.escape(name)}</h3>"
            f"<p><b>Category:</b> {html.escape(str(record['category_label']))}"
            f"<br><b>Summary:</b> {html.escape(str(record['summary']))}"
            f"<br><b>Operator Note:</b> {html.escape(str(record['operator_note']))}</p>"
            "<p style='color:#96a5b8;'>PDF preview stays external to preserve rendering fidelity. Use Open Selected Artifact for the full document.</p>"
            "</div>"
        )
    else:
        window.art_preview.setHtml(
            "<div style='color:#eef4fb;'>"
            f"<h3>{html.escape(name)}</h3>"
            f"<p><b>Category:</b> {html.escape(str(record['category_label']))}"
            f"<br><b>Summary:</b> {html.escape(str(record['summary']))}"
            f"<br><b>Operator Note:</b> {html.escape(str(record['operator_note']))}</p>"
            "<p style='color:#96a5b8;'>No inline preview is available for this file type yet.</p>"
            "</div>"
        )


def open_selected_artifact(window) -> None:
    record = _selected_record(window)
    if record is None:
        return
    path = str(record.get("path", ""))
    if not path:
        return
    # The path arrives in server JSON — a hostile or MitM'd backend can
    # otherwise direct the OS shell handler at any file the operator can
    # read/execute. Funnel through the artifact-root sandbox and reject
    # executable suffixes outright.
    try:
        safe_target = ensure_under_artifact_root(path, allow_shell_open=True)
    except UnsafeArtifactPath as exc:
        window.statusBar().showMessage(f"Artifact open blocked: {exc}", 8000)
        return
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(safe_target)))
