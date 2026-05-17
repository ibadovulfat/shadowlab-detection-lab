from __future__ import annotations

import html
import json
import os
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtGui import QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QTabWidget,
    QTreeWidget,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)
from PySide6.QtCore import QObject, QThread, QTimer, Qt, Signal

try:
    from _audit_log import AuditLogStore, actor_workspace_pair
except ImportError:  # pragma: no cover
    from desktop._audit_log import AuditLogStore, actor_workspace_pair

try:
    from _audit_mirror import install_backend_mirror as _install_audit_mirror
except ImportError:  # pragma: no cover
    from desktop._audit_mirror import install_backend_mirror as _install_audit_mirror

try:
    from _action_common import ActionGate, ReasonCapture
except ImportError:  # pragma: no cover
    from desktop._action_common import ActionGate, ReasonCapture

try:
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason

try:
    from process_hunt_jobs import ProcessWorker as _FileAnalysisWorker
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker as _FileAnalysisWorker


# Decision verbs that flip an analyst's classification of a sample.
# Marking "suspicious" escalates handling and goes to the audit chain
# with a structured reason; "benign" still gets audited but doesn't
# require a ticket because clearing a sample isn't an escalation.
DECISION_REQUIRES_REASON: frozenset[str] = frozenset({"suspicious"})

# Per-action click debounce. The decision endpoints are mostly local
# state but Export JSON writes to disk and a double-click could spawn
# duplicate file-write dialogs.
FILE_ANALYSIS_DEBOUNCE_SECONDS = 1.0

# Sample-history retention — kept in-memory + persisted alongside the
# audit log so the analyst can pivot back to a recent sample without
# re-running the full scan.
FILE_ANALYSIS_HISTORY_LIMIT = 20

FILE_ANALYSIS_AUDIT_RETENTION = 500


class IntelWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        # Shared audit store — same class Antivirus / History / Enterprise
        # use, distinct path so each console grep-able alone.
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=FILE_ANALYSIS_AUDIT_RETENTION,
        )
        _install_audit_mirror(self._audit_store, app, source_slug="intel")
        # Shared action plumbing. Intel has no per-controller allowlist
        # (action names are dynamic — `decision:suspicious`,
        # `analyze-file`, `export-json`, `persistence-remediate`, etc.)
        # so the gate uses a permissive allowlist; the per-action
        # debounce is what keeps the operator from spamming external
        # provider quotas.
        self._gate = ActionGate(
            allowlist=frozenset({
                "decision:suspicious", "decision:benign", "analyze-file",
                "analyze-exe", "export-json", "persistence-remediate",
                "threat-lookup-hash", "threat-lookup-ip",
            }),
            debounce_seconds=FILE_ANALYSIS_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        self._last_action_click: dict[str, float] = {}
        self._async_jobs: list[tuple[QThread, _FileAnalysisWorker]] = []
        # Sample history — newest-first list of {path, sha256, label,
        # score, decision, ts}. Persisted to disk so a desktop restart
        # doesn't lose the analyst's recent investigation queue.
        self._sample_history: list[dict] = []

    # ------------------------------------------------------------------ #
    # Audit + reason helpers (paylaşılan model: AuditLogStore +
    # _response_dialog) — same pattern as Antivirus / Enterprise.
    # ------------------------------------------------------------------ #

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "file-analysis-audit-log.json"

    def sample_history_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "file-analysis-sample-history.json"

    def _check_action_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. Legacy `_last_action_click`
        # mirror is kept for tests that read it directly.
        ok = self._gate.check(action)
        if ok:
            self._last_action_click[action] = time.time()
        return ok

    def _capture_reason(self, action: str) -> dict | None:
        result = _prompt_response_reason(self.app, action)
        if result is None:
            self.app.statusBar().showMessage(
                f"`{action}` cancelled — structured reason required."
            )
            return None
        ticket, category, text = result
        return {
            "ticket_id": ticket,
            "reason_category": category,
            "reason_text": text,
            "reason_summary": f"[{category}] {ticket}: {text}",
        }

    def _record_audit(
        self,
        *,
        category: str,
        action: str,
        target: str,
        severity: str,
        status: str,
        payload,
        reason: dict | None = None,
    ) -> dict:
        actor, workspace = actor_workspace_pair(self.app)
        return self._audit_store.append(
            category=category,
            action=action,
            target=target,
            severity=severity,
            status=status,
            payload=payload,
            actor=actor,
            workspace=workspace,
            reason=reason,
        )

    # ------------------------------------------------------------------ #
    # Sample history
    # ------------------------------------------------------------------ #

    def load_sample_history(self) -> list[dict]:
        path = self.sample_history_path()
        try:
            if not path.exists():
                return []
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(loaded, list):
            return []
        return [item for item in loaded if isinstance(item, dict)][:FILE_ANALYSIS_HISTORY_LIMIT]

    def save_sample_history(self) -> None:
        path = self.sample_history_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(self._sample_history[:FILE_ANALYSIS_HISTORY_LIMIT], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            return

    def _record_sample_in_history(self, *, path: str, sha256: str, label: str, score: int, decision: str) -> None:
        # Drop earlier entry with the same SHA-256 so the list deduplicates
        # — analysing the same sample twice should bump it to the top, not
        # leave a stale row beneath the fresh one.
        if sha256:
            self._sample_history = [item for item in self._sample_history if item.get("sha256") != sha256]
        else:
            self._sample_history = [item for item in self._sample_history if item.get("path") != path]
        self._sample_history.insert(0, {
            "path": str(path or ""),
            "sha256": str(sha256 or ""),
            "label": str(label or ""),
            "score": int(score or 0),
            "decision": str(decision or ""),
            "ts": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
        })
        del self._sample_history[FILE_ANALYSIS_HISTORY_LIMIT:]
        self.save_sample_history()
        self._refresh_sample_history_ui()

    def _refresh_sample_history_ui(self) -> None:
        app = self.app
        if not hasattr(app, "ma_sample_history_list"):
            return
        list_widget = app.ma_sample_history_list
        list_widget.clear()
        if not self._sample_history:
            placeholder = QListWidgetItem("No samples analyzed yet")
            placeholder.setFlags(placeholder.flags() & ~Qt.ItemIsEnabled)
            list_widget.addItem(placeholder)
            return
        for item in self._sample_history:
            label = str(item.get("label") or "unknown") or "unknown"
            decision = str(item.get("decision") or "")
            score = int(item.get("score") or 0)
            sha = str(item.get("sha256") or "")
            sha_preview = (sha[:10] + "…") if len(sha) > 12 else (sha or "no-hash")
            path = Path(str(item.get("path") or "")).name or "—"
            decision_tag = f" · {decision}" if decision else ""
            text = f"{path}\n[{label.upper()} / {score}] {sha_preview}{decision_tag}"
            qitem = QListWidgetItem(text)
            qitem.setData(Qt.UserRole, item)
            list_widget.addItem(qitem)

    def build_persistence_tab(self) -> QWidget:
        """Product-grade Persistence & Autoruns workspace.

        Replaces the previous 3-button / 4-column flat-table layout with:
          * Header strip - last refreshed + workspace badge + Refresh All.
          * Search bar + type-filter chips (Registry / Scheduled Task / Service / Startup Folder / WMI / Driver / Other).
          * Zengin Findings cədvəli - Name / Type / MITRE / Signer / SHA-256 / Path zone / Created / Details — sortable, tone-coded.
          * Pivot row — Show in Processes / Graph / Send to Case.
          * Empty state CTA + loading skeleton + workspace badge.
        Remediation now demands confirmation modal + sudo gate +
        structured reason + best-effort registry/task backup before
        delete.
        """
        try:
            from _panel_kit import build_kpi_strip, BusyController, install_empty_table_placeholder
        except ImportError:
            from desktop._panel_kit import build_kpi_strip, BusyController, install_empty_table_placeholder
        from PySide6.QtGui import QKeySequence
        from PySide6.QtWidgets import QAbstractItemView, QCheckBox as _QCheck, QLineEdit as _QLE
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(
            l,
            "Persistence & Autoruns",
            "Enumerate, filter, and remediate persistence mechanisms - autoruns, scheduled tasks, services, WMI subscriptions, startup entries. MITRE technique + signature + path zone surfaced inline.",
        )

        # --- Header strip - last refreshed + workspace badge + Refresh All.
        header = QWidget()
        hl = QHBoxLayout(header)
        hl.setContentsMargins(0, 0, 0, 0)
        hl.setSpacing(12)
        self._persist_last_refresh = QLabel("Last refreshed: never")
        self._persist_last_refresh.setStyleSheet("color:#9aa5b1; font-size:12px;")
        hl.addWidget(self._persist_last_refresh)
        self._persist_workspace_badge = QLabel("workspace: -")
        self._persist_workspace_badge.setStyleSheet(
            "color:#cbd5e0; background:#1f2933; padding:4px 10px; border-radius:8px;"
            " font-size:11px; font-weight:600;"
        )
        hl.addWidget(self._persist_workspace_badge)
        hl.addStretch(1)
        refresh_all_btn = QPushButton("Refresh All (Ctrl+R)")
        refresh_all_btn.setShortcut(QKeySequence("Ctrl+R"))
        refresh_all_btn.clicked.connect(app.refresh_persistence)
        app._bind_capability(refresh_all_btn, "can_view_persistence")
        hl.addWidget(refresh_all_btn)
        l.addWidget(header)

        # --- KPI strip.
        kpi_strip, self._persist_kpis = build_kpi_strip(
            w, ("Total", "Critical", "Unsigned", "User-writable", "Recent 24h"),
        )
        l.addWidget(kpi_strip)

        # --- Filter card: search bar + type chips + reset.
        filter_card = QFrame()
        filter_card.setProperty("card", True)
        fo = QVBoxLayout(filter_card)
        fo.setContentsMargins(8, 6, 8, 6)
        fo.setSpacing(6)
        # Row 1: search (replaces the legacy `app.persist_filter` field
        # which lived outside the tab; we proxy it so existing handlers
        # keep working).
        f1 = QHBoxLayout()
        f1.setContentsMargins(0, 0, 0, 0)
        f1.setSpacing(6)
        search_lbl = QLabel("🔍")
        search_lbl.setStyleSheet("color:#9aa5b1;font-size:12px;")
        if not hasattr(app, "persist_filter"):
            app.persist_filter = _QLE()
        app.persist_filter.setPlaceholderText("filter by name / path / signer / type / details…")
        app.persist_filter.setClearButtonEnabled(True)
        app.persist_filter.textChanged.connect(lambda _: self._apply_persistence_filters())
        f1.addWidget(search_lbl)
        f1.addWidget(app.persist_filter)
        fo.addLayout(f1)
        # Row 2: type filter chips.
        f2 = QHBoxLayout()
        f2.setContentsMargins(0, 0, 0, 0)
        f2.setSpacing(6)
        type_lbl = QLabel("TYPES")
        type_lbl.setStyleSheet("color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;")
        f2.addWidget(type_lbl)
        self._persist_type_chips: dict[str, _QCheck] = {}
        for slug in ("registry", "scheduled_task", "service", "startup_folder", "wmi", "driver", "other"):
            label = slug.replace("_", " ").title()
            chk = _QCheck(label)
            chk.setChecked(True)
            chk.setStyleSheet("QCheckBox { color:#cbd5e0; font-size:11px; padding:2px 6px; }")
            chk.toggled.connect(self._apply_persistence_filters)
            self._persist_type_chips[slug] = chk
            f2.addWidget(chk)
        f2.addStretch(1)
        reset_btn = QPushButton("Reset Filters")
        reset_btn.setMaximumWidth(110)
        reset_btn.clicked.connect(self._reset_persistence_filters)
        f2.addWidget(reset_btn)
        fo.addLayout(f2)
        l.addWidget(filter_card)

        # --- Action row.
        actions = QWidget()
        ar = QHBoxLayout(actions)
        ar.setContentsMargins(0, 0, 0, 0)
        ar.setSpacing(8)
        refresh_btn = QPushButton("Refresh Persistence")
        refresh_btn.setToolTip("Re-enumerate every persistence vector on the monitored host.")
        refresh_btn.clicked.connect(app.refresh_persistence)
        backup_btn = QPushButton("Backup Selected")
        backup_btn.setToolTip(
            "Export the highlighted entry (registry hive value / scheduled task XML / service config)\n"
            "to a JSON file before any destructive action. Recommended pre-flight."
        )
        backup_btn.clicked.connect(self._backup_selected_persistence)
        pivot_proc_btn = QPushButton("Show in Processes")
        pivot_proc_btn.setToolTip("Open the Processes tab and try to focus on the binary referenced by the selected entry.")
        pivot_proc_btn.clicked.connect(self._persistence_pivot_to_processes)
        pivot_graph_btn = QPushButton("Show in Graph")
        pivot_graph_btn.setToolTip("Rebuild the Entity Graph and surface this persistence anchor.")
        pivot_graph_btn.clicked.connect(self._persistence_pivot_to_graph)
        case_btn = QPushButton("Send to Case")
        case_btn.setToolTip("Attach the highlighted persistence entry to the active enterprise case.")
        case_btn.clicked.connect(self._persistence_send_to_case)
        remediate = QPushButton("⚠ Remediate Selected")
        remediate.setStyleSheet(
            "QPushButton { color: #feb2b2; } QPushButton:hover { background:#5f1d1d; }"
        )
        remediate.setToolTip(
            "Destructive — backs up the entry first, then deletes the registry value /\n"
            "scheduled task / service. Requires confirmation + structured reason + sudo window."
        )
        remediate.clicked.connect(app.remediate_selected_persistence)
        # Snapshot lifecycle - persist the full filtered enumeration to
        # disk so a later refresh can be diffed against a baseline. The
        # workflow mirrors the Timeline + Graph snapshot pattern, which
        # operators already know.
        snapshot_save_btn = QPushButton("Save Snapshot")
        snapshot_save_btn.setToolTip(
            "Write the live persistence enumeration to JSON for later diff. Includes risk score, signer,\n"
            "SHA-256, MITRE, path zone, and created timestamp per entry."
        )
        snapshot_save_btn.clicked.connect(self._save_persistence_snapshot)
        snapshot_diff_btn = QPushButton("Diff vs Snapshot")
        snapshot_diff_btn.setToolTip(
            "Load a previously-saved snapshot and report added / removed / risk-drifted entries."
        )
        snapshot_diff_btn.clicked.connect(self._diff_persistence_snapshot)
        export_btn = QPushButton("Export Selected")
        export_btn.setToolTip(
            "Export the selected entry as a standalone forensic JSON bundle (raw payload + risk\n"
            "breakdown + workspace + timestamp) suitable for a case attachment."
        )
        export_btn.clicked.connect(self._export_selected_persistence)
        for btn in (refresh_btn, backup_btn, pivot_proc_btn, pivot_graph_btn, case_btn,
                    snapshot_save_btn, snapshot_diff_btn, export_btn, remediate):
            app._bind_capability(btn, "can_view_persistence")
            ar.addWidget(btn)
        ar.addStretch(1)
        l.addWidget(app._panel_card("Persistence Actions", actions, None))
        # Centralised busy controller so the action surface locks during
        # a refresh / remediation.
        self._persistence_busy = BusyController(
            app,
            [
                refresh_all_btn, refresh_btn, backup_btn,
                pivot_proc_btn, pivot_graph_btn, case_btn,
                snapshot_save_btn, snapshot_diff_btn, export_btn, remediate,
            ],
        )

        # --- Zengin Findings cədvəli: 9 sütun (Risk leading).
        app.persist_table = QTableWidget(0, 9)
        app.persist_table.setHorizontalHeaderLabels([
            "Risk", "Name", "Type", "MITRE", "Signer", "SHA-256", "Path Zone", "Created", "Path",
        ])
        app._style_table(app.persist_table)
        app.persist_table.setSortingEnabled(True)
        app.persist_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        app.persist_table.itemSelectionChanged.connect(app.show_selected_persistence)
        install_empty_table_placeholder(
            app.persist_table,
            "No persistence entries enumerated yet - press Refresh Persistence to begin a scan.",
        )

        app.persist_detail = QTextEdit()
        app.persist_detail.setReadOnly(True)
        app.persist_detail.setPlainText(
            "Select a Findings row to surface its raw enumeration payload here.\n\n"
            "First-time setup:\n"
            "  1. Press Refresh All (Ctrl+R) to enumerate autoruns, services, scheduled tasks, WMI subscriptions, and startup entries.\n"
            "  2. Use the filter chips above to scope by mechanism type.\n"
            "  3. Backup any candidate entry before remediating - destructive actions are unrecoverable through the UI."
        )
        split = QSplitter(Qt.Horizontal)
        split.addWidget(app._panel_card(
            "Persistence Findings", app.persist_table,
            lambda: app._open_panel_window("Persistence Findings", app._clone_table(app.persist_table)),
        ))
        split.addWidget(app._panel_card(
            "Persistence Detail", app.persist_detail,
            lambda: app._open_panel_window("Persistence Detail", app._clone_text_view(app.persist_detail)),
        ))
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        l.addWidget(split, 1)
        self._update_persistence_workspace_badge()
        return w

    # ------------------------------------------------------------------ #
    # Persistence helpers - filter / pivot / backup / classification
    # ------------------------------------------------------------------ #

    @staticmethod
    def _classify_persistence_type(item: dict) -> str:
        """Normalize the server-side type / path into a filter slug."""
        raw = str(item.get("type", "")).lower()
        path = str(item.get("path", "")).lower()
        details = str(item.get("details", "")).lower()
        blob = f"{raw} {path} {details}"
        if "registry" in raw or any(k in blob for k in ("hkcu", "hklm", "currentversion\\run")):
            return "registry"
        if "schedule" in raw or "schtask" in blob or "task" in raw:
            return "scheduled_task"
        if raw in {"service", "services"} or "sc query" in blob:
            return "service"
        if "startup" in raw or "startup folder" in blob:
            return "startup_folder"
        if "wmi" in raw or "subscription" in blob or "eventconsumer" in blob:
            return "wmi"
        if "driver" in raw or path.endswith(".sys"):
            return "driver"
        return "other"

    @staticmethod
    def _classify_path_zone(path: str) -> tuple[str, str]:
        """Return (zone_label, tone) where tone ∈ {ok, warn, crit, neutral}.

        Persistence in System32 / Program Files = expected (low risk).
        Persistence in AppData / Public / Temp = high risk (user-writable).
        """
        p = (path or "").replace("/", "\\").lower()
        if not p:
            return ("unknown", "neutral")
        protected_tokens = ("\\windows\\system32", "\\windows\\syswow64", "\\program files", "\\program files (x86)", "/usr/", "/lib/")
        user_tokens = ("\\users\\public", "\\appdata\\", "\\temp\\", "\\downloads\\", "/tmp/", "/home/")
        if any(token in p for token in protected_tokens):
            return ("protected", "ok")
        if any(token in p for token in user_tokens):
            return ("user-writable", "crit")
        if "\\windows\\" in p:
            return ("windows", "warn")
        return ("other", "neutral")

    @staticmethod
    def _mitre_for_persistence(item: dict) -> str:
        """Best-effort MITRE sub-technique mapping for a persistence entry."""
        slug = IntelWorkspaceController._classify_persistence_type(item)  # type: ignore[attr-defined]
        path = str(item.get("path", "")).lower()
        details = str(item.get("details", "")).lower()
        # Honour server-provided mapping if it exists.
        explicit = item.get("mitre") or item.get("mitre_technique") or ""
        if explicit:
            return str(explicit).upper()
        if "ifeo" in details or "image file execution options" in path:
            return "T1546.012"
        if "appinit" in details or "appinit_dlls" in path:
            return "T1546.010"
        if slug == "registry":
            return "T1547.001"
        if slug == "scheduled_task":
            return "T1053.005"
        if slug == "service":
            return "T1543.003"
        if slug == "startup_folder":
            return "T1547.001"
        if slug == "wmi":
            return "T1546.003"
        if slug == "driver":
            return "T1543.003"
        return "T1547"

    def _update_persistence_workspace_badge(self) -> None:
        try:
            wid = ""
            if hasattr(self.app, "workspace_id") and hasattr(self.app.workspace_id, "text"):
                wid = self.app.workspace_id.text().strip()
            wid = wid or (getattr(self.app, "current_auth_context", {}) or {}).get("workspace_id", "default")
            self._persist_workspace_badge.setText(f"workspace: {wid}")
        except Exception:
            self._persist_workspace_badge.setText("workspace: default")

    def _apply_persistence_filters(self) -> None:
        """Re-render the table from `app.persistence_items` honouring the
        search field + active type chips."""
        return self.apply_persistence_filter()

    def _reset_persistence_filters(self) -> None:
        if hasattr(self.app, "persist_filter"):
            self.app.persist_filter.clear()
        for chk in getattr(self, "_persist_type_chips", {}).values():
            chk.setChecked(True)
        self._apply_persistence_filters()

    # ---- Pivot + backup ------------------------------------------------

    def _selected_persistence_record(self) -> dict | None:
        table = self.app.persist_table
        row = table.currentRow()
        if row < 0:
            return None
        anchor = table.item(row, 0)
        if anchor is not None:
            rec = anchor.data(Qt.UserRole)
            if isinstance(rec, dict):
                return rec
        # Legacy fallback for tables built before the row anchor existed.
        items = getattr(self.app, "filtered_persistence_items", []) or []
        if row < len(items):
            return items[row]
        return None

    def _persistence_pivot_to_processes(self) -> None:
        record = self._selected_persistence_record()
        if record is None:
            self.app.statusBar().showMessage("Select an entry first.", 4000)
            return
        try:
            for idx in range(self.app.tabs.count()):
                if self.app.tabs.tabText(idx) == "Processes":
                    self.app.tabs.setCurrentIndex(idx)
                    break
        except Exception:
            pass
        # Best-effort: stuff the binary path into the antivirus target
        # field so the process hunter has a starting cursor.
        path = str(record.get("path", ""))
        if hasattr(self.app, "antivirus_target_path") and path:
            try:
                self.app.antivirus_target_path.setText(path)
            except Exception:
                pass
        self.app.statusBar().showMessage(
            f"Pivoted to Processes (path: {path[:60]})" if path else "Pivoted to Processes", 5000,
        )

    def _persistence_pivot_to_graph(self) -> None:
        record = self._selected_persistence_record()
        if record is None:
            self.app.statusBar().showMessage("Select an entry first.", 4000)
            return
        try:
            for idx in range(self.app.tabs.count()):
                if self.app.tabs.tabText(idx) == "Graph":
                    self.app.tabs.setCurrentIndex(idx)
                    break
        except Exception:
            pass
        if hasattr(self.app, "refresh_entity_graph"):
            self.app.refresh_entity_graph()
        self.app.statusBar().showMessage("Pivoted to Entity Graph.", 4000)

    def _persistence_send_to_case(self) -> None:
        record = self._selected_persistence_record()
        if record is None:
            self.app.statusBar().showMessage("Select an entry first.", 4000)
            return
        if hasattr(self.app, "open_enterprise_case_for_incident"):
            self.app.open_enterprise_case_for_incident(prefix="PERS-")
            self.app.statusBar().showMessage(
                f"Forwarded `{record.get('name')}` to enterprise case.", 5000,
            )
        else:
            self.app.statusBar().showMessage("Enterprise case integration unavailable.", 5000)

    # ------------------------------------------------------------------ #
    # P1 forensic helpers - snapshot save/diff, audit chain, export
    # ------------------------------------------------------------------ #

    def _persistence_audit(self, action: str, *, target: str = "", payload_size: int = 0, extra: dict | None = None) -> None:
        """Best-effort audit chain emission for persistence forensic actions.

        Mirrors the Timeline tab's `_record_audit` pattern: server-side
        `/audit/desktop` for the SOC dashboard + local JSONL fallback
        under `shadowlab_out/persistence-audit-log.jsonl` so chain-of-
        custody never goes dark during an investigation.
        """
        record = {
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "category": "persistence",
            "action": action,
            "target": target,
            "payload_size": int(payload_size or 0),
            "actor": "",
            "workspace": "",
        }
        try:
            ctx = getattr(self.app, "current_auth_context", {}) or {}
            record["actor"] = str(ctx.get("actor") or ctx.get("subject") or "")
            record["workspace"] = str(ctx.get("workspace_id") or "default")
        except Exception:
            pass
        if extra:
            record.update(extra)
        try:
            self.app._post(
                "/audit/desktop",
                json={"source": "desktop:persistence", "entry": record},
                timeout=8,
                raise_for_status=False,
            )
        except Exception:
            pass
        try:
            from pathlib import Path as _Path
            log_path = _Path.cwd() / "shadowlab_out" / "persistence-audit-log.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            return

    def _save_persistence_snapshot(self) -> None:
        """Persist the current filtered enumeration to disk for later diff."""
        app = self.app
        items = getattr(app, "filtered_persistence_items", []) or []
        if not items:
            app.statusBar().showMessage("Refresh first - nothing to snapshot.", 4000)
            return
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        from PySide6.QtWidgets import QFileDialog
        default = f"shadowlab_out/persistence_snapshot_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            app, "Save Persistence Snapshot", default, "JSON (*.json)",
        )
        if not path:
            return
        # Re-extract per-row Risk score so the snapshot is self-contained
        # and can be diffed without re-running the heuristic.
        enriched: list[dict] = []
        table = app.persist_table
        for r, item in enumerate(items):
            risk_cell = table.item(r, 0) if r < table.rowCount() else None
            risk_text = risk_cell.text() if risk_cell else ""
            enriched.append({
                **item,
                "_risk_label": risk_text,
                "_path_zone": self._classify_path_zone(str(item.get("path", "")))[0],
                "_mitre": self._mitre_for_persistence(item),
            })
        payload = {
            "saved_at": time.time(),
            "saved_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "filter": app.persist_filter.text() if hasattr(app, "persist_filter") else "",
            "active_types": [s for s, c in self._persist_type_chips.items() if c.isChecked()],
            "entry_count": len(enriched),
            "entries": _redact(enriched),
        }
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            app.statusBar().showMessage(
                f"Snapshot saved: {path} ({len(enriched)} entries)", 6000,
            )
            self._persistence_audit("snapshot-save", target=path, payload_size=len(enriched))
        except Exception as exc:
            app._show_error(app.persist_detail, "Snapshot save failed", exc)

    def _diff_persistence_snapshot(self) -> None:
        """Load a previously-saved snapshot and report added / removed /
        risk-drifted entries vs the live filtered view."""
        from PySide6.QtWidgets import QFileDialog
        app = self.app
        path, _ = QFileDialog.getOpenFileName(
            app, "Open Persistence Snapshot", "shadowlab_out/", "JSON (*.json)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                snapshot = json.load(handle)
        except Exception as exc:
            app._show_error(app.persist_detail, "Snapshot load failed", exc)
            return
        # The snapshot file is operator-chosen and may be hand-edited or
        # planted: tolerate a non-object top level and non-dict entries
        # instead of raising AttributeError out of the action handler.
        if not isinstance(snapshot, dict):
            snapshot = {}
        snap_entries = [
            e for e in (snapshot.get("entries", []) or []) if isinstance(e, dict)
        ]
        live_entries = [
            e for e in (getattr(app, "filtered_persistence_items", []) or [])
            if isinstance(e, dict)
        ]

        def _ident(entry: dict) -> tuple[str, str, str]:
            return (
                str(entry.get("name", "")),
                str(entry.get("type", "")),
                str(entry.get("path", "")),
            )
        live_idx = {_ident(e): e for e in live_entries}
        snap_idx = {_ident(e): e for e in snap_entries}
        added = sorted(set(live_idx) - set(snap_idx))
        removed = sorted(set(snap_idx) - set(live_idx))
        drifted: list[tuple[tuple[str, str, str], str, str]] = []
        for ident, live_e in live_idx.items():
            if ident not in snap_idx:
                continue
            snap_e = snap_idx[ident]
            live_signer = str(live_e.get("signer", ""))
            snap_signer = str(snap_e.get("signer", ""))
            live_hash = str(live_e.get("sha256", ""))
            snap_hash = str(snap_e.get("sha256", ""))
            if (live_signer and snap_signer and live_signer != snap_signer) or (
                live_hash and snap_hash and live_hash != snap_hash
            ):
                drifted.append((ident, snap_hash[:12] or snap_signer, live_hash[:12] or live_signer))

        lines = [
            "═══ Persistence Diff ═══",
            f"Snapshot file:  {path}",
            f"Snapshot saved: {snapshot.get('saved_at_iso', '?')}  ({snapshot.get('entry_count', 0)} entries)",
            f"Live view:      {len(live_entries)} entries",
            "",
            f"Added   ({len(added):3d}):",
        ]
        for ident in added[:25]:
            lines.append(f"  + [{ident[1]}] {ident[0][:60]}  @ {ident[2][:60]}")
        if len(added) > 25:
            lines.append(f"  … (+{len(added) - 25} more)")
        lines.append("")
        lines.append(f"Removed ({len(removed):3d}):")
        for ident in removed[:25]:
            lines.append(f"  - [{ident[1]}] {ident[0][:60]}  @ {ident[2][:60]}")
        if len(removed) > 25:
            lines.append(f"  … (+{len(removed) - 25} more)")
        lines.append("")
        lines.append(f"Signer / hash drift ({len(drifted):3d}):")
        for ident, before, after in drifted[:15]:
            lines.append(f"  ~ {ident[0][:50]}  {before} -> {after}")
        app.persist_detail.setPlainText("\n".join(lines))
        app.statusBar().showMessage(
            f"Diff: +{len(added)} / -{len(removed)} / {len(drifted)} drifted", 7000,
        )
        self._persistence_audit(
            "snapshot-diff",
            target=path,
            payload_size=len(live_entries),
            extra={"added": len(added), "removed": len(removed), "drifted": len(drifted)},
        )

    def _export_selected_persistence(self) -> None:
        """Forensic single-entry export — raw payload + risk breakdown +
        workspace + timestamp, suitable for a case attachment."""
        from PySide6.QtWidgets import QFileDialog
        record = self._selected_persistence_record()
        if record is None:
            self.app.statusBar().showMessage("Select an entry first.", 4000)
            return
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        # Re-derive scoring context so the exported bundle is self-
        # describing (an analyst opening the JSON six months later
        # shouldn't need ShadowLab to interpret it).
        zone_label, zone_tone = self._classify_path_zone(str(record.get("path", "")))
        slug = self._classify_persistence_type(record)
        mitre = self._mitre_for_persistence(record)
        ctx = getattr(self.app, "current_auth_context", {}) or {}
        bundle = {
            "exported_at": time.time(),
            "exported_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "workspace": ctx.get("workspace_id", "default"),
            "actor": ctx.get("actor") or ctx.get("subject", ""),
            "entry": _redact(record),
            "derived": {
                "type_slug": slug,
                "path_zone": zone_label,
                "path_zone_tone": zone_tone,
                "mitre": mitre,
                "scoring_formula": (
                    "+30 user-writable path, +20 unsigned/invalid signer, "
                    "+15 rare MITRE technique, +15 created <24h, "
                    "+10 heuristic markers (runonce/encoded ps/temp/appdata), "
                    "-10 protected path + valid signer"
                ),
            },
        }
        safe = "".join(ch for ch in str(record.get("name", "entry")) if ch.isalnum() or ch in {"-", "_"}) or "entry"
        default = f"shadowlab_out/persistence_export_{safe}_{int(time.time())}.json"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Export Persistence Entry", default, "JSON (*.json)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(bundle, handle, indent=2, ensure_ascii=False, default=str)
            self.app.statusBar().showMessage(f"Forensic bundle written: {path}", 6000)
            self._persistence_audit("export", target=path, payload_size=1)
        except Exception as exc:
            self.app._show_error(self.app.persist_detail, "Forensic export failed", exc)

    def _backup_selected_persistence(self) -> None:
        """Persist the selected entry (raw payload) to disk before
        any destructive action. Real backend backup (regedit export /
        schtasks /xml) would happen here once the server endpoint
        ships - for now we snapshot what the API returned."""
        from PySide6.QtWidgets import QFileDialog
        record = self._selected_persistence_record()
        if record is None:
            self.app.statusBar().showMessage("Select an entry first.", 4000)
            return
        default = f"shadowlab_out/persistence_backup_{int(time.time())}.json"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Backup Persistence Entry", default, "JSON (*.json)",
        )
        if not path:
            return
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "backed_up_at": time.time(),
                        "entry": _redact(record),
                        "advice": (
                            "Restore by re-running the original autorun creation flow OR "
                            "manually re-importing this JSON via the integration tooling. "
                            "ShadowLab persists the raw payload so the analyst has a known-"
                            "good reference if the remediation needs to be reverted."
                        ),
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            self.app.statusBar().showMessage(f"Backup written: {path}", 6000)
        except Exception as exc:
            self.app._show_error(self.app.persist_detail, "Backup write failed", exc)

    def build_threat_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(10)
        title = QLabel("Threat Intel Workspace")
        title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        sub = QLabel("Panelized intel workflow with compact layout and popout windows.")
        sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        l.addWidget(title)
        l.addWidget(sub)

        summary = QWidget(); sr = QHBoxLayout(summary)
        sr.setContentsMargins(0, 0, 0, 0)
        sr.setSpacing(8)
        app.ti_last_type = QLabel("Last Query: -")
        app.ti_last_value = QLabel("Value: -")
        app.ti_last_source = QLabel("Source: -")
        for item in [app.ti_last_type, app.ti_last_value, app.ti_last_source]:
            sr.addWidget(item)
        sr.addStretch(1)
        l.addWidget(app._panel_card("Current Query Context", summary, None))

        controls = QWidget(); cr = QHBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        auto_hash = QPushButton("Use Selected Process Hash"); auto_hash.clicked.connect(app.use_selected_process_hash)
        auto_ip = QPushButton("Use Selected Process IP"); auto_ip.clicked.connect(app.use_selected_process_ip)
        hash_btn = QPushButton("Lookup Hash"); hash_btn.clicked.connect(app.lookup_hash)
        ip_btn = QPushButton("Lookup IP"); ip_btn.clicked.connect(app.lookup_ip)
        scan_btn = QPushButton("Scan Selected Executable"); scan_btn.clicked.connect(app.scan_selected_process); app._bind_capability(scan_btn, "can_run_hunt")
        for btn in [auto_hash, auto_ip, hash_btn, ip_btn, scan_btn]:
            cr.addWidget(btn)
        cr.addStretch(1)
        l.addWidget(app._panel_card("Threat Actions", controls, None))

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        app.threat_history_table = QTableWidget(0, 3)
        app.threat_history_table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        app.threat_history_table.itemSelectionChanged.connect(app.show_selected_threat_history)
        app._style_table(app.threat_history_table)
        ll.addWidget(app._panel_card("Threat History", app.threat_history_table, app._open_threat_history_panel))
        app.threat_out = QTextEdit(); app.threat_out.setReadOnly(True); app.threat_out.setPlainText("Threat enrichment output will appear here after a hash, IP, or selected process executable is analyzed.")
        split.addWidget(left)
        split.addWidget(app._panel_card("Threat Analysis Output", app.threat_out, app._open_threat_output_panel))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def build_malware_analyst_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        w.setProperty("no_vertical_scroll", True)
        app._tab_header(l, "File Analysis Console", "Static malware analysis workflow for intake, structural evidence, YARA/DIE signals, import behavior, strings, and analyst decisioning.")

        # ------------------------------------------------------------------
        # Loaded-file badge + drag-drop hint. Replaces the separate
        # "File Analysis Actions" card title with a live status strip
        # so the operator sees the current sample at a glance.
        # ------------------------------------------------------------------
        from PySide6.QtWidgets import QLineEdit
        app.ma_file_path = QLineEdit()
        app.ma_file_path.setPlaceholderText("File path for analysis — drag-drop a sample, paste a path, or pick via Browse")
        app.ma_file_path.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        app.ma_loaded_badge = QLabel("No sample loaded")
        app.ma_loaded_badge.setStyleSheet(
            "background:#101a24;color:#7fd7ff;border:1px solid #355179;border-radius:8px;"
            "padding:6px 12px;font-size:11px;font-weight:800;"
        )
        app.ma_loaded_hash = QLabel("SHA-256: —")
        app.ma_loaded_hash.setStyleSheet(
            "background:#101a24;color:#c8d8ea;border:1px solid #243446;border-radius:8px;"
            "padding:6px 10px;font-size:10px;font-family:Consolas,monospace;"
        )
        app.ma_loaded_decision = QLabel("Decision: —")
        app.ma_loaded_decision.setStyleSheet(
            "background:#101a24;color:#c8d8ea;border:1px solid #243446;border-radius:8px;"
            "padding:6px 10px;font-size:10px;font-weight:700;"
        )

        path_strip = QWidget()
        ps = QHBoxLayout(path_strip)
        ps.setContentsMargins(0, 0, 0, 0); ps.setSpacing(8)
        ps.addWidget(app.ma_file_path, 4)
        browse_btn = QPushButton("Browse"); browse_btn.clicked.connect(app.pick_malware_analyst_file)
        ps.addWidget(browse_btn)
        ps.addWidget(app.ma_loaded_badge)
        ps.addWidget(app.ma_loaded_hash, 2)
        ps.addWidget(app.ma_loaded_decision)

        # ------------------------------------------------------------------
        # Action buttons grouped by intent + colour-coded — same pattern
        # as Enterprise. Five visual groups so the analyst eye-tracks to
        # the verb category instead of a wall of identical buttons.
        # ------------------------------------------------------------------
        use_process_btn = QPushButton("Use Process"); use_process_btn.clicked.connect(app.use_selected_process_for_malware_analysis)
        analyze_file_btn = QPushButton("Analyze File"); analyze_file_btn.clicked.connect(app.run_malware_analyst_file_scan)
        analyze_process_btn = QPushButton("Analyze EXE"); analyze_process_btn.clicked.connect(app.run_malware_analyst_process_scan)
        refresh_btn = QPushButton("Readiness"); refresh_btn.clicked.connect(app.refresh_malware_analyst_status)
        mark_benign_btn = QPushButton("Mark Benign"); mark_benign_btn.clicked.connect(lambda: self.mark_malware_analysis_decision("benign"))
        mark_suspicious_btn = QPushButton("Mark Suspicious"); mark_suspicious_btn.clicked.connect(lambda: self.mark_malware_analysis_decision("suspicious"))
        export_btn = QPushButton("Export JSON"); export_btn.clicked.connect(self.export_malware_analysis_json)
        app._bind_capability(use_process_btn, "can_run_hunt")
        app._bind_capability(analyze_file_btn, "can_run_hunt")
        app._bind_capability(analyze_process_btn, "can_run_hunt")

        action_row = QWidget()
        action_layout = QHBoxLayout(action_row)
        action_layout.setContentsMargins(0, 0, 0, 0); action_layout.setSpacing(8)
        action_groups: list[tuple[str, str, list]] = [
            ("Intake",   "#5e7493", [use_process_btn, refresh_btn]),
            ("Analyze",  "#3a6ea8", [analyze_file_btn, analyze_process_btn]),
            ("Decision", "#3a8a64", [mark_benign_btn]),
            ("Escalate", "#a8763a", [mark_suspicious_btn]),
            ("Export",   "#3a8aa8", [export_btn]),
        ]
        for label_text, accent, buttons in action_groups:
            if not buttons:
                continue
            group = QFrame()
            group.setProperty("card", True)
            group.setStyleSheet(
                "QFrame[card='true']{"
                f"background:#0e1720;border:1px solid {accent};border-radius:7px;padding:2px 4px;"
                "}"
            )
            group_layout = QHBoxLayout(group)
            group_layout.setContentsMargins(6, 2, 6, 2); group_layout.setSpacing(3)
            cap = QLabel(label_text)
            cap.setStyleSheet(f"color:{accent};font-size:9px;font-weight:800;letter-spacing:0.5px;")
            group_layout.addWidget(cap)
            for btn in buttons:
                btn.setFixedHeight(28)
                group_layout.addWidget(btn)
            action_layout.addWidget(group)
        action_layout.addStretch(1)

        l.addWidget(path_strip)
        l.addWidget(action_row)

        # ------------------------------------------------------------------
        # Detect It Easy Readiness — moved to a thin status strip below
        # the action row so it doesn't consume a whole card. Single row
        # of badges, no inner whitespace.
        # ------------------------------------------------------------------
        status_strip = QFrame(); status_strip.setProperty("card", True)
        status_strip.setStyleSheet(
            "QFrame[card='true']{background:#0e1720;border:1px solid #243446;border-radius:7px;padding:2px 6px;}"
        )
        ss_layout = QHBoxLayout(status_strip)
        ss_layout.setContentsMargins(8, 4, 8, 4); ss_layout.setSpacing(8)
        readiness_label = QLabel("DIE Readiness")
        readiness_label.setStyleSheet("color:#96a5b8;font-size:9px;font-weight:800;letter-spacing:0.5px;")
        ss_layout.addWidget(readiness_label)
        app.ma_status_badge = QLabel("DIE Status: unknown")
        app.ma_repo_badge = QLabel("Repo: -")
        app.ma_runtime_badge = QLabel("Runtime: -")
        app.ma_yara_badge = QLabel("YARA: local")
        app.ma_provider_badge = QLabel("Providers: local metadata")
        for item in [app.ma_status_badge, app.ma_repo_badge, app.ma_runtime_badge, app.ma_yara_badge, app.ma_provider_badge]:
            item.setStyleSheet("background:#101a24;color:#c8d8ea;border:1px solid #243446;border-radius:8px;padding:4px 8px;font-size:10px;font-weight:800;")
            ss_layout.addWidget(item)
        ss_layout.addStretch(1)
        l.addWidget(status_strip)

        # ------------------------------------------------------------------
        # 3-pane main splitter: Sample History (left) | File Posture
        # (middle) | High-Signal Findings (right). Sample history was
        # missing entirely in the previous design — analysts had to
        # re-run analysis to revisit a sample. The list is hydrated
        # from `shadowlab_out/file-analysis-sample-history.json` on
        # startup and click-to-load.
        # ------------------------------------------------------------------
        app.ma_sample_history_list = QListWidget()
        app.ma_sample_history_list.setStyleSheet(
            "QListWidget{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}"
            "QListWidget::item{padding:6px 8px;border-bottom:1px solid #1a2a3d;}"
            "QListWidget::item:selected{background:#1a2b3f;}"
        )
        app.ma_sample_history_list.itemClicked.connect(self._on_sample_history_clicked)

        # Each tab widget must explicitly stretch to fill the File
        # Posture panel — the previous build relied on Qt's default
        # size policy, which left the content browser at its minimum
        # height with empty space below. Setting Expanding/Expanding
        # on every tab body makes the browser fill the panel.
        app.ma_summary = QTextBrowser()
        app.ma_summary.setProperty("role", "brief")
        app.ma_summary.setMinimumHeight(120)
        app.ma_summary.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_summary.setHtml(self.malware_empty_state_html("No file loaded", "Browse, drag-drop, or use a selected process executable, then run analysis."))
        app.ma_highlights = QTableWidget(0, 4)
        app.ma_highlights.setHorizontalHeaderLabels(["Signal", "Category", "Severity", "Detail"])
        app._style_table(app.ma_highlights)
        app.ma_highlights.setMinimumHeight(120)
        app.ma_highlights.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_output = QTextEdit()
        app.ma_output.setReadOnly(True)
        app.ma_output.setMinimumHeight(120)
        app.ma_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_output.setPlainText("Raw Detect It Easy output will appear here after a file or process executable is analyzed.")
        app.ma_evidence = QTextBrowser()
        app.ma_evidence.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_evidence.setHtml(self.malware_empty_state_html("Evidence not collected", "Run analysis to see hashes, PE headers, signer, sections, imports, overlay, and timestamps."))
        app.ma_strings = QTextBrowser()
        app.ma_strings.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_strings.setHtml(self.malware_empty_state_html("Strings not extracted", "Run analysis to categorize URLs, domains, registry keys, commands, credentials, and crypto markers."))
        app.ma_imports = QTextBrowser()
        app.ma_imports.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_imports.setHtml(self.malware_empty_state_html("Imports not categorized", "Run analysis to classify APIs by injection, persistence, credential access, networking, evasion, and crypto."))
        app.ma_providers = QTextBrowser()
        app.ma_providers.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.ma_providers.setHtml(self.malware_provider_readiness_html({}))
        app.ma_last_result = {}
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # `_panel_card` whitelists known scrollable widget types as
        # "expanding" — QTabWidget isn't in that list, so without this
        # property hint the panel adds the tabs at minimum height and
        # leaves the rest of the card empty.
        tabs.setProperty("panel_expand", True)
        tabs.addTab(app.ma_summary, "Decision")
        tabs.addTab(app.ma_evidence, "Evidence")
        tabs.addTab(app.ma_imports, "Imports")
        tabs.addTab(app.ma_strings, "Strings")
        tabs.addTab(app.ma_output, "Raw")
        tabs.addTab(app.ma_providers, "Providers")

        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(8)
        main_split.setChildrenCollapsible(False)
        main_split.setStyleSheet(
            "QSplitter::handle{background:#1a2b3f;border:1px solid #243446;border-radius:3px;margin:2px;}"
            "QSplitter::handle:hover{background:#2a4666;border-color:#3a5680;}"
        )
        main_split.addWidget(app._panel_card("Sample History", app.ma_sample_history_list, None))
        main_split.addWidget(app._panel_card("File Posture", tabs, None))
        main_split.addWidget(app._panel_card("High-Signal Findings", app.ma_highlights, lambda: app._open_panel_window("File Analysis Findings", app._clone_table(app.ma_highlights))))
        main_split.setStretchFactor(0, 2)
        main_split.setStretchFactor(1, 5)
        main_split.setStretchFactor(2, 3)
        l.addWidget(main_split, 1)

        # Hydrate sample history from disk + render the list.
        self._sample_history = self.load_sample_history()
        self._refresh_sample_history_ui()

        # ------------------------------------------------------------------
        # Drag-drop sample support. The whole tab accepts a file drop;
        # filename goes into the path input. Operator can then click
        # Analyze File to kick off the worker.
        # ------------------------------------------------------------------
        w.setAcceptDrops(True)

        def _drag_enter(event):
            if event.mimeData().hasUrls() and len(event.mimeData().urls()) >= 1:
                event.acceptProposedAction()

        def _drop(event):
            urls = event.mimeData().urls()
            if not urls:
                return
            local = urls[0].toLocalFile()
            if local and os.path.isfile(local):
                app.ma_file_path.setText(local)
                app.ma_loaded_badge.setText(f"Loaded: {Path(local).name}")
                app.statusBar().showMessage(f"File queued for analysis: {local}")
            else:
                # A folder, a non-existent path, or a remote/UNC URL — do
                # not queue it; the backend would just error on it.
                app.statusBar().showMessage("Drop a single existing local file (folders and remote URLs are ignored).")
            event.acceptProposedAction()

        w.dragEnterEvent = _drag_enter  # type: ignore[assignment]
        w.dropEvent = _drop  # type: ignore[assignment]

        # ------------------------------------------------------------------
        # Keyboard shortcuts — analyst muscle memory matters in a
        # malware-analyst console. Owned by the tab so they don't fire
        # while the operator is on a different tab.
        # ------------------------------------------------------------------
        QShortcut(QKeySequence("Ctrl+O"), w).activated.connect(app.pick_malware_analyst_file)
        QShortcut(QKeySequence("Ctrl+Return"), w).activated.connect(app.run_malware_analyst_file_scan)
        QShortcut(QKeySequence("Ctrl+B"), w).activated.connect(lambda: self.mark_malware_analysis_decision("benign"))
        QShortcut(QKeySequence("Ctrl+Shift+S"), w).activated.connect(lambda: self.mark_malware_analysis_decision("suspicious"))
        QShortcut(QKeySequence("Ctrl+E"), w).activated.connect(self.export_malware_analysis_json)
        QShortcut(QKeySequence("Ctrl+R"), w).activated.connect(app.refresh_malware_analyst_status)

        return w

    def _on_sample_history_clicked(self, item: QListWidgetItem) -> None:
        """Restore a sample from the history list back into the input.

        Doesn't auto-run analysis (operator might want to inspect the
        path before re-running) — just sets the path and updates the
        loaded-file badges.
        """
        app = self.app
        meta = item.data(Qt.UserRole)
        if not isinstance(meta, dict):
            return
        path = str(meta.get("path") or "")
        if path:
            app.ma_file_path.setText(path)
        sha = str(meta.get("sha256") or "")
        decision = str(meta.get("decision") or "")
        # If the file is gone (or was replaced at the same path by a new
        # drop), the stored SHA/decision no longer describe the bytes on
        # disk. Showing them would let the analyst act on a stale verdict
        # — blank them and warn instead.
        file_present = bool(path) and os.path.isfile(path)
        if not file_present:
            sha = ""
            decision = ""
        if hasattr(app, "ma_loaded_badge"):
            app.ma_loaded_badge.setText(f"Loaded: {Path(path).name or '—'}")
        if hasattr(app, "ma_loaded_hash"):
            preview = (sha[:18] + "…") if len(sha) > 20 else (sha or "—")
            app.ma_loaded_hash.setText(f"SHA-256: {preview}")
        if hasattr(app, "ma_loaded_decision"):
            tag = decision.upper() if decision else "—"
            app.ma_loaded_decision.setText(f"Decision: {tag}")
        if file_present:
            app.statusBar().showMessage(f"Sample restored from history: {path}")
        else:
            app.statusBar().showMessage(
                f"⚠ History path no longer on disk — re-analyze before trusting any verdict: {path}"
            )

    def refresh_persistence(self) -> None:
        app = self.app
        busy = getattr(self, "_persistence_busy", None)
        if busy is not None:
            busy.set_busy(True, "Enumerating persistence vectors…")
        try:
            try:
                app.persistence_items = app._get("/persistence").json()
            except Exception as exc:
                app._show_error(app.persist_detail, "Persistence refresh failed", exc)
                return
            app.apply_persistence_filter()
            # Surface last-refreshed timestamp + workspace context.
            if hasattr(self, "_persist_last_refresh"):
                self._persist_last_refresh.setText(
                    f"Last refreshed: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                )
            self._update_persistence_workspace_badge()
            # A successful refresh proves an attended session - reset
            # the sudo window so destructive remediations may proceed
            # within the next 5 minutes.
            self._persist_last_remediation_check = time.time()
            self._persistence_audit(
                "refresh",
                target=f"items={len(getattr(app, 'persistence_items', []) or [])}",
                payload_size=len(getattr(app, "persistence_items", []) or []),
            )
        finally:
            if busy is not None:
                busy.set_busy(False)

    def apply_persistence_filter(self) -> None:
        app = self.app
        filt = (app.persist_filter.text() if hasattr(app, "persist_filter") else "").strip().lower()
        active_types = {
            slug for slug, chk in getattr(self, "_persist_type_chips", {}).items()
            if chk.isChecked()
        }
        # Defence-in-depth: if the API ever returns a JSON object/scalar
        # instead of a list, iterating it would yield dict keys (str) and
        # crash `_classify_persistence_type`. Keep only dict records.
        items_all = [
            i for i in (getattr(app, "persistence_items", []) or [])
            if isinstance(i, dict)
        ]
        items: list[dict] = []
        for item in items_all:
            # Substring filter against the full JSON blob.
            if filt and filt not in json.dumps(item, default=str).lower():
                continue
            # Type chip filter.
            slug = self._classify_persistence_type(item)
            if active_types and slug not in active_types:
                continue
            items.append(item)
        app.filtered_persistence_items = items

        table = app.persist_table
        try:
            table.setSortingEnabled(False)
            table.clearSpans()
        except AttributeError:
            pass
        table.setRowCount(len(items))
        risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        unsigned_count = 0
        user_writable_count = 0
        recent_count = 0
        now_ts = time.time()
        for r, item in enumerate(items):
            slug = self._classify_persistence_type(item)
            zone_label, zone_tone = self._classify_path_zone(str(item.get("path", "")))
            mitre = self._mitre_for_persistence(item)
            signer = str(item.get("signer") or item.get("signature_status") or "")
            sha256 = str(item.get("sha256") or item.get("hash") or "")
            sha_short = sha256[:12] if sha256 else "—"
            created_raw = item.get("created_at") or item.get("modified_at") or ""
            created_epoch = 0.0
            created_display = "—"
            if isinstance(created_raw, (int, float)) and created_raw:
                created_epoch = float(created_raw)
            elif isinstance(created_raw, str) and created_raw.replace(".", "", 1).isdigit():
                created_epoch = float(created_raw)
            if created_epoch:
                created_display = time.strftime("%Y-%m-%d %H:%M", time.localtime(created_epoch))
            elif isinstance(created_raw, str) and created_raw:
                created_display = created_raw

            # Composite risk score - documented formula:
            #   +30 path is user-writable (AppData / Public / Temp)
            #   +20 signer is unsigned / invalid / broken
            #   +15 type ∈ {WMI, IFEO, AppInit} (rare = suspicious)
            #   +15 created within last 24h (fresh persistence is a flag)
            #   +10 heuristic markers (runonce / powershell encoded / temp)
            #   -10 path is `protected` + signer is `valid`
            score = 0
            if zone_tone == "crit":
                score += 30
                user_writable_count += 1
            sl = signer.lower()
            if not signer or any(tok in sl for tok in ("unsigned", "invalid", "broken")):
                score += 20
                unsigned_count += 1
            rare = ("T1546.003", "T1546.010", "T1546.012")
            if mitre.upper() in rare:
                score += 15
            if created_epoch and (now_ts - created_epoch) <= 86400:
                score += 15
                recent_count += 1
            risk_text = json.dumps(item, default=str).lower()
            if any(token in risk_text for token in ("runonce", "powershell -enc", "temp\\", "appdata\\", "/tmp/")):
                score += 10
            if zone_tone == "ok" and "valid" in sl:
                score -= 10
            score = max(0, min(100, score))
            if score >= 70:
                risk_label, risk_tone, risk_bucket = "CRITICAL", "crit", "critical"
            elif score >= 45:
                risk_label, risk_tone, risk_bucket = "HIGH", "warn", "high"
            elif score >= 20:
                risk_label, risk_tone, risk_bucket = "MEDIUM", "warn", "medium"
            else:
                risk_label, risk_tone, risk_bucket = "LOW", "ok", "low"
            risk_counts[risk_bucket] = risk_counts.get(risk_bucket, 0) + 1

            cells = [
                f"{score:>3d} · {risk_label}",
                str(item.get("name", "")),
                slug.replace("_", " ").title(),
                mitre,
                signer or "unsigned",
                sha_short,
                zone_label,
                created_display,
                str(item.get("path", "")),
            ]
            for c, value in enumerate(cells):
                cell = QTableWidgetItem(value)
                table.setItem(r, c, cell)
            # Anchor the source record on the row itself. Column sorting
            # reorders rows but not `filtered_persistence_items`, so
            # resolving the selection by `currentRow()` index would act
            # on the wrong (possibly destructive) entry after a sort.
            # Qt keeps item data with the item across sorts.
            anchor_cell = table.item(r, 0)
            if anchor_cell is not None:
                anchor_cell.setData(Qt.UserRole, item)
            # Tone-code Risk column (0).
            risk_cell = table.item(r, 0)
            if risk_cell is not None:
                colour = {"ok": "#9ae6b4", "warn": "#f6e05e", "crit": "#feb2b2"}.get(risk_tone, "#cbd5e0")
                risk_cell.setForeground(QColor(colour))
                rf = risk_cell.font(); rf.setBold(True); risk_cell.setFont(rf)
            # Tone-code Path Zone cell (column 6 - shifted from 5).
            zone_cell = table.item(r, 6)
            if zone_cell is not None:
                tone_colour = {"ok": "#9ae6b4", "warn": "#f6e05e", "crit": "#feb2b2"}.get(zone_tone, "#cbd5e0")
                zone_cell.setForeground(QColor(tone_colour))
                zf = zone_cell.font(); zf.setBold(True); zone_cell.setFont(zf)
            # Signer cell tone (column 4 - shifted from 3).
            signer_cell = table.item(r, 4)
            if signer_cell is not None:
                if not signer or "unsigned" in sl or "invalid" in sl or "broken" in sl:
                    signer_cell.setForeground(QColor("#feb2b2"))
                elif "valid" in sl or "trusted" in sl:
                    signer_cell.setForeground(QColor("#9ae6b4"))
            # Heuristic row tint kept for the legacy markers.
            if zone_tone != "crit" and any(
                token in risk_text for token in ("runonce", "powershell", "temp", "appdata", "startup")
            ):
                app._paint_row(table, r, QColor("#3a2e18"))

        # Push aggregate counters into the KPI strip.
        try:
            chips = getattr(self, "_persist_kpis", None) or {}
            total = len(items)
            critical = risk_counts.get("critical", 0)
            chips["total"].update(str(total), "ok" if total else "neutral", "post-filter")
            chips["critical"].update(
                str(critical),
                "ok" if critical == 0 else ("warn" if critical < 3 else "crit"),
                "risk ≥ 70",
            )
            chips["unsigned"].update(
                str(unsigned_count),
                "ok" if unsigned_count == 0 else ("warn" if unsigned_count < 5 else "crit"),
                "trust gap",
            )
            chips["user_writable"].update(
                str(user_writable_count),
                "ok" if user_writable_count == 0 else ("warn" if user_writable_count < 3 else "crit"),
                "AppData / Public / Temp",
            )
            chips["recent_24h"].update(
                str(recent_count),
                "ok" if recent_count == 0 else "warn",
                "created in the last day",
            )
        except (AttributeError, KeyError):
            pass
        try:
            table.setSortingEnabled(True)
        except AttributeError:
            pass

        if not items:
            state = (
                "No persistence items matched the active filters."
                if filt or len(active_types) < len(self._persist_type_chips)
                else "No persistence entries were returned by the backend."
            )
            app.persist_detail.setPlainText(state)
        else:
            app.persist_detail.setPlainText(
                f"Showing {len(items)} persistence items."
                + (f"\nActive filter: {filt}" if filt else "")
                + (f"\nTypes: {', '.join(sorted(active_types))}" if len(active_types) < len(self._persist_type_chips) else "")
                + "\n\nSelect a row to inspect full details and decide whether remediation is justified."
            )

    def show_selected_persistence(self) -> None:
        app = self.app
        row = app.persist_table.currentRow()
        if row < 0: return
        # Resolve via the row anchor (sort-safe), same as the destructive
        # path — indexing filtered_persistence_items by currentRow() would
        # show a different entry after the operator sorts a column.
        detail = self._selected_persistence_record() or {}
        if not detail:
            detail = {}
            for c, key in enumerate(["name","type","path","details"]):
                item = app.persist_table.item(row, c); detail[key] = item.text() if item else ""
        app.persist_detail.setPlainText(json.dumps(detail, indent=2))

    # P0 forensic sudo window — analyst must have refreshed (proof of
    # live session) within 5 minutes before destructive remediation.
    PERSISTENCE_SUDO_WINDOW_SECONDS = 5 * 60

    def _persistence_sudo_required(self) -> bool:
        last = getattr(self, "_persist_last_remediation_check", 0.0)
        return (time.time() - float(last or 0)) >= self.PERSISTENCE_SUDO_WINDOW_SECONDS

    def remediate_selected_persistence(self) -> None:
        app = self.app
        row = app.persist_table.currentRow()
        if row < 0:
            app.statusBar().showMessage("Select a persistence row first.")
            return
        if not self._check_action_gate("persistence-remediate"):
            return
        # Pull the rich record - schema is Risk / Name / Type / MITRE /
        # Signer / SHA-256 / Path Zone / Created / Path. Path lives in
        # column 8, Name in 1. Read by index so legacy 4-column callers
        # still resolve to something sensible.
        def _cell(c: int) -> str:
            item = app.persist_table.item(row, c)
            return item.text() if item is not None else ""
        cols = app.persist_table.columnCount()
        if cols >= 9:
            name      = _cell(1)
            item_type = _cell(2)
            signer    = _cell(4)
            zone      = _cell(6)
            path      = _cell(8)
        else:  # legacy 4-column layout
            name = _cell(0); item_type = _cell(1); path = _cell(2); signer = ""; zone = ""

        # The Type column shows a UI-derived classification label
        # ("Registry", "Service", ...). The backend enum only accepts the
        # scanner's verbatim type ("Registry Run Key", "Windows Service",
        # ...), so sending the cell label 422s every Registry/Service/
        # Driver/WMI remediation. Resolve the authoritative record (row-
        # anchored, sort-safe) and use its real type/path/name.
        record = self._selected_persistence_record()
        _label_to_enum = {
            "registry": "Registry Run Key",
            "scheduled task": "Scheduled Task",
            "scheduled_task": "Scheduled Task",
            "service": "Windows Service",
            "startup folder": "Startup Folder",
            "startup_folder": "Startup Folder",
        }
        if isinstance(record, dict):
            name = str(record.get("name") or name)
            path = str(record.get("path") or path)
            server_type = str(record.get("type") or "").strip()
            item_type = server_type or _label_to_enum.get(item_type.strip().lower(), item_type)
        else:
            item_type = _label_to_enum.get(item_type.strip().lower(), item_type)

        # Sudo gate - block destructive action on stale sessions.
        if self._persistence_sudo_required():
            warn = QMessageBox(app)
            warn.setWindowTitle("Sudo window expired")
            warn.setIcon(QMessageBox.Warning)
            warn.setText("Refresh Persistence first to renew the sudo window.")
            warn.setInformativeText(
                "Destructive persistence actions require a refresh within the last 5 minutes "
                "so an attended session is verifiable. Click OK to refresh, then re-issue the "
                "remediation."
            )
            warn.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            if warn.exec() == QMessageBox.Ok:
                self.refresh_persistence()
            return

        confirm = QMessageBox(app)
        confirm.setWindowTitle("Confirm persistence remediation")
        confirm.setIcon(QMessageBox.Critical)
        # Name/path/signer are attacker-controlled (a malicious autorun
        # picks its own strings). QMessageBox auto-renders rich text, so
        # unescaped markup here could spoof or hide the real target on
        # the very dialog the analyst uses to authorise an irreversible
        # delete. Escape every interpolated value.
        confirm.setText(f"Remediate {html.escape(name)} ({html.escape(item_type)})?")
        info_lines = [
            f"<b>Path:</b> <code>{html.escape(path)}</code>",
            f"<b>Type:</b> {html.escape(item_type)}",
        ]
        if zone:
            info_lines.append(f"<b>Path zone:</b> {html.escape(zone)}")
        if signer:
            info_lines.append(f"<b>Signer:</b> {html.escape(signer)}")
        info_lines.extend([
            "",
            "<b>This will delete the registry value / scheduled task / service entry</b>",
            "from the host. A backup of the raw payload is written to <code>shadowlab_out/</code>",
            "before the delete is issued so the change can be replayed by hand.",
            "",
            "A structured reason will be required next for the audit chain.",
        ])
        confirm.setInformativeText("<br>".join(info_lines))
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        # Backup-before-delete - always write a JSON record under
        # shadowlab_out/ so the analyst has a reference if they need to
        # restore the entry by hand. Reuse the record resolved above so
        # the backup matches the entry actually being deleted.
        if not isinstance(record, dict) or not record:
            record = {"name": name, "type": item_type, "path": path}
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        try:
            from pathlib import Path as _Path
            backup_dir = _Path.cwd() / "shadowlab_out" / "persistence_backups"
            backup_dir.mkdir(parents=True, exist_ok=True)
            safe_name = "".join(ch for ch in name if ch.isalnum() or ch in {"-", "_"}) or "entry"
            backup_path = backup_dir / f"{int(time.time())}_{safe_name}.json"
            with backup_path.open("w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "backed_up_at": time.time(),
                        "entry": _redact(record),
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            app.statusBar().showMessage(f"Pre-delete backup: {backup_path}", 6000)
        except Exception:
            # Backup failure must not silently stop the destructive
            # path - the operator already confirmed - but we surface
            # the error so they know there's no rollback file.
            app.statusBar().showMessage("⚠ Pre-delete backup failed - proceeding without rollback file.", 6000)
        # Persistence delete is not reversible — capture a ticket so
        # the SOC can audit which autorun was removed and why.
        reason = self._capture_reason(f"persistence-remediate ({item_type})")
        if reason is None:
            return
        try:
            result = app._post(
                "/persistence/remediate",
                json={
                    "item_type": item_type,
                    "path": path,
                    "name": name,
                    "reason": {
                        "ticket_id": reason["ticket_id"],
                        "category": reason["reason_category"],
                        "text": reason["reason_text"],
                    },
                },
                timeout=40,
            ).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        self._record_audit(
            category="persistence",
            action="remediate",
            target=f"{name} [{item_type}] {path}",
            severity="high",
            status="ok" if ok else "failed",
            payload={"item": {"name": name, "type": item_type, "path": path}, "response": result},
            reason=reason,
        )
        if not ok:
            app._show_error(app.persist_detail, "Persistence remediation failed", Exception(error))
            return
        app._show_json(app.persist_detail, result)
        self.refresh_persistence()

    def lookup_hash(self) -> None:
        app = self.app
        if not app.hash_input.text().strip(): return
        # P1: per-action debounce. External provider quotas are tight
        # (VirusTotal: 4 req/min on free tier). Without a debounce a
        # spam click sequence trips the rate limit and bans the key
        # for an hour.
        if not self._check_action_gate("threat-lookup-hash"):
            return
        payload = {
            "file_hash": app.hash_input.text().strip(),
            "virustotal_api_key": app.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": app.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": app.yaraify_key.text().strip() or None,
        }
        if not any([payload["virustotal_api_key"], payload["malwarebazaar_auth_key"], payload["yaraify_auth_key"]]):
            app.statusBar().showMessage("Enter at least one hash lookup API key")
            return
        try: result = app._post("/threat-intel/hash/lookup", json=payload).json()
        except Exception as exc: app._show_error(app.threat_out, "Hash lookup failed", exc); return
        app._show_json(app.threat_out, result)
        self.record_threat_history("hash", app.hash_input.text().strip(), "MalwareBazaar + YARAify + VirusTotal", result)
        app._switch_to_tab("Threat Intel")

    def malware_empty_state_html(self, title: str, body: str, *, accent: str = "#7fd7ff") -> str:
        # Tall empty-state body that fills the File Posture panel
        # instead of showing a tiny card at the top with white space
        # below. Includes a quick-start checklist + shortcut legend so
        # the analyst always sees something useful while no sample is
        # loaded.
        steps = (
            ("1. Intake", "Drag-drop a sample, paste a path, or click Browse / Use Process."),
            ("2. Analyze", "Click Analyze File for an on-disk binary or Analyze EXE for the selected live process."),
            ("3. Inspect", "Switch through Evidence, Imports, Strings, Raw, and Providers to triage."),
            ("4. Decide",  "Mark Benign clears the sample; Mark Suspicious escalates and requires a structured reason."),
            ("5. Export",  "Export JSON saves a forensic bundle — destination is sanity-checked against system folders."),
        )
        steps_html = "".join(
            f"<tr><td style='color:{accent};font-weight:800;padding:4px 10px 4px 0;white-space:nowrap;'>{html.escape(step_title)}</td>"
            f"<td style='color:#c8d8ea;padding:4px 0;'>{html.escape(step_body)}</td></tr>"
            for step_title, step_body in steps
        )
        shortcuts = (
            ("Ctrl+O", "Browse for a file"),
            ("Ctrl+Enter", "Analyze File"),
            ("Ctrl+B", "Mark Benign"),
            ("Ctrl+Shift+S", "Mark Suspicious"),
            ("Ctrl+E", "Export JSON"),
            ("Ctrl+R", "Refresh DIE readiness"),
        )
        shortcut_chips = "".join(
            f"<span style='display:inline-block;border:1px solid #243446;border-radius:6px;"
            f"padding:3px 8px;margin:3px;color:#c8d8ea;background:#0e1720;font-size:11px;'>"
            f"<b style='color:{accent};font-family:Consolas,monospace;'>{html.escape(key)}</b> "
            f"<span style='color:#96a5b8;'>· {html.escape(desc)}</span>"
            "</span>"
            for key, desc in shortcuts
        )
        return (
            "<div style='padding:8px;'>"
            f"<div style='border:1px solid #243446;border-radius:9px;padding:14px;background:#101a24;margin-bottom:10px;'>"
            f"<h3 style='margin:0 0 6px;color:{accent};font-size:15px;'>{html.escape(title)}</h3>"
            f"<p style='margin:0;color:#96a5b8;font-size:12px;'>{html.escape(body)}</p>"
            "</div>"
            "<div style='border:1px solid #243446;border-radius:9px;padding:14px;background:#0e1720;margin-bottom:10px;'>"
            "<h4 style='margin:0 0 8px;color:#c8d8ea;font-size:12px;letter-spacing:0.4px;'>WORKFLOW</h4>"
            "<table style='border-collapse:collapse;font-size:12px;width:100%;'>"
            f"{steps_html}"
            "</table>"
            "</div>"
            "<div style='border:1px solid #243446;border-radius:9px;padding:14px;background:#0e1720;'>"
            "<h4 style='margin:0 0 6px;color:#c8d8ea;font-size:12px;letter-spacing:0.4px;'>KEYBOARD SHORTCUTS</h4>"
            f"<div>{shortcut_chips}</div>"
            "</div>"
            "</div>"
        )

    def malware_provider_readiness_html(self, status: dict) -> str:
        die_state = str(status.get("status") or "unknown")
        backend = str(status.get("backend") or "local")
        inventory = status.get("signature_inventory", {}) if isinstance(status.get("signature_inventory"), dict) else {}
        rows = [
            ("Detect It Easy", die_state, backend, "packer/toolchain/filetype signatures",
             "Static identification of packers, compilers, linkers, and file-type families. Drives the DIE matches surfaced in the Decision tab."),
            ("PE structural analyzer", "ready", "pefile", "headers, sections, imports, resources",
             "Header/section anomalies, suspicious section names, overlay detection, import-table classification, and resource walking."),
            ("Local YARA", "ready", "local", "rule pack available through Security Ops",
             "On-disk YARA rule pack maintained via Security Ops. Matches surface in High-Signal Findings under category=`yara`."),
            ("YARAify / VT / MalwareBazaar", "on demand", "intel", "available from Threat Intel/Process enrichment when keys exist",
             "Cloud reputation providers — populate keys in Primary Controls and the Decision tab will fold their verdicts into the fused score."),
        ]
        state_color = {"ready": "#7fe39d", "unknown": "#ffcf7a", "on demand": "#7fd7ff"}
        table_rows = "".join(
            "<tr>"
            f"<td style='padding:8px 10px;'><b style='color:#eef4fb;'>{html.escape(name)}</b></td>"
            f"<td style='padding:8px 10px;'><span style='color:{state_color.get(state.lower(), '#c8d8ea')};font-weight:800;'>{html.escape(state)}</span></td>"
            f"<td style='padding:8px 10px;color:#c8d8ea;'>{html.escape(source)}</td>"
            f"<td style='padding:8px 10px;color:#c8d8ea;'>{html.escape(signal)}</td>"
            "</tr>"
            f"<tr><td colspan='4' style='padding:0 10px 10px;color:#96a5b8;font-size:11px;border-bottom:1px solid #1a2a3d;'>{html.escape(detail)}</td></tr>"
            for name, state, source, signal, detail in rows
        )
        # Inventory KPI strip — replaces the small bottom paragraph so
        # the Providers panel actually fills the available height
        # instead of leaving big empty space below the table.
        kpi_html = (
            "<table width='100%' style='border-collapse:separate;border-spacing:6px;margin-top:10px;'><tr>"
            f"<td style='border:1px solid #243446;border-radius:8px;padding:10px;background:#0e1720;'>"
            f"<div style='color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;'>DIE DB SIGNATURES</div>"
            f"<div style='color:#7fd7ff;font-size:18px;font-weight:800;margin-top:4px;'>{html.escape(str(inventory.get('db_signatures', 0)))}</div>"
            f"</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;padding:10px;background:#0e1720;'>"
            f"<div style='color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;'>PEID RULE FILES</div>"
            f"<div style='color:#bda4ff;font-size:18px;font-weight:800;margin-top:4px;'>{html.escape(str(inventory.get('peid_rule_files', 0)))}</div>"
            f"</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;padding:10px;background:#0e1720;'>"
            f"<div style='color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;'>YARA RULE FILES</div>"
            f"<div style='color:#7fe39d;font-size:18px;font-weight:800;margin-top:4px;'>{html.escape(str(inventory.get('yara_rule_files', 0)))}</div>"
            f"</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;padding:10px;background:#0e1720;'>"
            f"<div style='color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;'>RUNTIME BACKEND</div>"
            f"<div style='color:#ffcf7a;font-size:14px;font-weight:800;margin-top:4px;'>{html.escape(backend)}</div>"
            f"</td>"
            "</tr></table>"
        )
        # Operator guidance section — pulls `guidance` from the readiness
        # response if the backend supplied one, otherwise falls back to
        # a sensible default checklist so the panel never looks empty.
        guidance_items = status.get("guidance") if isinstance(status.get("guidance"), list) else []
        if not guidance_items:
            guidance_items = [
                "Configure VirusTotal / MalwareBazaar / YARAify keys in Primary Controls to enable the on-demand intel providers.",
                "Run Security Ops → YARA workflow to keep the local YARA rule pack current.",
                "Use Process / Analyze EXE pulls the on-disk image — the same path the engine analyses, not a clone.",
                "DIE 'unknown' is normal until you click Readiness once after a desktop launch.",
            ]
        guidance_html = "".join(
            f"<li style='margin:4px 0;color:#c8d8ea;'>{html.escape(str(item))}</li>"
            for item in guidance_items[:8]
        )
        return (
            "<div style='padding:8px;'>"
            "<h3 style='margin:0 0 10px;color:#eef4fb;font-size:14px;'>Provider Readiness</h3>"
            "<div style='border:1px solid #243446;border-radius:9px;background:#0e1720;padding:6px 0;'>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;font-size:10px;letter-spacing:0.4px;'>"
            "<th align='left' style='padding:8px 10px;'>PROVIDER</th>"
            "<th align='left' style='padding:8px 10px;'>STATE</th>"
            "<th align='left' style='padding:8px 10px;'>SOURCE</th>"
            "<th align='left' style='padding:8px 10px;'>SIGNAL</th>"
            "</tr>"
            + table_rows
            + "</table></div>"
            + kpi_html
            + "<div style='border:1px solid #243446;border-radius:9px;background:#0e1720;padding:12px 14px;margin-top:10px;'>"
            "<h4 style='margin:0 0 6px;color:#c8d8ea;font-size:11px;letter-spacing:0.4px;'>OPERATOR GUIDANCE</h4>"
            f"<ul style='margin:0;padding-left:18px;font-size:12px;'>{guidance_html}</ul>"
            "</div>"
            "</div>"
        )

    def malware_score_label(self, score: int) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"

    def lookup_ip(self) -> None:
        app = self.app
        if not app.ip_input.text().strip(): return
        # P1: per-action debounce — AbuseIPDB free tier is 1000/day
        # but enforces a per-second cap. Spam-click would trip it.
        if not self._check_action_gate("threat-lookup-ip"):
            return
        try: result = app._get(f"/threat-intel/ip/{app.ip_input.text().strip()}").json()
        except Exception as exc: app._show_error(app.threat_out, "IP lookup failed", exc); return
        app._show_json(app.threat_out, result)
        self.record_threat_history("ip", app.ip_input.text().strip(), "AbuseIPDB", result)
        app._switch_to_tab("Threat Intel")

    def use_selected_process_hash(self) -> None:
        app = self.app
        if not app.selected_process:
            app.statusBar().showMessage("First select a process to auto-fill its hash")
            return
        hash_value = app.selected_process.get("sha256") or ""
        app.hash_input.setText(hash_value)
        app.ti_last_type.setText("Last Query: process hash prepared")
        app.ti_last_value.setText(f"Value: {hash_value[:20]}..." if hash_value else "Value: unavailable")
        app.threat_out.setPlainText(f"Prepared process hash for lookup:\n{hash_value or 'unavailable'}")
        app._switch_to_tab("Threat Intel")

    def use_selected_process_ip(self) -> None:
        app = self.app
        if not app.selected_process:
            app.statusBar().showMessage("First select a process to auto-fill its remote IP")
            return
        connections = app.selected_process.get("network_connections") or []
        candidate = ""
        for connection in connections:
            if "->" in connection:
                right = connection.split("->", 1)[1]
                candidate = right.split(":")[0]
                break
        app.ip_input.setText(candidate)
        app.ti_last_type.setText("Last Query: process IP prepared")
        app.ti_last_value.setText(f"Value: {candidate or 'unavailable'}")
        app.threat_out.setPlainText(f"Prepared process IP for lookup:\n{candidate or 'unavailable'}")
        app._switch_to_tab("Threat Intel")

    def pick_malware_analyst_file(self) -> None:
        app = self.app
        file_path, _ = QFileDialog.getOpenFileName(app, "Select File for Detect It Easy Analysis")
        if file_path:
            app.ma_file_path.setText(file_path)

    def use_selected_process_for_malware_analysis(self) -> None:
        app = self.app
        if not app.selected_process:
            app.statusBar().showMessage("First select a process to prepare file analysis")
            return
        exe_path = str(app.selected_process.get("exe") or "")
        app.ma_file_path.setText(exe_path)
        app._switch_to_tab("File Analysis")
        app.statusBar().showMessage("Selected process executable copied into File Analysis workspace")

    def refresh_malware_analyst_status(self) -> None:
        app = self.app
        try:
            result = app._get("/malware-analyst/status", timeout=30).json()
        except Exception as exc:
            app._show_error(app.ma_output, "File Analysis status refresh failed", exc)
            return
        inventory = result.get("signature_inventory", {}) if isinstance(result, dict) else {}
        guidance = result.get("guidance", []) if isinstance(result.get("guidance", []), list) else []
        runtime_badge, runtime_location = app._malware_analyst_runtime_status(result)
        app.ma_status_badge.setText(f"DIE Status: {result.get('status', 'unknown')}")
        app.ma_repo_badge.setText(f"Repo: {'ready' if result.get('die_repo_path') else 'missing'}")
        app.ma_runtime_badge.setText(runtime_badge)
        app.ma_provider_badge.setText(f"Providers: DIE {result.get('status', 'unknown')} / PE ready")
        if hasattr(app, "ma_providers"):
            app.ma_providers.setHtml(self.malware_provider_readiness_html(result))
        if "File Analysis Decision" not in app.ma_summary.toPlainText():
            app.ma_summary.setHtml(
                "<h3>File Analysis Readiness</h3>"
                f"<p><b>Status:</b> {html.escape(str(result.get('status', 'unknown')))}"
                f"<br><b>MIT License:</b> {html.escape(str(result.get('mit_license_detected', False)))}"
                f"<br><b>Repo Path:</b> {html.escape(str(result.get('die_repo_path', '') or 'Not detected'))}"
                f"<br><b>Runtime Location:</b> {html.escape(runtime_location)}"
                f"<br><b>DB Signatures:</b> {html.escape(str(inventory.get('db_signatures', 0)))}"
                f"<br><b>PEiD Rule Files:</b> {html.escape(str(inventory.get('peid_rule_files', 0)))}"
                f"<br><b>YARA Rule Files:</b> {html.escape(str(inventory.get('yara_rule_files', 0)))}</p>"
                f"<p><b>Guidance:</b></p><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in guidance) or '<li>No guidance available.</li>'}</ul>"
            )
        if not app.ma_output.toPlainText().strip():
            app._show_json(app.ma_output, result)
        app.statusBar().showMessage("File Analysis readiness refreshed")

    def run_malware_analyst_file_scan(self) -> None:
        app = self.app
        file_path = app.ma_file_path.text().strip()
        if not file_path:
            app.statusBar().showMessage("Provide a file path for file analysis")
            app.ma_summary.setHtml(self.malware_empty_state_html("No file loaded", "Provide a file path before starting analysis.", accent="#f4c26b"))
            return
        if not self._check_action_gate("analyze-file"):
            return
        app.ma_summary.setHtml(self.malware_empty_state_html("Scanning file", "Static analysis is running on the worker thread; UI stays responsive.", accent="#7fd7ff"))
        self._submit_async_scan(
            label=f"file-analysis ({Path(file_path).name})",
            work=lambda: app._post("/malware-analyst/file", json={"file_path": file_path}, timeout=120).json(),
            on_success=lambda result: self.render_malware_analyst_result(result, source="file", value=file_path),
            on_failure=lambda message: (
                app._show_error(app.ma_output, "File Analysis file scan failed", Exception(message)),
                app.ma_summary.setHtml(self.malware_empty_state_html("Scan failed", message, accent="#ff8f70")),
            ),
            timeout_seconds=140,
        )

    def run_malware_analyst_process_scan(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, name = ident
        if not self._check_action_gate("analyze-exe"):
            return
        app.ma_summary.setHtml(self.malware_empty_state_html("Scanning executable", f"Static analysis is running for {name} ({pid}) on the worker thread.", accent="#7fd7ff"))
        self._submit_async_scan(
            label=f"file-analysis (PID {pid})",
            work=lambda: app._get(f"/malware-analyst/processes/{pid}", timeout=120).json(),
            on_success=lambda result: self.render_malware_analyst_result(result, source="process executable", value=f"{name} ({pid})"),
            on_failure=lambda message: (
                app._show_error(app.ma_output, "File Analysis process scan failed", Exception(message)),
                app.ma_summary.setHtml(self.malware_empty_state_html("Scan failed", message, accent="#ff8f70")),
            ),
            timeout_seconds=140,
        )

    def _submit_async_scan(
        self,
        *,
        label: str,
        work,
        on_success,
        on_failure,
        timeout_seconds: int = 140,
    ) -> None:
        """Light-weight QThread+Worker for file analysis backend calls.

        File analysis can take 60-120s for large binaries (DIE +
        PE-structure + YARA + import classification). Without this,
        the UI freezes for the full duration. Each call gets its own
        thread + watchdog.
        """
        app = self.app
        thread = QThread(app)
        worker = _FileAnalysisWorker(work)
        worker.moveToThread(thread)
        finished = {"value": False}

        def cleanup() -> None:
            try:
                self._async_jobs.remove((thread, worker))
            except ValueError:
                pass
            thread.quit()
            thread.wait(2000)
            worker.deleteLater()
            thread.deleteLater()

        def handle_success(result) -> None:
            if finished["value"]:
                return
            finished["value"] = True
            try:
                on_success(result)
            finally:
                cleanup()

        def handle_failure(message: str) -> None:
            if finished["value"]:
                return
            finished["value"] = True
            try:
                on_failure(message)
            finally:
                cleanup()

        def watchdog() -> None:
            if finished["value"]:
                return
            finished["value"] = True
            app.statusBar().showMessage(f"{label} timed out after {timeout_seconds}s.")
            cleanup()

        thread.started.connect(worker.run)
        worker.finished.connect(handle_success)
        worker.failed.connect(handle_failure)
        self._async_jobs.append((thread, worker))
        QTimer.singleShot(int(max(1, timeout_seconds)) * 1000, watchdog)
        thread.start()

    def render_malware_analyst_result(self, result: dict, *, source: str, value: str) -> None:
        app = self.app
        die = result.get("die", {}) if isinstance(result.get("die"), dict) else {}
        highlights = result.get("highlights", []) if isinstance(result.get("highlights", []), list) else []
        process = result.get("process", {}) if isinstance(result.get("process"), dict) else {}
        static_analysis = result.get("static_analysis", {}) if isinstance(result.get("static_analysis"), dict) else {}
        combined_static = result.get("combined_static", {}) if isinstance(result.get("combined_static"), dict) else {}
        pe_structure = result.get("pe_structure", {}) if isinstance(result.get("pe_structure"), dict) else {}
        evidence = result.get("evidence", {}) if isinstance(result.get("evidence"), dict) else {}
        decision = result.get("decision", {}) if isinstance(result.get("decision"), dict) else {}
        imports_by_category = result.get("import_categories", {}) if isinstance(result.get("import_categories"), dict) else {}
        string_indicators = result.get("string_indicators", {}) if isinstance(result.get("string_indicators"), dict) else {}
        score = int(combined_static.get("score", static_analysis.get("score", 0)) or 0)
        label = str(combined_static.get("severity") or self.malware_score_label(score))
        suspicious_indicators = static_analysis.get("suspicious_indicators", []) if isinstance(static_analysis.get("suspicious_indicators"), list) else []
        runtime_badge, runtime_location = app._malware_analyst_runtime_status(die)
        app.ma_last_result = result
        # Update loaded-file badges + sample history. The badges live
        # in the path strip, the history list lives in the left rail —
        # both stay in sync with the latest analysis without forcing
        # the operator to scroll back up to the top.
        sha = str(result.get("file_sha256") or result.get("sha256") or evidence.get("sha256") or "")
        path_value = str(result.get("file_path") or value or "")
        analyst_decision = result.get("analyst_decision", {}) if isinstance(result.get("analyst_decision"), dict) else {}
        decision_label = str(analyst_decision.get("decision") or "")
        if hasattr(app, "ma_loaded_badge"):
            app.ma_loaded_badge.setText(f"Loaded: {Path(path_value).name or '—'}")
        if hasattr(app, "ma_loaded_hash"):
            preview = (sha[:18] + "…") if len(sha) > 20 else (sha or "—")
            app.ma_loaded_hash.setText(f"SHA-256: {preview}")
        if hasattr(app, "ma_loaded_decision"):
            app.ma_loaded_decision.setText(f"Decision: {decision_label.upper() or '—'}")
        # Record in sample history once per (sha256, decision) tuple —
        # `_record_sample_in_history` deduplicates by SHA so re-running
        # analysis bumps the row to the top instead of duplicating.
        try:
            self._record_sample_in_history(
                path=path_value,
                sha256=sha,
                label=label,
                score=score,
                decision=decision_label,
            )
        except Exception:
            pass
        # Audit the analysis run itself (non-decision) so a SOC manager
        # can grep the chain for "who scanned which sample when". No
        # reason required — analysis is read-only on the host.
        try:
            self._record_audit(
                category="file-analysis",
                action="scan",
                target=f"sha256={sha or 'unknown'} path={Path(path_value).name}",
                severity="low",
                status="ok",
                payload={"source": source, "label": label, "score": score, "value": value},
            )
        except Exception:
            pass
        finding_rows = self.malware_finding_rows(result)
        app.ma_highlights.setRowCount(len(finding_rows[:24]))
        for row, item in enumerate(finding_rows[:24]):
            for col, key in enumerate(["signal", "category", "severity", "detail"]):
                app.ma_highlights.setItem(row, col, QTableWidgetItem(str(item.get(key, ""))))
        app.ma_summary.setHtml(
            "<h3>File Analysis Decision</h3>"
            f"<p><b>Source:</b> {html.escape(source)}"
            f"<br><b>Value:</b> {html.escape(value)}"
            f"<br><b>Analysis Scope:</b> {html.escape('On-disk executable image' if source == 'process executable' else 'Selected file on disk')}"
            f"<br><b>Status:</b> {html.escape(str(result.get('status', 'unknown')))}"
            f"<br><b>Summary:</b> {html.escape(str(result.get('summary', '')))}"
            f"<br><b>Static Verdict:</b> {html.escape(str(static_analysis.get('verdict', 'unknown')))}"
            f"<br><b>Severity:</b> {html.escape(label.upper())}"
            f"<br><b>Score:</b> {score}"
            f"<br><b>PE Structure Score:</b> {html.escape(str(pe_structure.get('risk', {}).get('score', 0) if isinstance(pe_structure.get('risk'), dict) else 0))}"
            f"<br><b>DIE Runtime:</b> {html.escape(runtime_location)}"
            f"<br><b>Recommended action:</b> {html.escape(str(decision.get('recommended_action', 'review')))}</p>"
            f"<p><b>Operator Note:</b> This result is based on static file evidence, not live memory behavior.</p>"
            f"{'<p><b>Process:</b> ' + html.escape(str(process.get('name', ''))) + ' | <b>SHA256:</b> ' + html.escape(str(process.get('sha256', '') or 'n/a')) + '</p>' if process else ''}"
            f"<p><b>Highlights:</b> {html.escape(str(len(finding_rows)))}"
            f"<br><b>Reasoning:</b> {html.escape('; '.join(str(item) for item in decision.get('reasons', [])[:5]) if isinstance(decision.get('reasons'), list) else 'Review evidence tabs.')}</p>"
        )
        app.ma_evidence.setHtml(self.render_malware_evidence_html(result, evidence, pe_structure))
        app.ma_imports.setHtml(self.render_import_categories_html(imports_by_category))
        app.ma_strings.setHtml(self.render_string_categories_html(string_indicators))
        app.ma_providers.setHtml(self.malware_provider_readiness_html(die))
        app._show_json(app.ma_output, result)
        app.ma_status_badge.setText(f"DIE Status: {die.get('status', result.get('status', 'unknown'))}")
        app.ma_repo_badge.setText(f"Repo: {'ready' if die.get('die_repo_path') else 'missing'}")
        app.ma_runtime_badge.setText(runtime_badge)
        app.ma_provider_badge.setText(f"Providers: DIE {die.get('status', 'unknown')} / PE {pe_structure.get('status', 'unknown')}")
        self.record_threat_history("malware-analyst", value, "Detect It Easy", result)
        app._switch_to_tab("File Analysis")

    def malware_finding_rows(self, result: dict) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for item in result.get("highlights", []) or []:
            if isinstance(item, dict):
                rows.append({"signal": "DIE", "category": str(item.get("category", "")), "severity": "info", "detail": str(item.get("text", ""))})
        static_analysis = result.get("static_analysis", {}) if isinstance(result.get("static_analysis"), dict) else {}
        for item in static_analysis.get("suspicious_indicators", []) or []:
            rows.append({"signal": "Static", "category": "indicator", "severity": str(static_analysis.get("severity", "medium")), "detail": str(item)})
        pe_structure = result.get("pe_structure", {}) if isinstance(result.get("pe_structure"), dict) else {}
        pe_risk = pe_structure.get("risk", {}) if isinstance(pe_structure.get("risk"), dict) else {}
        for item in pe_risk.get("reasons", []) or []:
            rows.append({"signal": "PE", "category": "structure", "severity": str(pe_risk.get("severity", "medium")), "detail": str(item)})
        decision = result.get("decision", {}) if isinstance(result.get("decision"), dict) else {}
        for item in decision.get("reasons", []) or []:
            rows.append({"signal": "Decision", "category": "workflow", "severity": str(decision.get("severity", "low")), "detail": str(item)})
        return rows

    def render_malware_evidence_html(self, result: dict, evidence: dict, pe_structure: dict) -> str:
        headers = pe_structure.get("headers", {}) if isinstance(pe_structure.get("headers"), dict) else {}
        overlay = pe_structure.get("overlay", {}) if isinstance(pe_structure.get("overlay"), dict) else {}
        signature = pe_structure.get("signature", {}) if isinstance(pe_structure.get("signature"), dict) else {}
        sections = pe_structure.get("sections", []) if isinstance(pe_structure.get("sections"), list) else []
        section_rows = "".join(
            f"<tr><td>{html.escape(str(sec.get('name','')))}</td><td>{html.escape(str(sec.get('entropy','')))}</td><td>{html.escape(str(sec.get('raw_size','')))}</td><td>{'RWX' if sec.get('rwx') else ''}</td></tr>"
            for sec in sections[:12]
            if isinstance(sec, dict)
        )
        return (
            "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Evidence Detail</h3>"
            f"<p style='color:#c8d8ea;'><b>File:</b> {html.escape(str(result.get('file_path', evidence.get('file_path',''))))}<br>"
            f"<b>SHA256:</b> {html.escape(str(evidence.get('sha256', 'n/a')))}<br>"
            f"<b>Size:</b> {html.escape(str(evidence.get('size', 'n/a')))} bytes | <b>Type:</b> {html.escape(str(evidence.get('file_type', 'n/a')))}<br>"
            f"<b>Machine:</b> {html.escape(str(headers.get('machine','n/a')))} | <b>Subsystem:</b> {html.escape(str(headers.get('subsystem','n/a')))} | <b>Entrypoint:</b> {html.escape(str(headers.get('entry_point','n/a')))}<br>"
            f"<b>Imphash:</b> {html.escape(str(headers.get('imphash','n/a')))}<br>"
            f"<b>Signature:</b> {html.escape(str(signature.get('status','unknown')))} | <b>Signer:</b> {html.escape(str(signature.get('signer_subject','')))}<br>"
            f"<b>Overlay:</b> {html.escape(str(overlay.get('size', 0)))} bytes</p>"
            "<table width='100%' cellspacing='0' cellpadding='5' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Section</th><th align='left'>Entropy</th><th align='left'>Raw Size</th><th align='left'>Flags</th></tr>"
            + section_rows
            + "</table>"
        )

    def render_import_categories_html(self, categories: dict) -> str:
        if not categories:
            return self.malware_empty_state_html("No import categories", "The sample did not expose categorized imports or PE parsing was unavailable.")
        blocks = []
        for category, values in categories.items():
            if not values:
                continue
            items = "".join(f"<li>{html.escape(str(item))}</li>" for item in list(values)[:18])
            blocks.append(f"<h4 style='color:#7fd7ff;margin:8px 0 3px;'>{html.escape(str(category).title())}</h4><ul>{items}</ul>")
        return "".join(blocks) or self.malware_empty_state_html("No suspicious imports", "No high-signal import category matched.")

    def render_string_categories_html(self, categories: dict) -> str:
        if not categories:
            return self.malware_empty_state_html("No string categories", "No high-signal strings were extracted.")
        blocks = []
        for category, values in categories.items():
            if not values:
                continue
            items = "".join(f"<li>{html.escape(str(item)[:220])}</li>" for item in list(values)[:18])
            blocks.append(f"<h4 style='color:#ffcf7a;margin:8px 0 3px;'>{html.escape(str(category).title())}</h4><ul>{items}</ul>")
        return "".join(blocks) or self.malware_empty_state_html("No high-signal strings", "Strings were extracted but no suspicious category matched.")

    def mark_malware_analysis_decision(self, decision: str) -> None:
        app = self.app
        result = getattr(app, "ma_last_result", {}) or {}
        if not result:
            app.statusBar().showMessage("Run file analysis before marking a decision.")
            app.ma_summary.setHtml(self.malware_empty_state_html("No analysis to mark", "Run analysis first, then mark the sample benign or suspicious.", accent="#f4c26b"))
            return
        decision = str(decision or "").lower().strip()
        if decision not in {"benign", "suspicious"}:
            app.statusBar().showMessage(f"Decision `{decision}` is not in the allowlist.")
            return
        if not self._check_action_gate(f"decision:{decision}"):
            return

        previous_decision = ""
        previous = result.get("analyst_decision") if isinstance(result.get("analyst_decision"), dict) else {}
        if previous:
            previous_decision = str(previous.get("decision") or "")

        # Marking a sample SUSPICIOUS escalates triage — capture a
        # structured reason. Marking BENIGN is a clearance decision and
        # is audited but doesn't require a ticket.
        reason: dict | None = None
        if decision in DECISION_REQUIRES_REASON:
            reason = self._capture_reason(f"file-decision:{decision}")
            if reason is None:
                return
        elif previous_decision == "suspicious" and decision == "benign":
            # Downgrading a previously suspicious classification IS an
            # escalation event in the other direction — also gate on
            # structured reason so a colleague can't silently overturn
            # an incident-confirmed flag.
            reason = self._capture_reason("file-decision:downgrade-to-benign")
            if reason is None:
                return

        actor, _ws = actor_workspace_pair(app)
        # P0 fix: previous code wrote `"time": "local"` (literal string,
        # not a timestamp) and dropped the actor. Real ISO timestamp +
        # tz + actor now go into the result so the on-disk JSON record
        # is forensically sound.
        decision_record = {
            "decision": decision,
            "source": "desktop",
            "actor": actor,
            "ts": datetime.now().astimezone().strftime("%Y-%m-%dT%H:%M:%S%z"),
            "previous_decision": previous_decision or None,
        }
        if reason:
            decision_record["ticket_id"] = reason["ticket_id"]
            decision_record["reason_category"] = reason["reason_category"]
            decision_record["reason_text"] = reason["reason_text"]
        result["analyst_decision"] = decision_record
        app.ma_last_result = result

        sha = str(result.get("file_sha256") or result.get("sha256") or "")
        path = str(result.get("file_path") or "current sample")
        score = int(result.get("combined_static", {}).get("score", 0) or 0) if isinstance(result.get("combined_static"), dict) else 0
        severity = "high" if decision == "suspicious" else "medium"
        self._record_audit(
            category="file-analysis",
            action=f"decision:{decision}",
            target=f"sha256={sha or 'unknown'} path={Path(path).name}",
            severity=severity,
            status="ok",
            payload={
                "decision": decision_record,
                "score": score,
                "previous_decision": previous_decision,
            },
            reason=reason,
        )
        # Mirror into sample history so the operator sees the new decision
        # on the left rail without re-running analysis.
        label = str(result.get("combined_static", {}).get("severity", "unknown") or "unknown") if isinstance(result.get("combined_static"), dict) else "unknown"
        self._record_sample_in_history(path=path, sha256=sha, label=label, score=score, decision=decision)

        app.statusBar().showMessage(f"File analysis marked {decision} (audited).")
        self.render_malware_analyst_result(result, source="analyst decision", value=path)

    def export_malware_analysis_json(self) -> None:
        app = self.app
        result = getattr(app, "ma_last_result", {}) or {}
        if not result:
            app.statusBar().showMessage("Run file analysis before exporting.")
            return
        if not self._check_action_gate("export-json"):
            return
        file_path, _ = QFileDialog.getSaveFileName(app, "Export File Analysis JSON", "shadowlab-file-analysis.json", "JSON Files (*.json)")
        if not file_path:
            return
        # P0 export-destination guard. Resolve the REAL path first so
        # `..` traversal and 8.3 short names cannot bypass the check,
        # then refuse the entire Windows tree, Program Files, and any
        # Startup folder (a renamed .json/.bat/.lnk dropped there is a
        # logon-persistence / overwrite hazard).
        try:
            dest_resolved = Path(file_path).resolve()
        except Exception:
            dest_resolved = Path(file_path)
        dest_lower = str(dest_resolved).lower().replace("/", "\\")
        system_root = str(
            Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        ).lower().replace("/", "\\")
        blocked_prefixes = [
            system_root + "\\",
            os.environ.get("ProgramFiles", r"C:\Program Files").lower().replace("/", "\\") + "\\",
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().replace("/", "\\") + "\\",
        ]
        if any(dest_lower.startswith(p) for p in blocked_prefixes) or "\\start menu\\programs\\startup\\" in dest_lower:
            app._show_error(
                app.ma_output,
                "Export destination blocked",
                Exception(f"Refusing to write file analysis JSON into a Windows system folder: {file_path}"),
            )
            self._record_audit(
                category="file-analysis",
                action="export-json",
                target=str(file_path),
                severity="medium",
                status="blocked",
                payload={"reason": "export-destination-guard"},
            )
            return
        # Exporting moves sensitive metadata (hashes, signers, command
        # extraction) off the appliance — capture a structured reason
        # so the chain-of-custody is intact.
        reason = self._capture_reason("export-json")
        if reason is None:
            return
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        try:
            with open(file_path, "w", encoding="utf-8") as handle:
                # Match the in-UI Raw tab: never let provider keys / tokens
                # folded into the backend result leave the appliance.
                json.dump(_redact(result), handle, indent=2, ensure_ascii=False)
            ok = True
            error = ""
        except Exception as exc:
            ok = False
            error = str(exc)
        sha = str(result.get("file_sha256") or result.get("sha256") or "")
        self._record_audit(
            category="file-analysis",
            action="export-json",
            target=f"sha256={sha or 'unknown'} dest={file_path}",
            severity="medium",
            status="ok" if ok else "failed",
            payload={"destination": file_path, "error": error or None},
            reason=reason,
        )
        if not ok:
            app._show_error(app.ma_output, "File analysis export failed", Exception(error))
            return
        app.statusBar().showMessage(f"File analysis exported: {file_path}")

    def record_threat_history(self, query_type: str, value: str, source: str, payload) -> None:
        app = self.app
        app.threat_history.insert(0, {"type": query_type, "value": value, "source": source, "payload": json.dumps(payload, indent=2, ensure_ascii=False)})
        app.threat_history = app.threat_history[:20]
        self.refresh_threat_history_table()
        if hasattr(app, "ti_last_type"):
            app.ti_last_type.setText(f"Last Query: {query_type}")
        display_value = value if len(value) <= 28 else value[:28] + "..."
        if hasattr(app, "ti_last_value"):
            app.ti_last_value.setText(f"Value: {display_value}")
        if hasattr(app, "ti_last_source"):
            app.ti_last_source.setText(f"Source: {source}")

    def refresh_threat_history_table(self) -> None:
        app = self.app
        if not hasattr(app, "threat_history_table"):
            return
        app.threat_history_table.setRowCount(len(app.threat_history))
        for row, item in enumerate(app.threat_history):
            values = [item.get("type", ""), item.get("value", ""), item.get("source", "")]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                app.threat_history_table.setItem(row, col, cell)
            if item.get("type") == "process":
                app._paint_row(app.threat_history_table, row, QColor("#e0a640"))
            elif item.get("type") == "ip":
                app._paint_row(app.threat_history_table, row, QColor("#2f9e67"))

    def show_selected_threat_history(self) -> None:
        app = self.app
        if not hasattr(app, "threat_history_table"):
            return
        row = app.threat_history_table.currentRow()
        if row < 0 or row >= len(app.threat_history):
            return
        app.threat_out.setPlainText(app.threat_history[row].get("payload", ""))
