from __future__ import annotations

import html
import json
import time
from pathlib import Path

try:
    import artifacts_ops
except ImportError:
    from desktop import artifacts_ops

try:
    from _audit_log import AuditLogStore, actor_workspace_pair
except ImportError:  # pragma: no cover
    from desktop._audit_log import AuditLogStore, actor_workspace_pair

try:
    from _audit_mirror import install_backend_mirror as _install_audit_mirror
except ImportError:  # pragma: no cover
    from desktop._audit_mirror import install_backend_mirror as _install_audit_mirror

try:
    from _action_common import submit_async_call
except ImportError:  # pragma: no cover
    from desktop._action_common import submit_async_call

try:
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason

try:
    from _safe_paths import UnsafeArtifactPath, ensure_under_artifact_root
except ImportError:  # pragma: no cover
    from desktop._safe_paths import UnsafeArtifactPath, ensure_under_artifact_root

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from PySide6.QtCore import Qt


# Server-accepted incident-status values. The combo already constrains
# the operator's choice but a client-side allowlist makes the contract
# explicit and trips a clear status-bar message if a future combo
# entry typoes its way in.
INCIDENT_STATUS_ALLOWLIST: frozenset[str] = frozenset({
    "open", "investigating", "contained", "closed",
})

# Statuses that flip the incident into a terminal / contained state.
# These require a structured reason so the audit chain captures *why*
# the SOC closed / contained the incident — not just that they did.
INCIDENT_TERMINAL_STATES: frozenset[str] = frozenset({"closed", "contained"})

# Per-action click debounce. The /incidents PATCH is non-idempotent
# enough that a double-click could overwrite a freshly-applied note
# from a peer analyst.
INCIDENT_UPDATE_DEBOUNCE_SECONDS = 1.0

HISTORY_AUDIT_RETENTION = 500


class HistoryWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        # Shared audit store — same class Antivirus uses, distinct path
        # so each console's chain is grep-able in isolation.
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=HISTORY_AUDIT_RETENTION,
        )
        _install_audit_mirror(self._audit_store, app, source_slug="history")
        self._last_incident_click: float = 0.0
        # Live filters applied to the incident table — set by the
        # filter-row controls created in `build_history_tab`.
        self._incident_filters: dict[str, str] = {"status": "all", "severity": "all"}
        self._incident_inventory: list[dict] = []

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "history-audit-log.json"

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def _reject_unsafe_export_path(self, path: str) -> bool:
        """Return True (and surface an error) if `path` resolves into the
        Windows tree, Program Files, or a Startup folder. Resolving the
        real path first defeats `..` traversal and 8.3 short names.
        Mirrors the File-Analysis / Timeline export hardening."""
        import os
        try:
            dest = str(Path(path).resolve()).lower().replace("/", "\\")
        except Exception:
            dest = str(path).lower().replace("/", "\\")
        system_root = str(
            Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        ).lower().replace("/", "\\")
        blocked = [
            system_root + "\\",
            os.environ.get("ProgramFiles", r"C:\Program Files").lower().replace("/", "\\") + "\\",
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().replace("/", "\\") + "\\",
        ]
        if any(dest.startswith(p) for p in blocked) or "\\start menu\\programs\\startup\\" in dest:
            self.app._show_error(
                self.app.art_detail,
                "Export destination blocked",
                Exception(f"Refusing to write into a Windows system / Startup folder: {path}"),
            )
            return True
        return False

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

    def build_quarantine_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(l, "Quarantine & Alert Workspace", "Manage quarantined processes, restore items, configure alert webhooks.")
        row = QWidget(); r = QHBoxLayout(row)
        for text, fn in [("Refresh Quarantine", app.refresh_quarantine), ("Restore Selected", app.restore_selected_quarantine), ("Delete Selected", app.delete_selected_quarantine), ("Test Webhook", app.test_alert_webhook), ("Save Webhook", app.save_alert_webhook)]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            r.addWidget(b)
        r.addStretch(1); l.addWidget(app._panel_card("Quarantine Controls", row, None))
        app.quarantine_table = QTableWidget(0, 6); app.quarantine_table.setHorizontalHeaderLabels(["ID","Process","Original Path","Quarantine Path","Status","Created"]); app._style_table(app.quarantine_table)
        app.quarantine_detail = QTextEdit(); app.quarantine_detail.setReadOnly(True)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(app._panel_card("Quarantine Items", app.quarantine_table, lambda: app._open_panel_window("Quarantine Items", app._clone_table(app.quarantine_table))))
        split.addWidget(app._panel_card("Quarantine Detail", app.quarantine_detail, lambda: app._open_panel_window("Quarantine Detail", app._clone_text_view(app.quarantine_detail))))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def build_history_tab(self) -> QWidget:
        """Product-level History redesign.

        Layout:
          * Top: tab header + KPI strip (4 tiles) + inline filter row
                 + auto-refresh toggle + Refresh button
          * Main: 3-pane horizontal splitter
              - Left (35%):  Incidents table + selected-incident editor
                             card (Update Incident only enabled when
                             a row is picked).
              - Right (65%): inner QTabWidget — Responses · Telemetry ·
                             Alerts · Remediations · Auth · Audit Chain
          * Per-tab content stretches to fill (no empty whitespace).

        Replaces the previous design where 6 tables were forced
        side-by-side at the top, "Update Incident" was active without a
        selection, and the local audit chain was crammed into a thin
        strip at the bottom.
        """
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(l, "History & Incident Log", "Incidents, response actions, telemetry, alerts, remediations and auth audit trail — workspace-aware, audit-mirror enabled.")

        # ------------------------------------------------------------------
        # KPI strip — 4 tiles surface the answer to "what should I look
        # at?" without making the operator scan tables.
        # ------------------------------------------------------------------
        app.history_kpi_open_inc = QLabel("--")
        app.history_kpi_responses = QLabel("--")
        app.history_kpi_alerts = QLabel("--")
        app.history_kpi_anomalies = QLabel("--")
        app.history_kpi_open_inc_sub = QLabel("incidents in open / investigating")
        app.history_kpi_responses_sub = QLabel("response events recorded")
        app.history_kpi_alerts_sub = QLabel("alerts surfaced")
        app.history_kpi_anomalies_sub = QLabel("auth anomalies (admin)")
        kpi_strip = QWidget()
        kpi_layout = QHBoxLayout(kpi_strip)
        kpi_layout.setContentsMargins(0, 0, 0, 0)
        kpi_layout.setSpacing(8)
        for tile in (
            self._kpi_tile("OPEN INCIDENTS", app.history_kpi_open_inc, app.history_kpi_open_inc_sub, "#ff8b8b"),
            self._kpi_tile("RESPONSES", app.history_kpi_responses, app.history_kpi_responses_sub, "#7fd7ff"),
            self._kpi_tile("ALERTS", app.history_kpi_alerts, app.history_kpi_alerts_sub, "#ffd166"),
            self._kpi_tile("AUTH ANOMALIES", app.history_kpi_anomalies, app.history_kpi_anomalies_sub, "#bda4ff"),
        ):
            kpi_layout.addWidget(tile, 1)
        l.addWidget(kpi_strip)

        # ------------------------------------------------------------------
        # Inline filter row — incident filter chips + auto-refresh
        # checkbox + manual refresh button. Replaces the previous
        # standalone "Incident Filters" card that wasted a whole row of
        # chrome on three controls.
        # ------------------------------------------------------------------
        toolbar = QFrame(); toolbar.setProperty("card", True)
        toolbar.setStyleSheet(
            "QFrame[card='true']{background:#0e1720;border:1px solid #243446;border-radius:7px;padding:2px 6px;}"
        )
        tb = QHBoxLayout(toolbar)
        tb.setContentsMargins(8, 4, 8, 4); tb.setSpacing(8)
        section = QLabel("Filters")
        section.setStyleSheet("color:#96a5b8;font-size:9px;font-weight:800;letter-spacing:0.5px;")
        tb.addWidget(section)
        app.incident_status_filter = QComboBox()
        app.incident_status_filter.addItems(["All status", *sorted(INCIDENT_STATUS_ALLOWLIST)])
        app.incident_severity_filter = QComboBox()
        app.incident_severity_filter.addItems(["All severity", "critical", "high", "medium", "low", "info"])
        app.incident_status_filter.currentTextChanged.connect(
            lambda value: self._update_incident_filter("status", "all" if value.lower().startswith("all") else value.lower())
        )
        app.incident_severity_filter.currentTextChanged.connect(
            lambda value: self._update_incident_filter("severity", "all" if value.lower().startswith("all") else value.lower())
        )
        tb.addWidget(app.incident_status_filter)
        tb.addWidget(app.incident_severity_filter)
        app.incident_filter_status_label = QLabel("0 / 0 incidents")
        app.incident_filter_status_label.setStyleSheet("color:#7fe39d;font-size:10px;font-weight:700;")
        tb.addWidget(app.incident_filter_status_label)
        tb.addStretch(1)
        # Refresh button + auto-refresh toggle on the right.
        from PySide6.QtWidgets import QCheckBox
        app.history_auto_refresh = QCheckBox("Auto-refresh (60s)")
        app.history_auto_refresh.setStyleSheet("color:#c8d8ea;font-size:11px;")
        app.history_auto_refresh.setChecked(False)
        app.history_auto_refresh.toggled.connect(self._toggle_history_auto_refresh)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(26)
        refresh_btn.clicked.connect(app.refresh_history)
        tb.addWidget(app.history_auto_refresh)
        tb.addWidget(refresh_btn)
        l.addWidget(toolbar)

        # ------------------------------------------------------------------
        # Tables (created up-front, wired into splitter below).
        # ------------------------------------------------------------------
        app.resp_table = QTableWidget(0, 4); app.resp_table.setHorizontalHeaderLabels(["Timestamp","Action","PID","Process"]); app._style_table(app.resp_table)
        app.resp_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.tel_table = QTableWidget(0, 5); app.tel_table.setHorizontalHeaderLabels(["ts","cpu","mem","threads","tcp"]); app._style_table(app.tel_table)
        app.tel_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.inc_table = QTableWidget(0, 5); app.inc_table.setHorizontalHeaderLabels(["Incident ID","Severity","Status","Owner","Title"]); app._style_table(app.inc_table)
        app.inc_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.inc_table.itemSelectionChanged.connect(self._on_incident_selection_changed)
        app.alert_table = QTableWidget(0, 4); app.alert_table.setHorizontalHeaderLabels(["Created","Type","Severity","Status"]); app._style_table(app.alert_table)
        app.alert_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.rem_table = QTableWidget(0, 4); app.rem_table.setHorizontalHeaderLabels(["Created","Type","Target","Status"]); app._style_table(app.rem_table)
        app.rem_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.auth_table = QTableWidget(0, 5); app.auth_table.setHorizontalHeaderLabels(["Created","Event","Outcome","Role","Path"]); app._style_table(app.auth_table); app._bind_capability(app.auth_table, "can_manage_integrations")
        app.auth_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.auth_anomaly_view = QTextEdit(); app.auth_anomaly_view.setReadOnly(True); app.auth_anomaly_view.setPlainText("Auth anomaly findings will appear here for privileged roles after history is refreshed."); app._bind_capability(app.auth_anomaly_view, "can_manage_integrations")
        app.auth_anomaly_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ------------------------------------------------------------------
        # Local audit chain — surfaces the desktop-side audit log
        # (incident updates, response actions echoed from other consoles)
        # so an operator on History can verify a colleague's
        # close/contain reason without leaving the tab.
        # ------------------------------------------------------------------
        app.history_audit_view = QTextBrowser()
        app.history_audit_view.setOpenExternalLinks(False)
        app.history_audit_view.setMinimumHeight(140)
        app.history_audit_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.history_audit_view.setStyleSheet(
            "QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;"
            "color:#eef4fb;font-family:Consolas,monospace;font-size:11px;}"
        )
        self._audit_inventory: list[dict] = self.load_audit_log()
        self._render_local_audit_panel()

        # ------------------------------------------------------------------
        # Selected-incident editor — only enabled when a row is
        # selected. The previous design had this active permanently
        # at the top with empty fields, which fooled new operators
        # into clicking Update Incident with no incident selected.
        # ------------------------------------------------------------------
        editor_card = QFrame(); editor_card.setProperty("card", True)
        editor_card.setStyleSheet("QFrame[card='true']{background:#0e1720;border:1px solid #243446;border-radius:9px;}")
        ec = QVBoxLayout(editor_card)
        ec.setContentsMargins(12, 10, 12, 12); ec.setSpacing(8)
        app.history_editor_title = QLabel("No incident selected")
        app.history_editor_title.setStyleSheet("color:#ffcf7a;font-size:12px;font-weight:800;letter-spacing:0.3px;")
        ec.addWidget(app.history_editor_title)
        editor_form = QHBoxLayout(); editor_form.setSpacing(8)
        app.incident_status = QComboBox(); app.incident_status.addItems(sorted(INCIDENT_STATUS_ALLOWLIST))
        app.incident_owner = QLineEdit()
        app.incident_owner.setPlaceholderText("Owner")
        app.incident_notes = QLineEdit()
        app.incident_notes.setPlaceholderText("Notes")
        save_incident = QPushButton("Update Incident")
        save_incident.clicked.connect(app.update_selected_incident)
        save_incident.setToolTip(
            "Updates the SELECTED incident. Closing or containing requires "
            "a structured reason (ticket + category + narrative)."
        )
        app._bind_capability(save_incident, "can_manage_incidents")
        # Public reference so we can enable/disable on selection.
        app.history_save_incident_btn = save_incident
        save_incident.setEnabled(False)
        app.incident_status.setEnabled(False)
        app.incident_owner.setEnabled(False)
        app.incident_notes.setEnabled(False)
        editor_form.addWidget(QLabel("Status"))
        editor_form.addWidget(app.incident_status)
        editor_form.addWidget(QLabel("Owner"))
        editor_form.addWidget(app.incident_owner, 1)
        editor_form.addWidget(QLabel("Notes"))
        editor_form.addWidget(app.incident_notes, 2)
        editor_form.addWidget(save_incident)
        ec.addLayout(editor_form)

        # ------------------------------------------------------------------
        # Left rail — Incidents table + editor card stacked.
        # ------------------------------------------------------------------
        left_rail = QWidget()
        ll = QVBoxLayout(left_rail)
        ll.setContentsMargins(0, 0, 0, 0); ll.setSpacing(8)
        ll.addWidget(
            app._panel_card(
                "Incidents",
                app.inc_table,
                lambda: app._open_panel_window("Incidents", app._clone_table(app.inc_table)),
            ),
            3,
        )
        ll.addWidget(editor_card, 0)

        # ------------------------------------------------------------------
        # Right pane — inner tabs. 6 different table types live here
        # without competing for horizontal space.
        # ------------------------------------------------------------------
        right_tabs = QTabWidget()
        right_tabs.setDocumentMode(True)
        right_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_tabs.setProperty("panel_expand", True)

        responses_page = self._wrap_in_card_page(
            "Response Activity",
            app.resp_table,
            lambda: app._open_panel_window("Response Activity", app._clone_table(app.resp_table)),
        )
        telemetry_page = self._wrap_in_card_page(
            "Telemetry",
            app.tel_table,
            lambda: app._open_panel_window("Telemetry", app._clone_table(app.tel_table)),
        )
        alerts_page = self._wrap_in_card_page(
            "Alerts",
            app.alert_table,
            lambda: app._open_panel_window("Alerts", app._clone_table(app.alert_table)),
        )
        remediations_page = self._wrap_in_card_page(
            "Remediations",
            app.rem_table,
            lambda: app._open_panel_window("Remediations", app._clone_table(app.rem_table)),
        )

        # Auth tab — events table + anomaly text view side-by-side.
        auth_page = QWidget()
        auth_layout = QHBoxLayout(auth_page)
        auth_layout.setContentsMargins(0, 0, 0, 0); auth_layout.setSpacing(8)
        auth_split = QSplitter(Qt.Horizontal)
        auth_split.setChildrenCollapsible(False)
        auth_split.addWidget(
            app._panel_card("Auth Events", app.auth_table, lambda: app._open_panel_window("Auth Events", app._clone_table(app.auth_table)))
        )
        auth_split.addWidget(
            app._panel_card("Auth Anomalies", app.auth_anomaly_view, lambda: app._open_panel_window("Auth Anomalies", app._clone_text_view(app.auth_anomaly_view)))
        )
        auth_split.setStretchFactor(0, 2)
        auth_split.setStretchFactor(1, 1)
        auth_layout.addWidget(auth_split)

        audit_page = QWidget()
        audit_layout = QVBoxLayout(audit_page)
        audit_layout.setContentsMargins(0, 0, 0, 0); audit_layout.setSpacing(0)
        audit_layout.addWidget(
            app._panel_card(
                "Local Audit Chain (incident updates + response echoes)",
                app.history_audit_view,
                lambda: app._open_panel_window("History Audit Chain", app._clone_text_view(app.history_audit_view)),
            ),
            1,
        )

        right_tabs.addTab(responses_page, "Responses")
        right_tabs.addTab(telemetry_page, "Telemetry")
        right_tabs.addTab(alerts_page, "Alerts")
        right_tabs.addTab(remediations_page, "Remediations")
        right_tabs.addTab(auth_page, "Auth")
        right_tabs.addTab(audit_page, "Audit Chain")

        # ------------------------------------------------------------------
        # Main horizontal splitter — operator can drag to widen the
        # incidents column when a deep-investigation flow needs more
        # row visibility.
        # ------------------------------------------------------------------
        main_split = QSplitter(Qt.Horizontal)
        main_split.setChildrenCollapsible(False)
        main_split.setHandleWidth(8)
        main_split.setStyleSheet(
            "QSplitter::handle{background:#1a2b3f;border:1px solid #243446;border-radius:3px;margin:2px;}"
            "QSplitter::handle:hover{background:#2a4666;border-color:#3a5680;}"
        )
        main_split.addWidget(left_rail)
        main_split.addWidget(right_tabs)
        main_split.setStretchFactor(0, 35)
        main_split.setStretchFactor(1, 65)
        l.addWidget(main_split, 1)

        # Auto-refresh timer — created lazily via the toggle helper.
        self._history_auto_refresh_timer = None
        return w

    # ------------------------------------------------------------------ #
    # Layout helpers
    # ------------------------------------------------------------------ #

    def _kpi_tile(self, title: str, value_label, sub_label, accent: str) -> QWidget:
        tile = QFrame()
        tile.setProperty("card", True)
        tile.setStyleSheet(
            "QFrame[card='true']{background:#0e1720;border:1px solid #243446;border-radius:9px;}"
        )
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(12, 8, 12, 8); layout.setSpacing(0)
        cap = QLabel(title)
        cap.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.5px;")
        value_label.setStyleSheet(f"color:{accent};font-size:22px;font-weight:800;")
        sub_label.setStyleSheet("color:#c8d8ea;font-size:10px;")
        sub_label.setWordWrap(True)
        layout.addWidget(cap)
        layout.addWidget(value_label)
        layout.addWidget(sub_label)
        tile.setMinimumHeight(76)
        return tile

    def _wrap_in_card_page(self, title: str, content, expand_fn) -> QWidget:
        """Wrap a single widget in a panel card + page so it slots
        into a QTabWidget cleanly with the same chrome the rest of
        the app uses."""
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(0)
        layout.addWidget(self.app._panel_card(title, content, expand_fn))
        return page

    def _on_incident_selection_changed(self) -> None:
        """Enable the editor only when an incident is actually picked
        and pre-fill the form. Replaces the previous always-enabled
        editor that would silently no-op when no row was selected."""
        app = self.app
        # Defer to the existing handler that mirrors row → editor.
        app.show_selected_incident()
        row = app.inc_table.currentRow()
        has_selection = row >= 0
        if hasattr(app, "history_save_incident_btn"):
            app.history_save_incident_btn.setEnabled(has_selection)
        for widget in (app.incident_status, app.incident_owner, app.incident_notes):
            widget.setEnabled(has_selection)
        if hasattr(app, "history_editor_title"):
            if has_selection:
                inc_id_item = app.inc_table.item(row, 0)
                inc_id = inc_id_item.text() if inc_id_item else ""
                app.history_editor_title.setText(f"Editing incident #{inc_id}")
                app.history_editor_title.setStyleSheet(
                    "color:#7fe39d;font-size:12px;font-weight:800;letter-spacing:0.3px;"
                )
            else:
                app.history_editor_title.setText("No incident selected")
                app.history_editor_title.setStyleSheet(
                    "color:#ffcf7a;font-size:12px;font-weight:800;letter-spacing:0.3px;"
                )

    def _toggle_history_auto_refresh(self, checked: bool) -> None:
        """Auto-refresh helper — 60s timer that re-runs `refresh_history`
        while the operator is parked on the History tab. Honoured only
        when the checkbox is on; toggles cleanly without leaking
        timers."""
        from PySide6.QtCore import QTimer

        app = self.app
        if not checked:
            if self._history_auto_refresh_timer is not None:
                self._history_auto_refresh_timer.stop()
            app.statusBar().showMessage("History auto-refresh disabled.")
            return
        if self._history_auto_refresh_timer is None:
            self._history_auto_refresh_timer = QTimer(app)
            self._history_auto_refresh_timer.setInterval(60_000)
            self._history_auto_refresh_timer.timeout.connect(app.refresh_history)
        self._history_auto_refresh_timer.start()
        app.statusBar().showMessage("History auto-refresh enabled (60s).")

    def _update_history_kpis(
        self,
        *,
        incidents: list,
        responses: list,
        alerts: list,
        anomalies,
    ) -> None:
        """Recompute KPI tile values from the latest refresh payload.

        Called by `_apply_history_render` so the tiles always match the
        rendered tables. Anomalies is `None` when the auth endpoint
        failed or admin is locked — tile shows '--' in that case.
        """
        app = self.app
        if hasattr(app, "history_kpi_open_inc"):
            open_count = sum(
                1 for item in (incidents or [])
                if isinstance(item, dict)
                and str(item.get("status", "")).lower() in {"open", "investigating"}
            )
            app.history_kpi_open_inc.setText(str(open_count))
        if hasattr(app, "history_kpi_responses"):
            app.history_kpi_responses.setText(str(len(responses or [])))
        if hasattr(app, "history_kpi_alerts"):
            pending = sum(
                1 for item in (alerts or [])
                if isinstance(item, dict)
                and str(item.get("status", "")).lower() not in {"delivered", "ack", "acknowledged", "closed"}
            )
            app.history_kpi_alerts.setText(str(pending))
        if hasattr(app, "history_kpi_anomalies"):
            if anomalies is None:
                app.history_kpi_anomalies.setText("--")
            elif isinstance(anomalies, list):
                app.history_kpi_anomalies.setText(str(len(anomalies)))
            else:
                app.history_kpi_anomalies.setText("0")

    def build_artifacts_tab(self) -> QWidget:
        """Product-grade Artifacts & Evidence Store.

        Layout:
          1. Tab header.
          2. Header strip - last refreshed + workspace badge + KPI strip
             (Total / Locker Size / Newest / Oldest / Missing).
          3. Filter card - search + type-filter chips.
          4. Action row - Refresh + Open + Verify Hash + Send to Case
             + Export + Delete (destructive).
          5. Splitter - Artifact List (table with type/size/modified/
             SHA-256/signature columns) | Preview + Detail (redacted).

        Replaces the previous design where the list was a flat QListWidget
        with no metadata columns, no filter, no integrity surface, and
        the only actions were Refresh + Open.
        """
        try:
            from _panel_kit import (
                BusyController, build_kpi_strip, install_empty_table_placeholder, redact_payload,
            )
        except ImportError:
            from desktop._panel_kit import (
                BusyController, build_kpi_strip, install_empty_table_placeholder, redact_payload,
            )
        from PySide6.QtGui import QKeySequence
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(
            l,
            "Artifacts & Evidence Store",
            "Browse, preview and open forensic artifacts captured during monitoring and hunt sessions. SHA-256, signature, and chain-of-custody are surfaced inline.",
        )

        # --- Header strip: last refreshed + workspace badge + Refresh All
        header_row = QWidget()
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        self._artifacts_last_refresh = QLabel("Last refreshed: never")
        self._artifacts_last_refresh.setStyleSheet("color:#9aa5b1; font-size:12px;")
        header_layout.addWidget(self._artifacts_last_refresh)
        self._artifacts_workspace_badge = QLabel("workspace: -")
        self._artifacts_workspace_badge.setStyleSheet(
            "color:#cbd5e0; background:#1f2933; padding:4px 10px; border-radius:8px;"
            " font-size:11px; font-weight:600;"
        )
        self._artifacts_workspace_badge.setToolTip(
            "Workspace whose artifact locker the list below is scoped to."
        )
        header_layout.addWidget(self._artifacts_workspace_badge)
        header_layout.addStretch(1)
        refresh_all_btn = QPushButton("Refresh All (Ctrl+R)")
        refresh_all_btn.setShortcut(QKeySequence("Ctrl+R"))
        refresh_all_btn.clicked.connect(app.refresh_artifacts)
        app._bind_capability(refresh_all_btn, "can_view_history")
        header_layout.addWidget(refresh_all_btn)
        l.addWidget(header_row)

        # KPI strip intentionally omitted on this tab - the live table
        # already surfaces every artifact's size / modified / signature
        # status, so the five aggregate chips were redundant noise. The
        # `_artifacts_kpis` attribute is left as `None` so the refresh
        # path's chip-update block becomes a no-op.
        self._artifacts_kpis = None

        # --- Filter card: search bar + type-filter chips + Reset.
        from PySide6.QtWidgets import QCheckBox as _QCheck
        filter_card = QFrame()
        filter_card.setProperty("card", True)
        filter_outer = QVBoxLayout(filter_card)
        filter_outer.setContentsMargins(8, 6, 8, 6)
        filter_outer.setSpacing(6)
        # Row 1: search.
        f1 = QHBoxLayout()
        f1.setContentsMargins(0, 0, 0, 0)
        f1.setSpacing(6)
        search_lbl = QLabel("🔍")
        search_lbl.setStyleSheet("color:#9aa5b1;font-size:12px;")
        self._artifacts_search = QLineEdit()
        self._artifacts_search.setPlaceholderText("filter by name, category, summary…")
        self._artifacts_search.setClearButtonEnabled(True)
        self._artifacts_search.textChanged.connect(self._apply_artifact_filters)
        f1.addWidget(search_lbl)
        f1.addWidget(self._artifacts_search)
        filter_outer.addLayout(f1)
        # Row 2: type chips + reset.
        f2 = QHBoxLayout()
        f2.setContentsMargins(0, 0, 0, 0)
        f2.setSpacing(6)
        type_lbl = QLabel("TYPES")
        type_lbl.setStyleSheet("color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;")
        f2.addWidget(type_lbl)
        self._artifact_type_chips: dict[str, _QCheck] = {}
        for slug in ("json", "csv", "html", "pdf", "image", "binary", "other"):
            chk = _QCheck(slug.upper())
            chk.setChecked(True)
            chk.setStyleSheet(
                "QCheckBox { color:#cbd5e0; font-size:11px; padding:2px 6px; }"
                "QCheckBox::indicator { width:12px; height:12px; }"
            )
            chk.toggled.connect(self._apply_artifact_filters)
            self._artifact_type_chips[slug] = chk
            f2.addWidget(chk)
        self._artifacts_filter_status = QLabel("0 / 0 artifacts")
        self._artifacts_filter_status.setStyleSheet(
            "color:#7fe39d;font-size:10px;font-weight:700;"
        )
        f2.addWidget(self._artifacts_filter_status)
        f2.addStretch(1)
        reset_btn = QPushButton("Reset Filters")
        reset_btn.setMaximumWidth(110)
        reset_btn.clicked.connect(self._reset_artifact_filters)
        f2.addWidget(reset_btn)
        filter_outer.addLayout(f2)
        l.addWidget(filter_card)

        # --- Action row.
        controls = QWidget()
        cr = QHBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        refresh_btn = QPushButton("Refresh Artifacts")
        refresh_btn.setToolTip("Reload the artifact manifest from the API and re-hash the visible rows.")
        refresh_btn.clicked.connect(app.refresh_artifacts)
        open_btn = QPushButton("Open Selected")
        open_btn.setToolTip("Open the highlighted artifact in the platform's default viewer.")
        open_btn.clicked.connect(app.open_selected_artifact)
        verify_btn = QPushButton("Verify Hash")
        verify_btn.setToolTip(
            "Re-compute the on-disk SHA-256 and compare it against the integrity manifest. "
            "Mismatches mean the file was modified after capture."
        )
        verify_btn.clicked.connect(self._verify_selected_artifact_hash)
        case_btn = QPushButton("Send to Case")
        case_btn.setToolTip("Attach the highlighted artifact to the active enterprise case.")
        case_btn.clicked.connect(self._send_artifact_to_case)
        export_btn = QPushButton("Export Manifest")
        export_btn.setToolTip("Download the artifact manifest as JSON or CSV.")
        export_btn.clicked.connect(self._export_artifact_manifest)
        delete_btn = QPushButton("⚠ Delete Selected")
        delete_btn.setToolTip(
            "Destructive - requires confirmation. The file is removed from disk; "
            "audit chain records the actor + reason."
        )
        delete_btn.setStyleSheet(
            "QPushButton{background:#2c1820;color:#feb2b2;border:1px solid #5f1d1d;"
            "border-radius:8px;padding:4px 8px;font-weight:600;font-size:10px;}"
            "QPushButton:hover{background:#3d2129;border-color:#8a2a2a;color:#ffd0d0;}"
            "QPushButton:pressed{background:#511c1c;border-color:#a83232;padding-top:5px;padding-bottom:3px;}"
            "QPushButton:disabled{background:#1f1418;color:#7a5a5a;border-color:#3a2024;}"
        )
        delete_btn.clicked.connect(self._delete_selected_artifact)
        _artifact_btn_qss = (
            "QPushButton{background:#1a2a3d;color:#c8d8ea;border:1px solid #2c4260;"
            "border-radius:8px;padding:4px 8px;font-weight:600;font-size:10px;}"
            "QPushButton:hover{background:#23394f;border-color:#4a6c95;color:#eaf2fb;}"
            "QPushButton:pressed{background:#2f4f70;border-color:#5d8aa8;padding-top:5px;padding-bottom:3px;}"
            "QPushButton:disabled{background:#141d28;color:#5e6f80;border-color:#23303f;}"
        )
        for btn in (refresh_btn, open_btn, verify_btn, case_btn, export_btn):
            btn.setStyleSheet(_artifact_btn_qss)
        for btn in (refresh_btn, open_btn, verify_btn, case_btn, export_btn, delete_btn):
            app._bind_capability(btn, "can_view_history")
            cr.addWidget(btn)
        cr.addStretch(1)
        l.addWidget(app._panel_card("Artifact Actions", controls, None))
        # Single busy controller flips every action surface during a refresh.
        self._artifacts_busy = BusyController(
            app, [refresh_all_btn, refresh_btn, open_btn, verify_btn, case_btn, export_btn, delete_btn],
        )

        # --- Artifact table: zengin sütunlar əvəzinə yalın QListWidget.
        app.art_list = QTableWidget(0, 7)
        app.art_list.setHorizontalHeaderLabels(["Name", "Type", "Size", "Modified", "SHA-256", "Signature", "Workspace"])
        app._style_table(app.art_list)
        app.art_list.setSortingEnabled(True)
        from PySide6.QtWidgets import QAbstractItemView as _QAIV
        app.art_list.setSelectionBehavior(_QAIV.SelectRows)
        app.art_list.itemSelectionChanged.connect(app.show_selected_artifact)
        install_empty_table_placeholder(
            app.art_list,
            "No artifacts recorded yet - run Monitor or trigger a hunt to populate the locker.",
        )

        # --- Preview + Detail panels (right side of splitter).
        app.art_preview = QTextBrowser()
        app.art_preview.setMinimumHeight(180)
        app.art_preview.setHtml(
            "<div style='padding:6px;color:#9aa5b1;'>"
            "Pick an artifact on the left to surface an inline preview. "
            "Binary files show metadata only; large text payloads are truncated to 256 KB to keep the UI responsive."
            "</div>"
        )
        app.art_detail = QTextEdit()
        app.art_detail.setReadOnly(True)
        app.art_detail.setPlainText(
            "Artifact detail metadata (path, category, summary, SHA-256, signature status) lands here. "
            "Sensitive fields are auto-redacted before display."
        )

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        rl.addWidget(app._panel_card("Artifact Preview", app.art_preview,
                                     lambda: app._open_panel_window("Artifact Preview", app._clone_text_view(app.art_preview))))
        rl.addWidget(app._panel_card("Artifact Detail", app.art_detail,
                                     lambda: app._open_panel_window("Artifact Detail", app._clone_text_view(app.art_detail))))

        s = QSplitter(Qt.Horizontal)
        s.addWidget(app._panel_card("Artifact List", app.art_list,
                                    lambda: app._open_panel_window("Artifact List", app._clone_table(app.art_list))))
        s.addWidget(right)
        s.setStretchFactor(0, 2)
        s.setStretchFactor(1, 3)
        l.addWidget(s, 1)
        # Initial placeholder snapshot so the page is readable before
        # the first refresh.
        self._update_artifacts_workspace_badge()
        return w

    def refresh_history(self) -> None:
        app = self.app
        # Async refresh: 7 sequential `_get` calls
        # (`/history/responses`, `/history/telemetry`, `/incidents`,
        # `/history/alerts`, `/history/remediations`, `/history/auth`,
        # `/history/auth/anomalies`) used to lock the UI thread for
        # the cumulative timeout. Now they run on a worker; the
        # render still happens on the UI thread via the `on_success`
        # callback. Partial-failure tolerant — each fetch's exception
        # is captured and the render uses defaults for the missing
        # endpoint instead of skipping the rest.
        admin_view = bool(app.auth_context.get("capabilities", {}).get("can_manage_integrations"))
        if hasattr(app, "monitor_out") and not app.monitor_out.toPlainText().strip():
            app.monitor_out.setHtml(
                "<div style='color:#9fb2c6;padding:6px;'>"
                "History refresh running on worker thread — UI stays responsive..."
                "</div>"
            )

        def _gather() -> dict:
            partials: dict = {"errors": []}
            calls = [
                ("responses", lambda: app._get("/history/responses").json()),
                ("telemetry", lambda: app._get("/history/telemetry").json()),
                ("incidents", lambda: app._get("/incidents").json()),
                ("alerts", lambda: app._get("/history/alerts").json()),
                ("remediations", lambda: app._get("/history/remediations").json()),
            ]
            if admin_view:
                calls.extend([
                    ("auth", lambda: app._get("/history/auth").json()),
                    ("auth_anomalies", lambda: app._get("/history/auth/anomalies").json()),
                ])
            for key, fn in calls:
                try:
                    partials[key] = fn()
                except Exception as exc:
                    partials[key] = None
                    partials["errors"].append({"endpoint": key, "error": str(exc)})
            return partials

        def _on_done(partials: dict) -> None:
            self._apply_history_render(partials, admin_view=admin_view)

        def _on_err(message: str) -> None:
            app.statusBar().showMessage(f"History refresh failed: {message}")

        submit_async_call(
            parent=app,
            label="history refresh",
            work=_gather,
            on_success=_on_done,
            on_failure=_on_err,
            timeout_seconds=60,
        )

    def _apply_history_render(self, partials: dict, *, admin_view: bool) -> None:
        """Render the history workspace from a worker-collected payload.

        Pulled out of `refresh_history` so the gather/render split is
        explicit. Every endpoint that failed in the worker thread shows
        up as `None` here — defaults to an empty list so a single
        endpoint hiccup doesn't blank the rest of the workspace.
        """
        app = self.app
        # Every list below is iterated with item.get(...). A malformed or
        # hostile backend can return a non-list (dict error envelope) or
        # a list with non-dict elements; without this filter that raises
        # AttributeError/TypeError and blanks the entire workspace
        # (KPIs, audit panel, timeline, dashboard). Mirror the telemetry
        # guard for every history list, and feed the SAME filtered lists
        # to _update_history_kpis so counts match the rendered tables.
        def _dicts(value) -> list[dict]:
            return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []

        resp = _dicts(partials.get("responses"))
        telemetry_history = _dicts(partials.get("telemetry"))
        tel_table = telemetry_history[:200]
        tel_chart = list(reversed(tel_table))
        app.latest_history_telemetry_rows = tel_chart
        incidents = _dicts(partials.get("incidents"))
        alerts = _dicts(partials.get("alerts"))
        remediations = _dicts(partials.get("remediations"))
        auth_events = _dicts(partials.get("auth"))
        anomalies = partials.get("auth_anomalies")

        app.resp_table.setRowCount(len(resp))
        for r, item in enumerate(resp):
            for c, value in enumerate([item.get("timestamp", ""), item.get("action", ""), item.get("pid", ""), item.get("process_name", "")]):
                app.resp_table.setItem(r, c, QTableWidgetItem(str(value)))
            app._paint_row(app.resp_table, r, app._severity_color("high" if item.get("action") == "KILL" else "medium"))

        app.tel_table.setRowCount(len(tel_table))
        for r, item in enumerate(tel_table):
            for c, value in enumerate([item.get("ts", ""), item.get("cpu", ""), item.get("mem_percent", ""), item.get("proc_threads", ""), item.get("tcp_conns", "")]):
                app.tel_table.setItem(r, c, QTableWidgetItem(str(value)))
            try:
                cpu = float(item.get("cpu", 0) or 0)
            except (TypeError, ValueError):
                cpu = 0.0
            if cpu >= 30:
                app._paint_row(app.tel_table, r, QColor("#d64550"))
        if app.latest_monitor_rows:
            app.metric_tel.setText(f"Telemetry Rows: {len(app.latest_monitor_rows)}")
            app._update_cpu_chart(app.latest_monitor_rows)
        else:
            app.metric_tel.setText(f"Telemetry Rows: {len(tel_chart)}")
            app._update_cpu_chart(tel_chart)
        if not tel_chart and not app.latest_monitor_rows and not app.monitor_out.toPlainText().strip():
            app.monitor_out.setHtml("<div style='color:#9fb2c6;padding:6px;'>Run a monitor session to populate telemetry trend data.</div>")

        # Cache the full incident list so the filter row can re-render
        # without a backend round-trip when the operator flips a chip.
        self._incident_inventory = incidents if isinstance(incidents, list) else []
        self._render_incident_table(self._incident_inventory)
        if incidents:
            latest_incident = incidents[0]
            severity = str(latest_incident.get("severity", "unknown"))
            app.metric_inc.setStyleSheet(
                "background:#121b27;border:1px solid #2c4260;border-radius:10px;padding:6px 10px;"
                f"color:{app._severity_color(severity).name()};font-weight:700;font-size:11px;"
            )
            app.metric_inc.setText(f"Last Incident: {latest_incident.get('incident_id', '-') or '-'} ({severity})")
            if not app.latest_monitor_result:
                telemetry_count = len(app.latest_monitor_rows) if app.latest_monitor_rows else len(tel_chart)
                incident_payload = {
                    "incident": latest_incident,
                    "summary": {
                        "process_count": len(resp),
                        "connection_count": sum(app._safe_int(item.get("tcp_conns", 0)) for item in tel_table[:20]),
                        "severity": severity,
                    },
                    "telemetry_count": telemetry_count,
                    "telemetry_rows": tel_chart,
                }
                app.monitor_out.setHtml(app._render_monitor_brief(incident_payload, latest_incident))
        else:
            app.metric_inc.setStyleSheet(
                "background:#121b27;color:#c8d8ea;border:1px solid #2c4260;border-radius:10px;padding:6px 10px;font-weight:600;font-size:11px;"
            )
            app.metric_inc.setText("Last Incident: --")

        app.alert_table.setRowCount(len(alerts))
        for r, item in enumerate(alerts):
            values = [item.get("created_at", ""), item.get("destination_type", ""), item.get("severity", ""), item.get("status", "")]
            for c, value in enumerate(values):
                app.alert_table.setItem(r, c, QTableWidgetItem(str(value)))
            app._paint_row(app.alert_table, r, app._severity_color(item.get("severity", "")))

        app.rem_table.setRowCount(len(remediations))
        for r, item in enumerate(remediations):
            values = [item.get("created_at", ""), item.get("item_type", ""), item.get("target", ""), item.get("status", "")]
            for c, value in enumerate(values):
                app.rem_table.setItem(r, c, QTableWidgetItem(str(value)))
            app._paint_row(app.rem_table, r, app._severity_color("medium" if item.get("status") == "applied" else "high"))

        if admin_view:
            app.auth_table.setRowCount(len(auth_events))
            for r, item in enumerate(auth_events):
                values = [item.get("created_at", ""), item.get("event_type", ""), item.get("outcome", ""), item.get("role", ""), item.get("path", "")]
                for c, value in enumerate(values):
                    app.auth_table.setItem(r, c, QTableWidgetItem(str(value)))
                severity = "high" if item.get("outcome") == "denied" else "low"
                app._paint_row(app.auth_table, r, app._severity_color(severity))
            if anomalies is None:
                app.auth_anomaly_view.setPlainText("Auth anomaly load failed (see status bar for endpoint error).")
            elif anomalies:
                app.auth_anomaly_view.setPlainText(json.dumps(anomalies, indent=2, ensure_ascii=False))
            else:
                app.auth_anomaly_view.setPlainText("No auth anomalies detected in the current audit window.")
        else:
            app.auth_table.setRowCount(0)
            app.auth_anomaly_view.setPlainText("Auth audit and anomaly history is visible to admin users only.")

        app.refresh_timeline()
        if app.auth_context.get("capabilities", {}).get("can_view_quarantine"):
            app.refresh_antivirus_workspace()
        app.refresh_hosts()
        if hasattr(app, "dash_metrics"):
            app._refresh_dashboard_panels()
        # Refresh KPI tiles from the same payload — operator sees
        # "open incidents" / "alerts" / "anomalies" counts at a glance
        # without scanning the tables.
        self._update_history_kpis(
            incidents=incidents,
            responses=resp,
            alerts=alerts,
            anomalies=anomalies if admin_view else None,
        )

        # Surface partial failures so the operator knows which endpoint
        # came back empty.
        errors = partials.get("errors") or []
        if errors:
            bad = ", ".join(sorted({str(e.get("endpoint", "?")) for e in errors}))
            app.statusBar().showMessage(f"History refresh complete (partial: {bad}).")
        else:
            app.statusBar().showMessage("History refresh complete.")

    # ------------------------------------------------------------------ #
    # Incident filter + render helpers
    # ------------------------------------------------------------------ #

    def _update_incident_filter(self, key: str, value: str) -> None:
        self._incident_filters[key] = (value or "all").strip().lower() or "all"
        self._render_incident_table(self._incident_inventory)

    def _passes_incident_filter(self, item: dict) -> bool:
        f = self._incident_filters
        if f.get("status", "all") not in {"all", ""} and str(item.get("status", "")).lower() != f["status"]:
            return False
        if f.get("severity", "all") not in {"all", ""} and str(item.get("severity", "")).lower() != f["severity"]:
            return False
        return True

    def _render_incident_table(self, incidents: list[dict]) -> None:
        app = self.app
        filtered = [item for item in incidents if self._passes_incident_filter(item)]
        app.inc_table.setRowCount(len(filtered))
        for r, item in enumerate(filtered):
            values = [
                item.get("incident_id", ""),
                item.get("severity", ""),
                item.get("status", ""),
                item.get("owner", ""),
                item.get("title", ""),
            ]
            for c, value in enumerate(values):
                app.inc_table.setItem(r, c, QTableWidgetItem(str(value)))
            app._paint_row(app.inc_table, r, app._severity_color(item.get("severity", "")))
        if hasattr(app, "incident_filter_status_label"):
            app.incident_filter_status_label.setText(
                f"{len(filtered)} / {len(incidents)} incidents shown"
            )

    def _render_local_audit_panel(self) -> None:
        """Render the desktop-side audit chain into the History tab.

        Shows the most recent 40 entries with severity-colored status
        chips so an analyst can scan recent close/contain/quarantine
        decisions without opening a JSON file. Sources both the
        in-memory mirror and the on-disk store.
        """
        app = self.app
        if not hasattr(app, "history_audit_view"):
            return
        entries = list(self._audit_inventory or self._audit_store.entries() or [])[:40]
        if not entries:
            app.history_audit_view.setHtml(
                "<p style='color:#96a5b8;'>No local audit activity yet. "
                "Incident close/contain decisions, quarantine actions, and "
                "response echoes will appear here.</p>"
            )
            return

        def _status_color(status: str) -> str:
            return {
                "ok": "#7fe39d",
                "blocked": "#ffcf7a",
                "failed": "#ff6b8a",
                "cancelled": "#f4c26b",
                "partial": "#ffcf7a",
            }.get(str(status).lower(), "#7fd7ff")

        rows = []
        for entry in entries:
            ticket = str(entry.get("ticket_id", "") or "")
            category = str(entry.get("reason_category", "") or "")
            reason_text = str(entry.get("reason_text", "") or "")
            reason_block = ""
            if ticket or category or reason_text:
                reason_block = (
                    f"<br><span style='color:#96a5b8;'>"
                    f"<b>Ticket:</b> {html.escape(ticket or '-')} &nbsp;"
                    f"<b>Category:</b> {html.escape(category or '-')} &nbsp;"
                    f"<b>Reason:</b> {html.escape(reason_text[:160])}"
                    f"</span>"
                )
            rows.append(
                "<tr>"
                f"<td style='color:#96a5b8;'>{html.escape(str(entry.get('timestamp', '-')))}</td>"
                f"<td><b>{html.escape(str(entry.get('action', '-')))}</b>"
                f" <span style='color:#7fd7ff;'>·</span> "
                f"{html.escape(str(entry.get('category', '-')))}"
                f"</td>"
                f"<td>{html.escape(str(entry.get('target', '-'))[:80])}</td>"
                f"<td>{html.escape(str(entry.get('actor', '-')))}</td>"
                f"<td><span style='color:{_status_color(entry.get('status', ''))};font-weight:800;'>"
                f"{html.escape(str(entry.get('status', '-')))}</span>"
                f"{reason_block}</td>"
                "</tr>"
            )
        html_payload = (
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:11px;'>"
            "<tr style='color:#96a5b8;'>"
            "<th align='left'>Time</th>"
            "<th align='left'>Action</th>"
            "<th align='left'>Target</th>"
            "<th align='left'>Actor</th>"
            "<th align='left'>Status / Reason</th>"
            "</tr>"
            + "".join(rows)
            + "</table>"
        )
        app.history_audit_view.setHtml(html_payload)

    def show_selected_incident(self) -> None:
        app = self.app
        row = app.inc_table.currentRow()
        if row < 0:
            return
        app.incident_status.setCurrentText(app.inc_table.item(row, 2).text() if app.inc_table.item(row, 2) else "open")
        app.incident_owner.setText(app.inc_table.item(row, 3).text() if app.inc_table.item(row, 3) else "")

    def update_selected_incident(self) -> None:
        app = self.app
        row = app.inc_table.currentRow()
        if row < 0:
            app.statusBar().showMessage("Select an incident row first.")
            return
        # Per-action debounce — the /incidents PATCH is non-idempotent
        # enough that a double-click could overwrite a peer analyst's
        # freshly-applied note.
        now = time.time()
        if now - self._last_incident_click < INCIDENT_UPDATE_DEBOUNCE_SECONDS:
            app.statusBar().showMessage("Incident update is rate-limited; try again in a moment.")
            return
        self._last_incident_click = now

        incident_id = app.inc_table.item(row, 0).text() if app.inc_table.item(row, 0) else ""
        if not incident_id:
            app.statusBar().showMessage("Selected row has no incident ID.")
            return
        new_status = app.incident_status.currentText().strip().lower()
        if new_status not in INCIDENT_STATUS_ALLOWLIST:
            app.statusBar().showMessage(
                f"Status `{new_status}` is not in the client allowlist {sorted(INCIDENT_STATUS_ALLOWLIST)}."
            )
            return

        # The previous status (column 2) tells us whether this is a
        # state escalation that needs a forensic justification — moving
        # to closed/contained always does.
        prev_status_item = app.inc_table.item(row, 2)
        prev_status = prev_status_item.text().strip().lower() if prev_status_item else ""
        is_terminal_change = (
            new_status in INCIDENT_TERMINAL_STATES and new_status != prev_status
        )

        reason: dict | None = None
        if is_terminal_change:
            reason = self._capture_reason(f"incident-{new_status} (id={incident_id})")
            if reason is None:
                return  # operator cancelled the modal; abort silently

        payload = {
            "status": new_status,
            "owner": app.incident_owner.text().strip(),
            "notes": app.incident_notes.text().strip(),
        }
        if reason:
            # Send the structured reason to the backend too — when
            # /incidents starts persisting it, the field is already
            # plumbed; today the server ignores unknown keys.
            payload["reason"] = {
                "ticket_id": reason["ticket_id"],
                "category": reason["reason_category"],
                "text": reason["reason_text"],
            }

        try:
            result = app._patch(f"/incidents/{incident_id}", json=payload, timeout=20).json()
            ok = True
            error_message = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error_message = str(exc)

        actor, workspace = actor_workspace_pair(app)
        audit_entry = self._audit_store.append(
            category="incident",
            action=f"status:{new_status}" if new_status != prev_status else "update",
            target=str(incident_id),
            severity="high" if is_terminal_change else "medium",
            status="ok" if ok else "failed",
            payload={
                "request": payload,
                "response": result,
                "previous_status": prev_status,
            },
            actor=actor,
            workspace=workspace,
            reason=reason,
        )
        # Mirror into the local-panel inventory so the chain rendering
        # picks up the new entry without re-reading the disk.
        if not isinstance(getattr(self, "_audit_inventory", None), list):
            self._audit_inventory = []
        self._audit_inventory.insert(0, audit_entry)
        del self._audit_inventory[HISTORY_AUDIT_RETENTION:]
        self._render_local_audit_panel()

        if not ok:
            app.statusBar().showMessage(f"Incident update failed: {error_message}")
            return
        app.statusBar().showMessage(
            f"Incident {incident_id} → {new_status}"
            + (f" (reason: {reason['reason_summary']})" if reason else "")
        )
        self.refresh_history()

    # ------------------------------------------------------------------ #
    # Artifacts tab helpers (P0 upgrades)
    # ------------------------------------------------------------------ #

    def _apply_artifact_filters(self) -> None:
        """Hide / show artifact rows based on search text + type chips."""
        table = getattr(self.app, "art_list", None)
        if table is None or not hasattr(table, "rowCount"):
            return
        needle = (self._artifacts_search.text() if hasattr(self, "_artifacts_search") else "").strip().lower()
        active_types = {
            slug for slug, chk in getattr(self, "_artifact_type_chips", {}).items()
            if chk.isChecked()
        }
        records_by_name = {
            str(r.get("name", "")): r
            for r in getattr(self.app, "artifact_records", []) or []
        }
        visible_count = 0
        total_rows = table.rowCount()
        for row in range(table.rowCount()):
            cell = table.item(row, 0)
            if cell is None:
                continue
            name = cell.text()
            record = records_by_name.get(name, {})
            type_slug = str(record.get("type_slug", "other"))
            summary = str(record.get("summary", ""))
            category = str(record.get("category_label", ""))
            haystack = " ".join([name, summary, category, type_slug]).lower()
            hide = False
            if needle and needle not in haystack:
                hide = True
            if type_slug not in active_types:
                hide = True
            table.setRowHidden(row, hide)
            if not hide:
                visible_count += 1
        if hasattr(self, "_artifacts_filter_status"):
            if total_rows == 0:
                self._artifacts_filter_status.setText("0 / 0 artifacts - refresh first")
                self._artifacts_filter_status.setStyleSheet(
                    "color:#ffcf7a;font-size:10px;font-weight:700;"
                )
            else:
                self._artifacts_filter_status.setText(f"{visible_count} / {total_rows} artifacts")
                tone = "#7fe39d" if visible_count else "#ffcf7a"
                self._artifacts_filter_status.setStyleSheet(
                    f"color:{tone};font-size:10px;font-weight:700;"
                )
        if total_rows == 0:
            self.app.statusBar().showMessage("Artifact list is not loaded yet. Press Refresh All first.")

    def _reset_artifact_filters(self) -> None:
        if hasattr(self, "_artifacts_search"):
            self._artifacts_search.clear()
        for chk in getattr(self, "_artifact_type_chips", {}).values():
            chk.setChecked(True)
        self._apply_artifact_filters()

    def _update_artifacts_workspace_badge(self) -> None:
        try:
            workspace_id = ""
            if hasattr(self.app, "workspace_id") and hasattr(self.app.workspace_id, "text"):
                workspace_id = self.app.workspace_id.text().strip()
            workspace_id = workspace_id or (
                getattr(self.app, "current_auth_context", {}) or {}
            ).get("workspace_id", "default")
            self._artifacts_workspace_badge.setText(f"workspace: {workspace_id}")
        except Exception:
            self._artifacts_workspace_badge.setText("workspace: default")

    def _verify_selected_artifact_hash(self) -> None:
        """Re-hash the selected artifact and compare against the manifest."""
        from PySide6.QtWidgets import QMessageBox as _QMB
        record = artifacts_ops._selected_record(self.app)
        if record is None:
            self.app.statusBar().showMessage("Select an artifact row first.", 4000)
            return
        path = Path(str(record.get("path", "")))
        if not path.exists():
            _QMB.warning(self.app, "Hash verification", "On-disk artifact is missing - cannot recompute.")
            return
        recomputed = artifacts_ops._sha256_file(path)
        signature_status = str(record.get("signature_status", "unsigned"))
        # Compare against the integrity manifest's AUTHORITATIVE expected
        # hash. Comparing against record["sha256"] (the hash taken at the
        # last refresh) only ever catches tampering between refresh and
        # verify and rubber-stamps a file that was already tampered
        # before the refresh — i.e. a no-op integrity check.
        expected = str(record.get("expected_sha256", "") or "").lower()
        baseline = expected or str(record.get("sha256", ""))
        baseline_label = "Manifest expected" if expected else "Refresh-time hash (no manifest baseline)"
        same = bool(recomputed) and bool(baseline) and recomputed.lower() == baseline.lower()
        message = (
            f"<b>Artifact:</b> {html.escape(str(record.get('name', '')))}<br>"
            f"<b>{html.escape(baseline_label)}:</b> <code>{html.escape(baseline) or '—'}</code><br>"
            f"<b>Recomputed:</b> <code>{html.escape(recomputed) or '—'}</code><br>"
            f"<b>Manifest status:</b> {html.escape(signature_status)}<br>"
            f"<b>Result:</b> {'✓ match' if same else '✗ MISMATCH'}"
        )
        dlg = _QMB(self.app)
        dlg.setIcon(_QMB.Information if same else _QMB.Warning)
        dlg.setWindowTitle("Hash verification")
        dlg.setTextFormat(Qt.RichText)
        dlg.setText(message)
        dlg.exec()

    def _send_artifact_to_case(self) -> None:
        """Forward the selected artifact's metadata to the active enterprise case."""
        record = artifacts_ops._selected_record(self.app)
        if record is None:
            self.app.statusBar().showMessage("Select an artifact row first.", 4000)
            return
        # Re-use the existing "open enterprise case for incident" plumbing
        # so the artifact lands in the same workspace as the case.
        if hasattr(self.app, "open_enterprise_case_for_incident"):
            self.app.open_enterprise_case_for_incident(prefix="ART-")
            self.app.statusBar().showMessage(
                f"Forwarded `{record.get('name')}` metadata to enterprise case.", 5000,
            )
        else:
            self.app.statusBar().showMessage(
                "Enterprise case integration unavailable in this build.", 5000,
            )

    def _export_artifact_manifest(self) -> None:
        """Dump the live artifact manifest (JSON or CSV) to disk."""
        from PySide6.QtWidgets import QFileDialog
        records = list(getattr(self.app, "artifact_records", []) or [])
        if not records:
            self.app.statusBar().showMessage("Refresh first - the manifest is empty.", 4000)
            return
        default = f"shadowlab_out/artifact_manifest_{time.strftime('%Y%m%d_%H%M%S')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Export artifact manifest", default, "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        if self._reject_unsafe_export_path(path):
            return
        try:
            if path.lower().endswith(".json"):
                with open(path, "w", encoding="utf-8") as handle:
                    serialisable = [
                        {k: v for k, v in r.items() if k not in {"path_obj"}}
                        for r in records
                    ]
                    json.dump(serialisable, handle, indent=2, ensure_ascii=False, default=str)
            else:
                import csv as _csv
                with open(path, "w", encoding="utf-8", newline="") as handle:
                    writer = _csv.writer(handle)
                    writer.writerow(["name", "category", "size", "modified", "sha256", "signature", "path"])
                    for r in records:
                        writer.writerow([
                            r.get("name", ""), r.get("category_label", ""), r.get("size", 0),
                            r.get("modified", ""), r.get("sha256", ""),
                            r.get("signature_status", ""), r.get("path", ""),
                        ])
            self.app.statusBar().showMessage(f"Exported {len(records)} rows to {path}", 6000)
        except Exception as exc:
            self.app._show_error(self.app.art_detail, "Manifest export failed", exc)

    def _delete_selected_artifact(self) -> None:
        """Destructive — confirmation + capability check, then unlink the file."""
        from PySide6.QtWidgets import QMessageBox as _QMB
        record = artifacts_ops._selected_record(self.app)
        if record is None:
            self.app.statusBar().showMessage("Select an artifact row first.", 4000)
            return
        raw_path = str(record.get("path", ""))
        # `record["path"]` is server-supplied — without this gate a
        # compromised backend can hand the desktop any absolute path
        # the operator has write rights to (hosts file, AV manifests,
        # autoruns) and `path.unlink()` would happily oblige.
        try:
            path = ensure_under_artifact_root(raw_path)
        except UnsafeArtifactPath as exc:
            self.app._show_error(
                self.app.art_detail,
                "Artifact delete blocked",
                f"Refusing to delete a path outside the evidence locker: {exc}",
            )
            return
        confirm = _QMB(self.app)
        confirm.setWindowTitle("Confirm artifact deletion")
        confirm.setIcon(_QMB.Critical)
        confirm.setText(f"Permanently delete `{record.get('name')}`?")
        confirm.setInformativeText(
            f"<b>Path:</b> <code>{html.escape(str(path))}</code><br>"
            f"<b>Size:</b> {record.get('size_human', '—')}<br>"
            f"<b>SHA-256:</b> <code>{record.get('sha256', '—')}</code><br><br>"
            "This removes the file from the evidence locker. The audit chain still "
            "records the deletion event; the file itself cannot be recovered through "
            "the UI once this confirmation closes."
        )
        confirm.setStandardButtons(_QMB.Cancel | _QMB.Ok)
        if confirm.exec() != _QMB.Ok:
            return
        try:
            if path.exists():
                path.unlink()
            self.app.statusBar().showMessage(f"Deleted {path.name}", 5000)
            self.refresh_artifacts()
        except Exception as exc:
            self.app._show_error(self.app.art_detail, "Artifact delete failed", exc)

    def refresh_artifacts(self) -> None:
        artifacts_ops.refresh_artifacts(self.app)

    def render_html_source_preview(self, text: str, title: str) -> None:
        artifacts_ops.render_html_source_preview(self.app, text, title)

    def refresh_quarantine(self) -> None:
        self.app.antivirus_controller.refresh_quarantine_inventory()

    def restore_selected_quarantine(self) -> None:
        self.app.antivirus_controller.restore_selected_quarantine()

    def delete_selected_quarantine(self) -> None:
        self.app.antivirus_controller.delete_selected_quarantine()

    def test_alert_webhook(self) -> None:
        self.app.antivirus_controller.test_alert_webhook()

    def save_alert_webhook(self) -> None:
        self.app.antivirus_controller.save_alert_webhook()

    def show_selected_artifact(self) -> None:
        artifacts_ops.show_selected_artifact(self.app)

    def open_selected_artifact(self) -> None:
        artifacts_ops.open_selected_artifact(self.app)
