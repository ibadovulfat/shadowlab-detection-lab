from __future__ import annotations

import html
import json
import time
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, Qt
from PySide6.QtGui import QColor, QCursor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QHeaderView,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    from process_hunt_scoring import (
        RiskPolicyCache,
        command_entropy,
        is_protected_process,
        is_public_network_destination,
        risk_pill_text,
        score_process,
        signature_pill_text,
        state_pill_text,
    )
except ImportError:  # pragma: no cover - import path differs in test envs
    from desktop.process_hunt_scoring import (
        RiskPolicyCache,
        command_entropy,
        is_protected_process,
        is_public_network_destination,
        risk_pill_text,
        score_process,
        signature_pill_text,
        state_pill_text,
    )

try:
    from process_hunt_jobs import ProcessWorker, bulk_scan_timeout
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker, bulk_scan_timeout

try:
    from _audit_mirror import install_backend_mirror as _install_audit_mirror
except ImportError:  # pragma: no cover
    from desktop._audit_mirror import install_backend_mirror as _install_audit_mirror

try:
    from _response_dialog import REASON_CATEGORIES as _SHARED_REASON_CATEGORIES
    from _response_dialog import prompt_response_reason as _shared_prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import REASON_CATEGORIES as _SHARED_REASON_CATEGORIES
    from desktop._response_dialog import prompt_response_reason as _shared_prompt_response_reason


# Server-side allowlist mirrored from api/routes/processes.py::process_action.
# Keep in sync — adding a new server action requires explicit client opt-in.
RESPONSE_ACTION_ALLOWLIST: frozenset[str] = frozenset({
    "suspend", "resume", "kill", "kill-tree", "quarantine",
})

# Minimum gap between two consecutive response-action button clicks. Stops
# operators from rage-clicking "Kill" three times if the first call is
# slow and accidentally killing siblings spawned in the meantime.
RESPONSE_DEBOUNCE_SECONDS = 1.0


class _ProcessAuditMirrorShim:
    """Minimal `AuditLogStore`-shaped object so `install_backend_mirror`
    can wire fire-and-forget POSTs to `/audit/desktop` for the Process
    Hunt console without rewriting its inline JSON persistence.

    Process Hunt predates the shared `AuditLogStore` and writes audit
    rows directly with `save_process_audit_log`. Rather than refactor
    that path, we hand the mirror helper a tiny shim that just stores
    the callback; `append_process_audit` calls `fire(entry)` after
    each successful append.
    """

    def __init__(self) -> None:
        self._callback = None

    def set_mirror_callback(self, callback) -> None:
        self._callback = callback

    def fire(self, entry: dict) -> None:
        if self._callback is None:
            return
        try:
            self._callback(entry)
        except Exception:
            # Mirror failure must not crash the controller — local
            # JSON persistence is the source of truth.
            return


class ProcessHuntWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        # Late-binding lambda — tests override `risk_policy_path` on the
        # instance after construction to point at a tmp file.
        self._risk_policy_cache = RiskPolicyCache(lambda: self.risk_policy_path())
        self._last_response_click: dict[str, float] = {}
        # Evidence frozen snapshot: when an analyst is actively
        # investigating a target we keep the first-seen profile so a
        # background refresh doesn't mutate the viewport mid-decision.
        self._evidence_freeze: dict | None = None
        # PID-only reputation entries get a separate set so we can mark
        # them stale across reboots — OS PIDs are reused.
        self._pid_only_reputation_keys: set[str] = set()
        # Backend audit mirror — same wiring all other consoles use,
        # via a shim because Process Hunt has its own audit persistence.
        self._audit_mirror_shim = _ProcessAuditMirrorShim()
        _install_audit_mirror(self._audit_mirror_shim, app, source_slug="process")

    def build_tab(self) -> QWidget:
        return self._build_processes_page()

    def _build_processes_page(self) -> QWidget:
        app = self.app
        w = QWidget()
        w.setProperty("no_vertical_scroll", True)
        l = QVBoxLayout(w)
        l.setContentsMargins(6, 6, 6, 6)
        l.setSpacing(6)

        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(10)
        title_block = QWidget()
        title_layout = QVBoxLayout(title_block)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)
        title = QLabel("Process Hunt Console")
        title.setStyleSheet("font-size:16px;font-weight:800;color:#f4f7fb;")
        subtitle = QLabel("Prioritize live processes by provenance, signature, behavior, network exposure, and response readiness.")
        subtitle.setStyleSheet("color:#96a5b8;font-size:11px;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        header_layout.addWidget(title_block, 1)
        app.process_hunt_badge = QLabel("Hunt: not loaded")
        app.process_hunt_badge.setStyleSheet("background:#4a5568;color:white;padding:5px 10px;border-radius:8px;font-weight:800;font-size:11px;")
        header_layout.addWidget(app.process_hunt_badge, 0, Qt.AlignTop | Qt.AlignRight)
        l.addWidget(header)

        app.process_kpi_total = QLabel("--")
        app.process_kpi_elevated = QLabel("--")
        app.process_kpi_unsigned = QLabel("--")
        app.process_kpi_response = QLabel("--")
        app.process_kpi_total_sub = QLabel("loaded processes")
        app.process_kpi_elevated_sub = QLabel("risk >= medium")
        app.process_kpi_unsigned_sub = QLabel("signature gaps")
        app.process_kpi_response_sub = QLabel("selected target")
        kpis = QWidget()
        kpis.setMaximumHeight(70)
        kpi_layout = QHBoxLayout(kpis)
        kpi_layout.setContentsMargins(0, 0, 0, 0)
        kpi_layout.setSpacing(8)
        # KPI tiles double as filter shortcuts — clicking ELEVATED snaps
        # the risk filter to "High", clicking UNSIGNED filters by
        # signature gap, and clicking TOTAL clears all filters.
        kpi_layout.addWidget(
            self._kpi_tile("TOTAL", app.process_kpi_total, app.process_kpi_total_sub, "#7fd7ff",
                           on_click=self._kpi_filter_clear, tooltip="Click: clear all filters"),
            1,
        )
        kpi_layout.addWidget(
            self._kpi_tile("ELEVATED", app.process_kpi_elevated, app.process_kpi_elevated_sub, "#f4c26b",
                           on_click=lambda: self._kpi_filter_apply(risk="High"),
                           tooltip="Click: filter to High risk"),
            1,
        )
        kpi_layout.addWidget(
            self._kpi_tile("UNSIGNED", app.process_kpi_unsigned, app.process_kpi_unsigned_sub, "#ff8f70",
                           on_click=lambda: self._kpi_filter_apply(text="unsigned"),
                           tooltip="Click: filter by signature gap"),
            1,
        )
        kpi_layout.addWidget(
            self._kpi_tile("RESPONSE", app.process_kpi_response, app.process_kpi_response_sub, "#7fe39d"),
            1,
        )
        l.addWidget(kpis)

        filters = QFrame()
        filters.setProperty("card", True)
        filters.setMaximumHeight(44)
        filters_layout = QHBoxLayout(filters)
        filters_layout.setContentsMargins(8, 5, 8, 5)
        filters_layout.setSpacing(8)
        filter_label = QLabel("Queue")
        filter_label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;")
        app.process_filter_text = QLineEdit()
        app.process_filter_text.setPlaceholderText("Filter by name, PID, user, path, signature, reason")
        app.process_filter_text.setMaximumHeight(28)
        app.process_filter_risk = QComboBox()
        app.process_filter_risk.addItems(["All risk", "Critical", "High", "Medium", "Low"])
        app.process_filter_risk.setMaximumHeight(28)
        app.process_filter_state = QComboBox()
        app.process_filter_state.addItems(["All states", "Unreviewed", "Investigating", "Benign", "Suspicious", "Contained"])
        app.process_filter_state.setMaximumHeight(28)
        app.process_provider_readiness = QLabel("")
        app.process_provider_readiness.setTextFormat(Qt.RichText)
        app.process_provider_readiness.setStyleSheet("color:#c8d8ea;font-size:10px;font-weight:700;")
        app.process_command_hint = QLabel("Select a row to inspect. Check rows only for bulk actions.")
        app.process_command_hint.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:700;")
        app.process_command_hint.setMinimumWidth(190)
        app.process_command_hint.setMaximumWidth(320)
        app.process_job_status = QLabel("Jobs: idle")
        app.process_job_status.setStyleSheet("color:#7fe39d;font-size:10px;font-weight:800;")
        app.process_job_status.setFixedWidth(78)
        app.process_cancel_btn = QPushButton("Cancel Job")
        app.process_cancel_btn.setFixedHeight(26)
        app.process_cancel_btn.setFixedWidth(94)
        app.process_cancel_btn.setEnabled(False)
        app.process_cancel_btn.clicked.connect(self.cancel_process_job)
        app.process_dry_run_toggle = QCheckBox("Dry-run")
        app.process_dry_run_toggle.setToolTip("Simulate response actions and write audit without calling the backend action endpoint.")
        app.process_dry_run_toggle.setStyleSheet("color:#ffcf7a;font-size:10px;font-weight:800;")
        app.process_filter_text.textChanged.connect(self.apply_process_filters)
        app.process_filter_risk.currentTextChanged.connect(self.apply_process_filters)
        app.process_filter_state.currentTextChanged.connect(self.apply_process_filters)
        filters_layout.addWidget(filter_label)
        filters_layout.addWidget(app.process_filter_text, 2)
        filters_layout.addWidget(app.process_filter_risk)
        filters_layout.addWidget(app.process_filter_state)
        filters_layout.addWidget(app.process_provider_readiness, 1)
        filters_layout.addWidget(app.process_command_hint, 1)
        filters_layout.addWidget(app.process_job_status)
        filters_layout.addWidget(app.process_cancel_btn)
        filters_layout.addWidget(app.process_dry_run_toggle)
        l.addWidget(filters)

        s = QSplitter(Qt.Horizontal)
        s.setHandleWidth(2)
        app.process_inventory = []
        app.process_triage_state: dict[str, str] = {}
        app.process_audit_log: list[dict[str, str]] = self.load_process_audit_log()
        app.process_reputation_cache: dict[str, dict] = self.load_process_reputation_cache()
        app.process_command_buttons: dict[str, QPushButton] = {}
        app.process_async_jobs: list[tuple[QThread, ProcessWorker]] = []
        app.process_active_job: dict | None = None
        app.process_job_history: list[dict[str, str]] = []
        app.proc_table = QTableWidget(0, 9)
        app.proc_table.setHorizontalHeaderLabels(["Risk", "PID", "Name", "State", "User", "CPU %", "Memory %", "Signature", "Reasons"])
        app.proc_table.itemSelectionChanged.connect(app.show_selected_process)
        app.proc_table.cellClicked.connect(self.activate_process_row)
        app.proc_table.itemChanged.connect(lambda _item: self.update_provider_readiness())
        app._style_table(app.proc_table)
        app.proc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        app.proc_table.setSelectionMode(QAbstractItemView.SingleSelection)
        app.proc_table.setSortingEnabled(True)
        header = app.proc_table.horizontalHeader()
        header.setSortIndicatorShown(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(8, QHeaderView.Stretch)
        process_list_card = app._panel_card("Risk-Ranked Processes", app.proc_table, app._open_process_table_panel)
        app.proc_detail = QTextEdit()
        app.proc_detail.setReadOnly(True)
        app.proc_detail.setMinimumHeight(180)
        app.proc_detail.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.proc_detail.setHtml(self._empty_detail_html())
        process_detail_card = app._panel_card("Selected Process Posture", app.proc_detail, app._open_process_detail_panel)
        app.hunt_out = QTextEdit()
        app.hunt_out.setReadOnly(True)
        app.hunt_out.setMinimumHeight(180)
        app.hunt_out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.hunt_out.setPlaceholderText("Analysis, triage, trace, YARA, strings, and AI results will appear here.")
        app.hunt_out.setHtml(self.empty_state_html("Ready for investigation", "Load processes, select a target, then run triage, forensics, intel enrichment, or response."))
        app.tree_view = QTreeWidget()
        app.tree_view.setHeaderLabels(["Process Tree", "PID"])
        app.tree_view.setMinimumHeight(180)
        app.tree_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.tree_view.setToolTip("Process lineage will appear here after you build a tree from the selected process.")
        app.internals_table = QTableWidget(0, 4)
        app.internals_table.setHorizontalHeaderLabels(["Kind", "Path / Detail", "Mode / Perms", "FD / Size"])
        app._style_table(app.internals_table)
        app.internals_table.setMinimumHeight(180)
        app.internals_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        investigation_tabs = QTabWidget()
        investigation_tabs.setDocumentMode(True)
        investigation_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        investigation_tabs.setStyleSheet(
            "QTabWidget::pane{border:none;margin-top:0;padding-top:0;}"
            "QTabBar::tab{margin-right:2px;}"
        )
        investigation_tabs.addTab(app.hunt_out, "Output")
        investigation_tabs.addTab(app.tree_view, "Tree")
        investigation_tabs.addTab(app.internals_table, "Internals")
        app.process_audit_view = QTextEdit()
        app.process_audit_view.setReadOnly(True)
        app.process_audit_view.setHtml(self.empty_state_html("No process actions yet", "Response, state changes, and high-impact commands will be written here with actor, target, and result."))
        investigation_tabs.addTab(app.process_audit_view, "Audit")
        app.process_timeline_view = QTextEdit()
        app.process_timeline_view.setReadOnly(True)
        app.process_timeline_view.setHtml(self.empty_state_html("No process timeline", "Select a process to see start, reputation, triage, and response events."))
        investigation_tabs.addTab(app.process_timeline_view, "Timeline")
        app.process_provider_view = QTextEdit()
        app.process_provider_view.setReadOnly(True)
        app.process_provider_view.setHtml(self.render_provider_readiness_html())
        investigation_tabs.addTab(app.process_provider_view, "Providers")
        app.process_job_view = QTextEdit()
        app.process_job_view.setReadOnly(True)
        app.process_job_view.setHtml(self.render_job_status_html())
        investigation_tabs.addTab(app.process_job_view, "Jobs")
        app.process_risk_policy_view = QTextEdit()
        app.process_risk_policy_view.setReadOnly(True)
        app.process_risk_policy_view.setHtml(self.render_risk_policy_html())
        investigation_tabs.addTab(app.process_risk_policy_view, "Risk Policy")
        investigation_card = QFrame()
        investigation_card.setProperty("card", True)
        investigation_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        investigation_layout = QVBoxLayout(investigation_card)
        investigation_layout.setContentsMargins(12, 6, 12, 8)
        investigation_layout.setSpacing(0)
        investigation_layout.addWidget(investigation_tabs, 1)
        actions = QFrame()
        actions.setProperty("card", True)
        actions_layout = QVBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(0)
        process_capabilities = self.command_capability_map()
        action_items = [
            ("Run Monitor", app.run_monitor),
            ("Load Processes", app.refresh_processes),
            ("Refresh Processes", app.refresh_processes),
            ("Auto Triage", app.run_auto_triage),
            ("AI Analyst", app.run_ai_analysis),
            ("Clear Output", self.clear_analysis_output),
            ("Scan Selected", app.scan_selected_processes_vt),
            ("Scan All", app.scan_all_processes_vt),
            ("Scan Executable", app.scan_selected_process),
            ("Memory Analysis", app.run_memory_analysis),
            ("Executable YARA", app.run_yara_scan),
            ("Sandbox", app.run_sandbox_trace),
            ("Process Tree", app.load_process_tree),
            ("Internals", app.load_selected_internals),
            ("Strings", app.run_strings_analysis),
            ("Use Process Hash", app.use_selected_process_hash),
            ("Use Process IP", app.use_selected_process_ip),
            ("Copy Command", self.copy_selected_command_line),
            ("Export Package", self.export_selected_process_package),
            ("Clear Reputation", self.clear_reputation_cache),
            ("Lookup Hash", app.lookup_hash),
            ("Lookup IP", app.lookup_ip),
            ("Investigating", lambda: self.set_selected_triage_state("Investigating")),
            ("Suspicious", lambda: self.set_selected_triage_state("Suspicious")),
            ("Benign", lambda: self.set_selected_triage_state("Benign")),
            ("Contained", lambda: self.set_selected_triage_state("Contained")),
            ("Triage Respond", app.run_triage_response),
            ("Suspend", lambda: app.process_action("suspend")),
            ("Resume", lambda: app.process_action("resume")),
            ("Kill", lambda: app.process_action("kill")),
            ("Kill Tree", lambda: app.process_action("kill-tree")),
            ("Quarantine", lambda: app.process_action("quarantine")),
        ]
        button_labels = {
            "Run Monitor": "Run Monitor",
            "Load Processes": "Load Proc",
            "Refresh Processes": "Refresh",
            "Auto Triage": "Auto Triage",
            "AI Analyst": "AI Analyst",
            "Clear Output": "Clear",
            "Scan Selected": "Scan Sel",
            "Scan All": "Scan All",
            "Scan Executable": "Scan EXE",
            "Memory Analysis": "Memory",
            "Executable YARA": "EXE YARA",
            "Process Tree": "Tree",
            "Internals": "Internals",
            "Strings": "Strings",
            "Use Process Hash": "Use Hash",
            "Use Process IP": "Use IP",
            "Copy Command": "Copy Cmd",
            "Export Package": "Export",
            "Clear Reputation": "Clear Rep",
            "Lookup Hash": "Lookup Hash",
            "Lookup IP": "Lookup IP",
            "Investigating": "Investigate",
            "Suspicious": "Suspicious",
            "Benign": "Benign",
            "Contained": "Contained",
            "Triage Respond": "Respond",
            "Suspend": "Suspend",
            "Resume": "Resume",
            "Kill": "Kill",
            "Kill Tree": "Kill Tree",
            "Quarantine": "Quarantine",
        }
        action_lookup = {text: fn for text, fn in action_items}
        capability_hints = {
            "can_run_hunt": "Requires analyst or admin access.",
            "can_run_triage": "Requires analyst or admin access.",
            "can_manage_process_actions": "Requires admin access with dangerous process actions enabled by lab policy.",
        }

        def command_row(groups_for_row: list[tuple[str, list[str], bool]]) -> QWidget:
            row_wrap = QWidget()
            row_layout = QHBoxLayout(row_wrap)
            row_layout.setContentsMargins(6, 4, 6, 4)
            row_layout.setSpacing(7)
            for group_name, names, danger in groups_for_row:
                group = QFrame()
                group.setProperty("card", True)
                group.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
                group_layout = QHBoxLayout(group)
                group_layout.setContentsMargins(6, 3, 6, 3)
                group_layout.setSpacing(4)
                label = QLabel(group_name)
                label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;")
                label.setFixedWidth(54)
                group_layout.addWidget(label)
                for action_name in names:
                    btn = QPushButton(button_labels.get(action_name, action_name))
                    btn.clicked.connect(
                        lambda _checked=False, name=action_name, callback=action_lookup[action_name]: (
                            self.run_process_command(name, callback)
                        )
                    )
                    btn.setCursor(QCursor(Qt.PointingHandCursor))
                    app.process_command_buttons[action_name] = btn
                    capability = process_capabilities.get(action_name)
                    if capability:
                        app._bind_capability(btn, capability)
                        btn.setToolTip(capability_hints.get(capability, "Requires an authorized role."))
                    btn.setFixedHeight(27)
                    btn.setFixedWidth(self.command_button_width(action_name, btn.sizeHint().width()))
                    if danger:
                        base, border = "#3f2430", "#6b3a4d"
                        hover_bg, hover_bd = "#542e3c", "#8a2a2a"
                        press_bg, press_bd = "#6b2436", "#a83232"
                        dis_bg, dis_fg, dis_bd = "#241419", "#7a5a5a", "#3a2024"
                    else:
                        base, border = "#1a2a3d", "#2c4260"
                        hover_bg, hover_bd = "#23394f", "#4a6c95"
                        press_bg, press_bd = "#2f4f70", "#5d8aa8"
                        dis_bg, dis_fg, dis_bd = "#141d28", "#5e6f80", "#23303f"
                    btn.setStyleSheet(
                        f"QPushButton{{background:{base};color:#c8d8ea;border:1px solid {border};"
                        "border-radius:7px;padding:2px 6px;font-weight:700;font-size:10px;}"
                        f"QPushButton:hover{{background:{hover_bg};border-color:{hover_bd};color:#eaf2fb;}}"
                        f"QPushButton:pressed{{background:{press_bg};border-color:{press_bd};padding-top:3px;padding-bottom:1px;}}"
                        f"QPushButton:disabled{{background:{dis_bg};color:{dis_fg};border-color:{dis_bd};}}"
                    )
                    group_layout.addWidget(btn)
                row_layout.addWidget(group)
            row_layout.addStretch(1)
            return row_wrap

        for row_groups in self.command_group_rows():
            actions_layout.addWidget(command_row(row_groups))
        app.proc_table.setMinimumHeight(260)
        app.proc_detail.setMinimumHeight(168)
        investigation_tabs.setMinimumHeight(260)
        app.proc_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        s.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        actions.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        s.setMinimumHeight(420)
        s.setChildrenCollapsible(False)
        right_stack = QWidget()
        right_stack_layout = QVBoxLayout(right_stack)
        right_stack_layout.setContentsMargins(0, 0, 0, 0)
        right_stack_layout.setSpacing(8)
        right_stack_layout.addWidget(process_detail_card, 2)
        right_stack_layout.addWidget(investigation_card, 3)
        s.addWidget(process_list_card)
        s.addWidget(right_stack)
        s.setStretchFactor(0, 50)
        s.setStretchFactor(1, 50)
        QTimer.singleShot(0, lambda: s.setSizes([980, 980]))
        QTimer.singleShot(0, self.update_provider_readiness)
        QTimer.singleShot(0, self.update_command_affordance)
        l.addWidget(s, 1)
        actions.setMaximumHeight(82)
        l.addWidget(actions, 0)
        return w

    def _kpi_tile(self, title: str, value: QLabel, sub: QLabel, accent: str,
                  *, on_click=None, tooltip: str | None = None) -> QWidget:
        tile = QFrame()
        tile.setProperty("card", True)
        tile.setMinimumHeight(62)
        tile.setMaximumHeight(68)
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(0)
        label = QLabel(title)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;")
        value.setStyleSheet(f"color:{accent};font-size:18px;font-weight:800;")
        sub.setStyleSheet("color:#c8d8ea;font-size:10px;")
        sub.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addWidget(sub)
        if on_click is not None:
            tile.setCursor(QCursor(Qt.PointingHandCursor))
            if tooltip:
                tile.setToolTip(tooltip)
            # Lambda binds the handler — Qt's event filter would have
            # been overkill for a one-shot click target.
            tile.mousePressEvent = lambda _event, fn=on_click: fn()
        return tile

    def _kpi_filter_clear(self) -> None:
        app = self.app
        if not hasattr(app, "process_filter_text"):
            return
        app.process_filter_text.clear()
        if hasattr(app, "process_filter_risk"):
            app.process_filter_risk.setCurrentText("All risk")
        if hasattr(app, "process_filter_state"):
            app.process_filter_state.setCurrentText("All states")
        # The combos already trigger apply_process_filters via their
        # currentTextChanged signal; the explicit call below covers the
        # case where the user cleared an already-empty filter.
        self.apply_process_filters()
        app.statusBar().showMessage("Process filters cleared.")

    def _kpi_filter_apply(self, *, text: str | None = None, risk: str | None = None) -> None:
        app = self.app
        if not hasattr(app, "process_filter_text"):
            return
        if text is not None:
            app.process_filter_text.setText(text)
        if risk is not None and hasattr(app, "process_filter_risk"):
            app.process_filter_risk.setCurrentText(risk)
        self.apply_process_filters()
        descriptor = ", ".join(part for part in [f"text=`{text}`" if text else "", f"risk=`{risk}`" if risk else ""] if part)
        app.statusBar().showMessage(f"Process filter applied: {descriptor or 'no change'}.")

    def command_button_text(self, label: str, action_name: str, danger: bool) -> str:
        if danger:
            return f"{label} [DANGER]"
        if action_name in {"Scan Selected", "Scan All", "Scan Executable", "Lookup Hash", "Lookup IP"}:
            return f"{label} [PROV]"
        if action_name in {"Triage Respond"}:
            return f"{label} [ADMIN]"
        if action_name in {"Clear Reputation"}:
            return f"{label} [CACHE]"
        return label

    def command_button_width(self, action_name: str, hint_width: int) -> int:
        compact = {
            "Refresh Processes": 86,
            "Clear Output": 78,
            "Auto Triage": 94,
            "AI Analyst": 104,
            "Scan Selected": 82,
            "Scan All": 78,
            "Scan Executable": 82,
            "Memory Analysis": 82,
            "Executable YARA": 86,
            "Sandbox": 78,
            "Process Tree": 70,
            "Internals": 82,
            "Strings": 72,
            "Use Process Hash": 86,
            "Use Process IP": 78,
            "Copy Command": 82,
            "Export Package": 70,
            "Clear Reputation": 82,
            "Lookup Hash": 92,
            "Lookup IP": 82,
            "Investigating": 86,
            "Suspicious": 88,
            "Benign": 74,
            "Contained": 88,
            "Triage Respond": 82,
            "Suspend": 76,
            "Resume": 74,
            "Kill": 58,
            "Kill Tree": 78,
            "Quarantine": 92,
        }
        return compact.get(action_name, max(62, min(94, hint_width + 8)))

    def command_group_rows(self) -> list[list[tuple[str, list[str], bool]]]:
        return [
            [
                ("Load", ["Run Monitor", "Load Processes", "Refresh Processes", "Clear Output"], False),
                ("Triage", ["Auto Triage", "AI Analyst", "Scan Selected", "Scan All", "Scan Executable"], False),
                ("Intel", ["Use Process Hash", "Use Process IP", "Copy Command", "Export Package", "Clear Reputation", "Lookup Hash", "Lookup IP"], False),
            ],
            [
                ("State", ["Investigating", "Suspicious", "Benign", "Contained"], False),
                ("Forensics", ["Memory Analysis", "Executable YARA", "Sandbox", "Process Tree", "Internals", "Strings"], False),
                ("Response", ["Triage Respond", "Suspend", "Resume", "Kill", "Kill Tree", "Quarantine"], True),
            ],
        ]

    def command_capability_map(self) -> dict[str, str]:
        hunt_actions = {
            "Refresh Processes", "Scan Selected", "Scan All", "Scan Executable", "Memory Analysis",
            "Internals", "Strings", "Executable YARA", "Sandbox", "Process Tree", "AI Analyst",
            "Use Process Hash", "Use Process IP", "Copy Command", "Export Package", "Clear Reputation",
            "Lookup Hash", "Lookup IP", "Investigating", "Suspicious", "Benign", "Contained",
        }
        mapping = {name: "can_run_hunt" for name in hunt_actions}
        mapping["Run Monitor"] = "can_run_monitor"
        mapping["Load Processes"] = "can_run_hunt"
        mapping["Auto Triage"] = "can_run_triage"
        for name in {"Triage Respond", "Suspend", "Resume", "Kill", "Kill Tree", "Quarantine"}:
            mapping[name] = "can_manage_process_actions"
        return mapping

    def command_access_matrix(self, capabilities: dict[str, bool]) -> dict[str, bool]:
        matrix = {}
        for action, capability in self.command_capability_map().items():
            matrix[action] = bool(capabilities.get(capability))
        return matrix

    def focus_hunt(self) -> None:
        self.app._switch_to_tab("Processes")

    def clear_analysis_output(self) -> None:
        app = self.app
        app.hunt_out.setHtml(self.empty_state_html("Ready for investigation", "Select a process, then run triage, memory, YARA, strings, tree, internals, or sandbox trace."))
        app.tree_view.clear()
        app.internals_table.setRowCount(0)
        app.statusBar().showMessage("Process investigation output cleared.")

    def run_async_job(self, label: str, work, on_success, on_failure=None, *, timeout_seconds: int = 120) -> None:
        app = self.app
        if getattr(app, "process_active_job", None):
            app.statusBar().showMessage(f"Another process job is already running: {app.process_active_job.get('label')}")
            app.hunt_out.setHtml(self.empty_state_html("Job already running", "Cancel or wait for the current job before starting another process operation.", accent="#f4c26b"))
            self.update_job_status_view()
            return
        thread = QThread(app)
        worker = ProcessWorker(work)
        worker.moveToThread(thread)
        job = {"id": f"job-{int(time.time() * 1000) % 1000000:06d}", "label": label, "thread": thread, "worker": worker, "cancelled": False, "started": time.time(), "timeout_seconds": timeout_seconds, "status": "running"}

        def cleanup() -> None:
            self.record_job_history(job)
            was_active = getattr(app, "process_active_job", None) is job
            try:
                app.process_async_jobs.remove((thread, worker))
            except ValueError:
                pass
            if was_active:
                app.process_active_job = None
            if was_active and hasattr(app, "process_job_status"):
                app.process_job_status.setText("Jobs: idle")
            if was_active and hasattr(app, "process_cancel_btn"):
                app.process_cancel_btn.setEnabled(False)
            self.update_job_status_view()
            thread.quit()
            thread.wait(2000)
            worker.deleteLater()
            thread.deleteLater()

        def handle_success(result) -> None:
            if job.get("cancelled"):
                cleanup()
                return
            job["status"] = "completed"
            job["finished"] = time.time()
            on_success(result)
            cleanup()

        def handle_failure(message: str) -> None:
            if job.get("cancelled"):
                cleanup()
                return
            job["status"] = "failed"
            job["error"] = message
            job["finished"] = time.time()
            if on_failure:
                on_failure(message)
            else:
                app.statusBar().showMessage(f"{label} failed: {message}")
            cleanup()

        def timeout_job() -> None:
            if getattr(app, "process_active_job", None) is not job:
                return
            job["cancelled"] = True
            job["status"] = "timeout"
            job["finished"] = time.time()
            self.record_job_history(job)
            app.process_active_job = None
            if hasattr(app, "process_job_status"):
                app.process_job_status.setText("Jobs: timeout")
            if hasattr(app, "process_cancel_btn"):
                app.process_cancel_btn.setEnabled(False)
            self.update_job_status_view()
            app.hunt_out.setHtml(self.empty_state_html("Job timed out", f"{label} exceeded {timeout_seconds}s and was cancelled.", accent="#ff8f70"))
            app.statusBar().showMessage(f"{label} timed out.")

        thread.started.connect(worker.run)
        worker.finished.connect(handle_success)
        worker.failed.connect(handle_failure)
        app.process_async_jobs.append((thread, worker))
        app.process_active_job = job
        if hasattr(app, "process_job_status"):
            app.process_job_status.setText(f"Jobs: {label}")
        if hasattr(app, "process_cancel_btn"):
            app.process_cancel_btn.setEnabled(True)
        self.update_job_status_view()
        app.statusBar().showMessage(f"{label} running in background...")
        QTimer.singleShot(max(1, int(timeout_seconds)) * 1000, timeout_job)
        thread.start()

    def cancel_process_job(self) -> None:
        app = self.app
        job = getattr(app, "process_active_job", None)
        if not job:
            app.statusBar().showMessage("No process job is running.")
            return
        job["cancelled"] = True
        job["status"] = "cancelled"
        job["finished"] = time.time()
        label = str(job.get("label") or "Process job")
        self.record_job_history(job)
        app.process_active_job = None
        if hasattr(app, "process_job_status"):
            app.process_job_status.setText("Jobs: cancelled")
        if hasattr(app, "process_cancel_btn"):
            app.process_cancel_btn.setEnabled(False)
        self.update_job_status_view()
        app.hunt_out.setHtml(self.empty_state_html("Job cancelled", f"{label} was cancelled by the operator.", accent="#f4c26b"))
        app.statusBar().showMessage(f"{label} cancelled.")

    def render_job_status_html(self) -> str:
        app = self.app
        job = getattr(app, "process_active_job", None)
        if not job:
            history = getattr(app, "process_job_history", []) or []
            if not history:
                return self.empty_state_html("No running process jobs", "Refresh, scan, memory, YARA, sandbox, strings, tree, internals, triage, and AI jobs run in the background when started.", accent="#7fd7ff")
            rows = "".join(
                "<tr>"
                f"<td>{html.escape(str(item.get('time', '-')))}</td>"
                f"<td>{html.escape(str(item.get('id', '-')))}</td>"
                f"<td><b>{html.escape(str(item.get('label', '-')))}</b></td>"
                f"<td style='color:{self.audit_status_color(str(item.get('status', 'info')))};font-weight:800;'>{html.escape(str(item.get('status', '-')))}</td>"
                f"<td>{html.escape(str(item.get('elapsed', '-')))}</td>"
                f"<td>{html.escape(str(item.get('error', '')))}</td>"
                "</tr>"
                for item in history[:10]
            )
            return (
                "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Recent Process Jobs</h3>"
                "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;'>"
                "<tr style='color:#96a5b8;'><th align='left'>Time</th><th align='left'>Job ID</th><th align='left'>Operation</th><th align='left'>Status</th><th align='left'>Elapsed</th><th align='left'>Error</th></tr>"
                + rows
                + "</table>"
            )
        started = float(job.get("started", time.time()) or time.time())
        elapsed = max(0.0, time.time() - started)
        timeout = int(job.get("timeout_seconds", 0) or 0)
        remaining = max(0, timeout - int(elapsed)) if timeout else 0
        return (
            "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Running Job</h3>"
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Job ID</th><th align='left'>Operation</th><th align='left'>Status</th><th align='left'>Elapsed</th><th align='left'>Timeout</th><th align='left'>Cancel Semantics</th></tr>"
            f"<tr><td>{html.escape(str(job.get('id', '-')))}</td><td><b>{html.escape(str(job.get('label', '-')))}</b></td><td style='color:#7fe39d;font-weight:800;'>{html.escape(str(job.get('status', 'running')))}</td><td>{elapsed:.1f}s</td><td>{remaining}s remaining</td><td>Best-effort UI cancellation; backend request may finish server-side if already dispatched.</td></tr>"
            "</table>"
        )

    def update_job_status_view(self) -> None:
        if hasattr(self.app, "process_job_view"):
            self.app.process_job_view.setHtml(self.render_job_status_html())

    def record_job_history(self, job: dict) -> None:
        app = self.app
        status = str(job.get("status") or "running")
        if status == "running" or not hasattr(app, "process_job_history"):
            return
        job_id = str(job.get("id") or "")
        if any(str(item.get("id")) == job_id for item in app.process_job_history):
            return
        started = float(job.get("started", time.time()) or time.time())
        finished = float(job.get("finished", time.time()) or time.time())
        app.process_job_history.insert(0, {
            "time": time.strftime("%H:%M:%S", time.localtime(finished)),
            "id": job_id,
            "label": str(job.get("label") or "-"),
            "status": status,
            "elapsed": f"{max(0.0, finished - started):.1f}s",
            "error": str(job.get("error") or ""),
        })
        del app.process_job_history[20:]

    def empty_state_html(self, title: str, body: str, *, accent: str = "#7fd7ff") -> str:
        return (
            f"<div style='border:1px solid #243446;border-radius:8px;padding:12px;background:#101a24;'>"
            f"<h3 style='margin:0 0 6px;color:{accent};'>{html.escape(title)}</h3>"
            f"<p style='margin:0;color:#96a5b8;'>{html.escape(body)}</p>"
            "</div>"
        )

    def run_process_command(self, action_name: str, callback) -> None:
        app = self.app
        app.statusBar().showMessage(f"{action_name} requested.")
        target_required = {
            "Auto Triage", "AI Analyst", "Scan Selected", "Scan Executable", "Memory Analysis",
            "Executable YARA", "Sandbox", "Process Tree", "Internals", "Strings", "Use Process Hash",
            "Use Process IP", "Copy Command", "Export Package", "Investigating", "Suspicious", "Benign", "Contained",
            "Triage Respond", "Suspend", "Resume", "Kill", "Kill Tree", "Quarantine",
        }
        if action_name in target_required and not self.selected_identity():
            app.hunt_out.setHtml(self.empty_state_html("No target selected", "Select a process row before running this command. Bulk checkboxes are only for grouped operations.", accent="#f4c26b"))
            app.statusBar().showMessage("No target selected.")
            self.update_command_affordance()
            return
        if action_name in {"Scan Selected", "Scan All", "Scan Executable", "Lookup Hash", "Lookup IP"} and not any(self.scan_payload().values()):
            app.hunt_out.setHtml(self.empty_state_html("Threat intel provider missing", "Configure VirusTotal, MalwareBazaar, or YARAify credentials before running enrichment.", accent="#f4c26b"))
            app.statusBar().showMessage("Threat intel provider missing.")
            self.update_command_affordance()
            return
        try:
            callback()
        except Exception as exc:
            app._show_error(app.hunt_out, f"{action_name} failed", exc)
            app.statusBar().showMessage(f"{action_name} failed: {exc}")
        finally:
            self.update_command_affordance()

    def update_command_affordance(self) -> None:
        app = self.app
        if not hasattr(app, "process_command_hint"):
            return
        selected = self.selected_identity()
        providers_ready = any(self.scan_payload().values())
        if not selected:
            app.process_command_hint.setText("No target selected")
            hint = "Select a process row first."
        elif not providers_ready:
            pid, name = selected
            app.process_command_hint.setText(f"Target: {name} ({pid}) | Intel providers missing")
            hint = "Target selected. Intel enrichment needs VT, MalwareBazaar, or YARAify credentials."
        else:
            pid, name = selected
            app.process_command_hint.setText(f"Target: {name} ({pid}) | Providers ready")
            hint = "Target selected. Commands are ready."
        for action_name, btn in getattr(app, "process_command_buttons", {}).items():
            policy = self.command_policy_label(action_name)
            if not btn.isEnabled():
                btn.setToolTip(btn.toolTip() or f"{policy} Blocked by current RBAC policy.")
                continue
            if action_name in {"Scan Selected", "Scan All", "Scan Executable", "Lookup Hash", "Lookup IP"} and not providers_ready:
                btn.setToolTip(f"{policy} Provider missing: configure VT, MalwareBazaar, or YARAify first.")
            elif action_name not in {"Run Monitor", "Load Processes", "Refresh Processes", "Clear Output", "Scan All"} and not selected:
                btn.setToolTip(f"{policy} No target selected: click a process row first.")
            else:
                btn.setToolTip(f"{policy} {hint}")

    def command_policy_label(self, action_name: str) -> str:
        if action_name in {"Triage Respond", "Suspend", "Resume", "Kill", "Kill Tree", "Quarantine"}:
            return "[DANGER][ADMIN]"
        if action_name in {"Scan Selected", "Scan All", "Scan Executable", "Lookup Hash", "Lookup IP"}:
            return "[PROVIDER]"
        if action_name == "Clear Reputation":
            return "[CACHE]"
        return "[ANALYST]"

    def copy_selected_command_line(self) -> None:
        app = self.app
        profile = getattr(app, "selected_process", None) or {}
        cmdline = profile.get("cmdline", "")
        if isinstance(cmdline, list):
            cmdline = " ".join(str(part) for part in cmdline)
        cmdline = str(cmdline or "").strip()
        if not cmdline:
            app.statusBar().showMessage("No command line available for the selected process.")
            return
        QGuiApplication.clipboard().setText(cmdline)
        self.append_process_audit("copy-command", str(profile.get("pid", "-")), str(profile.get("name", "-")), "copied command line to clipboard")
        app.statusBar().showMessage("Command line copied to clipboard.")

    def export_selected_process_package(self) -> None:
        app = self.app
        profile = getattr(app, "selected_process", None) or {}
        if not profile:
            app.hunt_out.setHtml(self.empty_state_html("No target selected", "Select a process before exporting an investigation package.", accent="#f4c26b"))
            return
        score, label, reasons = self.score_process(profile)
        package = {
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "workspace_id": app.workspace_id.text() if hasattr(app, "workspace_id") else "default",
            "actor": app.auth_context.get("role", "operator") if isinstance(getattr(app, "auth_context", None), dict) else "operator",
            "risk": {"label": label, "score": score, "reasons": reasons},
            "process": profile,
            "reputation": getattr(app, "process_reputation_cache", {}),
            "audit": getattr(app, "process_audit_log", []),
        }
        default_name = f"shadowlab-process-{profile.get('pid', 'target')}.json"
        target, _ = QFileDialog.getSaveFileName(app, "Export Process Investigation", default_name, "JSON Files (*.json)")
        if not target:
            return
        Path(target).write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding="utf-8")
        self.append_process_audit("export-package", str(profile.get("pid", "-")), str(profile.get("name", "-")), str(target))
        app.statusBar().showMessage(f"Process package exported: {target}")

    def reputation_cache_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "process-reputation-cache.json"

    def reputation_cache_ttl_seconds(self) -> int:
        return 7 * 24 * 60 * 60

    def audit_log_path(self) -> Path:
        # Persist audit log next to the reputation cache so forensic
        # chain (who ran what, when, why) survives an app crash. Used by
        # `append_process_audit` and reloaded on controller startup.
        return Path.cwd() / "shadowlab_out" / "process-audit-log.json"

    AUDIT_LOG_RETENTION = 500

    def load_process_reputation_cache(self) -> dict[str, dict]:
        path = self.reputation_cache_path()
        try:
            if not path.exists():
                return {}
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                return {}
            now = time.time()
            ttl = self.reputation_cache_ttl_seconds()
            kept: dict[str, dict] = {}
            for key, value in loaded.items():
                if not isinstance(value, dict):
                    continue
                if now - float(value.get("cached_at", 0) or 0) > ttl:
                    continue
                key_str = str(key)
                # PID-only verdicts (numeric key) are dropped on
                # restart — OS PIDs are reused so a stale "malicious"
                # tag would mis-classify a brand-new process.
                if value.get("_volatile") is True:
                    continue
                if key_str.isdigit():
                    continue
                kept[key_str] = value
            return kept
        except Exception:
            return {}

    def save_process_reputation_cache(self) -> None:
        path = self.reputation_cache_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Strip PID-only entries from disk so a crash/restart never
            # resurrects a verdict tied to a recycled PID.
            sanitized = {
                key: value
                for key, value in self.app.process_reputation_cache.items()
                if isinstance(value, dict) and value.get("_volatile") is not True and not str(key).isdigit()
            }
            path.write_text(json.dumps(sanitized, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            return

    def load_process_audit_log(self) -> list[dict[str, str]]:
        path = self.audit_log_path()
        try:
            if not path.exists():
                return []
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(loaded, list):
            return []
        # Newest-first on disk; drop anything older than retention.
        return [item for item in loaded if isinstance(item, dict)][: self.AUDIT_LOG_RETENTION]

    def save_process_audit_log(self) -> None:
        app = self.app
        path = self.audit_log_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            log = list(getattr(app, "process_audit_log", []) or [])[: self.AUDIT_LOG_RETENTION]
            path.write_text(json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            return

    def clear_reputation_cache(self) -> None:
        app = self.app
        app.process_reputation_cache.clear()
        path = self.reputation_cache_path()
        try:
            if path.exists():
                path.unlink()
        except Exception:
            pass
        self.append_process_audit("clear-reputation-cache", "-", "-", "local reputation cache cleared")
        app.hunt_out.setHtml(self.empty_state_html("Reputation cache cleared", "Cached process scan verdicts were removed from local storage.", accent="#7fe39d"))
        if getattr(app, "selected_process", None):
            score, label, reasons = self.score_process(app.selected_process)
            app.proc_detail.setHtml(self.render_process_detail(app.selected_process, score, label, reasons))

    def append_process_audit(self, action: str, pid: str, name: str, result: str, metadata: dict | None = None) -> None:
        app = self.app
        actor = ""
        workspace = ""
        if isinstance(getattr(app, "auth_context", None), dict):
            actor = str(app.auth_context.get("role") or app.auth_context.get("actor") or "operator")
        if hasattr(app, "workspace_id"):
            try:
                workspace = app.workspace_id.text().strip() or ""
            except Exception:
                workspace = ""
        metadata = metadata or {}
        entry = {
            "time": time.strftime("%H:%M:%S"),
            # ISO 8601 with offset for forensics; the short `time` field
            # above stays for the existing UI table rendering.
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z") or time.strftime("%Y-%m-%dT%H:%M:%S"),
            "request_id": str(metadata.get("request_id") or f"ui-{int(time.time() * 1000) % 1000000:06d}"),
            "actor": actor or "operator",
            "workspace": workspace or "default",
            "action": action,
            "target": f"{name} ({pid})",
            "result": result,
            "policy": str(metadata.get("policy") or self.audit_policy_for(action)),
            "mode": str(metadata.get("mode") or ("dry-run" if str(action).startswith("dry-run:") else "live")),
            "rollback": str(metadata.get("rollback") or "n/a"),
            "status": str(metadata.get("status") or self.audit_status_from_result(result)),
        }
        # Carry through structured reason metadata when supplied by
        # `process_action` so the JSON record on disk has ticket ID +
        # category instead of an opaque "reason: blah" string.
        for key in ("ticket_id", "reason_category", "reason_text"):
            if metadata.get(key):
                entry[key] = str(metadata.get(key))
        app.process_audit_log.insert(0, entry)
        # Trim in-memory tail so an angry click-storm doesn't OOM the UI.
        del app.process_audit_log[self.AUDIT_LOG_RETENTION:]
        # Best-effort persistence — disk failure is logged silently
        # because dropping the audit-render path on an I/O hiccup is
        # worse for forensics than a missing flush.
        self.save_process_audit_log()
        # Mirror to backend `/audit/desktop` (fire-and-forget). Same
        # cross-console pattern Antivirus / Enterprise / etc. use.
        self._audit_mirror_shim.fire(entry)
        self.update_process_timeline()
        rows = []
        for item in app.process_audit_log[:12]:
            status_color = self.audit_status_color(item.get("status", "info"))
            rows.append(
                "<tr>"
                f"<td>{html.escape(item['time'])}</td>"
                f"<td style='color:#96a5b8;'>{html.escape(item.get('request_id', '-'))}</td>"
                f"<td>{html.escape(item['actor'])}</td>"
                f"<td>{html.escape(item['action'])}</td>"
                f"<td>{html.escape(item['target'])}</td>"
                f"<td>{html.escape(item.get('mode', '-'))}</td>"
                f"<td>{html.escape(item.get('policy', '-'))}</td>"
                f"<td>{html.escape(item.get('rollback', '-'))}</td>"
                f"<td><span style='color:{status_color};font-weight:800;'>{html.escape(item.get('status', 'info'))}</span></td>"
                f"<td>{html.escape(item['result'])}</td>"
                "</tr>"
            )
        table = (
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Time</th><th align='left'>Request</th><th align='left'>Actor</th><th align='left'>Action</th><th align='left'>Target</th><th align='left'>Mode</th><th align='left'>Policy</th><th align='left'>Rollback</th><th align='left'>Status</th><th align='left'>Result</th></tr>"
            + "".join(rows)
            + "</table>"
        )
        app.process_audit_view.setHtml(table)

    def audit_status_from_result(self, result: str) -> str:
        value = str(result or "").lower()
        if "blocked" in value:
            return "blocked"
        if "failed" in value or "error" in value:
            return "failed"
        if "cancel" in value:
            return "cancelled"
        if "simulated" in value or "completed" in value or "cleared" in value:
            return "ok"
        return "info"

    def audit_status_color(self, status: str) -> str:
        return {
            "ok": "#7fe39d",
            "blocked": "#ffcf7a",
            "failed": "#ff6b8a",
            "cancelled": "#f4c26b",
        }.get(str(status).lower(), "#7fd7ff")

    def audit_policy_for(self, action: str) -> str:
        if str(action).startswith("dry-run:"):
            return "simulation"
        if action in {"kill", "kill-tree", "quarantine", "suspend", "resume", "triage-response", "respond", "Triage Respond"}:
            return "admin response"
        if action in {"reputation-scan", "clear-reputation-cache"}:
            return "intel/cache"
        if action in {"set-state", "copy-command", "export-package"}:
            return "operator workflow"
        return "local"

    def update_process_timeline(self) -> None:
        app = self.app
        if not hasattr(app, "process_timeline_view"):
            return
        profile = getattr(app, "selected_process", None) or {}
        events: list[dict[str, str]] = []
        create_time = profile.get("create_time")
        if isinstance(create_time, (int, float)) and create_time > 0:
            events.append({
                "time": time.strftime("%H:%M:%S", time.localtime(float(create_time))),
                "event": "process-start",
                "detail": f"{profile.get('name', '-')} ({profile.get('pid', '-')})",
            })
        if profile:
            events.append({"time": time.strftime("%H:%M:%S"), "event": "selected", "detail": f"{profile.get('name', '-')} ({profile.get('pid', '-')})"})
        for item in reversed(getattr(app, "process_audit_log", [])[:8]):
            events.append({"time": item.get("time", ""), "event": item.get("action", ""), "detail": f"{item.get('target', '')}: {item.get('result', '')}"})
        if not events:
            app.process_timeline_view.setHtml(self.empty_state_html("No process timeline", "Select a process to see start, reputation, triage, and response events."))
            return
        rows = "".join(
            f"<tr><td style='color:#96a5b8;'>{html.escape(event['time'])}</td><td><b>{html.escape(event['event'])}</b></td><td>{html.escape(event['detail'])}</td></tr>"
            for event in events[-12:]
        )
        app.process_timeline_view.setHtml(
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Time</th><th align='left'>Event</th><th align='left'>Detail</th></tr>"
            + rows
            + "</table>"
        )

    def current_checked_pids(self) -> set[str]:
        app = self.app
        checked_pids: set[str] = set()
        for row in range(app.proc_table.rowCount()):
            check_item = app.proc_table.item(row, 0)
            pid_item = app.proc_table.item(row, 1)
            if check_item and pid_item and check_item.checkState() == Qt.Checked:
                checked_pids.add(pid_item.text())
        return checked_pids

    def refresh_processes(self) -> None:
        app = self.app
        if hasattr(app, "process_hunt_badge"):
            app.process_hunt_badge.setText("Hunt: loading")
            app.process_hunt_badge.setStyleSheet("background:#4a5568;color:white;padding:7px 12px;border-radius:8px;font-weight:800;")
        if hasattr(app, "proc_detail"):
            app.proc_detail.setHtml(self.empty_state_html("Loading process inventory", "Collecting live process metadata, scoring weak signals, and rebuilding the hunt queue."))
        if hasattr(app, "hunt_out"):
            app.hunt_out.setHtml(self.empty_state_html("Loading processes", "The command surface will update when the process queue is ready."))
        app.statusBar().showMessage("Loading process inventory...")

        def failed(message: str) -> None:
            app._show_error(app.proc_detail, "Failed to load processes", Exception(message))
            if hasattr(app, "process_hunt_badge"):
                app.process_hunt_badge.setText("Hunt: failed")
                app.process_hunt_badge.setStyleSheet("background:#6b2d3c;color:white;padding:7px 12px;border-radius:8px;font-weight:800;")

        self.run_async_job("Process refresh", lambda: app._get("/processes").json(), self.apply_process_refresh_result, failed)

    def apply_process_refresh_result(self, items: list[dict]) -> None:
        app = self.app
        checked_pids = self.current_checked_pids()
        ranked = []
        for process in items:
            score, label, reasons = self.score_process(process)
            enriched = dict(process)
            enriched["_risk_score"] = score
            enriched["_risk_label"] = label
            enriched["_risk_reasons"] = reasons
            enriched["_triage_state"] = app.process_triage_state.get(str(process.get("pid", "")), "Unreviewed")
            ranked.append(enriched)
        ranked.sort(key=lambda item: (int(item.get("_risk_score", 0) or 0), float(item.get("cpu_percent", 0) or 0)), reverse=True)
        app.process_inventory = ranked
        elevated_count = len([item for item in ranked if int(item.get("_risk_score", 0) or 0) >= 45])
        unsigned_count = len([item for item in ranked if str(item.get("signature_status", "") or "").lower() in {"unsigned", "unknown", "invalid", "n/a", "none", ""}])
        self.render_process_rows(ranked, checked_pids)
        if not items:
            app.selected_process = None
            app.tree_view.clear()
            app.internals_table.setRowCount(0)
            app.proc_detail.setHtml(self._empty_detail_html("No live processes are currently available. Confirm agent telemetry and refresh the workspace."))
            app.hunt_out.setHtml(self.empty_state_html("No live processes", "Confirm backend telemetry permissions, then refresh the process queue.", accent="#f4c26b"))
            app.statusBar().showMessage("No live processes available")
        else:
            app.statusBar().showMessage(f"Loaded {len(items)} processes | elevated={elevated_count} unsigned={unsigned_count}")
        app.metric_proc.setText(f"Processes: {len(items)}")
        self.update_process_kpis(total=len(items), elevated=elevated_count, unsigned=unsigned_count)
        self.update_provider_readiness()
        self.update_command_affordance()

    def apply_process_filters(self) -> None:
        app = self.app
        rows = getattr(app, "process_inventory", []) or []
        checked_pids = self.current_checked_pids()
        query = app.process_filter_text.text().strip().lower() if hasattr(app, "process_filter_text") else ""
        risk_filter = app.process_filter_risk.currentText().lower() if hasattr(app, "process_filter_risk") else "all risk"
        state_filter = app.process_filter_state.currentText().lower() if hasattr(app, "process_filter_state") else "all states"
        filtered = []
        for item in rows:
            haystack = " ".join(
                [
                    str(item.get("pid", "")),
                    str(item.get("name", "")),
                    str(item.get("username", "")),
                    str(item.get("exe", "")),
                    str(item.get("signature_status", "")),
                    " ".join(str(reason) for reason in item.get("_risk_reasons", [])),
                ]
            ).lower()
            if query and query not in haystack:
                continue
            if risk_filter != "all risk" and str(item.get("_risk_label", "")).lower() != risk_filter:
                continue
            if state_filter != "all states" and str(item.get("_triage_state", "unreviewed")).lower() != state_filter:
                continue
            filtered.append(item)
        self.render_process_rows(filtered, checked_pids)
        if hasattr(app, "process_hunt_badge"):
            app.process_hunt_badge.setText(f"Hunt: {len(filtered)}/{len(rows)} visible")
        self.update_command_affordance()

    def render_process_rows(self, rows: list[dict], checked_pids: set[str]) -> None:
        app = self.app
        app.proc_table.setSortingEnabled(False)
        app.proc_table.blockSignals(True)
        app.proc_table.setRowCount(len(rows))
        for i, process in enumerate(rows):
            pid_value = str(process.get("pid", ""))
            risk_label = str(process.get("_risk_label", "low"))
            reasons = process.get("_risk_reasons", [])
            risk_item = QTableWidgetItem(self.risk_pill_text(risk_label, process.get("_risk_score", 0)))
            risk_item.setData(Qt.UserRole, int(process.get("_risk_score", 0) or 0))
            risk_item.setFlags(risk_item.flags() | Qt.ItemIsUserCheckable)
            risk_item.setCheckState(Qt.Checked if pid_value in checked_pids else Qt.Unchecked)
            risk_item.setToolTip("\n".join(str(reason) for reason in reasons[:8]))
            app.proc_table.setItem(i, 0, risk_item)
            reason_text = "; ".join(str(reason) for reason in reasons[:3])
            state = process.get("_triage_state", "Unreviewed")
            signature = process.get("signature_status", "n/a")
            protected = self.is_protected_process(str(process.get("name", "")))
            if protected and "protected process" not in reason_text.lower():
                reason_text = f"protected process; {reason_text}" if reason_text else "protected process"
            values = [
                pid_value,
                process.get("name", ""),
                self.state_pill_text(str(state)),
                process.get("username", "") or "-",
                process.get("cpu_percent", ""),
                process.get("memory_percent", ""),
                self.signature_pill_text(str(signature)),
                reason_text,
            ]
            for j, value in enumerate(values, start=1):
                item = QTableWidgetItem(str(value))
                if j in {1, 5, 6}:
                    try:
                        item.setData(Qt.UserRole, float(value))
                    except Exception:
                        pass
                raw_value = str(value)
                if j == 2:
                    raw_value = str(process.get("name", ""))
                item.setToolTip(
                    "\n".join(
                        [
                            f"PID: {pid_value}",
                            f"Name: {process.get('name', '-')}",
                            f"State: {state}",
                            f"Path: {process.get('exe', '-')}",
                            f"Signature: {signature}",
                            f"Reasons: {reason_text or '-'}",
                        ]
                    )
                )
                if j == 2 and protected:
                    item.setText(f"{raw_value} [PROTECTED]")
                app.proc_table.setItem(i, j, item)
            try:
                cpu_val = float(process.get("cpu_percent", 0) or 0)
            except Exception:
                cpu_val = 0.0
            try:
                mem_val = float(process.get("memory_percent", 0) or 0)
            except Exception:
                mem_val = 0.0
            if risk_label == "critical":
                app._paint_row(app.proc_table, i, QColor("#5c1f2d"))
            elif risk_label == "high":
                app._paint_row(app.proc_table, i, QColor("#5a2d22"))
            elif risk_label == "medium" or cpu_val >= 20 or mem_val >= 5:
                app._paint_row(app.proc_table, i, QColor("#59461f"))
        app.proc_table.blockSignals(False)
        app.proc_table.setSortingEnabled(True)

    # The pill / classification helpers are thin facades over
    # `process_hunt_scoring` — the math lives there for headless tests.
    def risk_pill_text(self, label: str, score) -> str:
        return risk_pill_text(label, score)

    def state_pill_text(self, state: str) -> str:
        return state_pill_text(state)

    def signature_pill_text(self, signature: str) -> str:
        return signature_pill_text(signature)

    def is_protected_process(self, name: str) -> bool:
        return is_protected_process(name)

    def activate_process_row(self, row: int, _column: int = 0, *, checked: bool = False) -> None:
        app = self.app
        if row < 0 or row >= app.proc_table.rowCount():
            return
        app.proc_table.selectRow(row)
        app.proc_table.setCurrentCell(row, 1)
        risk_item = app.proc_table.item(row, 0)
        if checked and risk_item is not None and risk_item.checkState() != Qt.Checked:
            risk_item.setCheckState(Qt.Checked)
        self.show_selected_process()
        self.update_provider_readiness()
        self.update_command_affordance()

    def checked_process_rows(self) -> list[int]:
        app = self.app
        rows: list[int] = []
        for row in range(app.proc_table.rowCount()):
            pid_item = app.proc_table.item(row, 0)
            if pid_item and pid_item.checkState() == Qt.Checked:
                rows.append(row)
        return rows

    def selected_process_rows(self) -> list[int]:
        app = self.app
        rows: list[int] = []
        selection_model = app.proc_table.selectionModel() if getattr(app, "proc_table", None) else None
        if selection_model is not None:
            rows = sorted(index.row() for index in selection_model.selectedRows())
        if not rows:
            current_row = app.proc_table.currentRow()
            if current_row >= 0:
                rows = [current_row]
        return rows

    def selected_identity(self):
        app = self.app
        rows = self.selected_process_rows()
        if not rows:
            return None
        row = rows[0]
        pid_item = app.proc_table.item(row, 1)
        name_item = app.proc_table.item(row, 2)
        if not pid_item or not name_item:
            return None
        return pid_item.text(), name_item.text()

    def selected_process_or_warn(self):
        ident = self.selected_identity()
        if not ident:
            self.app.hunt_out.setHtml(self.empty_state_html("No process selected", "Select a process row first. Bulk checkboxes are for grouped actions; the active row drives detail, triage, and single-target response.", accent="#f4c26b"))
            self.app.statusBar().showMessage("Select a live process first to inspect, scan, or respond.")
            return None
        return ident

    def show_selected_process(self) -> None:
        """Fetch profile detail off the UI thread.

        The previous implementation issued a synchronous `_get` here,
        which froze the desktop for 200-800ms on every row click — long
        enough that operators missed-clicked rows during a hunt. The
        new path runs the request on a short-lived worker, tracks the
        latest selection token, and ignores stale responses if the
        analyst clicks again before the previous fetch returns.
        """
        app = self.app
        ident = self.selected_identity()
        if not ident:
            return
        pid, _ = ident
        token = (str(pid), time.time())
        self._pending_detail_token = token
        # Show a transient loading state in the detail panel while the
        # request is in flight, but DON'T overwrite if we already have
        # a profile for this PID — avoids flicker on rapid re-selection.
        existing = getattr(app, "selected_process", None) or {}
        if str(existing.get("pid", "")) != str(pid):
            app.proc_detail.setHtml(self._empty_detail_html(f"Loading detail for PID {pid}..."))

        thread = QThread(app)
        worker = ProcessWorker(lambda: app._get(f"/processes/{pid}").json())
        worker.moveToThread(thread)

        def cleanup() -> None:
            thread.quit()
            thread.wait(1500)
            worker.deleteLater()
            thread.deleteLater()

        def on_success(profile: dict) -> None:
            try:
                if getattr(self, "_pending_detail_token", None) != token:
                    return  # superseded by a newer click
                if not isinstance(profile, dict):
                    return
                # Snapshot evidence — first load locks the analyst's
                # view of this target. A subsequent refresh can update
                # the cache but the badge in render_process_detail
                # tells the operator the snapshot is from time T.
                profile = dict(profile)
                profile.setdefault("_frozen_at", time.strftime("%Y-%m-%d %H:%M:%S"))
                self._evidence_freeze = profile
                app.selected_process = profile
                score, label, reasons = self.score_process(profile)
                app.proc_detail.setHtml(self.render_process_detail(profile, score, label, reasons))
                self.update_process_kpis(selected=f"{profile.get('name', '-')} ({label})")
                self.update_process_timeline()
                plain = app.hunt_out.toPlainText()
                if not plain.strip() or "Ready for investigation" in plain or "No process selected" in plain or "Process investigation output is empty." in plain:
                    app.hunt_out.setHtml(self.empty_state_html(
                        f"Target selected: {profile.get('name', 'process')} ({profile.get('pid')})",
                        f"Risk {label.upper()} / {score}. Run Auto Triage for decisioning, Memory/YARA/Strings for forensics, or Intel enrichment for reputation.",
                    ))
            finally:
                cleanup()

        def on_failure(message: str) -> None:
            try:
                if getattr(self, "_pending_detail_token", None) != token:
                    return
                app._show_error(app.proc_detail, "Failed to load process detail", Exception(message))
            finally:
                cleanup()

        thread.started.connect(worker.run)
        worker.finished.connect(on_success)
        worker.failed.connect(on_failure)
        thread.start()

    def _empty_detail_html(self, message: str | None = None) -> str:
        body = message or "Select a process to inspect provenance, signature, execution path, command line, network exposure, and response risk."
        return (
            "<h3 style='margin:0 0 8px;color:#f4f7fb;'>No Process Selected</h3>"
            f"<p style='color:#96a5b8;'>{html.escape(body)}</p>"
            "<div style='border:1px solid #243446;border-radius:8px;padding:9px;margin-top:8px;'>"
            "<b>Expected product signals</b><br>"
            "Signature trust, parent/child lineage, user-writable path, command-line indicators, network connections, "
            "hash availability, and response guardrails.</div>"
        )

    def risk_policy_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "config" / "process_risk_policy.json"

    def risk_scoring_config(self) -> dict:
        # Defaults + loaded policy live in `process_hunt_scoring`. The
        # cache is mtime-aware so a 400-row refresh hits the disk at
        # most once instead of ~6000 times.
        return self._risk_policy_cache.get()

    def risk_weight(self, name: str) -> int:
        return self._risk_policy_cache.weight(name)

    def render_risk_policy_html(self) -> str:
        config = self.risk_scoring_config()
        weights = config.get("weights", {}) if isinstance(config.get("weights"), dict) else {}
        allowlist = config.get("known_good_windows", []) if isinstance(config.get("known_good_windows"), list) else []
        suppressions = config.get("suppressions", []) if isinstance(config.get("suppressions"), list) else []
        top_weights = sorted(weights.items(), key=lambda item: str(item[0]))[:24]
        weight_rows = "".join(
            f"<tr><td>{html.escape(str(name))}</td><td>{html.escape(str(value))}</td></tr>"
            for name, value in top_weights
        )
        return (
            "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Risk Scoring Policy</h3>"
            f"<p style='margin:0 0 8px;color:#96a5b8;'>Loaded from <b>{html.escape(str(self.risk_policy_path()))}</b>. "
            "This controls local process ranking before provider reputation is available.</p>"
            f"{self._small_badge('Known-good', str(len(allowlist)), '#7fe39d')}"
            f"{self._small_badge('Suppressions', str(len(suppressions)), '#ffcf7a')}"
            f"{self._small_badge('Weights', str(len(weights)), '#7fd7ff')}"
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;margin-top:8px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Signal</th><th align='left'>Weight</th></tr>"
            + weight_rows
            + "</table>"
        )

    def score_process(self, process: dict) -> tuple[int, str, list[str]]:
        # Pure scoring lives in `process_hunt_scoring.score_process`.
        # The controller threads in the cached policy + weight lookup
        # so 400-row refreshes don't re-load the policy file 6000 times,
        # while suppression/known-good lists still reflect the test's
        # tmp policy override.
        policy = self._risk_policy_cache.get()
        return score_process(process, policy=policy, weight_fn=self._risk_policy_cache.weight)

    def command_entropy(self, value: str) -> float:
        return command_entropy(value)

    def is_public_network_destination(self, value: str) -> bool:
        return is_public_network_destination(value)

    def render_process_detail(self, profile: dict, score: int, label: str, reasons: list[str]) -> str:
        app = self.app
        network_connections = profile.get("network_connections") or []
        if isinstance(network_connections, list):
            network_preview = "".join(
                f"<li>{html.escape(str(item))} {'<b style=\"color:#ff8f70;\">public</b>' if self.is_public_network_destination(str(item)) else '<span style=\"color:#7fe39d;\">local/private</span>'}</li>"
                for item in network_connections[:8]
            ) or "<li>No network connections reported.</li>"
        else:
            network_preview = f"<li>{html.escape(str(network_connections))}</li>"
        cmdline = profile.get("cmdline", "")
        if isinstance(cmdline, list):
            cmdline = " ".join(str(part) for part in cmdline)
        exe = str(profile.get("exe", "") or "")
        exe_parent = str(Path(exe).parent) if exe else "unavailable"
        signature = profile.get("signature") if isinstance(profile.get("signature"), dict) else {}
        signature_status = str(signature.get("status") or profile.get("signature_status") or "unknown")
        signer = str(signature.get("signer") or "unavailable")
        issuer = str(signature.get("issuer") or "unavailable")
        thumbprint = str(signature.get("thumbprint") or "unavailable")
        trust_state = str(signature.get("trust_state") or signature_status or "unknown")
        not_after = str(signature.get("not_after") or "unavailable")
        parent_signature = profile.get("parent_signature") if isinstance(profile.get("parent_signature"), dict) else {}
        parent_signer = str(parent_signature.get("signer") or parent_signature.get("status") or "unavailable")
        parent_cmdline = str(profile.get("parent_cmdline") or "unavailable")
        session_id = str(profile.get("session_id") or "unknown")
        integrity_level = str(profile.get("integrity_level") or "unknown")
        child_processes = profile.get("child_processes") if isinstance(profile.get("child_processes"), list) else []
        child_rows = "".join(
            f"<li>{html.escape(str(child.get('name', '-')))} ({html.escape(str(child.get('pid', '-')))})</li>"
            for child in child_processes[:6]
            if isinstance(child, dict)
        ) or "<li>No direct child processes reported.</li>"
        lineage_child = html.escape(str(child_processes[0].get("name", "child")) if child_processes and isinstance(child_processes[0], dict) else "no child")
        lineage_html = (
            "<div style='border:1px solid #243446;border-radius:8px;padding:7px;color:#c8d8ea;'>"
            f"{html.escape(str(profile.get('parent_name') or 'unknown parent'))}"
            " <span style='color:#7fd7ff;'>-></span> "
            f"<b>{html.escape(str(profile.get('name') or 'selected'))}</b>"
            " <span style='color:#7fd7ff;'>-></span> "
            f"{lineage_child}"
            "</div>"
        )
        create_time = profile.get("create_time")
        start_time = "unavailable"
        age_text = "unavailable"
        if isinstance(create_time, (int, float)) and create_time > 0:
            start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(create_time)))
            age_seconds = max(0.0, time.time() - float(create_time))
            if age_seconds < 60:
                age_text = f"{age_seconds:.0f}s"
            elif age_seconds < 3600:
                age_text = f"{age_seconds / 60:.0f}m"
            else:
                age_text = f"{age_seconds / 3600:.1f}h"
        execution_context = profile.get("execution_context") if isinstance(profile.get("execution_context"), dict) else {}
        context_flags = [
            ("User-writable path", execution_context.get("user_writable_path")),
            ("Browser parent", execution_context.get("browser_parent")),
            ("Office parent", execution_context.get("office_parent")),
            ("LOLBin", execution_context.get("lolbin")),
            ("Proxy execution", execution_context.get("proxy_execution")),
            ("Script-like command", execution_context.get("script_like")),
        ]
        context_rows = "".join(
            f"<span style='display:inline-block;border:1px solid #243446;border-radius:8px;padding:3px 7px;margin:2px;color:{'#ffcf7a' if active else '#96a5b8'};'>{html.escape(label_text)}: {'yes' if active else 'no'}</span>"
            for label_text, active in context_flags
        )
        rep_cache = getattr(app, "process_reputation_cache", {})
        rep_key = str(profile.get("sha256") or "")
        pid_key = str(profile.get("pid") or "")
        rep = rep_cache.get(rep_key, {}) or rep_cache.get(pid_key, {}) if (rep_key or pid_key) else {}
        reputation = self.reputation_label(rep, bool(profile.get("sha256")))
        reputation_rows = self.reputation_badges(rep, bool(profile.get("sha256")))
        partial_rows = self.partial_telemetry_badges(profile)
        reason_rows = self.render_reason_sections(reasons)
        guardrails = []
        process_name = str(profile.get("name", "") or "").lower()
        exe_lower = exe.lower().replace("/", "\\")
        if process_name in {"lsass.exe", "services.exe", "wininit.exe", "csrss.exe", "smss.exe", "winlogon.exe"}:
            guardrails.append("critical Windows process name: destructive response requires extra review")
        if "\\windows\\system32\\" in exe_lower and str(profile.get("signature_status", "")).lower() not in {"unsigned", "invalid"}:
            guardrails.append("system path with trusted-ish signature: prefer triage before kill/quarantine")
        if not profile.get("sha256"):
            guardrails.append("no hash available: collect evidence before reputation lookup")
        if label in {"high", "critical"}:
            guardrails.append("run Auto Triage before containment unless active impact is confirmed")
        guardrail_rows = "".join(f"<li>{html.escape(item)}</li>" for item in guardrails[:5]) or "<li>No destructive-response guardrail triggered.</li>"
        mitre_hints = self.mitre_hints(profile, reasons)
        mitre_rows = "".join(f"<li>{html.escape(item)}</li>" for item in mitre_hints) or "<li>No ATT&CK hint from current metadata.</li>"
        # Evidence freeze: rendered as a small banner so the analyst
        # knows the snapshot timestamp — useful when the auto-refresh
        # ticker fires mid-investigation. The freeze is captured the
        # first time `show_selected_process` resolves the profile.
        frozen_at = str(profile.get("_frozen_at") or "")
        freeze_banner = ""
        if frozen_at:
            freeze_banner = (
                "<div style='border:1px solid #355179;background:#16273c;border-radius:8px;"
                "padding:5px 9px;margin:0 0 6px;color:#7fd7ff;font-size:11px;font-weight:700;'>"
                f"Evidence frozen at {html.escape(frozen_at)} — auto-refresh will not mutate this snapshot."
                "</div>"
            )
        return (
            "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Selected Process Posture</h3>"
            + freeze_banner +
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:separate;border-spacing:5px;font-size:12px;'>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Risk</b><br>{html.escape(label.upper())} / {score}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>PID</b><br>{html.escape(str(profile.get('pid', '-')))}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Name</b><br>{html.escape(str(profile.get('name', '-')))}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>User</b><br>{html.escape(str(profile.get('username', '-')))}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Parent</b><br>{html.escape(str(profile.get('parent_name') or '-'))} ({html.escape(str(profile.get('ppid') or '-'))})</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Children</b><br>{len(child_processes)}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Start Time</b><br>{html.escape(start_time)} ({html.escape(age_text)})</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Status</b><br>{html.escape(str(profile.get('status', '-')))}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Session</b><br>{html.escape(session_id)}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Integrity</b><br>{html.escape(integrity_level)}</td></tr>"
            f"<tr><td style='border:1px solid #243446;border-radius:8px;'><b>Hash Reputation</b><br>{html.escape(reputation)}</td>"
            f"<td style='border:1px solid #243446;border-radius:8px;'><b>Signature</b><br>{html.escape(signature_status)}</td></tr>"
            "</table>"
            f"<h4 style='margin:8px 0 3px;color:#ffcf7a;'>Telemetry Quality</h4><div>{partial_rows}</div>"
            f"<h4 style='margin:8px 0 3px;color:#7fd7ff;'>Lineage</h4>{lineage_html}"
            f"<h4 style='margin:8px 0 3px;color:#bda4ff;'>Reputation</h4><div>{reputation_rows}</div>"
            f"<p style='color:#96a5b8;margin:7px 0 0;'><b>Path:</b> {html.escape(exe or 'unavailable')}<br>"
            f"<b>Directory:</b> {html.escape(exe_parent)}<br>"
            f"<b>SHA-256:</b> {html.escape(str(profile.get('sha256', '-') or '-'))}<br>"
            f"<b>Command:</b> {html.escape(str(cmdline or 'unavailable')[:500])}</p>"
            f"<h4 style='margin:8px 0 3px;color:#7fe39d;'>Signer / Trust Chain</h4>"
            f"<p style='color:#96a5b8;margin:0;'><b>Trust:</b> {html.escape(trust_state)}<br><b>Signer:</b> {html.escape(signer[:240])}<br><b>Issuer:</b> {html.escape(issuer[:240])}<br><b>Expires:</b> {html.escape(not_after)}<br><b>Thumbprint:</b> {html.escape(thumbprint)}</p>"
            f"<h4 style='margin:8px 0 3px;color:#7fe39d;'>Parent Enrichment</h4>"
            f"<p style='color:#96a5b8;margin:0;'><b>Parent signer:</b> {html.escape(parent_signer[:240])}<br><b>Parent command:</b> {html.escape(parent_cmdline[:500])}</p>"
            f"<h4 style='margin:8px 0 3px;color:#7fd7ff;'>User / Session Context</h4><div>{context_rows}</div>"
            f"<h4 style='margin:8px 0 3px;color:#7fd7ff;'>Direct Children</h4><ul>{child_rows}</ul>"
            f"<h4 style='margin:8px 0 3px;color:#ffcf7a;'>Risk Explanation</h4>{reason_rows}"
            f"<h4 style='margin:8px 0 3px;color:#ff8f70;'>Response Guardrails</h4><ul>{guardrail_rows}</ul>"
            f"<h4 style='margin:8px 0 3px;color:#bda4ff;'>ATT&amp;CK Hints</h4><ul>{mitre_rows}</ul>"
            f"<h4 style='margin:8px 0 3px;color:#7fd7ff;'>Network Exposure</h4><ul>{network_preview}</ul>"
        )

    def reputation_label(self, rep: dict, has_hash: bool) -> str:
        if not has_hash:
            return "blocked: no SHA-256"
        if not rep:
            return "not scanned"
        severity = str(rep.get("severity") or rep.get("verdict") or "unknown").lower()
        score = rep.get("score")
        stale = self.is_reputation_stale(rep)
        label = f"{severity} / {score}" if score is not None else severity
        return f"{label} (stale)" if stale else label

    def reputation_badges(self, rep: dict, has_hash: bool) -> str:
        if not has_hash:
            return self._small_badge("Hash", "missing", "#ffcf7a")
        if not rep:
            return self._small_badge("Reputation", "not scanned", "#96a5b8")
        badges = [
            self._small_badge("Fusion", str(rep.get("severity") or "unknown"), self.reputation_color(str(rep.get("severity") or ""))),
            self._small_badge("Score", str(rep.get("score", "-")), "#7fd7ff"),
            self._small_badge("Confidence", str(rep.get("confidence") or "unknown"), "#bda4ff"),
        ]
        if self.is_reputation_stale(rep):
            badges.append(self._small_badge("Cache", "stale", "#ffcf7a"))
        for provider in ("virustotal", "malwarebazaar", "yaraify", "antivirus"):
            if provider in rep:
                badges.append(self._small_badge(provider.upper(), str(rep.get(provider) or "seen")[:28], "#7fe39d"))
        return "".join(badges)

    def is_reputation_stale(self, rep: dict) -> bool:
        try:
            cached_at = float(rep.get("cached_at", 0) or 0)
        except Exception:
            return False
        return cached_at > 0 and time.time() - cached_at > 24 * 60 * 60

    def partial_telemetry_badges(self, profile: dict) -> str:
        def state(label: str, ok: bool, blocked: bool = False) -> tuple[str, str, str]:
            if ok:
                return label, "ok", "#7fe39d"
            if blocked:
                return label, "blocked", "#ff8f70"
            return label, "partial", "#ffcf7a"

        exe = str(profile.get("exe") or "")
        access_denied = bool(profile.get("access_denied") or profile.get("partial_telemetry"))
        checks = [
            state("Hash", bool(profile.get("sha256")), bool(exe)),
            state("Signature", str(profile.get("signature_status") or "").lower() not in {"", "unknown", "n/a"}, bool(exe)),
            state("Parent", bool(profile.get("parent_name")), access_denied),
            state("Session", str(profile.get("session_id") or "unknown").lower() != "unknown", access_denied),
            state("Integrity", str(profile.get("integrity_level") or "unknown").lower() != "unknown", access_denied),
            state("Network", bool(profile.get("network_connections")), False),
            state("Children", bool(profile.get("child_processes")), False),
        ]
        badges = [self._small_badge(label, value, color) for label, value, color in checks]
        if access_denied:
            badges.append(self._small_badge("Telemetry", "partial access", "#ff8f70"))
        return "".join(badges)

    def reputation_color(self, severity: str) -> str:
        value = severity.lower()
        if value in {"critical", "malicious"}:
            return "#ff6b8a"
        if value in {"high", "suspicious"}:
            return "#ff8f70"
        if value == "medium":
            return "#ffcf7a"
        if value == "low":
            return "#7fe39d"
        return "#96a5b8"

    def _small_badge(self, label: str, value: str, color: str) -> str:
        return (
            f"<span style='display:inline-block;border:1px solid #243446;border-radius:8px;"
            f"padding:3px 7px;margin:2px;color:{color};background:#101a24;'>"
            f"{html.escape(label)}: <b>{html.escape(value)}</b></span>"
        )

    def render_reason_sections(self, reasons: list[str]) -> str:
        buckets = {
            "Identity": [],
            "Execution": [],
            "Network": [],
            "Reputation": [],
            "Behavior": [],
            "Response Safety": [],
        }
        for reason in reasons[:10]:
            low = reason.lower()
            if any(token in low for token in ("signature", "sha-256", "hash", "known-good")):
                buckets["Reputation"].append(reason)
            elif any(token in low for token in ("network", "egress", "destination", "connection")):
                buckets["Network"].append(reason)
            elif any(token in low for token in ("parent", "child", "office", "browser", "lolbin", "command", "path", "spawned", "entropy")):
                buckets["Execution"].append(reason)
            elif any(token in low for token in ("cpu", "memory", "behavior")):
                buckets["Behavior"].append(reason)
            elif any(token in low for token in ("guardrail", "protected", "response")):
                buckets["Response Safety"].append(reason)
            else:
                buckets["Identity"].append(reason)
        sections = []
        for title, items in buckets.items():
            if not items:
                continue
            rows = "".join(f"<li>{html.escape(item)}</li>" for item in items)
            sections.append(f"<b style='color:#c8d8ea;'>{html.escape(title)}</b><ul style='margin-top:2px;'>{rows}</ul>")
        return "".join(sections) or "<p style='color:#96a5b8;'>No risk explanation available.</p>"

    def mitre_hints(self, profile: dict, reasons: list[str]) -> list[str]:
        name = str(profile.get("name", "") or "").lower()
        cmdline = profile.get("cmdline", "")
        cmd = " ".join(str(part) for part in cmdline) if isinstance(cmdline, list) else str(cmdline or "")
        value = f"{name} {cmd}".lower()
        hints: list[str] = []
        if "powershell" in value or "encodedcommand" in value or "invoke-" in value:
            hints.append("T1059.001 PowerShell")
        if any(term in value for term in ["cmd.exe", "wscript", "cscript", "mshta"]):
            hints.append("T1059 Command and Scripting Interpreter")
        if any(term in value for term in ["rundll32", "regsvr32"]):
            hints.append("T1218 Signed Binary Proxy Execution")
        if any(term in value for term in ["http://", "https://", "downloadstring"]):
            hints.append("T1105 Ingress Tool Transfer")
        if any("user-writable" in reason for reason in reasons):
            hints.append("T1036 Masquerading / suspicious staging path")
        return hints[:5]

    def update_process_kpis(self, *, total: int | None = None, elevated: int | None = None, unsigned: int | None = None, selected: str | None = None) -> None:
        app = self.app
        if total is not None and hasattr(app, "process_kpi_total"):
            app.process_kpi_total.setText(str(total))
            app.process_kpi_elevated.setText(str(elevated or 0))
            app.process_kpi_unsigned.setText(str(unsigned or 0))
            state = "ready" if total else "empty"
            app.process_hunt_badge.setText(f"Hunt: {state}")
            color = "#2f9e67" if total else "#4a5568"
            app.process_hunt_badge.setStyleSheet(f"background:{color};color:white;padding:7px 12px;border-radius:8px;font-weight:800;")
        if selected is not None and hasattr(app, "process_kpi_response"):
            app.process_kpi_response.setText("READY")
            app.process_kpi_response_sub.setText(selected[:42])

    def update_provider_readiness(self) -> None:
        app = self.app
        if not hasattr(app, "process_provider_readiness"):
            return
        selected_count = len(self.checked_process_rows())
        cache_stats = self.reputation_cache_stats()
        provider_summary = " ".join(
            [
                f"VT:{'ok' if app.vt_key.text().strip() else 'miss'}",
                f"MB:{'ok' if app.malwarebazaar_key.text().strip() else 'miss'}",
                f"Y:{'ok' if app.yaraify_key.text().strip() else 'miss'}",
                "L:ok",
            ]
        )
        app.process_provider_readiness.setText(
            f"<span style='color:#c8d8ea;'>Providers {html.escape(provider_summary)} | sel:{selected_count} | rep:{cache_stats['count']}/{cache_stats['stale']} stale</span>"
        )
        if hasattr(app, "process_provider_view"):
            app.process_provider_view.setHtml(self.render_provider_readiness_html())
        if hasattr(app, "process_risk_policy_view"):
            app.process_risk_policy_view.setHtml(self.render_risk_policy_html())

    def provider_states(self) -> list[dict[str, str | bool]]:
        app = self.app
        providers = [
            ("VirusTotal", "VT", bool(getattr(app, "vt_key", None) and app.vt_key.text().strip()), "hash reputation"),
            ("MalwareBazaar", "MB", bool(getattr(app, "malwarebazaar_key", None) and app.malwarebazaar_key.text().strip()), "malware family + sample intel"),
            ("YARAify", "YARAify", bool(getattr(app, "yaraify_key", None) and app.yaraify_key.text().strip()), "YARA + static enrichment"),
            ("Local Metadata", "Local", True, "process, signer, path, lineage, cache"),
        ]
        rows = []
        for name, short, ready, capability in providers:
            rows.append({
                "name": name,
                "short": short,
                "ready": ready,
                "state": "ready" if ready else "missing API key",
                "capability": capability,
                "last": "local realtime" if name == "Local Metadata" else "on demand",
            })
        return rows

    def render_provider_readiness_html(self) -> str:
        app = self.app
        cache_stats = self.reputation_cache_stats()
        selected = len(self.checked_process_rows()) if hasattr(app, "proc_table") else 0
        rows = []
        for provider in self.provider_states():
            ready = bool(provider["ready"])
            color = "#7fe39d" if ready else "#ffcf7a"
            rows.append(
                "<tr>"
                f"<td><b>{html.escape(str(provider['name']))}</b></td>"
                f"<td style='color:{color};font-weight:800;'>{html.escape(str(provider['state']))}</td>"
                f"<td>{html.escape(str(provider['capability']))}</td>"
                f"<td>{html.escape(str(provider['last']))}</td>"
                "</tr>"
            )
        return (
            "<h3 style='margin:0 0 6px;color:#f4f7fb;'>Provider Readiness</h3>"
            "<p style='margin:0 0 8px;color:#96a5b8;'>Intel providers are optional, but missing keys block reputation lookups. Local process metadata remains available.</p>"
            "<table width='100%' cellspacing='0' cellpadding='6' style='border-collapse:collapse;font-size:12px;'>"
            "<tr style='color:#96a5b8;'><th align='left'>Provider</th><th align='left'>State</th><th align='left'>Signal</th><th align='left'>Last Use</th></tr>"
            + "".join(rows)
            + "</table>"
            f"<p style='margin:8px 0 0;color:#c8d8ea;'><b>Selected targets:</b> {selected} &nbsp; "
            f"<b>Reputation cache:</b> {cache_stats['count']} verdict(s), {cache_stats['stale']} stale, latest {html.escape(str(cache_stats['latest']))}</p>"
        )

    def reputation_cache_stats(self) -> dict[str, int | str]:
        cache = getattr(self.app, "process_reputation_cache", {}) or {}
        stale = 0
        latest = 0.0
        for value in cache.values():
            if not isinstance(value, dict):
                continue
            try:
                cached_at = float(value.get("cached_at", 0) or 0)
            except Exception:
                cached_at = 0.0
            latest = max(latest, cached_at)
            if cached_at and self.is_reputation_stale(value):
                stale += 1
        return {
            "count": len(cache),
            "stale": stale,
            "latest": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(latest)) if latest else "never",
        }

    def set_selected_triage_state(self, state: str) -> None:
        app = self.app
        rows = self.checked_process_rows() or self.selected_process_rows()
        if not rows:
            app.statusBar().showMessage("Select or tick process rows before changing triage state.")
            return
        changed = 0
        for row in rows:
            pid_item = app.proc_table.item(row, 1)
            if not pid_item:
                continue
            pid = pid_item.text()
            app.process_triage_state[pid] = state
            name_item = app.proc_table.item(row, 2)
            self.append_process_audit("set-state", pid, name_item.text() if name_item else "-", state)
            changed += 1
        for item in getattr(app, "process_inventory", []) or []:
            pid = str(item.get("pid", ""))
            if pid in app.process_triage_state:
                item["_triage_state"] = app.process_triage_state[pid]
        self.apply_process_filters()
        app.statusBar().showMessage(f"Marked {changed} process(es) as {state}.")

    def process_action(self, action: str) -> None:
        app = self.app
        # P0-3: Client-side allowlist mirrors api/routes/processes.py.
        # The backend already rejects unknown actions, but a client-side
        # check stops a typo / future button from ever reaching the
        # network — and stops a confused operator from seeing a 400.
        if action not in RESPONSE_ACTION_ALLOWLIST:
            app.hunt_out.setHtml(self.empty_state_html(
                "Action not permitted",
                f"`{action}` is not in the response allowlist {sorted(RESPONSE_ACTION_ALLOWLIST)}. "
                "Update RESPONSE_ACTION_ALLOWLIST in process_hunt_ops.py if this is a new server endpoint.",
                accent="#ff6b8a",
            ))
            app.statusBar().showMessage(f"Action `{action}` blocked by client-side allowlist.")
            return
        # P1: Per-action rate-limit. The backend `kill` is non-idempotent
        # — rage-clicking can target sibling PIDs spawned in the gap
        # between two clicks, especially for short-lived workers.
        now = time.time()
        last = float(self._last_response_click.get(action, 0.0) or 0.0)
        if now - last < RESPONSE_DEBOUNCE_SECONDS:
            app.statusBar().showMessage(f"`{action}` is rate-limited; try again in a moment.")
            return
        self._last_response_click[action] = now

        rows = self.checked_process_rows() or self.selected_process_rows()
        if not rows:
            app.statusBar().showMessage("Tick one or more process rows first")
            return
        targets: list[tuple[str, str]] = []
        for row in rows:
            pid_item = app.proc_table.item(row, 1)
            name_item = app.proc_table.item(row, 2)
            if pid_item and name_item:
                targets.append((pid_item.text(), name_item.text()))
        if not targets:
            app.statusBar().showMessage("No valid process rows selected")
            return
        primary_pid, primary_name = targets[0]
        process_profile = app.selected_process or {}
        protected_names = {"system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe"}
        protected_targets = [f"{name} ({pid})" for pid, name in targets if str(name).strip().lower() in protected_names]
        if protected_targets and action in {"kill", "kill-tree", "quarantine", "suspend"}:
            detail = "Blocked protected target(s): " + ", ".join(protected_targets[:6])
            app.hunt_out.setHtml(self.empty_state_html("Response blocked by guardrail", detail, accent="#ff8f70"))
            for pid, name in targets:
                if str(name).strip().lower() in protected_names:
                    self.append_process_audit(action, pid, name, "blocked: protected process")
            app.statusBar().showMessage(detail)
            return
        impact = "high" if any(token in str(primary_name).lower() for token in ["lsass", "wininit", "services", "svchost"]) else "moderate"
        rollback = "low" if action in {"kill", "kill-tree"} else "medium" if action == "quarantine" else "high"
        selection_mode = "checked" if self.checked_process_rows() else "selected"
        scope_line = (
            f"Run '{action}' on {primary_name} (PID {primary_pid})?"
            if len(targets) == 1
            else f"Run '{action}' on {len(targets)} {selection_mode} processes?\nPrimary target: {primary_name} (PID {primary_pid})"
        )
        prompt = (
            f"{scope_line}\n\n"
            + self.action_policy_preview(action, targets, impact, rollback, process_profile)
        )
        if QMessageBox.question(app, "Confirm Action", prompt) != QMessageBox.Yes:
            return
        if len(targets) > 1 and action in {"kill", "kill-tree", "quarantine", "suspend"}:
            typed, ok = QInputDialog.getText(
                app,
                "Bulk Action Safety Check",
                f"Type {len(targets)} to confirm this bulk '{action}' action.",
            )
            if not ok or typed.strip() != str(len(targets)):
                app.hunt_out.setHtml(self.empty_state_html("Bulk response cancelled", "The target count confirmation did not match.", accent="#f4c26b"))
                app.statusBar().showMessage("Bulk response cancelled: target count mismatch.")
                return
        # P0-6: Structured response reason — ticket ID + category + free
        # text. The previous "min 8 chars" gate accepted "asdfasdf" and
        # buried the audit. Now operators must pick a category and
        # supply a ticket reference (or explicitly mark "no-ticket"
        # which is highlighted in the audit row).
        reason_payload = self._prompt_response_reason(action)
        if reason_payload is None:
            app.hunt_out.setHtml(self.empty_state_html(
                "Response cancelled",
                "A ticket ID and a structured reason are required for response actions.",
                accent="#f4c26b",
            ))
            app.statusBar().showMessage("Response cancelled: structured reason required.")
            return
        ticket_id, reason_category, reason_text = reason_payload
        reason_summary = f"[{reason_category}] {ticket_id}: {reason_text}"
        reason_metadata = {
            "ticket_id": ticket_id,
            "reason_category": reason_category,
            "reason_text": reason_text,
        }
        if getattr(app, "process_dry_run_toggle", None) is not None and app.process_dry_run_toggle.isChecked():
            for pid, name in targets:
                self.append_process_audit(
                    f"dry-run:{action}",
                    pid,
                    name,
                    f"simulated only | reason: {reason_summary}",
                    {"mode": "dry-run", "policy": "simulation", "rollback": rollback, "status": "ok", **reason_metadata},
                )
            app.hunt_out.setHtml(self.empty_state_html(
                f"Dry-run complete: {action}",
                f"Simulated response for {len(targets)} target(s). No backend action endpoint was called.",
                accent="#7fd7ff",
            ))
            app.statusBar().showMessage(f"Dry-run {action}: {len(targets)} target(s) simulated.")
            return
        succeeded = 0
        failures: list[str] = []
        for pid, name in targets:
            try:
                result = app._post(f"/processes/{pid}/actions/{action}", params={"process_name": name}, timeout=20).json()
                succeeded += 1
                request_id = result.get("request_id") or result.get("id") or result.get("event_id")
                self.append_process_audit(
                    action,
                    pid,
                    name,
                    f"{result.get('message') or result.get('status') or 'completed'} | reason: {reason_summary}",
                    {"request_id": request_id, "mode": "live", "policy": "admin response", "rollback": rollback, "status": "ok", **reason_metadata},
                )
            except Exception as exc:
                failures.append(f"{name} ({pid}): {exc}")
                self.append_process_audit(
                    action,
                    pid,
                    name,
                    f"failed: {exc} | reason: {reason_summary}",
                    {"mode": "live", "policy": "admin response", "rollback": rollback, "status": "failed", **reason_metadata},
                )
        app.refresh_history()
        if failures:
            app.hunt_out.setPlainText("\n".join([f"Action: {action}", f"Succeeded: {succeeded}/{len(targets)}", "", "Failures:", *failures[:20]]))
        else:
            app.hunt_out.setHtml(self.empty_state_html(f"Response complete: {action}", f"Succeeded on {succeeded}/{len(targets)} selected process(es). Audit tab has the action record.", accent="#7fe39d"))
        app.statusBar().showMessage(f"{action}: {succeeded}/{len(targets)} process(es) completed")

    # Class attribute kept for any external code asserting on the
    # category taxonomy. The actual validation/prompt lives in
    # `desktop/_response_dialog.py` so the Antivirus console can reuse it.
    REASON_CATEGORIES: tuple[str, ...] = _SHARED_REASON_CATEGORIES

    def _prompt_response_reason(self, action: str) -> tuple[str, str, str] | None:
        return _shared_prompt_response_reason(self.app, action)

    def action_policy_preview(self, action: str, targets: list[tuple[str, str]], impact: str, rollback: str, profile: dict) -> str:
        protected_count = sum(1 for _pid, name in targets if self.is_protected_process(name))
        dry_run = bool(getattr(self.app, "process_dry_run_toggle", None) and self.app.process_dry_run_toggle.isChecked())
        policy = "dry-run simulation" if dry_run else "admin dangerous-action policy"
        # `profile` is the last detail-fetched process; it only describes
        # the action target if its PID matches the primary target. Showing
        # a stale exe here would make the operator confirm a destructive
        # action against misleading evidence.
        primary_pid = str(targets[0][0]).strip() if targets else ""
        if profile and primary_pid and str(profile.get("pid", "")).strip() == primary_pid:
            exe_line = profile.get("exe", "n/a")
        else:
            exe_line = "n/a (open the target row to load its profile)"
        return (
            f"Target count: {len(targets)}\n"
            f"Protected targets: {protected_count}\n"
            f"Dry-run: {'on' if dry_run else 'off'}\n"
            f"Backend policy: {policy}\n"
            f"Impact preview: {impact}\n"
            f"Rollback confidence: {rollback}\n"
            f"Executable: {exe_line}\n"
        )

    def scan_selected_process(self) -> None:
        app = self.app
        ident = self.selected_identity()
        if not ident:
            app.statusBar().showMessage("Select a process first")
            return
        pid, _ = ident
        payload = self.scan_payload()
        if not any(payload.values()):
            app.statusBar().showMessage("Enter at least one threat-intel API key")
            return
        app.hunt_out.setHtml(self.empty_state_html("Threat scan running", f"Scanning PID {pid} with configured intel providers."))

        def done(result: dict) -> None:
            self.cache_reputation(pid, result)
            app._show_json(app.hunt_out, result)
            source = "VirusTotal + MalwareBazaar + YARAify"
            value = str(app.selected_process.get("sha256", "-")) if app.selected_process else f"PID {pid}"
            app._record_threat_history("process", value, source, result)
            self.focus_hunt()

        self.run_async_job(
            f"Threat scan PID {pid}",
            lambda: app._post(f"/processes/{pid}/scan", json=payload, timeout=60).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "Threat scan failed", Exception(message)),
            timeout_seconds=75,
        )

    def cache_reputation(self, pid: str | int, result: dict) -> None:
        app = self.app
        fusion = result.get("fusion", {}) if isinstance(result.get("fusion"), dict) else {}
        # Two cache shapes:
        #  * "stable" — keyed by SHA-256, persisted, used across restarts
        #  * "volatile" — keyed by PID, in-memory only, dropped on
        #    restart because OS PIDs are reused and a recycled PID
        #    would otherwise inherit the previous occupant's verdict.
        stable_summary = {
            "severity": fusion.get("severity") or "unknown",
            "score": fusion.get("score"),
            "confidence": fusion.get("confidence") or "unknown",
            "cached_at": time.time(),
        }
        for provider in ("virustotal", "malwarebazaar", "yaraify"):
            value = result.get(provider)
            if isinstance(value, dict):
                stable_summary[provider] = value.get("verdict") or value.get("status") or value.get("summary") or "result"
        antivirus = result.get("antivirus")
        if isinstance(antivirus, dict):
            av_summary = antivirus.get("summary", {}) if isinstance(antivirus.get("summary"), dict) else {}
            stable_summary["antivirus"] = "infected" if av_summary.get("infected") else "clean/unknown"
        selected = getattr(app, "selected_process", None) or {}
        sha = str(selected.get("sha256") or "").strip()
        if sha:
            app.process_reputation_cache[sha] = stable_summary
        # Volatile copy by PID — distinct dict so the volatile flag
        # doesn't leak into the SHA-256 entry written to disk.
        volatile_summary = dict(stable_summary)
        volatile_summary["_volatile"] = True
        app.process_reputation_cache[str(pid)] = volatile_summary
        self._pid_only_reputation_keys.add(str(pid))
        self.save_process_reputation_cache()
        if selected:
            score, label, reasons = self.score_process(selected)
            app.proc_detail.setHtml(self.render_process_detail(selected, score, label, reasons))
        self.append_process_audit(
            "reputation-scan",
            str(pid),
            str(selected.get("name", "-")),
            self.reputation_label(stable_summary, bool(sha)),
        )

    def selected_process_ids(self) -> list[int]:
        app = self.app
        ids: list[int] = []
        for row in (self.checked_process_rows() or self.selected_process_rows()):
            item = app.proc_table.item(row, 1)
            if not item:
                continue
            try:
                ids.append(int(item.text()))
            except Exception:
                continue
        return sorted(set(ids))

    def scan_payload(self) -> dict[str, str | None]:
        app = self.app
        return {
            "virustotal_api_key": app.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": app.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": app.yaraify_key.text().strip() or None,
        }

    def scan_process_ids_bulk(self, process_ids: list[int], scope_label: str) -> None:
        app = self.app
        payload = self.scan_payload()
        if not (payload.get("virustotal_api_key") or payload.get("malwarebazaar_auth_key") or payload.get("yaraify_auth_key")):
            app.statusBar().showMessage("Enter at least one threat-intel API key")
            return
        if not process_ids:
            app.statusBar().showMessage("No processes selected for scan")
            return
        app.hunt_out.setHtml(self.empty_state_html("Bulk scan running", f"{scope_label}: scanning {len(process_ids)} process(es)."))

        def work() -> dict:
            results: list[dict] = []
            failed: list[dict[str, str]] = []
            for pid in process_ids:
                try:
                    scan = app._post(f"/processes/{pid}/scan", json=payload, timeout=60).json()
                    results.append({"pid": pid, "scan": scan})
                except Exception as exc:
                    failed.append({"pid": str(pid), "error": str(exc)})
            return {"scope": scope_label, "requested": len(process_ids), "succeeded": len(results), "failed": len(failed), "results": results, "errors": failed}

        def done(summary: dict) -> None:
            for item in summary.get("results", []):
                self.cache_reputation(item.get("pid"), item.get("scan", {}))
            app._show_json(app.hunt_out, summary)
            app.statusBar().showMessage(f"{scope_label}: scanned {summary.get('succeeded', 0)}/{len(process_ids)} process(es)")

        # P0-8 watchdog: previous formula was `len(pids) * 70` which
        # produced a 7000s timeout for 100 PIDs while the backend caps
        # each call at ~60s. `bulk_scan_timeout` clamps to a sane total
        # budget so the watchdog still fires within 10 minutes.
        watchdog_timeout = bulk_scan_timeout(per_call_seconds=70, count=len(process_ids))
        self.run_async_job(scope_label, work, done, lambda message: app._show_error(app.hunt_out, f"{scope_label} failed", Exception(message)), timeout_seconds=watchdog_timeout)

    def scan_selected_processes_vt(self) -> None:
        selected = self.selected_process_ids()
        if not selected:
            self.app.statusBar().showMessage("Tick one or more process rows to scan the selected set.")
            return
        self.scan_process_ids_bulk(selected, "Selected process scan")

    def scan_all_processes_vt(self) -> None:
        app = self.app
        process_ids: list[int] = []
        for row in range(app.proc_table.rowCount()):
            pid_item = app.proc_table.item(row, 1)
            if not pid_item:
                continue
            try:
                process_ids.append(int(pid_item.text()))
            except Exception:
                continue
        if not process_ids:
            app.statusBar().showMessage("Load processes first")
            return
        if QMessageBox.question(app, "Confirm Bulk Scan", f"Scan all loaded processes ({len(process_ids)}) with configured intel providers?") != QMessageBox.Yes:
            return
        self.scan_process_ids_bulk(process_ids, "All-process scan")

    def run_memory_analysis(self) -> None:
        app = self.app
        ident = self.selected_process_or_warn()
        if not ident:
            return
        pid, name = ident
        app.hunt_out.setHtml(self.empty_state_html("Memory analysis running", f"Collecting memory triage for {name} ({pid})."))
        self.run_async_job(
            f"Memory PID {pid}",
            lambda: app._get(f"/processes/{pid}/memory-analysis", params={"process_name": name}, timeout=40).json(),
            lambda result: (app._show_json(app.hunt_out, result), self.focus_hunt()),
            lambda message: app._show_error(app.hunt_out, "Memory analysis failed", Exception(message)),
            timeout_seconds=55,
        )

    def load_selected_internals(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        app.hunt_out.setHtml(self.empty_state_html("Internals loading", f"Loading handles and modules for PID {pid}."))

        def done(result: dict) -> None:
            rows = []
            for item in result.get("handles", []):
                rows.append(("Handle", item.get("Path", ""), item.get("Mode", ""), item.get("FD", "")))
            for item in result.get("modules", []):
                rows.append(("Module", item.get("Path", ""), item.get("Perms", ""), item.get("Size", "")))
            app.internals_table.setRowCount(len(rows))
            for r, row in enumerate(rows):
                for c, value in enumerate(row):
                    app.internals_table.setItem(r, c, QTableWidgetItem(str(value)))
            app._show_json(app.hunt_out, {"summary": {"handles": len(result.get("handles", [])), "modules": len(result.get("modules", []))}})
            self.focus_hunt()

        self.run_async_job(
            f"Internals PID {pid}",
            lambda: app._get(f"/processes/{pid}/internals", timeout=40).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "Internals load failed", Exception(message)),
            timeout_seconds=55,
        )

    def run_strings_analysis(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {
            "min_length": app.strings_min_length.value(),
            "patterns": [part.strip() for part in app.strings_patterns.text().split(",") if part.strip()],
        }
        app.hunt_out.setHtml(self.empty_state_html("Strings analysis running", f"Extracting strings for PID {pid}."))

        def done(result: dict) -> None:
            sample = result.get("sample", [])[:20]
            hits = result.get("pattern_hits", [])[:20]
            app.hunt_out.setPlainText("\n".join([
                f"Total Strings: {result.get('total_strings', 0)}",
                f"Pattern Hits: {len(result.get('pattern_hits', []))}",
                "",
                "Top Hits:",
                *hits,
                "",
                "Sample:",
                *sample,
            ]))
            self.focus_hunt()

        self.run_async_job(
            f"Strings PID {pid}",
            lambda: app._post(f"/processes/{pid}/strings", json=payload, timeout=60).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "Strings analysis failed", Exception(message)),
            timeout_seconds=75,
        )

    def run_yara_scan(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {"yaraify_auth_key": app.yaraify_key.text().strip() or None}
        app.hunt_out.setHtml(self.empty_state_html("YARA scan running", f"Scanning executable and YARAify context for PID {pid}."))

        def done(result: dict) -> None:
            app.hunt_out.setPlainText(app._format_yara_summary(result))
            exe_path = str(result.get("exe", "") or "")
            if exe_path:
                app.statusBar().showMessage(f"Executable YARA completed for on-disk image: {exe_path}")
            self.focus_hunt()

        self.run_async_job(
            f"YARA PID {pid}",
            lambda: app._post(f"/processes/{pid}/yara", json=payload, timeout=40).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "YARA scan failed", Exception(message)),
            timeout_seconds=55,
        )

    def run_sandbox_trace(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {"duration": app.trace_duration.value(), "interval": app.trace_interval.value()}
        app.hunt_out.setHtml(self.empty_state_html("Sandbox trace running", f"Tracing PID {pid} for {payload['duration']} second(s)."))

        def done(result: dict) -> None:
            events = result.get("events", [])
            app.hunt_out.setPlainText("\n".join([f"Collected Events: {len(events)}", ""] + [f"{event.get('time')} | {event.get('type')} | {event.get('detail')}" for event in events[:50]]))
            self.focus_hunt()

        self.run_async_job(
            f"Sandbox PID {pid}",
            lambda: app._post(f"/processes/{pid}/sandbox-trace", json=payload, timeout=payload["duration"] + 20).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "Sandbox trace failed", Exception(message)),
            timeout_seconds=int(payload["duration"]) + 35,
        )

    def load_process_tree(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        app.hunt_out.setHtml(self.empty_state_html("Process tree loading", f"Building lineage tree for PID {pid}."))

        def done(result: dict) -> None:
            app.tree_view.clear()

            def add_node(parent, node):
                item = QTreeWidgetItem([str(node.get("name")), str(node.get("pid"))])
                if parent is None:
                    app.tree_view.addTopLevelItem(item)
                else:
                    parent.addChild(item)
                for child in node.get("children", []):
                    add_node(item, child)

            add_node(None, result.get("root", {}))
            app.tree_view.expandAll()
            app.hunt_out.setPlainText(f"Process tree loaded for PID {pid}.")
            self.focus_hunt()

        self.run_async_job(
            f"Tree PID {pid}",
            lambda: app._get(f"/processes/{pid}/tree", timeout=30).json(),
            done,
            lambda message: app._show_error(app.hunt_out, "Process tree failed", Exception(message)),
            timeout_seconds=45,
        )

    def run_ai_analysis(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        app.hunt_out.setHtml(self.empty_state_html("AI analyst running", f"Generating process analysis for PID {pid}."))
        self.run_async_job(
            f"AI PID {pid}",
            lambda: app._get(f"/processes/{pid}/ai-analysis", timeout=30).json(),
            lambda result: (app.hunt_out.setPlainText(f"Risk: {result.get('risk')}\nConfidence: {result.get('confidence')}\n\n{result.get('analysis')}"), self.focus_hunt()),
            lambda message: app._show_error(app.hunt_out, "AI analysis failed", Exception(message)),
            timeout_seconds=45,
        )

    def run_auto_triage(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {
            "virustotal_api_key": app.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": app.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": app.yaraify_key.text().strip() or None,
            "trace_duration": min(10, app.trace_duration.value()),
            "strings_min_length": app.strings_min_length.value(),
            "strings_patterns": [part.strip() for part in app.strings_patterns.text().split(",") if part.strip()],
        }
        app.hunt_out.setHtml(self.empty_state_html("Auto triage running", f"Building decision package for PID {pid}."))
        self.run_async_job(
            f"Auto triage PID {pid}",
            lambda: app._post(f"/triage/{pid}", json=payload, timeout=120).json(),
            lambda result: (app.hunt_out.setPlainText(app._format_triage_summary(result)), self.focus_hunt()),
            lambda message: app._show_error(app.hunt_out, "Auto triage failed", Exception(message)),
            timeout_seconds=140,
        )

    def run_triage_response(self) -> None:
        app = self.app
        ident = app._selected_process_or_warn()
        if not ident:
            return
        pid, name = ident
        answer = QMessageBox.question(
            app,
            "Apply Triage Response",
            f"Apply policy-driven triage response for {name} (PID {pid})?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer != QMessageBox.Yes:
            return
        reason, ok = QInputDialog.getText(
            app,
            "Triage Response Reason Required",
            "Why is policy-driven response appropriate? This will be written to audit.",
        )
        reason = reason.strip()
        if not ok or len(reason) < 8:
            app.hunt_out.setHtml(self.empty_state_html("Triage response cancelled", "A response reason of at least 8 characters is required.", accent="#f4c26b"))
            app.statusBar().showMessage("Triage response cancelled: reason required.")
            return
        try:
            result = app._post(f"/triage/{pid}/respond", json={"process_name": name}, timeout=120).json()
        except Exception as exc:
            app._show_error(app.hunt_out, "Triage response failed", exc)
            self.append_process_audit("triage-response", str(pid), name, f"failed: {exc} | reason: {reason}")
            return
        app.hunt_out.setPlainText(app._format_response_execution(result))
        self.append_process_audit("triage-response", str(pid), name, f"completed | reason: {reason}")
        self.focus_hunt()
