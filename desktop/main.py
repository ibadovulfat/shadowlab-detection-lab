from __future__ import annotations

import html
import hmac
import json
import sys
import time
import hashlib
from pathlib import Path

import requests
from requests import Response
from PySide6.QtCore import QMargins, QSettings, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QBrush, QColor, QDesktopServices, QIcon, QPen, QPixmap
from PySide6.QtCharts import QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QBoxLayout, QComboBox, QDoubleSpinBox, QFormLayout, QGridLayout, QHBoxLayout, QLabel,
    QCheckBox, QInputDialog, QLineEdit, QListWidget, QMainWindow, QMessageBox, QMenu, QPushButton, QSpinBox,
    QDialog,
    QFrame, QScrollArea, QSplitter, QSizePolicy, QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QTextEdit,
    QToolButton,
    QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

try:
    import win32cred  # type: ignore
except Exception:
    win32cred = None


class ShadowLabDesktop(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ShadowLab")
        self.resize(1760, 980)
        self.settings = QSettings("ShadowLab", "Desktop")
        self.logo_path = Path(__file__).resolve().parent.parent / "static" / "shadowlab-logo-active.png"
        if self.logo_path.exists():
            self.setWindowIcon(QIcon(str(self.logo_path)))
        self.selected_process = None
        self.persistence_items = []
        self.artifacts = {}
        self.evidence_items = []
        self.latest_monitor_rows: list[dict] = []
        self.latest_monitor_result: dict = {}
        self.threat_history: list[dict[str, str]] = []
        self.custom_toolbar_buttons: list[dict[str, str]] = []
        self.auth_context: dict = {}
        self.capability_widgets: list[tuple[QWidget, str]] = []
        self.panel_windows: list[QDialog] = []
        self.auth_active = False
        self._enterprise_table_updating = False
        self.enterprise_selected_case_id: int | None = None
        self.enterprise_loaded_once = False
        self._theme()
        self._toolbar()
        self._ui()
        self.setStatusBar(QStatusBar())
        self.live_refresh_timer = QTimer(self)
        self.live_refresh_timer.setInterval(10000)
        self.live_refresh_timer.timeout.connect(self._auto_refresh_active_tab)
        self.live_refresh_timer.start()
        self.check_api_health()

    def _theme(self) -> None:
        self.setStyleSheet(
            "QMainWindow,QWidget{background:#10151d;color:#e5edf5;font-family:'Segoe UI',Arial,sans-serif;}"
            "QLineEdit,QSpinBox,QDoubleSpinBox,QComboBox{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;padding:2px 7px;}"
            "QLineEdit:focus,QSpinBox:focus,QDoubleSpinBox:focus,QComboBox:focus{border:1px solid #1d7df2;}"
            "QTextEdit,QTextBrowser,QTableWidget,QListWidget{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;padding:6px;}"
            "QPushButton{background:#1a2a3d;color:#c8d8ea;border:1px solid #2c4260;border-radius:8px;padding:6px 12px;font-weight:600;font-size:12px;} "
            "QPushButton:hover{background:#1d7df2;color:white;border-color:#1d7df2;} QPushButton:pressed{background:#155bc2;}"
            "QTabWidget::pane{border:1px solid #243446;border-radius:6px;} "
            "QTabBar::tab{background:#16202c;color:#96a5b8;padding:8px 14px;border:1px solid transparent;border-bottom:none;border-radius:6px 6px 0 0;margin-right:2px;font-size:12px;} "
            "QTabBar::tab:selected{background:#1d7df2;color:white;border-color:#1d7df2;} QTabBar::tab:hover{color:#eef4fb;background:#1d2a3a;}"
            "QHeaderView::section{background:#121b27;color:#96a5b8;border:none;border-right:1px solid #243446;border-bottom:1px solid #243446;padding:6px 8px;font-size:11px;font-weight:600;letter-spacing:0.5px;}"
            "QTableWidget{gridline-color:#1e2e40;alternate-background-color:#121b27;selection-background-color:#1a3558;}"
            "QFrame[card='true']{background:#121b27;border:1px solid #1e3050;border-radius:10px;}"
            "QTextEdit[role='brief'],QTextBrowser[role='brief']{background:#0e1720;border:1px solid #2b425b;border-radius:10px;padding:12px;color:#eef4fb;font-size:13px;}"
            "QScrollBar:vertical{background:#0e1720;width:8px;border-radius:4px;margin:0;} QScrollBar::handle:vertical{background:#2a3d55;border-radius:4px;min-height:24px;} QScrollBar::handle:vertical:hover{background:#3b5878;} QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{height:0;}"
            "QScrollBar:horizontal{background:#0e1720;height:8px;border-radius:4px;margin:0;} QScrollBar::handle:horizontal{background:#2a3d55;border-radius:4px;min-width:24px;} QScrollBar::handle:horizontal:hover{background:#3b5878;} QScrollBar::add-line:horizontal,QScrollBar::sub-line:horizontal{width:0;}"
            "QSplitter::handle{background:#1e3050;} QSplitter::handle:horizontal{width:2px;} QSplitter::handle:vertical{height:2px;}"
            "QCheckBox{spacing:6px;color:#96a5b8;} QCheckBox::indicator{width:14px;height:14px;border:1px solid #2c4260;border-radius:3px;background:#16202c;} QCheckBox::indicator:checked{background:#1d7df2;border-color:#1d7df2;}"
            "QListWidget::item:selected{background:#1a3558;color:#eef4fb;border-radius:4px;} QListWidget::item:hover{background:#1a2a3d;}"
            "QTreeWidget{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:8px;} QTreeWidget::item:selected{background:#1a3558;}"
            "QStatusBar{background:#0a1018;border-top:1px solid #1e3050;color:#96a5b8;font-size:11px;}"
            "QToolTip{background:#121b27;color:#eef4fb;border:1px solid #2b425b;border-radius:6px;padding:4px 8px;}"
        )

    def _toolbar(self) -> None:
        self.toolbar = QToolBar("Primary")
        self.toolbar.setMovable(False)
        self.toolbar.setFloatable(False)
        self.toolbar.setStyleSheet(
            "QToolBar{spacing:6px;padding:4px;border:none;background:#0f1823;}"
            "QToolButton{background:#16202c;color:#e5edf5;border:1px solid #243446;border-radius:7px;padding:6px 10px;font-size:12px;}"
            "QToolButton:hover{background:#1d7df2;border-color:#1d7df2;}"
        )
        self.addToolBar(self.toolbar)
        self._rebuild_toolbar()

    def _ui(self) -> None:
        content = QWidget()
        self.content_widget = content
        layout = QVBoxLayout(content)
        layout.setContentsMargins(4, 4, 4, 6)
        layout.setSpacing(8)
        hero = QWidget()
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(0, 0, 0, 0)
        hero_row.setSpacing(12)
        title_logo = QLabel()
        if self.logo_path.exists():
            title_logo.setPixmap(QPixmap(str(self.logo_path)).scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        title = QLabel("ShadowLab")
        title.setStyleSheet("font-size:26px;font-weight:700;padding:6px;color:#f4f7fb;")
        title_block = QWidget()
        title_layout = QVBoxLayout(title_block)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(0)
        sub = QLabel("Created by Ulfat Ibadov | Offensive Security Expert")
        sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        title_layout.addWidget(title)
        title_layout.addWidget(sub)
        hero_row.addWidget(title_logo)
        hero_row.addWidget(title_block)
        hero_row.addStretch(1)
        layout.addWidget(hero)

        controls = QWidget()
        controls.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.controls_row = QHBoxLayout(controls)
        self.controls_row.setContentsMargins(0, 0, 0, 0)
        self.controls_row.setSpacing(12)
        self.base = QLineEdit("http://127.0.0.1:8000")
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.api_key.setPlaceholderText("viewer / analyst / admin API key")
        self.remember_api_key = QCheckBox("Remember API key on this machine")
        self.api_key.setPlaceholderText("Paste viewer / analyst / admin API key")
        self.api_key.returnPressed.connect(self.activate_role_mode)
        self.activate_role_btn = QPushButton("OK")
        self.activate_role_btn.clicked.connect(self.activate_role_mode)
        self.auth_mode_badge = QLabel("Mode: locked")
        self.auth_mode_badge.setStyleSheet("color:#f4c26b;font-weight:700;")
        self.auth_mode_hint = QLabel("Enter an API key here, then press OK to unlock the right workflow.")
        self.auth_mode_hint.setWordWrap(True)
        self.auth_mode_hint.setStyleSheet("color:#96a5b8;font-size:12px;")
        self.approval_id = QLineEdit()
        self.approval_id.setPlaceholderText("Optional: approved change ID for corp/prod actions")
        self.duration = QSpinBox(); self.duration.setRange(5, 600); self.duration.setValue(30)
        self.interval = QDoubleSpinBox(); self.interval.setRange(0.1, 10.0); self.interval.setValue(1.0)
        self.vt_key = QLineEdit(); self.vt_key.setEchoMode(QLineEdit.Password)
        self.malwarebazaar_key = QLineEdit(); self.malwarebazaar_key.setEchoMode(QLineEdit.Password)
        self.yaraify_key = QLineEdit(); self.yaraify_key.setEchoMode(QLineEdit.Password)
        self.hash_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.persist_filter = QLineEdit()
        self.strings_min_length = QSpinBox(); self.strings_min_length.setRange(3, 20); self.strings_min_length.setValue(4)
        self.strings_patterns = QLineEdit("http,powershell,cmd,token,password,api")
        self.trace_duration = QSpinBox(); self.trace_duration.setRange(2, 60); self.trace_duration.setValue(5)
        self.trace_interval = QDoubleSpinBox(); self.trace_interval.setRange(0.1, 5.0); self.trace_interval.setValue(0.5)
        self.honeypot_filename = QLineEdit("passwords.txt")
        self.evidence_alert_name = QLineEdit("incident")
        self.net_range = QLineEdit("192.168.1.0/24")
        self.block_target = QLineEdit()
        self.block_gateway = QLineEdit()
        self.webhook_url = QLineEdit()
        self.whids_manager_url = QLineEdit("https://localhost:1520")
        self.whids_manager_api_key = QLineEdit()
        self.whids_manager_api_key.setEchoMode(QLineEdit.Password)
        self.whids_endpoint_uuid = QLineEdit()
        self.whids_artifact_since = QLineEdit()
        self.whids_artifact_limit = QSpinBox()
        self.whids_artifact_limit.setRange(1, 250)
        self.whids_artifact_limit.setValue(25)
        self.whids_scheduler_interval = QDoubleSpinBox()
        self.whids_scheduler_interval.setRange(30.0, 86400.0)
        self.whids_scheduler_interval.setValue(300.0)
        self.whids_ioc_payload = QTextEdit()
        self.whids_ioc_payload.setPlaceholderText('[{"uuid":"...","guuid":"...","source":"ShadowLab","value":"bad.example","type":"domain"}]')
        self.whids_rule_payload = QTextEdit()
        self.whids_rule_payload.setPlaceholderText('[{"Name":"ShadowLabRule","Condition":"$a","Matches":["$a: Image ~= C:/Temp/evil.exe"],"Actions":["kill"]}]')
        self.whids_rule_name = QLineEdit()
        self.integration_policy_payload = QTextEdit()
        self.integration_policy_payload.setPlaceholderText('{"providers":{"ossec":{"enabled":true}}}')
        self.hids_incident_id = QLineEdit()
        self.whids_verify_tls = QCheckBox("Verify TLS")
        self.whids_verify_tls.setChecked(True)
        self.whids_file_path = QLineEdit(str((Path(__file__).resolve().parent.parent / "shadowlab_out" / "whids-alerts.json")))
        self.hids_file_path = QLineEdit(str((Path(__file__).resolve().parent.parent / "shadowlab_out" / "ossec-alerts.log")))
        self.hids_live_interval = QDoubleSpinBox()
        self.hids_live_interval.setRange(0.5, 60.0)
        self.hids_live_interval.setValue(2.0)
        self.hids_live_start_at_end = QCheckBox("Start At End")
        self.hids_live_start_at_end.setChecked(True)

        ops_card = QFrame(); ops_card.setProperty("card", True); ops_card.setMinimumWidth(500)
        ops_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        ops_layout = QVBoxLayout(ops_card)
        ops_layout.setContentsMargins(14, 14, 14, 14)
        ops_layout.setSpacing(6)
        ops_title = QLabel("Primary Controls")
        ops_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        ops_sub = QLabel("Base access, fast lookups and day-to-day operator controls")
        ops_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        ops_form = QGridLayout()
        ops_form.setContentsMargins(0, 2, 0, 0)
        ops_form.setHorizontalSpacing(10)
        ops_form.setVerticalSpacing(8)
        ops_form.addWidget(self._field_block("API Base URL", self.base), 0, 0)
        auth_row = QWidget()
        auth_row_layout = QHBoxLayout(auth_row)
        auth_row_layout.setContentsMargins(0, 0, 0, 0)
        auth_row_layout.setSpacing(8)
        auth_row_layout.addWidget(self.api_key, 1)
        auth_row_layout.addWidget(self.activate_role_btn)
        access_status = QWidget()
        access_status_layout = QVBoxLayout(access_status)
        access_status_layout.setContentsMargins(0, 0, 0, 0)
        access_status_layout.setSpacing(2)
        self.auth_mode_badge.setStyleSheet("color:#f4c26b;font-weight:700;font-size:11px;")
        self.auth_mode_hint.setStyleSheet("color:#96a5b8;font-size:10px;")
        self.remember_api_key.setStyleSheet("font-size:10px;color:#96a5b8;")
        access_status_layout.addWidget(self.auth_mode_badge)
        access_status_layout.addWidget(self.auth_mode_hint)
        access_status_layout.addWidget(self.remember_api_key)
        ops_form.addWidget(self._field_block("Role-Based API Key", auth_row), 0, 1)
        ops_form.addWidget(self._field_block("Access Mode", access_status), 1, 0)
        ops_form.addWidget(self._field_block("Approval ID", self.approval_id), 1, 1)
        ops_form.addWidget(self._field_block("Monitor Duration (s)", self.duration), 2, 0)
        ops_form.addWidget(self._field_block("Monitor Interval (s)", self.interval), 2, 1)
        ops_form.addWidget(self._field_block("Threat Hash", self.hash_input), 3, 0)
        ops_form.addWidget(self._field_block("Threat IP", self.ip_input), 3, 1)
        ops_form.addWidget(self._field_block("Persistence Filter", self.persist_filter), 4, 0)
        ops_form.addWidget(self._field_block("Webhook URL", self.webhook_url), 4, 1)
        ops_layout.addWidget(ops_title)
        ops_layout.addWidget(ops_sub)
        ops_layout.addLayout(ops_form)

        adv_card = QFrame(); adv_card.setProperty("card", True); adv_card.setMinimumWidth(520)
        adv_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        adv_layout = QVBoxLayout(adv_card)
        adv_layout.setContentsMargins(14, 14, 14, 14)
        adv_layout.setSpacing(6)
        adv_title = QLabel("Advanced Hunt & Lab Settings")
        adv_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        adv_sub = QLabel("Advanced hunt, trace, deception and network lab inputs")
        adv_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        adv_form = QGridLayout()
        adv_form.setContentsMargins(0, 2, 0, 0)
        adv_form.setHorizontalSpacing(10)
        adv_form.setVerticalSpacing(8)
        adv_form.addWidget(self._field_block("VirusTotal API Key", self.vt_key), 0, 0)
        adv_form.addWidget(self._field_block("MalwareBazaar Auth-Key", self.malwarebazaar_key), 0, 1)
        adv_form.addWidget(self._field_block("YARAify Auth-Key", self.yaraify_key), 0, 2)
        adv_form.addWidget(self._field_block("Strings Min Length", self.strings_min_length), 1, 0)
        adv_form.addWidget(self._field_block("Trace Duration (s)", self.trace_duration), 1, 1)
        adv_form.addWidget(self._field_block("Trace Interval (s)", self.trace_interval), 1, 2)
        adv_form.addWidget(self._field_block("Evidence Alert Name", self.evidence_alert_name), 2, 0)
        adv_form.addWidget(self._field_block("Honeypot Filename", self.honeypot_filename), 2, 1)
        adv_form.addWidget(self._field_block("Network IP Range", self.net_range), 2, 2)
        adv_form.addWidget(self._field_block("Blocker Target IP", self.block_target), 3, 0)
        adv_form.addWidget(self._field_block("Blocker Gateway IP", self.block_gateway), 3, 1)
        adv_form.addWidget(self._field_block("Strings Patterns", self.strings_patterns), 3, 2)
        adv_layout.addWidget(adv_title)
        adv_layout.addWidget(adv_sub)
        adv_layout.addLayout(adv_form)
        self.advanced_card = adv_card

        self.ops_card = ops_card
        self.controls_row.addWidget(ops_card, 1)
        self.controls_row.addWidget(adv_card, 1)
        layout.addWidget(controls)

        top = QWidget()
        top_row = QHBoxLayout(top)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        self.health = QLabel("API status: unknown")
        self.auth_role = QLabel("Role: -")
        self.auth_summary = QLabel("Capabilities: -")
        top_row.addWidget(self.health)
        top_row.addWidget(self.auth_role)
        top_row.addWidget(self.auth_summary, 1)
        self.toggle_advanced_btn = QPushButton("Hide Advanced Settings")
        self.toggle_advanced_btn.clicked.connect(self.toggle_advanced_settings)
        top_row.addWidget(self.toggle_advanced_btn)
        top_row.addStretch(1)
        top_capabilities = {
            "Run Monitor": "can_run_monitor",
            "Filter Persistence": "can_view_persistence",
        }
        for btn_text, fn in [
            ("Run Monitor", self.run_monitor),
            ("Load Processes", self.refresh_processes),
            ("Lookup Hash", self.lookup_hash),
            ("Lookup IP", self.lookup_ip),
            ("Filter Persistence", self.apply_persistence_filter),
        ]:
            btn = QPushButton(btn_text)
            btn.clicked.connect(fn)
            if btn_text in top_capabilities:
                self._bind_capability(btn, top_capabilities[btn_text])
            top_row.addWidget(btn)
        layout.addWidget(top)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._scrollable_tab(self._dashboard_hub_tab()), "Dashboards")
        self.tabs.addTab(self._scrollable_tab(self._whids_tab()), "WHIDS")
        self.tabs.addTab(self._scrollable_tab(self._hids_tab()), "HIDS")
        self.tabs.addTab(self._scrollable_tab(self._overview_tab()), "Overview")
        self.tabs.addTab(self._scrollable_tab(self._process_tab(), allow_horizontal=True), "Processes")
        self.tabs.addTab(self._hunt_tab(), "Advanced Hunt")
        self.tabs.addTab(self._persistence_tab(), "Persistence")
        self.tabs.addTab(self._threat_tab(), "Threat Intel")
        self.tabs.addTab(self._deception_tab(), "Deception")
        self.tabs.addTab(self._network_tab(), "Network")
        self.tabs.addTab(self._hosts_tab(), "Hosts")
        self.tabs.addTab(self._scrollable_tab(self._graph_tab()), "Graph")
        self.tabs.addTab(self._timeline_tab(), "Timeline")
        self.tabs.addTab(self._quarantine_tab(), "Quarantine")
        self.tabs.addTab(self._history_tab(), "History")
        self.tabs.addTab(self._artifacts_tab(), "Artifacts")
        self.tabs.addTab(self._scrollable_tab(self._enterprise_tab(), allow_horizontal=True), "Enterprise")
        self.tabs.addTab(self._scrollable_tab(self._security_ops_tab()), "Security Ops")
        self.tabs.addTab(self._scenario_tab(), "Scenarios")
        self.tabs.addTab(self._scrollable_tab(self._about_tab()), "About / FAQ")
        self.tabs.setUsesScrollButtons(True)
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(content)
        self._load_settings()
        self._update_controls_layout()

    def _dashboard_hub_tab(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(8)

        title = QLabel("Multi Dashboard Wall")
        title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        subtitle = QLabel("Compact panels for SOC triage. Use Open Panel to move any card into a separate window.")
        subtitle.setStyleSheet("color:#96a5b8;font-size:12px;")
        root.addWidget(title)
        root.addWidget(subtitle)

        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        self.dash_metrics = QTextBrowser()
        self.dash_metrics.setProperty("role", "brief")
        self.dash_metrics.setMinimumHeight(92)
        self.dash_threat = QTextBrowser()
        self.dash_threat.setProperty("role", "brief")
        self.dash_threat.setMinimumHeight(92)
        self.dash_auth = QTextBrowser()
        self.dash_auth.setProperty("role", "brief")
        self.dash_auth.setMinimumHeight(92)
        self.dash_timeline = QTextBrowser()
        self.dash_timeline.setProperty("role", "brief")
        self.dash_timeline.setMinimumHeight(92)

        quick_actions = QWidget()
        quick_row = QHBoxLayout(quick_actions)
        quick_row.setContentsMargins(0, 0, 0, 0)
        quick_row.setSpacing(8)
        for text, fn in [
            ("Run Monitor", self.run_monitor),
            ("Load Processes", self.refresh_processes),
            ("Refresh History", self.refresh_history),
            ("Enterprise Triage", self.refresh_enterprise_workspace),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(fn)
            quick_row.addWidget(btn)
        quick_row.addStretch(1)

        grid.addWidget(self._panel_card("Live Metrics", self.dash_metrics, self._open_dashboard_metrics_panel), 0, 0)
        grid.addWidget(self._panel_card("Threat Snapshot", self.dash_threat, self._open_dashboard_threat_panel), 0, 1)
        grid.addWidget(self._panel_card("Auth & Policy", self.dash_auth, self._open_dashboard_auth_panel), 1, 0)
        grid.addWidget(self._panel_card("Timeline Story", self.dash_timeline, self._open_dashboard_timeline_panel), 1, 1)
        grid.addWidget(self._panel_card("Quick Actions", quick_actions, self._open_dashboard_actions_panel), 2, 0, 1, 2)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)

        root.addLayout(grid)
        return w

    def _whids_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)
        self._tab_header(l, "WHIDS Integration", "Use WHIDS manager API or exported detection files to ingest official WHIDS detections into ShadowLab.")

        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        top_layout.setSpacing(8)

        manager_row = QWidget()
        manager_layout = QHBoxLayout(manager_row)
        manager_layout.setContentsMargins(0, 0, 0, 0)
        manager_layout.setSpacing(8)
        manager_import_btn = QPushButton("Pull WHIDS Manager")
        manager_import_btn.clicked.connect(self.import_whids_manager)
        self._bind_capability(manager_import_btn, "can_manage_integrations")
        report_import_btn = QPushButton("Pull WHIDS Reports")
        report_import_btn.clicked.connect(self.import_whids_reports)
        self._bind_capability(report_import_btn, "can_manage_integrations")
        artifact_import_btn = QPushButton("Pull WHIDS Artifacts")
        artifact_import_btn.clicked.connect(self.import_whids_artifacts)
        self._bind_capability(artifact_import_btn, "can_manage_integrations")
        manager_refresh_btn = QPushButton("Refresh WHIDS")
        manager_refresh_btn.clicked.connect(self.refresh_whids_workspace)
        self._bind_capability(manager_refresh_btn, "can_manage_integrations")
        query_iocs_btn = QPushButton("Query IoCs")
        query_iocs_btn.clicked.connect(self.query_whids_iocs)
        self._bind_capability(query_iocs_btn, "can_manage_integrations")
        add_iocs_btn = QPushButton("Add IoCs")
        add_iocs_btn.clicked.connect(self.add_whids_iocs)
        self._bind_capability(add_iocs_btn, "can_manage_integrations")
        delete_iocs_btn = QPushButton("Delete IoCs")
        delete_iocs_btn.clicked.connect(self.delete_whids_iocs)
        self._bind_capability(delete_iocs_btn, "can_manage_integrations")
        query_rules_btn = QPushButton("Query Rules")
        query_rules_btn.clicked.connect(self.query_whids_rules)
        self._bind_capability(query_rules_btn, "can_manage_integrations")
        add_rules_btn = QPushButton("Add Rules")
        add_rules_btn.clicked.connect(self.add_whids_rules)
        self._bind_capability(add_rules_btn, "can_manage_integrations")
        delete_rules_btn = QPushButton("Delete Rule")
        delete_rules_btn.clicked.connect(self.delete_whids_rules)
        self._bind_capability(delete_rules_btn, "can_manage_integrations")
        scheduler_start_btn = QPushButton("Start Scheduler")
        scheduler_start_btn.clicked.connect(self.start_whids_scheduler)
        self._bind_capability(scheduler_start_btn, "can_manage_integrations")
        scheduler_stop_btn = QPushButton("Stop Scheduler")
        scheduler_stop_btn.clicked.connect(self.stop_whids_scheduler)
        self._bind_capability(scheduler_stop_btn, "can_manage_integrations")
        scheduler_status_btn = QPushButton("Scheduler Status")
        scheduler_status_btn.clicked.connect(self.refresh_whids_scheduler_status)
        self._bind_capability(scheduler_status_btn, "can_manage_integrations")
        load_policy_btn = QPushButton("Load Policy")
        load_policy_btn.clicked.connect(self.load_integration_policy)
        self._bind_capability(load_policy_btn, "can_manage_integrations")
        save_policy_btn = QPushButton("Save Policy")
        save_policy_btn.clicked.connect(self.save_integration_policy)
        self._bind_capability(save_policy_btn, "can_manage_integrations")
        manager_layout.addWidget(self._field_block("WHIDS Manager URL", self.whids_manager_url), 1)
        manager_layout.addWidget(self._field_block("X-Api-Key", self.whids_manager_api_key), 1)
        manager_layout.addWidget(self._field_block("Endpoint UUID (optional)", self.whids_endpoint_uuid), 1)
        manager_layout.addWidget(self.whids_verify_tls)
        manager_layout.addWidget(manager_import_btn)
        manager_layout.addWidget(report_import_btn)
        manager_layout.addWidget(artifact_import_btn)
        manager_layout.addWidget(manager_refresh_btn)

        file_row = QWidget()
        top_row = QHBoxLayout(file_row)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        import_btn = QPushButton("Import WHIDS File")
        import_btn.clicked.connect(self.import_whids_file)
        self._bind_capability(import_btn, "can_manage_integrations")
        top_row.addWidget(self._field_block("WHIDS Export File", self.whids_file_path), 1)
        top_row.addWidget(self._field_block("Artifacts Since (RFC3339)", self.whids_artifact_since), 1)
        top_row.addWidget(self._field_block("Artifact Limit", self.whids_artifact_limit))
        top_row.addWidget(self._field_block("Scheduler Poll (s)", self.whids_scheduler_interval))
        top_row.addWidget(import_btn)
        top_layout.addWidget(manager_row)
        top_layout.addWidget(file_row)

        lifecycle_row = QWidget()
        lifecycle_layout = QHBoxLayout(lifecycle_row)
        lifecycle_layout.setContentsMargins(0, 0, 0, 0)
        lifecycle_layout.setSpacing(8)
        lifecycle_layout.addWidget(self._field_block("WHIDS IoC JSON", self.whids_ioc_payload), 1)
        lifecycle_layout.addWidget(self._field_block("WHIDS Rule JSON", self.whids_rule_payload), 1)
        action_col = QWidget()
        action_layout = QVBoxLayout(action_col)
        action_layout.setContentsMargins(0, 0, 0, 0)
        action_layout.setSpacing(6)
        action_layout.addWidget(self._field_block("Rule Name / Filter", self.whids_rule_name))
        for btn in [query_iocs_btn, add_iocs_btn, delete_iocs_btn, query_rules_btn, add_rules_btn, delete_rules_btn]:
            action_layout.addWidget(btn)
        for btn in [scheduler_start_btn, scheduler_stop_btn, scheduler_status_btn]:
            action_layout.addWidget(btn)
        action_layout.addStretch(1)
        lifecycle_layout.addWidget(action_col)
        top_layout.addWidget(lifecycle_row)

        policy_row = QWidget()
        policy_layout = QHBoxLayout(policy_row)
        policy_layout.setContentsMargins(0, 0, 0, 0)
        policy_layout.setSpacing(8)
        policy_layout.addWidget(self._field_block("Response Policy JSON", self.integration_policy_payload), 1)
        policy_btn_col = QWidget()
        policy_btn_layout = QVBoxLayout(policy_btn_col)
        policy_btn_layout.setContentsMargins(0, 0, 0, 0)
        policy_btn_layout.setSpacing(6)
        policy_btn_layout.addWidget(load_policy_btn)
        policy_btn_layout.addWidget(save_policy_btn)
        policy_btn_layout.addStretch(1)
        policy_layout.addWidget(policy_btn_col)
        top_layout.addWidget(policy_row)

        self.whids_summary = QTextBrowser()
        self.whids_summary.setProperty("role", "brief")
        self.whids_summary.setMinimumHeight(120)
        self.whids_health_badge = QLabel("WHIDS: unknown")
        self.whids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        self.whids_table = QTableWidget(0, 5)
        self.whids_table.setHorizontalHeaderLabels(["Created", "Type", "Target", "Status", "Detail"])
        self.whids_table.itemSelectionChanged.connect(self.show_selected_whids_export)
        self._style_table(self.whids_table)
        self.whids_detail = QTextEdit()
        self.whids_detail.setReadOnly(True)
        self.whids_detail.setProperty("role", "brief")

        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._panel_card("WHIDS Export History", self.whids_table, lambda: self._open_panel_window("WHIDS Export History", self._clone_table(self.whids_table))))
        split.addWidget(self._panel_card("WHIDS Detail", self.whids_detail, lambda: self._open_panel_window("WHIDS Detail", self._clone_text_view(self.whids_detail))))
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        whids_actions = QWidget()
        whids_actions_row = QHBoxLayout(whids_actions)
        whids_actions_row.setContentsMargins(0, 0, 0, 0)
        whids_actions_row.setSpacing(8)
        open_whids_target_btn = QPushButton("Open Selected Target")
        open_whids_target_btn.clicked.connect(self.open_selected_whids_target)
        self._bind_capability(open_whids_target_btn, "can_manage_integrations")
        open_whids_case_btn = QPushButton("Open Enterprise Case")
        open_whids_case_btn.clicked.connect(lambda: self.open_enterprise_case_for_incident(prefix="WHIDS-"))
        self._bind_capability(open_whids_case_btn, "can_manage_incidents")
        whids_actions_row.addWidget(self.whids_health_badge)
        whids_actions_row.addWidget(open_whids_target_btn)
        whids_actions_row.addWidget(open_whids_case_btn)
        whids_actions_row.addStretch(1)
        l.addWidget(self._panel_card("WHIDS Summary", self.whids_summary, lambda: self._open_panel_window("WHIDS Summary", self._clone_text_view(self.whids_summary))))
        l.addWidget(self._panel_card("WHIDS Status", whids_actions, lambda: self._open_panel_window("WHIDS Status", QLabel("Use WHIDS status controls in the main workspace."))))
        l.addWidget(self._panel_card("WHIDS Controls", top, lambda: self._open_panel_window("WHIDS Controls", QLabel("Use the main WHIDS tab to import detections."))))
        l.addWidget(split, 1)
        return w

    def _hids_tab(self) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)
        self._tab_header(l, "HIDS Integration", "Import OSSEC or other HIDS alert files and inspect the normalized ShadowLab ingest history.")

        top = QWidget()
        top_row = QHBoxLayout(top)
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(8)
        import_btn = QPushButton("Import HIDS File")
        import_btn.clicked.connect(self.import_hids_file)
        self._bind_capability(import_btn, "can_manage_integrations")
        plan_response_btn = QPushButton("Plan Response")
        plan_response_btn.clicked.connect(lambda: self.orchestrate_hids_response(False))
        self._bind_capability(plan_response_btn, "can_manage_integrations")
        apply_response_btn = QPushButton("Apply Response")
        apply_response_btn.clicked.connect(lambda: self.orchestrate_hids_response(True))
        self._bind_capability(apply_response_btn, "can_manage_integrations")
        live_start_btn = QPushButton("Start Live Ingest")
        live_start_btn.clicked.connect(self.start_hids_live_ingest)
        self._bind_capability(live_start_btn, "can_manage_integrations")
        live_stop_btn = QPushButton("Stop Live Ingest")
        live_stop_btn.clicked.connect(self.stop_hids_live_ingest)
        self._bind_capability(live_stop_btn, "can_manage_integrations")
        live_status_btn = QPushButton("Live Status")
        live_status_btn.clicked.connect(self.refresh_hids_live_status)
        self._bind_capability(live_status_btn, "can_manage_integrations")
        refresh_btn = QPushButton("Refresh HIDS")
        refresh_btn.clicked.connect(self.refresh_hids_workspace)
        self._bind_capability(refresh_btn, "can_manage_integrations")
        top_row.addWidget(self._field_block("OSSEC / HIDS Alert File", self.hids_file_path), 1)
        top_row.addWidget(self._field_block("Incident ID", self.hids_incident_id), 1)
        top_row.addWidget(self._field_block("Live Poll (s)", self.hids_live_interval))
        top_row.addWidget(self.hids_live_start_at_end)
        top_row.addWidget(import_btn)
        top_row.addWidget(plan_response_btn)
        top_row.addWidget(apply_response_btn)
        top_row.addWidget(live_start_btn)
        top_row.addWidget(live_stop_btn)
        top_row.addWidget(live_status_btn)
        top_row.addWidget(refresh_btn)

        self.hids_summary = QTextBrowser()
        self.hids_summary.setProperty("role", "brief")
        self.hids_summary.setMinimumHeight(120)
        self.hids_health_badge = QLabel("HIDS: unknown")
        self.hids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        self.hids_table = QTableWidget(0, 5)
        self.hids_table.setHorizontalHeaderLabels(["Created", "Type", "Target", "Status", "Detail"])
        self.hids_table.itemSelectionChanged.connect(self.show_selected_hids_export)
        self._style_table(self.hids_table)
        self.hids_detail = QTextEdit()
        self.hids_detail.setReadOnly(True)
        self.hids_detail.setProperty("role", "brief")

        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._panel_card("HIDS Export History", self.hids_table, lambda: self._open_panel_window("HIDS Export History", self._clone_table(self.hids_table))))
        split.addWidget(self._panel_card("HIDS Detail", self.hids_detail, lambda: self._open_panel_window("HIDS Detail", self._clone_text_view(self.hids_detail))))
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        hids_actions = QWidget()
        hids_actions_row = QHBoxLayout(hids_actions)
        hids_actions_row.setContentsMargins(0, 0, 0, 0)
        hids_actions_row.setSpacing(8)
        open_hids_target_btn = QPushButton("Open Selected Target")
        open_hids_target_btn.clicked.connect(self.open_selected_hids_target)
        self._bind_capability(open_hids_target_btn, "can_manage_integrations")
        open_hids_case_btn = QPushButton("Open Enterprise Case")
        open_hids_case_btn.clicked.connect(lambda: self.open_enterprise_case_for_incident(prefix="OSSEC-"))
        self._bind_capability(open_hids_case_btn, "can_manage_incidents")
        hids_actions_row.addWidget(self.hids_health_badge)
        hids_actions_row.addWidget(open_hids_target_btn)
        hids_actions_row.addWidget(open_hids_case_btn)
        hids_actions_row.addStretch(1)
        l.addWidget(self._panel_card("HIDS Summary", self.hids_summary, lambda: self._open_panel_window("HIDS Summary", self._clone_text_view(self.hids_summary))))
        l.addWidget(self._panel_card("HIDS Status", hids_actions, lambda: self._open_panel_window("HIDS Status", QLabel("Use HIDS status controls in the main workspace."))))
        l.addWidget(self._panel_card("HIDS Controls", top, lambda: self._open_panel_window("HIDS Controls", QLabel("Use the main HIDS tab to import detections."))))
        l.addWidget(split, 1)
        return w

    def _panel_card(self, title: str, content: QWidget, expand_fn) -> QWidget:
        card = QFrame()
        card.setProperty("card", True)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(12, 10, 12, 12)
        card_layout.setSpacing(8)
        header = QWidget()
        header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(8)
        label = QLabel(title)
        label.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        expand_btn = QPushButton("Open Panel")
        expand_btn.setMaximumWidth(104)
        expand_btn.clicked.connect(expand_fn)
        header_row.addWidget(label)
        header_row.addStretch(1)
        header_row.addWidget(expand_btn)
        expanding_content = isinstance(content, (QTextEdit, QTextBrowser, QTableWidget, QListWidget, QTreeWidget))
        if expanding_content:
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        else:
            content.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card_layout.addWidget(header)
        card_layout.addWidget(content, 1 if expanding_content else 0)
        return card

    def _open_panel_window(self, title: str, body: QWidget) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        dlg.resize(1180, 760)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.addWidget(body)
        dlg.show()
        self.panel_windows.append(dlg)

    def _clone_table(self, source: QTableWidget) -> QTableWidget:
        clone = QTableWidget(source.rowCount(), source.columnCount())
        headers = []
        for col in range(source.columnCount()):
            item = source.horizontalHeaderItem(col)
            headers.append(item.text() if item else f"Column {col + 1}")
        clone.setHorizontalHeaderLabels(headers)
        for row in range(source.rowCount()):
            for col in range(source.columnCount()):
                cell = source.item(row, col)
                clone.setItem(row, col, QTableWidgetItem(cell.text() if cell else ""))
        self._style_table(clone)
        return clone

    def _clone_text_view(self, source: QWidget) -> QTextBrowser:
        clone = QTextBrowser()
        clone.setOpenExternalLinks(True)
        if isinstance(source, QTextBrowser):
            clone.setHtml(source.toHtml())
        elif isinstance(source, QTextEdit):
            clone.setPlainText(source.toPlainText())
        elif isinstance(source, QLabel):
            clone.setText(source.text())
        return clone

    def _enterprise_action_button(self, label: str, callback, capability: str | None = None) -> QPushButton:
        button = QPushButton(label)
        button.setMinimumHeight(32)
        button.clicked.connect(callback)
        if capability:
            self._bind_capability(button, capability)
        return button

    def _enterprise_menu_button(self, label: str, actions: list[tuple[str, object, str | None]]) -> QToolButton:
        button = QToolButton()
        button.setText(label)
        button.setPopupMode(QToolButton.InstantPopup)
        button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        button.setMinimumHeight(32)
        menu = QMenu(button)
        capability_bound = False
        for action_label, callback, capability in actions:
            action = QAction(action_label, button)
            action.triggered.connect(callback)
            menu.addAction(action)
            if capability and not capability_bound:
                self._bind_capability(button, capability)
                capability_bound = True
        button.setMenu(menu)
        return button

    def _copy_cpu_chart(self) -> QChartView:
        copied_series = QLineSeries()
        for point in self.cpu_series.pointsVector():
            copied_series.append(point)
        copied_chart = QChart()
        copied_chart.setTheme(QChart.ChartThemeDark)
        copied_chart.setBackgroundVisible(False)
        copied_chart.setPlotAreaBackgroundVisible(True)
        copied_chart.setPlotAreaBackgroundBrush(QColor("#121b27"))
        copied_chart.legend().hide()
        copied_chart.setTitle(self.cpu_chart.title() or "Telemetry CPU Trend")
        copied_chart.addSeries(copied_series)
        axis_x = QValueAxis(); axis_x.setTitleText("Samples")
        axis_y = QValueAxis(); axis_y.setTitleText("CPU %"); axis_y.setRange(0, 100)
        copied_chart.addAxis(axis_x, Qt.AlignBottom)
        copied_chart.addAxis(axis_y, Qt.AlignLeft)
        copied_series.attachAxis(axis_x)
        copied_series.attachAxis(axis_y)
        chart_view = QChartView(copied_chart)
        chart_view.setMinimumHeight(600)
        return chart_view

    def _open_overview_chart_panel(self) -> None:
        self._open_panel_window("Overview: Telemetry CPU Trend", self._copy_cpu_chart())

    def _open_overview_brief_panel(self) -> None:
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(self.monitor_out.toHtml())
        self._open_panel_window("Overview: Incident Brief", viewer)

    def _open_process_table_panel(self) -> None:
        self._open_panel_window("Processes: Table", self._clone_table(self.proc_table))

    def _open_process_detail_panel(self) -> None:
        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setPlainText(self.proc_detail.toPlainText())
        self._open_panel_window("Processes: Detail", detail)

    def _open_hunt_tree_panel(self) -> None:
        tree = QTreeWidget()
        tree.setHeaderLabels(["Process Tree", "PID"])
        for i in range(self.tree_view.topLevelItemCount()):
            root = self.tree_view.topLevelItem(i)
            cloned = QTreeWidgetItem(root)
            tree.addTopLevelItem(cloned)
        self._open_panel_window("Advanced Hunt: Process Tree", tree)

    def _open_hunt_internals_panel(self) -> None:
        self._open_panel_window("Advanced Hunt: Internals", self._clone_table(self.internals_table))

    def _open_hunt_output_panel(self) -> None:
        output = QTextEdit()
        output.setReadOnly(True)
        output.setPlainText(self.hunt_out.toPlainText())
        self._open_panel_window("Advanced Hunt: Output", output)

    def _open_threat_history_panel(self) -> None:
        self._open_panel_window("Threat Intel: History", self._clone_table(self.threat_history_table))

    def _open_threat_output_panel(self) -> None:
        output = QTextEdit()
        output.setReadOnly(True)
        output.setPlainText(self.threat_out.toPlainText())
        self._open_panel_window("Threat Intel: Analysis", output)

    def _open_dashboard_metrics_panel(self) -> None:
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(self.dash_metrics.toHtml())
        self._open_panel_window("Dashboard: Live Metrics", viewer)

    def _open_dashboard_threat_panel(self) -> None:
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(self.dash_threat.toHtml())
        self._open_panel_window("Dashboard: Threat Snapshot", viewer)

    def _open_dashboard_auth_panel(self) -> None:
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(self.dash_auth.toHtml())
        self._open_panel_window("Dashboard: Auth & Policy", viewer)

    def _open_dashboard_timeline_panel(self) -> None:
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(self.dash_timeline.toHtml())
        self._open_panel_window("Dashboard: Timeline Story", viewer)

    def _open_dashboard_actions_panel(self) -> None:
        panel = QWidget()
        row = QHBoxLayout(panel)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        for text, fn in [
            ("Run Monitor", self.run_monitor),
            ("Load Processes", self.refresh_processes),
            ("Refresh History", self.refresh_history),
            ("Enterprise Triage", self.refresh_enterprise_workspace),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(fn)
            row.addWidget(btn)
        row.addStretch(1)
        self._open_panel_window("Dashboard: Quick Actions", panel)

    def _refresh_dashboard_panels(self) -> None:
        metrics_html = (
            f"<h3>Live Metrics</h3>"
            f"<p>{html.escape(self.metric_proc.text())}<br>{html.escape(self.metric_tel.text())}<br>"
            f"{html.escape(self.metric_inc.text())}<br>{html.escape(self.metric_art.text())}</p>"
        )
        self.dash_metrics.setHtml(metrics_html)

        threat_lines = self.threat_history[:4]
        if threat_lines:
            items = "".join(
                f"<li><b>{html.escape(item.get('type', 'query'))}</b>: {html.escape(item.get('value', ''))}</li>"
                for item in threat_lines
            )
        else:
            items = "<li>No threat queries yet.</li>"
        self.dash_threat.setHtml(f"<h3>Threat Snapshot</h3><ul>{items}</ul>")

        role = str(self.auth_context.get("role", "viewer"))
        features = self.auth_context.get("features", {}) if isinstance(self.auth_context.get("features"), dict) else {}
        policy_profile = str(features.get("policy_profile", "lab"))
        self.dash_auth.setHtml(
            f"<h3>Auth & Policy</h3>"
            f"<p><b>Role:</b> {html.escape(role)}<br><b>Policy:</b> {html.escape(policy_profile)}<br>"
            f"<b>Dangerous Actions:</b> {html.escape(str(features.get('dangerous_actions_enabled', False)))}</p>"
        )

        timeline_text = self.timeline_summary.toHtml().strip() if hasattr(self, "timeline_summary") else ""
        if not timeline_text:
            timeline_text = "<h3>Timeline Story</h3><p>No timeline narrative yet. Run monitor and refresh timeline.</p>"
        self.dash_timeline.setHtml(timeline_text)

    def _overview_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)
        row = QWidget(); r = QHBoxLayout(row)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(12)
        self.metric_proc = QLabel("Processes: -"); self.metric_tel = QLabel("Telemetry Rows: -")
        self.metric_inc = QLabel("Last Incident: -"); self.metric_art = QLabel("Artifacts: -")
        for label in [self.metric_proc, self.metric_tel, self.metric_inc, self.metric_art]: r.addWidget(label)
        expand_chart_btn = QPushButton("Expand Chart")
        expand_chart_btn.clicked.connect(self._open_overview_chart_panel)
        expand_brief_btn = QPushButton("Expand Brief")
        expand_brief_btn.clicked.connect(self._open_overview_brief_panel)
        r.addWidget(expand_chart_btn)
        r.addWidget(expand_brief_btn)
        r.addStretch(1); l.addWidget(row)
        self.cpu_series = QLineSeries()
        self.cpu_chart = QChart()
        self.cpu_chart.setTheme(QChart.ChartThemeDark)
        self.cpu_chart.setBackgroundVisible(False)
        self.cpu_chart.setPlotAreaBackgroundVisible(True)
        self.cpu_chart.setPlotAreaBackgroundBrush(QColor("#121b27"))
        self.cpu_chart.setMargins(QMargins(8, 8, 8, 8))
        self.cpu_chart.legend().hide()
        self.cpu_chart.addSeries(self.cpu_series)
        self.cpu_chart.setTitle("Telemetry CPU Trend")
        self.cpu_axis_x = QValueAxis(); self.cpu_axis_x.setTitleText("Samples")
        self.cpu_axis_y = QValueAxis(); self.cpu_axis_y.setTitleText("CPU %"); self.cpu_axis_y.setRange(0, 100)
        self.cpu_chart.addAxis(self.cpu_axis_x, Qt.AlignBottom)
        self.cpu_chart.addAxis(self.cpu_axis_y, Qt.AlignLeft)
        self.cpu_series.attachAxis(self.cpu_axis_x)
        self.cpu_series.attachAxis(self.cpu_axis_y)
        self.cpu_chart_view = QChartView(self.cpu_chart)
        self.cpu_series.setColor(QColor("#28a0ff"))
        self.cpu_series.setPointsVisible(True)
        cpu_pen = QPen(QColor("#28a0ff"))
        cpu_pen.setWidth(3)
        self.cpu_series.setPen(cpu_pen)
        self.cpu_chart_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.cpu_chart_view.setFixedHeight(220)
        l.addWidget(self.cpu_chart_view)
        self.monitor_out = QTextBrowser()
        self.monitor_out.setReadOnly(True)
        self.monitor_out.setProperty("role", "brief")
        self.monitor_out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.monitor_out.setMinimumHeight(160)
        self.monitor_out.setOpenExternalLinks(True)
        l.addWidget(self.monitor_out)
        l.setStretch(1, 3)
        l.setStretch(2, 2)
        return w

    def _process_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8); s = QSplitter(Qt.Horizontal)
        process_panel_actions = QWidget()
        process_panel_row = QHBoxLayout(process_panel_actions)
        process_panel_row.setContentsMargins(0, 0, 0, 0)
        process_panel_row.setSpacing(8)
        pop_proc_table = QPushButton("Open Process Table")
        pop_proc_table.clicked.connect(self._open_process_table_panel)
        pop_proc_detail = QPushButton("Open Process Detail")
        pop_proc_detail.clicked.connect(self._open_process_detail_panel)
        process_panel_row.addWidget(pop_proc_table)
        process_panel_row.addWidget(pop_proc_detail)
        process_panel_row.addStretch(1)
        l.addWidget(process_panel_actions)
        self.proc_table = QTableWidget(0, 5); self.proc_table.setHorizontalHeaderLabels(["PID","Name","CPU %","Memory %","Signature"]); self.proc_table.itemSelectionChanged.connect(self.show_selected_process); self._style_table(self.proc_table)
        right = QWidget(); rl = QVBoxLayout(right); self.proc_detail = QTextEdit(); self.proc_detail.setReadOnly(True); rl.addWidget(self.proc_detail)
        actions = QWidget(); ar = QHBoxLayout(actions)
        process_capabilities = {
            "Auto Triage": "can_run_triage",
            "Threat Scan": "can_run_hunt",
            "Memory Analysis": "can_run_hunt",
            "Internals": "can_run_hunt",
            "Strings": "can_run_hunt",
            "YARA": "can_run_hunt",
            "Sandbox": "can_run_hunt",
            "Process Tree": "can_run_hunt",
            "AI Analyst": "can_run_hunt",
            "Suspend": "can_manage_process_actions",
            "Resume": "can_manage_process_actions",
            "Kill": "can_manage_process_actions",
            "Kill Tree": "can_manage_process_actions",
            "Quarantine": "can_manage_process_actions",
        }
        for text, fn in [("Auto Triage", self.run_auto_triage),("Threat Scan", self.scan_selected_process),("Memory Analysis", self.run_memory_analysis),("Internals", self.load_selected_internals),("Strings", self.run_strings_analysis),("YARA", self.run_yara_scan),("Sandbox", self.run_sandbox_trace),("Process Tree", self.load_process_tree),("AI Analyst", self.run_ai_analysis),("Suspend", lambda: self.process_action("suspend")),("Resume", lambda: self.process_action("resume")),("Kill", lambda: self.process_action("kill")),("Kill Tree", lambda: self.process_action("kill-tree")),("Quarantine", lambda: self.process_action("quarantine"))]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            self._bind_capability(b, process_capabilities[text])
            ar.addWidget(b)
        self.proc_table.setMinimumHeight(220)
        self.proc_detail.setMinimumHeight(220)
        s.setMinimumHeight(360)
        rl.addWidget(actions); s.addWidget(self.proc_table); s.addWidget(right); s.setStretchFactor(0, 2); s.setStretchFactor(1, 3); l.addWidget(s, 1); return w

    def _hunt_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(10)
        title = QLabel("Advanced Hunt Workspace")
        title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        sub = QLabel("Use compact hunt panels; expand any panel into a separate full window.")
        sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        l.addWidget(title)
        l.addWidget(sub)

        actions = QWidget(); ar = QHBoxLayout(actions)
        ar.setContentsMargins(0, 0, 0, 0)
        ar.setSpacing(8)
        for text, fn in [("Load Internals", self.load_selected_internals),("Extract Strings", self.run_strings_analysis),("Run YARA", self.run_yara_scan),("Sandbox Trace", self.run_sandbox_trace),("Process Tree", self.load_process_tree),("AI Analyst", self.run_ai_analysis)]:
            btn = QPushButton(text); btn.clicked.connect(fn); self._bind_capability(btn, "can_run_hunt"); ar.addWidget(btn)
        ar.addStretch(1)
        l.addWidget(actions)

        self.tree_view = QTreeWidget()
        self.tree_view.setHeaderLabels(["Process Tree", "PID"])
        self.tree_view.setMinimumHeight(180)
        self.internals_table = QTableWidget(0, 4)
        self.internals_table.setHorizontalHeaderLabels(["Kind", "Path / Detail", "Mode / Perms", "FD / Size"])
        self._style_table(self.internals_table)
        self.hunt_out = QTextEdit(); self.hunt_out.setReadOnly(True)

        hunt_split = QSplitter(Qt.Horizontal)
        left = QWidget(); left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)
        left_layout.addWidget(self._panel_card("Process Tree", self.tree_view, self._open_hunt_tree_panel))
        left_layout.addWidget(self._panel_card("Internals Table", self.internals_table, self._open_hunt_internals_panel))
        hunt_split.addWidget(left)
        hunt_split.addWidget(self._panel_card("Hunt Output", self.hunt_out, self._open_hunt_output_panel))
        hunt_split.setStretchFactor(0, 2)
        hunt_split.setStretchFactor(1, 3)
        l.addWidget(hunt_split, 1)
        return w

    def _persistence_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Persistence Workspace", "Enumerate, filter and remediate persistence mechanisms on the monitored host.")
        actions = QWidget(); ar = QHBoxLayout(actions)
        ar.setContentsMargins(0, 0, 0, 0)
        ar.setSpacing(8)
        remediate = QPushButton("Remediate Selected Persistence"); remediate.clicked.connect(self.remediate_selected_persistence); self._bind_capability(remediate, "can_manage_persistence")
        ar.addWidget(remediate)
        ar.addStretch(1)
        self.persist_table = QTableWidget(0, 4); self.persist_table.setHorizontalHeaderLabels(["Name","Type","Path","Details"]); self.persist_table.itemSelectionChanged.connect(self.show_selected_persistence); self._style_table(self.persist_table)
        self.persist_detail = QTextEdit(); self.persist_detail.setReadOnly(True)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._panel_card("Persistence Findings", self.persist_table, lambda: self._open_panel_window("Persistence Findings", self._clone_table(self.persist_table))))
        split.addWidget(self._panel_card("Persistence Detail", self.persist_detail, lambda: self._open_panel_window("Persistence Detail", self._clone_text_view(self.persist_detail))))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(self._panel_card("Persistence Actions", actions, lambda: self._open_panel_window("Persistence Actions", QLabel("Use this panel in main window to run remediation."))))
        l.addWidget(split, 1)
        return w

    def _threat_tab(self) -> QWidget:
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
        self.ti_last_type = QLabel("Last Query: -")
        self.ti_last_value = QLabel("Value: -")
        self.ti_last_source = QLabel("Source: -")
        for item in [self.ti_last_type, self.ti_last_value, self.ti_last_source]:
            sr.addWidget(item)
        sr.addStretch(1)
        l.addWidget(self._panel_card("Current Query Context", summary, self._open_threat_output_panel))

        controls = QWidget(); cr = QHBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        auto_hash = QPushButton("Use Selected Process Hash"); auto_hash.clicked.connect(self.use_selected_process_hash)
        auto_ip = QPushButton("Use Selected Process IP"); auto_ip.clicked.connect(self.use_selected_process_ip)
        hash_btn = QPushButton("Lookup Hash"); hash_btn.clicked.connect(self.lookup_hash)
        ip_btn = QPushButton("Lookup IP"); ip_btn.clicked.connect(self.lookup_ip)
        scan_btn = QPushButton("Scan Selected Process"); scan_btn.clicked.connect(self.scan_selected_process); self._bind_capability(scan_btn, "can_run_hunt")
        for btn in [auto_hash, auto_ip, hash_btn, ip_btn, scan_btn]:
            cr.addWidget(btn)
        cr.addStretch(1)
        l.addWidget(self._panel_card("Threat Actions", controls, self._open_threat_output_panel))

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        self.threat_history_table = QTableWidget(0, 3)
        self.threat_history_table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self.threat_history_table.itemSelectionChanged.connect(self.show_selected_threat_history)
        self._style_table(self.threat_history_table)
        ll.addWidget(self._panel_card("Threat History", self.threat_history_table, self._open_threat_history_panel))
        self.threat_out = QTextEdit(); self.threat_out.setReadOnly(True)
        split.addWidget(left)
        split.addWidget(self._panel_card("Threat Analysis Output", self.threat_out, self._open_threat_output_panel))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def _deception_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Deception & Evidence Workspace", "Deploy honeypots and canaries, capture and review evidence bundles.")
        top = QWidget(); tr = QHBoxLayout(top)
        tr.setContentsMargins(0, 0, 0, 0)
        tr.setSpacing(8)
        deception_capabilities = {
            "Deploy Honeypot": "can_manage_deception",
            "Check Honeypot": "can_view_deception",
            "Cleanup Honeypot": "can_manage_deception",
            "Deploy Canary": "can_manage_deception",
            "Check Canary": "can_view_deception",
            "Cleanup Canary": "can_manage_deception",
            "Capture Evidence": "can_capture_evidence",
            "Refresh Evidence": "can_view_evidence",
            "Delete Evidence": "can_delete_evidence",
        }
        for text, fn in [("Deploy Honeypot", self.deploy_honeypot),("Check Honeypot", self.check_honeypot),("Cleanup Honeypot", self.cleanup_honeypot),("Deploy Canary", self.deploy_canary),("Check Canary", self.check_canary),("Cleanup Canary", self.cleanup_canary),("Capture Evidence", self.capture_evidence),("Refresh Evidence", self.refresh_evidence),("Delete Evidence", self.delete_selected_evidence)]:
            btn = QPushButton(text)
            btn.clicked.connect(fn)
            self._bind_capability(btn, deception_capabilities[text])
            tr.addWidget(btn)
        tr.addStretch(1)
        l.addWidget(self._panel_card("Deception Actions", top, lambda: self._open_panel_window("Deception Actions", QLabel("Use this action strip in main workspace."))))
        split = QSplitter(Qt.Horizontal)
        self.evidence_list = QListWidget(); self.evidence_list.itemSelectionChanged.connect(self.show_selected_evidence)
        right = QWidget(); rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(8)
        self.deception_out = QTextEdit(); self.deception_out.setReadOnly(True)
        self.evidence_detail = QTextEdit(); self.evidence_detail.setReadOnly(True)
        open_evidence_btn = QPushButton("Open Selected Evidence"); open_evidence_btn.clicked.connect(self.open_selected_evidence); self._bind_capability(open_evidence_btn, "can_view_evidence")
        rl.addWidget(self._panel_card("Deception Output", self.deception_out, lambda: self._open_panel_window("Deception Output", self._clone_text_view(self.deception_out))))
        rl.addWidget(self._panel_card("Evidence Detail", self.evidence_detail, lambda: self._open_panel_window("Evidence Detail", self._clone_text_view(self.evidence_detail))))
        rl.addWidget(open_evidence_btn)
        split.addWidget(self._panel_card("Evidence List", self.evidence_list, lambda: self._open_panel_window("Evidence List", QLabel("Open evidence from main workspace list."))))
        split.addWidget(right)
        split.setStretchFactor(0, 1); split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def _network_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Network Workspace", "Capture packets, discover ARP devices, inspect connections and control the network blocker.")
        row = QWidget(); r = QHBoxLayout(row)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(8)
        self.sniff_duration = QSpinBox(); self.sniff_duration.setRange(5, 60); self.sniff_duration.setValue(10)
        sniff = QPushButton("Start Packet Capture"); sniff.clicked.connect(self.run_sniffer); self._bind_capability(sniff, "can_run_sniffer")
        scan = QPushButton("ARP Discovery"); scan.clicked.connect(self.scan_network_devices); self._bind_capability(scan, "can_manage_network_warfare")
        start_block = QPushButton("Start Blocker"); start_block.clicked.connect(self.start_network_blocker); self._bind_capability(start_block, "can_manage_network_warfare")
        stop_block = QPushButton("Stop Blocker"); stop_block.clicked.connect(self.stop_network_blocker); self._bind_capability(stop_block, "can_manage_network_warfare")
        r.addWidget(QLabel("Capture Duration")); r.addWidget(self.sniff_duration); r.addWidget(sniff); r.addWidget(scan); r.addWidget(start_block); r.addWidget(stop_block); r.addStretch(1)
        l.addWidget(self._panel_card("Network Controls", row, lambda: self._open_panel_window("Network Controls", QLabel("Use this control strip in main workspace."))))
        s = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(8)
        self.net_table = QTableWidget(0, 4); self.net_table.setHorizontalHeaderLabels(["Local","Remote","Status","PID"]); self._style_table(self.net_table)
        self.device_table = QTableWidget(0, 3); self.device_table.setHorizontalHeaderLabels(["IP","MAC","Vendor"]); self._style_table(self.device_table)
        ll.addWidget(self._panel_card("Connection Table", self.net_table, lambda: self._open_panel_window("Connection Table", self._clone_table(self.net_table))))
        ll.addWidget(self._panel_card("Discovered Devices", self.device_table, lambda: self._open_panel_window("Discovered Devices", self._clone_table(self.device_table))))
        self.net_out = QTextEdit(); self.net_out.setReadOnly(True)
        s.addWidget(left); s.addWidget(self._panel_card("Network Output", self.net_out, lambda: self._open_panel_window("Network Output", self._clone_text_view(self.net_out))))
        s.setStretchFactor(0, 2); s.setStretchFactor(1, 3); l.addWidget(s, 1); return w

    def _hosts_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Fleet Host Inventory", "View and refresh all registered ShadowLab agents and fleet hosts.")
        top = QWidget(); tr = QHBoxLayout(top)
        tr.setContentsMargins(0, 0, 0, 0)
        tr.setSpacing(8)
        btn = QPushButton("Refresh Hosts"); btn.clicked.connect(self.refresh_hosts); tr.addWidget(btn); tr.addStretch(1)
        self.host_table = QTableWidget(0, 7); self.host_table.setHorizontalHeaderLabels(["Host","Platform","Boot Time","API Status","Role","IP","Version"]); self._style_table(self.host_table)
        l.addWidget(self._panel_card("Host Actions", top, lambda: self._open_panel_window("Host Actions", QLabel("Use refresh from main workspace."))))
        l.addWidget(self._panel_card("Host Inventory", self.host_table, lambda: self._open_panel_window("Host Inventory", self._clone_table(self.host_table))), 1)
        return w

    def _graph_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Entity Graph Workspace", "Build and inspect the attack surface entity graph — nodes, edges and process-focused views.")
        top = QWidget(); r = QHBoxLayout(top)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(8)
        top.setMinimumHeight(42)
        top.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        refresh_btn = QPushButton("Refresh Entity Graph"); refresh_btn.clicked.connect(self.refresh_entity_graph)
        focus_btn = QPushButton("Build From Selected Process"); focus_btn.clicked.connect(self.refresh_selected_process_graph)
        open_btn = QPushButton("Open Interactive Graph"); open_btn.clicked.connect(self.open_entity_graph)
        r.addWidget(refresh_btn); r.addWidget(focus_btn); r.addWidget(open_btn); r.addStretch(1)
        l.addWidget(self._panel_card("Graph Controls", top, lambda: self._open_panel_window("Graph Controls", QLabel("Use graph controls in main workspace."))))
        self.graph_summary = QTextBrowser(); self.graph_summary.setMinimumHeight(140)
        graph_top = QWidget()
        graph_top_layout = QHBoxLayout(graph_top)
        graph_top_layout.setContentsMargins(0, 0, 0, 0)
        graph_top_layout.setSpacing(8)
        self.graph_findings = QTextBrowser(); self.graph_findings.setMinimumHeight(180)
        self.graph_focus_table = QTableWidget(0, 4); self.graph_focus_table.setHorizontalHeaderLabels(["Process","PID","Risk","Signature"]); self._style_table(self.graph_focus_table)
        self.graph_focus_table.setMinimumHeight(180)
        self.graph_group_table = QTableWidget(0, 2); self.graph_group_table.setHorizontalHeaderLabels(["Group","Count"]); self._style_table(self.graph_group_table)
        self.graph_group_table.setMinimumHeight(180)
        graph_top_layout.addWidget(self._panel_card("Priority Findings", self.graph_findings, lambda: self._open_panel_window("Priority Findings", self._clone_text_view(self.graph_findings))), 3)
        graph_top_layout.addWidget(self._panel_card("Hot Processes", self.graph_focus_table, lambda: self._open_panel_window("Hot Processes", self._clone_table(self.graph_focus_table))), 3)
        graph_top_layout.addWidget(self._panel_card("Graph Coverage", self.graph_group_table, lambda: self._open_panel_window("Graph Coverage", self._clone_table(self.graph_group_table))), 2)
        split = QSplitter(Qt.Horizontal)
        self.graph_nodes_table = QTableWidget(0, 5); self.graph_nodes_table.setHorizontalHeaderLabels(["Label","Group","Cluster","Risk","Title"]); self._style_table(self.graph_nodes_table)
        self.graph_edges_table = QTableWidget(0, 4); self.graph_edges_table.setHorizontalHeaderLabels(["From","To","Label","Width"]); self._style_table(self.graph_edges_table)
        self.graph_nodes_table.setMinimumHeight(240)
        self.graph_edges_table.setMinimumHeight(240)
        split.addWidget(self._panel_card("Entity Nodes", self.graph_nodes_table, lambda: self._open_panel_window("Entity Nodes", self._clone_table(self.graph_nodes_table))))
        split.addWidget(self._panel_card("Entity Edges", self.graph_edges_table, lambda: self._open_panel_window("Entity Edges", self._clone_table(self.graph_edges_table))))
        split.setStretchFactor(0, 2); split.setStretchFactor(1, 2)
        split.setChildrenCollapsible(False)
        self.graph_detail = QTextEdit(); self.graph_detail.setReadOnly(True); self.graph_detail.setMinimumHeight(180)
        l.addWidget(self._panel_card("Graph Summary", self.graph_summary, lambda: self._open_panel_window("Graph Summary", self._clone_text_view(self.graph_summary))))
        l.addWidget(graph_top)
        l.addWidget(split, 1)
        l.addWidget(self._panel_card("Graph Detail", self.graph_detail, lambda: self._open_panel_window("Graph Detail", self._clone_text_view(self.graph_detail))))
        return w

    def _timeline_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Timeline & Event Story", "Review chronological events, severity timeline and AI-generated narrative.")
        top = QWidget(); tr = QHBoxLayout(top)
        tr.setContentsMargins(0, 0, 0, 0)
        tr.setSpacing(8)
        btn = QPushButton("Refresh Timeline"); btn.clicked.connect(self.refresh_timeline); tr.addWidget(btn); tr.addStretch(1)
        l.addWidget(self._panel_card("Timeline Controls", top, lambda: self._open_panel_window("Timeline Controls", QLabel("Use refresh in main workspace."))))
        self.timeline_summary = QTextBrowser(); self.timeline_summary.setMinimumHeight(120)
        self.timeline_table = QTableWidget(0, 4); self.timeline_table.setHorizontalHeaderLabels(["Time","Type","Severity","Title"]); self.timeline_table.itemSelectionChanged.connect(self.show_selected_timeline); self._style_table(self.timeline_table)
        self.timeline_detail = QTextEdit(); self.timeline_detail.setReadOnly(True)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._panel_card("Timeline Events", self.timeline_table, lambda: self._open_panel_window("Timeline Events", self._clone_table(self.timeline_table))))
        split.addWidget(self._panel_card("Timeline Detail", self.timeline_detail, lambda: self._open_panel_window("Timeline Detail", self._clone_text_view(self.timeline_detail))))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(self._panel_card("Timeline Story", self.timeline_summary, lambda: self._open_panel_window("Timeline Story", self._clone_text_view(self.timeline_summary))))
        l.addWidget(split, 1)
        return w

    def _quarantine_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Quarantine & Alert Workspace", "Manage quarantined processes, restore items, configure alert webhooks.")
        row = QWidget(); r = QHBoxLayout(row)
        quarantine_capabilities = {
            "Refresh Quarantine": "can_view_quarantine",
            "Restore Selected": "can_manage_quarantine",
            "Delete Selected": "can_manage_quarantine",
            "Test Webhook": "can_manage_alerts",
            "Save Webhook": "can_manage_alerts",
        }
        for text, fn in [("Refresh Quarantine", self.refresh_quarantine), ("Restore Selected", self.restore_selected_quarantine), ("Delete Selected", self.delete_selected_quarantine), ("Test Webhook", self.test_alert_webhook), ("Save Webhook", self.save_alert_webhook)]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            self._bind_capability(b, quarantine_capabilities[text])
            r.addWidget(b)
        r.addStretch(1); l.addWidget(self._panel_card("Quarantine Controls", row, lambda: self._open_panel_window("Quarantine Controls", QLabel("Use controls in main workspace."))))
        self.quarantine_table = QTableWidget(0, 6); self.quarantine_table.setHorizontalHeaderLabels(["ID","Process","Original Path","Quarantine Path","Status","Created"]); self._style_table(self.quarantine_table)
        self.quarantine_detail = QTextEdit(); self.quarantine_detail.setReadOnly(True)
        split = QSplitter(Qt.Horizontal)
        split.addWidget(self._panel_card("Quarantine Items", self.quarantine_table, lambda: self._open_panel_window("Quarantine Items", self._clone_table(self.quarantine_table))))
        split.addWidget(self._panel_card("Quarantine Detail", self.quarantine_detail, lambda: self._open_panel_window("Quarantine Detail", self._clone_text_view(self.quarantine_detail))))
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def _history_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8); s = QSplitter(Qt.Horizontal)
        self._tab_header(l, "History & Incident Log", "View response actions, telemetry, incidents, alerts, remediations and auth audit trail.")
        controls = QWidget(); cr = QHBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        self.incident_status = QComboBox(); self.incident_status.addItems(["open","investigating","contained","closed"])
        self.incident_owner = QLineEdit()
        self.incident_notes = QLineEdit()
        save_incident = QPushButton("Update Incident"); save_incident.clicked.connect(self.update_selected_incident); self._bind_capability(save_incident, "can_manage_incidents")
        cr.addWidget(QLabel("Status")); cr.addWidget(self.incident_status)
        cr.addWidget(QLabel("Owner")); cr.addWidget(self.incident_owner)
        cr.addWidget(QLabel("Notes")); cr.addWidget(self.incident_notes)
        cr.addWidget(save_incident); cr.addStretch(1)
        self.resp_table = QTableWidget(0, 4); self.resp_table.setHorizontalHeaderLabels(["Timestamp","Action","PID","Process"]); self._style_table(self.resp_table)
        self.tel_table = QTableWidget(0, 5); self.tel_table.setHorizontalHeaderLabels(["ts","cpu","mem","threads","tcp"]); self._style_table(self.tel_table)
        self.inc_table = QTableWidget(0, 5); self.inc_table.setHorizontalHeaderLabels(["Incident ID","Severity","Status","Owner","Title"]); self.inc_table.itemSelectionChanged.connect(self.show_selected_incident); self._style_table(self.inc_table)
        self.alert_table = QTableWidget(0, 4); self.alert_table.setHorizontalHeaderLabels(["Created","Type","Severity","Status"]); self._style_table(self.alert_table)
        self.rem_table = QTableWidget(0, 4); self.rem_table.setHorizontalHeaderLabels(["Created","Type","Target","Status"]); self._style_table(self.rem_table)
        self.auth_table = QTableWidget(0, 5); self.auth_table.setHorizontalHeaderLabels(["Created","Event","Outcome","Role","Path"]); self._style_table(self.auth_table); self._bind_capability(self.auth_table, "can_manage_integrations")
        self.auth_anomaly_view = QTextEdit(); self.auth_anomaly_view.setReadOnly(True); self._bind_capability(self.auth_anomaly_view, "can_manage_integrations")
        s.addWidget(self.resp_table); s.addWidget(self.tel_table); s.addWidget(self.inc_table)
        bottom = QSplitter(Qt.Horizontal)
        bottom.addWidget(self.alert_table); bottom.addWidget(self.rem_table); bottom.addWidget(self.auth_table)
        audit_panel = QSplitter(Qt.Horizontal)
        audit_panel.addWidget(bottom); audit_panel.addWidget(self.auth_anomaly_view)
        audit_panel.setStretchFactor(0, 3); audit_panel.setStretchFactor(1, 2)
        l.addWidget(self._panel_card("Incident Controls", controls, lambda: self._open_panel_window("Incident Controls", QLabel("Use incident controls in main workspace."))))
        l.addWidget(s, 2); l.addWidget(audit_panel, 2); return w

    def _artifacts_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8); s = QSplitter(Qt.Horizontal)
        self._tab_header(l, "Artifacts & Evidence Store", "Browse, preview and open forensic artifacts captured during monitoring and hunt sessions.")
        self.art_list = QListWidget(); self.art_list.itemSelectionChanged.connect(self.show_selected_artifact)
        right = QWidget(); rl = QVBoxLayout(right); rl.setContentsMargins(0, 0, 0, 0); rl.setSpacing(8); self.art_preview = QTextBrowser(); self.art_preview.setMinimumHeight(180); self.art_detail = QTextEdit(); self.art_detail.setReadOnly(True); open_btn = QPushButton("Open Selected Artifact"); open_btn.clicked.connect(self.open_selected_artifact); rl.addWidget(self._panel_card("Artifact Preview", self.art_preview, lambda: self._open_panel_window("Artifact Preview", self._clone_text_view(self.art_preview)))); rl.addWidget(self._panel_card("Artifact Detail", self.art_detail, lambda: self._open_panel_window("Artifact Detail", self._clone_text_view(self.art_detail)))); rl.addWidget(open_btn)
        s.addWidget(self._panel_card("Artifact List", self.art_list, lambda: self._open_panel_window("Artifact List", QLabel("Use artifact list in main workspace.")))); s.addWidget(right); s.setStretchFactor(0, 1); s.setStretchFactor(1, 3); l.addWidget(s, 1); return w

    def _enterprise_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Enterprise Operations Center", "Case management, approvals, network assessment, web surface inspection and purple team replay.")
        controls_card = QFrame(); controls_card.setProperty("card", True)
        controls_inner = QVBoxLayout(controls_card)
        controls_inner.setContentsMargins(12, 10, 12, 10)
        controls_inner.setSpacing(6)
        controls_lbl = QLabel("Case &amp; Operations Controls")
        controls_lbl.setStyleSheet("font-size:12px;font-weight:700;color:#96a5b8;")
        controls_inner.addWidget(controls_lbl)
        controls_top = QWidget()
        controls_top_row = QHBoxLayout(controls_top)
        controls_top_row.setContentsMargins(0, 0, 0, 0)
        controls_top_row.setSpacing(8)
        self.enterprise_warning_banner = QLabel("Warnings will appear here when cases need attention.")
        self.enterprise_warning_banner.setStyleSheet("color:#ffd166;background:#1a2230;border:1px solid #2c4260;border-radius:8px;padding:8px 10px;font-weight:600;")
        self.enterprise_role_banner = QLabel("Role context will appear here.")
        self.enterprise_role_banner.setStyleSheet("color:#9fd0ff;background:#121b27;border:1px solid #2c4260;border-radius:8px;padding:8px 10px;font-weight:600;")
        self.enterprise_live_status = QLabel("Live sync idle")
        self.enterprise_live_status.setStyleSheet("color:#96a5b8;font-size:11px;")
        self.enterprise_auto_refresh = QCheckBox("Auto refresh")
        self.enterprise_auto_refresh.setChecked(True)
        self.enterprise_case_filter = QLineEdit()
        self.enterprise_case_filter.setPlaceholderText("Filter cases")
        self.enterprise_case_filter.textChanged.connect(self._apply_enterprise_filters)
        self.enterprise_case_filter.textChanged.connect(self._persist_enterprise_ui_state)
        self.enterprise_task_filter = QLineEdit()
        self.enterprise_task_filter.setPlaceholderText("Filter tasks")
        self.enterprise_task_filter.textChanged.connect(self._apply_enterprise_filters)
        self.enterprise_task_filter.textChanged.connect(self._persist_enterprise_ui_state)
        self.enterprise_activity_filter = QLineEdit()
        self.enterprise_activity_filter.setPlaceholderText("Filter activity")
        self.enterprise_activity_filter.textChanged.connect(self._apply_enterprise_filters)
        self.enterprise_activity_filter.textChanged.connect(self._persist_enterprise_ui_state)
        self.enterprise_auto_refresh.toggled.connect(self._persist_enterprise_ui_state)
        controls_top_row.addWidget(self.enterprise_warning_banner, 2)
        controls_top_row.addWidget(self.enterprise_role_banner, 1)
        controls_top_row.addWidget(self.enterprise_live_status)
        controls_top_row.addWidget(self.enterprise_auto_refresh)
        controls_top_row.addWidget(self.enterprise_case_filter)
        controls_top_row.addWidget(self.enterprise_task_filter)
        controls_top_row.addWidget(self.enterprise_activity_filter)
        controls_inner.addWidget(controls_top)
        controls = QWidget()
        cr = QVBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(8)
        self.enterprise_case_title = QLineEdit("Suspicious activity case")
        self.enterprise_case_title.setPlaceholderText("Case title")
        self.enterprise_case_owner = QLineEdit()
        self.enterprise_case_owner.setPlaceholderText("Owner")
        self.enterprise_case_priority = QComboBox(); self.enterprise_case_priority.addItems(["low", "medium", "high", "critical"])
        self.enterprise_mitre_bundle_path = QLineEdit(str(Path("C:/Users/ulfat/Documents/mitreattack-python-main/tests/resources/enterprise-bundle.json")))
        self.enterprise_mitre_bundle_path.setPlaceholderText("ATT&CK STIX bundle path")
        self.enterprise_replay_path = QLineEdit(str((Path(__file__).resolve().parent.parent / "shadowlab_out" / "incident_bundle.json")))
        self.enterprise_network_range = QLineEdit("127.0.0.1")
        refresh_btn = self._enterprise_action_button("Refresh", self.refresh_enterprise_workspace, "can_run_hunt")
        create_case_btn = self._enterprise_action_button("Create Case", self.create_enterprise_case, "can_manage_incidents")
        assign_btn = self._enterprise_action_button("Assign", self.assign_enterprise_case, "can_manage_incidents")
        update_task_btn = self._enterprise_action_button("Update Task", self.update_enterprise_task_status, "can_manage_incidents")
        mark_done_btn = self._enterprise_action_button("Mark Done", lambda: self.update_enterprise_task_status("done"), "can_manage_incidents")
        graph_btn = self._enterprise_action_button("Correlation", self.load_enterprise_case_graph, "can_run_hunt")
        board_btn = self._enterprise_action_button("Case Board", self.load_selected_case_board, "can_manage_incidents")
        export_case_btn = self._enterprise_action_button("Export Report", self.export_selected_case_report, "can_manage_integrations")
        export_mitre_btn = self._enterprise_action_button("ATT&CK Layer", self.export_enterprise_mitre_layer, "can_run_hunt")
        export_workbench_btn = self._enterprise_action_button("Workbench", self.export_enterprise_mitre_workbench, "can_run_hunt")
        approval_btn = self._enterprise_action_button("Approval", self.request_enterprise_approval, "can_manage_incidents")
        web_btn = self._enterprise_action_button("Web Surface", self.run_web_inspection, "can_run_hunt")
        net_btn = self._enterprise_action_button("Network", self.run_enterprise_network_assessment, "can_run_hunt")
        replay_btn = self._enterprise_action_button("Replay", self.run_purple_replay, "can_run_hunt")
        gaps_btn = self._enterprise_action_button("Gaps", self.load_telemetry_gaps, "can_run_hunt")
        load_mitre_btn = self._enterprise_action_button("Load ATT&CK", self.load_enterprise_mitre_bundle, "can_manage_integrations")
        add_btn = self._enterprise_menu_button(
            "Add",
            [
                ("Task", self.create_enterprise_task, "can_manage_incidents"),
                ("Note", self.add_enterprise_note, "can_manage_incidents"),
                ("Story", self.add_enterprise_story, "can_manage_incidents"),
                ("Pin Event", self.pin_enterprise_event, "can_manage_incidents"),
            ],
        )
        fields_row = QWidget()
        fields_layout = QHBoxLayout(fields_row)
        fields_layout.setContentsMargins(0, 0, 0, 0)
        fields_layout.setSpacing(8)
        for widget in [QLabel("Case"), self.enterprise_case_title, QLabel("Owner"), self.enterprise_case_owner, QLabel("Priority"), self.enterprise_case_priority]:
            fields_layout.addWidget(widget)
        fields_layout.addStretch(1)
        primary_row = QWidget()
        primary_layout = QHBoxLayout(primary_row)
        primary_layout.setContentsMargins(0, 0, 0, 0)
        primary_layout.setSpacing(8)
        for widget in [refresh_btn, create_case_btn, add_btn, assign_btn, board_btn, graph_btn, export_case_btn, export_mitre_btn, export_workbench_btn]:
            primary_layout.addWidget(widget)
        primary_layout.addStretch(1)
        secondary_row = QWidget()
        secondary_layout = QHBoxLayout(secondary_row)
        secondary_layout.setContentsMargins(0, 0, 0, 0)
        secondary_layout.setSpacing(8)
        for widget in [update_task_btn, mark_done_btn, approval_btn, web_btn, net_btn, replay_btn, gaps_btn, load_mitre_btn, self.enterprise_mitre_bundle_path]:
            secondary_layout.addWidget(widget)
        secondary_layout.addStretch(1)
        cr.addWidget(fields_row)
        cr.addWidget(primary_row)
        cr.addWidget(secondary_row)
        controls_scroll = QScrollArea()
        controls_scroll.setWidgetResizable(True)
        controls_scroll.setFrameShape(QFrame.NoFrame)
        controls_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        controls_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        controls_scroll.setFixedHeight(120)
        controls_scroll.setWidget(controls)
        controls_inner.addWidget(controls_scroll)
        l.addWidget(controls_card)

        triage_card = QFrame(); triage_card.setProperty("card", True); triage_layout = QVBoxLayout(triage_card)
        triage_title = QLabel("What Needs Attention Now")
        triage_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        self.enterprise_summary = QTextBrowser(); self.enterprise_summary.setMinimumHeight(150); self.enterprise_summary.setProperty("role", "brief")
        triage_layout.addWidget(triage_title); triage_layout.addWidget(self.enterprise_summary)
        l.addWidget(triage_card)

        metrics = QWidget()
        mr = QHBoxLayout(metrics)
        mr.setContentsMargins(0, 0, 0, 0)
        mr.setSpacing(8)
        open_cases_card, self.enterprise_open_cases_value = self._metric_card("Open Cases", "#8ec5ff")
        overdue_card, self.enterprise_overdue_value = self._metric_card("Overdue Tasks", "#ff8b8b")
        assignments_card, self.enterprise_assignments_value = self._metric_card("Assignments", "#ffd166")
        high_risk_card, self.enterprise_high_risk_value = self._metric_card("High Risk Assets", "#7bd389")
        for card in [open_cases_card, overdue_card, assignments_card, high_risk_card]:
            mr.addWidget(card, 1)
        l.addWidget(metrics)

        self.enterprise_kpi_chart = QChartView()
        self.enterprise_kpi_chart.setMinimumHeight(180)
        self.enterprise_kpi_chart.setRenderHint(self.enterprise_kpi_chart.renderHints())
        l.addWidget(self._panel_card("Operational Snapshot", self.enterprise_kpi_chart, lambda: self._open_panel_window("Operational Snapshot", QLabel("Use the main Enterprise tab for the live KPI chart."))))

        enterprise_sections = QTabWidget()
        enterprise_sections.setDocumentMode(True)
        enterprise_sections.setUsesScrollButtons(True)

        ops_page = QWidget()
        ops_layout = QHBoxLayout(ops_page)
        ops_layout.setContentsMargins(0, 0, 0, 0)
        ops_layout.setSpacing(8)
        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        self.enterprise_cases_table = QTableWidget(0, 6); self.enterprise_cases_table.setHorizontalHeaderLabels(["ID", "Title", "Priority", "Stage", "Owner", "Status"]); self._style_table(self.enterprise_cases_table); self.enterprise_cases_table.itemSelectionChanged.connect(self._on_enterprise_case_selection_changed)
        self.enterprise_assets_table = QTableWidget(0, 4); self.enterprise_assets_table.setHorizontalHeaderLabels(["PID", "Name", "Criticality", "Rationale"]); self._style_table(self.enterprise_assets_table)
        self.enterprise_detections_table = QTableWidget(0, 4); self.enterprise_detections_table.setHorizontalHeaderLabels(["Rule", "Version", "Status", "Notes"]); self._style_table(self.enterprise_detections_table)
        self.enterprise_notes_table = QTableWidget(0, 3); self.enterprise_notes_table.setHorizontalHeaderLabels(["Author", "Type", "Note"]); self._style_table(self.enterprise_notes_table); self.enterprise_notes_table.itemSelectionChanged.connect(self.show_selected_enterprise_note)
        self.enterprise_stories_table = QTableWidget(0, 3); self.enterprise_stories_table.setHorizontalHeaderLabels(["Title", "Confidence", "Author"]); self._style_table(self.enterprise_stories_table); self.enterprise_stories_table.itemSelectionChanged.connect(self.show_selected_enterprise_story)
        ll.addWidget(self._panel_card("Cases", self.enterprise_cases_table, lambda: self._open_panel_window("Enterprise Cases", self._clone_table(self.enterprise_cases_table))))
        ll.addWidget(self._panel_card("Critical Assets", self.enterprise_assets_table, lambda: self._open_panel_window("Enterprise Assets", self._clone_table(self.enterprise_assets_table))))
        ll.addWidget(self._panel_card("Detection Lifecycle", self.enterprise_detections_table, lambda: self._open_panel_window("Enterprise Detections", self._clone_table(self.enterprise_detections_table))))
        ll.addWidget(self._panel_card("Investigation Notes", self.enterprise_notes_table, lambda: self._open_panel_window("Investigation Notes", self._clone_table(self.enterprise_notes_table))))
        ll.addWidget(self._panel_card("Investigation Stories", self.enterprise_stories_table, lambda: self._open_panel_window("Investigation Stories", self._clone_table(self.enterprise_stories_table))))
        right = QWidget(); rl = QVBoxLayout(right)
        self.enterprise_narrative = QTextBrowser(); self.enterprise_narrative.setProperty("role", "brief"); self.enterprise_narrative.setMinimumHeight(180)
        self.enterprise_case_board = QTextBrowser(); self.enterprise_case_board.setProperty("role", "brief"); self.enterprise_case_board.setMinimumHeight(160)
        self.enterprise_case_timeline = QTableWidget(0, 4); self.enterprise_case_timeline.setHorizontalHeaderLabels(["Time", "Kind", "Severity", "Title"]); self._style_table(self.enterprise_case_timeline); self.enterprise_case_timeline.itemSelectionChanged.connect(self.show_selected_enterprise_timeline)
        self.enterprise_entity_links = QTableWidget(0, 4); self.enterprise_entity_links.setHorizontalHeaderLabels(["Entity", "Kind", "Evidence", "Examples"]); self._style_table(self.enterprise_entity_links); self.enterprise_entity_links.itemSelectionChanged.connect(self.show_selected_enterprise_link)
        self.enterprise_graph_summary = QTextBrowser(); self.enterprise_graph_summary.setProperty("role", "brief"); self.enterprise_graph_summary.setMinimumHeight(160)
        self.enterprise_mitre_summary = QTextBrowser(); self.enterprise_mitre_summary.setProperty("role", "brief"); self.enterprise_mitre_summary.setMinimumHeight(160)
        self.enterprise_case_mitre = QTextBrowser(); self.enterprise_case_mitre.setProperty("role", "brief"); self.enterprise_case_mitre.setMinimumHeight(160)
        self.enterprise_graph_focus = QTableWidget(0, 4); self.enterprise_graph_focus.setHorizontalHeaderLabels(["Process", "PID", "Risk", "Signature"]); self._style_table(self.enterprise_graph_focus)
        self.enterprise_assignments_table = QTableWidget(0, 4); self.enterprise_assignments_table.setHorizontalHeaderLabels(["Analyst", "Role", "Status", "Assigned By"]); self._style_table(self.enterprise_assignments_table); self.enterprise_assignments_table.itemSelectionChanged.connect(self.show_selected_enterprise_assignment)
        self.enterprise_tasks_table = QTableWidget(0, 4); self.enterprise_tasks_table.setHorizontalHeaderLabels(["Title", "Status", "Priority", "Assigned"]); self._style_table(self.enterprise_tasks_table); self.enterprise_tasks_table.itemSelectionChanged.connect(self.show_selected_enterprise_task); self.enterprise_tasks_table.itemChanged.connect(self._inline_update_enterprise_task)
        self.enterprise_activity_table = QTableWidget(0, 4); self.enterprise_activity_table.setHorizontalHeaderLabels(["Time", "Event", "Actor", "Summary"]); self._style_table(self.enterprise_activity_table); self.enterprise_activity_table.itemSelectionChanged.connect(self.show_selected_enterprise_activity)
        self.enterprise_notifications_table = QTableWidget(0, 4); self.enterprise_notifications_table.setHorizontalHeaderLabels(["Time", "Severity", "Category", "Message"]); self._style_table(self.enterprise_notifications_table); self.enterprise_notifications_table.itemSelectionChanged.connect(self.show_selected_enterprise_notification)
        self.enterprise_detail = QTextEdit(); self.enterprise_detail.setReadOnly(True)
        rl.addWidget(self._panel_card("Narrative", self.enterprise_narrative, lambda: self._open_panel_window("Enterprise Narrative", self._clone_text_view(self.enterprise_narrative))))
        rl.addWidget(self._panel_card("Case Board", self.enterprise_case_board, lambda: self._open_panel_window("Case Board", self._clone_text_view(self.enterprise_case_board))))
        rl.addWidget(self._panel_card("Assignments", self.enterprise_assignments_table, lambda: self._open_panel_window("Assignments", self._clone_table(self.enterprise_assignments_table))))
        rl.addWidget(self._panel_card("Tasks", self.enterprise_tasks_table, lambda: self._open_panel_window("Tasks", self._clone_table(self.enterprise_tasks_table))))
        rl.addWidget(self._panel_card("Activity Feed", self.enterprise_activity_table, lambda: self._open_panel_window("Activity Feed", self._clone_table(self.enterprise_activity_table))))
        rl.addWidget(self._panel_card("Notification Center", self.enterprise_notifications_table, lambda: self._open_panel_window("Notification Center", self._clone_table(self.enterprise_notifications_table))))
        rl.addWidget(self._panel_card("Case JSON Detail", self.enterprise_detail, lambda: self._open_panel_window("Case JSON Detail", self._clone_text_view(self.enterprise_detail))))
        split.addWidget(left); split.addWidget(right); split.setStretchFactor(0, 2); split.setStretchFactor(1, 3)
        ops_layout.addWidget(split)

        intel_page = QWidget()
        intel_layout = QHBoxLayout(intel_page)
        intel_layout.setContentsMargins(0, 0, 0, 0)
        intel_layout.setSpacing(8)
        intel_split = QSplitter(Qt.Horizontal)
        intel_left = QWidget(); intel_left_layout = QVBoxLayout(intel_left)
        intel_left_layout.setContentsMargins(0, 0, 0, 0)
        intel_left_layout.setSpacing(8)
        intel_left_layout.addWidget(self._panel_card("Critical Assets", self.enterprise_assets_table, lambda: self._open_panel_window("Enterprise Assets", self._clone_table(self.enterprise_assets_table))))
        intel_left_layout.addWidget(self._panel_card("Detection Lifecycle", self.enterprise_detections_table, lambda: self._open_panel_window("Enterprise Detections", self._clone_table(self.enterprise_detections_table))))
        intel_left_layout.addWidget(self._panel_card("ATT&CK Coverage", self.enterprise_mitre_summary, lambda: self._open_panel_window("ATT&CK Coverage", self._clone_text_view(self.enterprise_mitre_summary))))
        intel_left_layout.addWidget(self._panel_card("Case Timeline", self.enterprise_case_timeline, lambda: self._open_panel_window("Case Timeline", self._clone_table(self.enterprise_case_timeline))))
        intel_left_layout.addWidget(self._panel_card("Entity Links", self.enterprise_entity_links, lambda: self._open_panel_window("Entity Links", self._clone_table(self.enterprise_entity_links))))
        intel_right = QWidget(); intel_right_layout = QVBoxLayout(intel_right)
        intel_right_layout.setContentsMargins(0, 0, 0, 0)
        intel_right_layout.setSpacing(8)
        intel_right_layout.addWidget(self._panel_card("Case ATT&CK", self.enterprise_case_mitre, lambda: self._open_panel_window("Case ATT&CK", self._clone_text_view(self.enterprise_case_mitre))))
        intel_right_layout.addWidget(self._panel_card("Graph Correlation", self.enterprise_graph_summary, lambda: self._open_panel_window("Graph Correlation", self._clone_text_view(self.enterprise_graph_summary))))
        intel_right_layout.addWidget(self._panel_card("Graph Focus Processes", self.enterprise_graph_focus, lambda: self._open_panel_window("Graph Focus Processes", self._clone_table(self.enterprise_graph_focus))))
        intel_right_layout.addWidget(self._panel_card("Investigation Notes", self.enterprise_notes_table, lambda: self._open_panel_window("Investigation Notes", self._clone_table(self.enterprise_notes_table))))
        intel_right_layout.addWidget(self._panel_card("Investigation Stories", self.enterprise_stories_table, lambda: self._open_panel_window("Investigation Stories", self._clone_table(self.enterprise_stories_table))))
        intel_split.addWidget(intel_left)
        intel_split.addWidget(intel_right)
        intel_split.setStretchFactor(0, 2)
        intel_split.setStretchFactor(1, 3)
        intel_layout.addWidget(intel_split)

        enterprise_sections.addTab(ops_page, "Enterprise Ops")
        enterprise_sections.addTab(intel_page, "Enterprise Intel")
        l.addWidget(enterprise_sections, 1)
        return w

    def _security_ops_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Security Ops & Platform Readiness", "Signed integrity, observability, migrations, database readiness and secret lifecycle operations without disturbing existing workspaces.")
        controls = QWidget(); row = QHBoxLayout(controls); row.setContentsMargins(0, 0, 0, 0); row.setSpacing(8)
        refresh_btn = QPushButton("Refresh Security Ops"); refresh_btn.clicked.connect(self.refresh_security_ops_workspace); self._bind_capability(refresh_btn, "can_manage_integrations")
        export_btn = QPushButton("Export Ops Report"); export_btn.clicked.connect(self.export_security_ops_report); self._bind_capability(export_btn, "can_manage_integrations")
        refresh_integrity_btn = QPushButton("Refresh Integrity"); refresh_integrity_btn.clicked.connect(self.refresh_integrity_manifest); self._bind_capability(refresh_integrity_btn, "can_manage_integrations")
        rotate_btn = QPushButton("Rotate Secrets"); rotate_btn.clicked.connect(self.rotate_security_secrets); self._bind_capability(rotate_btn, "can_manage_integrations")
        clear_webhook_btn = QPushButton("Clear Webhook"); clear_webhook_btn.clicked.connect(self.clear_alert_webhook_secret); self._bind_capability(clear_webhook_btn, "can_manage_integrations")
        for btn in [refresh_btn, export_btn, refresh_integrity_btn, rotate_btn, clear_webhook_btn]:
            row.addWidget(btn)
        row.addStretch(1)
        l.addWidget(self._panel_card("Security Ops Controls", controls, lambda: self._open_panel_window("Security Ops Controls", QLabel("Use Security Ops controls in main workspace."))))

        self.security_ops_summary = QTextBrowser(); self.security_ops_summary.setProperty("role", "brief"); self.security_ops_summary.setMinimumHeight(150)
        l.addWidget(self._panel_card("Security Ops Summary", self.security_ops_summary, lambda: self._open_panel_window("Security Ops Summary", self._clone_text_view(self.security_ops_summary))))

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        self.security_integrity_table = QTableWidget(0, 2); self.security_integrity_table.setHorizontalHeaderLabels(["Bucket", "Count"]); self._style_table(self.security_integrity_table)
        self.security_platform_table = QTableWidget(0, 2); self.security_platform_table.setHorizontalHeaderLabels(["Domain", "Status"]); self._style_table(self.security_platform_table)
        ll.addWidget(self._panel_card("Integrity Drift", self.security_integrity_table, lambda: self._open_panel_window("Integrity Drift", self._clone_table(self.security_integrity_table))))
        ll.addWidget(self._panel_card("Platform Readiness", self.security_platform_table, lambda: self._open_panel_window("Platform Readiness", self._clone_table(self.security_platform_table))))
        right = QWidget(); rl = QVBoxLayout(right)
        self.security_ops_detail = QTextEdit(); self.security_ops_detail.setReadOnly(True)
        rl.addWidget(self._panel_card("Security Ops Detail", self.security_ops_detail, lambda: self._open_panel_window("Security Ops Detail", self._clone_text_view(self.security_ops_detail))))
        split.addWidget(left); split.addWidget(right); split.setStretchFactor(0, 2); split.setStretchFactor(1, 3)
        l.addWidget(split, 1)
        return w

    def _scenario_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        self._tab_header(l, "Attack Scenario Simulator", "Run built-in adversary simulation profiles to generate realistic telemetry for testing.")
        row = QWidget(); r = QHBoxLayout(row)
        r.setContentsMargins(0, 0, 0, 0)
        r.setSpacing(8)
        self.scenario = QComboBox(); self.scenario.addItems(["balanced","cpu-heavy","network-heavy","file-heavy","memory-heavy"])
        self.scenario_duration = QSpinBox(); self.scenario_duration.setRange(5, 300); self.scenario_duration.setValue(30)
        btn = QPushButton("Run Scenario"); btn.clicked.connect(self.run_scenario); self._bind_capability(btn, "can_run_scenarios"); r.addWidget(QLabel("Scenario")); r.addWidget(self.scenario); r.addWidget(QLabel("Duration")); r.addWidget(self.scenario_duration); r.addWidget(btn); r.addStretch(1)
        self.scenario_out = QTextEdit(); self.scenario_out.setReadOnly(True); l.addWidget(self._panel_card("Scenario Controls", row, lambda: self._open_panel_window("Scenario Controls", QLabel("Use scenario controls in main workspace.")))); l.addWidget(self._panel_card("Scenario Output", self.scenario_out, lambda: self._open_panel_window("Scenario Output", self._clone_text_view(self.scenario_out))), 1); return w

    def _about_tab(self) -> QWidget:
        w = QWidget(); root = QHBoxLayout(w)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(12)
        left_card = QFrame(); left_card.setProperty("card", True); l = QVBoxLayout(left_card)
        left_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        about = QTextBrowser(); about.setReadOnly(True); about.setHtml(
            "<h2>About ShadowLab</h2><p><b>Created by Ulfat Ibadov</b><br>Offensive Security Expert</p>"
            "<p>LinkedIn: <a href='https://www.linkedin.com/in/ibadovulfat/'>https://www.linkedin.com/in/ibadovulfat/</a><br>"
            "Portfolio: <a href='https://about.surf'>https://about.surf</a><br>"
            "GitHub: <a href='https://github.com/ibadovulfat'>https://github.com/ibadovulfat</a></p>"
            "<h3>FAQ</h3><p><b>What is this?</b><br>API-first Windows defensive operations platform.</p>"
            "<p><b>What can I do?</b><br>Monitor, inspect internals, run strings/YARA/sandbox analysis, check persistence, deploy deception, capture evidence, query threat intel, review history, inspect artifacts, run scenarios.</p>"
            "<p><b>Can this become EXE?</b><br>Yes, this desktop client is the base for packaging.</p>"
        ); about.setOpenExternalLinks(True); l.addWidget(about)
        row = QWidget(); r = QHBoxLayout(row)
        for label, url in [("LinkedIn", "https://www.linkedin.com/in/ibadovulfat/"),("Portfolio", "https://about.surf"),("GitHub", "https://github.com/ibadovulfat")]:
            b = QPushButton(label); b.clicked.connect(lambda _=False, u=url: QDesktopServices.openUrl(QUrl(u))); r.addWidget(b)
        r.addStretch(1); l.addWidget(row)

        right_card = QFrame(); right_card.setProperty("card", True)
        right_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        right_layout = QVBoxLayout(right_card)
        photo_title = QLabel("Creator Profile")
        photo_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        photo_sub = QLabel("Ulfat Ibadov")
        photo_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        profile_image = QLabel()
        static_dir = Path(__file__).resolve().parent.parent / "static"
        image_path = static_dir / "ulfat-profile.png"
        if not image_path.exists():
            image_path = static_dir / "ulfat-profile.jpg"
        pixmap = QPixmap(str(image_path))
        if not pixmap.isNull():
            profile_image.setPixmap(pixmap.scaled(320, 420, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        profile_image.setAlignment(Qt.AlignCenter)
        right_layout.addWidget(photo_title)
        right_layout.addWidget(photo_sub)
        right_layout.addWidget(profile_image)

        root.addWidget(left_card, 3)
        root.addWidget(right_card, 2)
        return w

    def _url(self, path: str) -> str: return self.base.text().rstrip("/") + path

    def _secret_name(self, key: str) -> str:
        return f"ShadowLabDesktop:{key}"

    def _load_secret(self, key: str) -> str:
        if win32cred is None:
            return str(self.settings.value(f"secret_fallback_{key}", ""))
        try:
            result = win32cred.CredRead(self._secret_name(key), win32cred.CRED_TYPE_GENERIC, 0)
            blob = result.get("CredentialBlob", b"")
            if isinstance(blob, bytes):
                return blob.decode("utf-16le", errors="ignore")
            return str(blob or "")
        except Exception:
            return ""

    def _save_secret(self, key: str, value: str) -> None:
        if win32cred is None:
            self.settings.setValue(f"secret_fallback_{key}", value)
            return
        credential = {
            "Type": win32cred.CRED_TYPE_GENERIC,
            "TargetName": self._secret_name(key),
            "UserName": "ShadowLabDesktop",
            "CredentialBlob": value,
            "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
        }
        win32cred.CredWrite(credential, 0)

    def _delete_secret(self, key: str) -> None:
        if win32cred is None:
            self.settings.remove(f"secret_fallback_{key}")
            return
        try:
            win32cred.CredDelete(self._secret_name(key), win32cred.CRED_TYPE_GENERIC, 0)
        except Exception:
            return

    def _auth_headers(self) -> dict[str, str]:
        api_key = self.api_key.text().strip()
        return {"X-API-Key": api_key} if api_key and self.auth_active else {}

    def _signed_headers(self, method: str, path: str) -> dict[str, str]:
        api_key = self.api_key.text().strip()
        if not self.auth_active or not api_key or method.upper() not in {"POST", "PATCH", "DELETE"}:
            return {}
        timestamp = str(int(time.time()))
        nonce = hashlib.sha256(f"{timestamp}:{path}:{time.time_ns()}".encode("utf-8")).hexdigest()[:24]
        payload = "\n".join([method.upper(), path, timestamp, nonce])
        signature = hmac.new(api_key.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "X-ShadowLab-Timestamp": timestamp,
            "X-ShadowLab-Nonce": nonce,
            "X-ShadowLab-Signature": signature,
        }

    def _approval_headers(self, method: str) -> dict[str, str]:
        if method.upper() not in {"POST", "PATCH", "DELETE"}:
            return {}
        approval_id = self.approval_id.text().strip()
        if not approval_id:
            return {}
        return {"X-ShadowLab-Approval-Id": approval_id}

    def _raise_for_api_error(self, response: Response) -> None:
        if response.ok:
            return
        detail = ""
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            detail = str(payload.get("detail") or payload.get("message") or "").strip()
        if not detail:
            detail = (response.text or "").strip()[:300]
        if not detail:
            detail = f"HTTP {response.status_code}"
        raise requests.HTTPError(f"HTTP {response.status_code}: {detail}", response=response)

    def _request(self, method: str, path: str, **kwargs) -> Response:
        should_raise = kwargs.pop("raise_for_status", True)
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update(self._auth_headers())
        headers.update(self._signed_headers(method, path))
        headers.update(self._approval_headers(method))
        response = requests.request(
            method,
            self._url(path),
            headers=headers,
            timeout=kwargs.pop("timeout", 20),
            **kwargs,
        )
        if should_raise:
            self._raise_for_api_error(response)
        return response

    def _get(self, path: str, **kwargs): return self._request("GET", path, **kwargs)
    def _post(self, path: str, **kwargs): return self._request("POST", path, **kwargs)
    def _patch(self, path: str, **kwargs): return self._request("PATCH", path, **kwargs)
    def _delete(self, path: str, **kwargs): return self._request("DELETE", path, **kwargs)

    def _json_response(self, response):
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as exc:
            snippet = (response.text or "").strip()[:300]
            message = snippet or "Empty response body"
            raise ValueError(f"Expected JSON response, got: {message}") from exc
    def _rebuild_toolbar(self) -> None:
        self.toolbar.clear()
        for label, fn in [
            ("API", self.check_api_health),
            ("Refresh", self.refresh_overview),
            ("Monitor", self.run_monitor),
            ("History", self.refresh_history),
        ]:
            action = QAction(label, self)
            action.triggered.connect(fn)
            self.toolbar.addAction(action)
        self.toolbar.addSeparator()
        add_action = QAction("Add Button", self)
        add_action.triggered.connect(self.add_custom_toolbar_button)
        self.toolbar.addAction(add_action)
        if self.custom_toolbar_buttons:
            self.toolbar.addSeparator()
        for item in self.custom_toolbar_buttons:
            action = QAction(item.get("label", "Shortcut"), self)
            action.triggered.connect(lambda _=False, shortcut=item: self.run_custom_toolbar_button(shortcut))
            self.toolbar.addAction(action)

    def _bind_capability(self, widget: QWidget, capability: str) -> QWidget:
        self.capability_widgets.append((widget, capability))
        return widget

    def _setup_form_layout(self, form: QFormLayout) -> None:
        form.setContentsMargins(0, 4, 0, 0)
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(14)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setFormAlignment(Qt.AlignTop)
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)
        form.setRowWrapPolicy(QFormLayout.DontWrapRows)

    def _normalize_form_labels(self, form: QFormLayout, width: int) -> None:
        for row in range(form.rowCount()):
            item = form.itemAt(row, QFormLayout.LabelRole)
            if item and item.widget():
                item.widget().setMinimumWidth(width)

    def _tab_header(self, layout: QBoxLayout, title: str, subtitle: str) -> None:
        """Adds a consistent title + subtitle header block to a tab layout."""
        hdr = QWidget()
        hdr_layout = QVBoxLayout(hdr)
        hdr_layout.setContentsMargins(0, 0, 0, 4)
        hdr_layout.setSpacing(3)
        t = QLabel(title)
        t.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        s = QLabel(subtitle)
        s.setStyleSheet("color:#96a5b8;font-size:12px;line-height:1.2;")
        s.setWordWrap(True)
        hdr_layout.addWidget(t)
        hdr_layout.addWidget(s)
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("background:#1e3050;max-height:1px;border:none;")
        hdr_layout.addWidget(sep)
        layout.addWidget(hdr)

    def _field_block(self, label_text: str, widget: QWidget) -> QWidget:
        block = QWidget()
        block.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 2)
        layout.setSpacing(3)
        label = QLabel(label_text)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:600;letter-spacing:0.5px;text-transform:uppercase;")
        label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        if isinstance(widget, (QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox)):
            widget.setMinimumHeight(34)
            widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        else:
            widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        layout.addWidget(label)
        layout.addWidget(widget)
        return block

    def _metric_card(self, label_text: str, accent: str) -> tuple[QFrame, QLabel]:
        card = QFrame()
        card.setProperty("card", True)
        card.setMinimumHeight(88)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(2)
        label = QLabel(label_text)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:700;letter-spacing:0.5px;")
        value = QLabel("0")
        value.setStyleSheet(f"color:{accent};font-size:24px;font-weight:800;")
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addStretch(1)
        return card, value

    def _set_metric_label(self, label: QLabel, value: str) -> None:
        label.setText(str(value))

    def _scrollable_tab(self, widget: QWidget, allow_horizontal: bool = False) -> QScrollArea:
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.NoFrame)
        area.setWidget(widget)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded if allow_horizontal else Qt.ScrollBarAlwaysOff)
        area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        return area

    def _on_tab_changed(self, index: int) -> None:
        self.settings.setValue("current_tab_index", index)
        try:
            tab_name = self.tabs.tabText(index)
        except Exception:
            return
        if tab_name == "Enterprise" and getattr(self, "enterprise_auto_refresh", None) and self.enterprise_auto_refresh.isChecked():
            self.enterprise_live_status.setText("Preparing enterprise workspace...")
            if not self.enterprise_loaded_once:
                QTimer.singleShot(150, self.refresh_enterprise_workspace)

    def _auto_refresh_active_tab(self) -> None:
        current_index = self.tabs.currentIndex()
        tab_name = self.tabs.tabText(current_index)
        if tab_name == "Enterprise" and getattr(self, "enterprise_auto_refresh", None) and self.enterprise_auto_refresh.isChecked():
            if self._selected_enterprise_case_id() is not None:
                self.load_selected_case_board()
            elif self.enterprise_loaded_once:
                self.refresh_enterprise_workspace()
        elif tab_name == "WHIDS" and self.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.refresh_whids_workspace()
        elif tab_name == "HIDS" and self.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.refresh_hids_workspace()

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_controls_layout()

    def _update_controls_layout(self) -> None:
        available_width = max(1080, self.width() - 28)
        stacked = available_width < 1420
        self.controls_row.setDirection(QBoxLayout.TopToBottom if stacked else QBoxLayout.LeftToRight)
        self.controls_row.setSpacing(10 if stacked else 12)
        self.ops_card.setMinimumWidth(0 if stacked else 560)
        self.advanced_card.setMinimumWidth(0 if stacked else 560)
        self.ops_card.setMaximumHeight(16777215)
        self.advanced_card.setMaximumHeight(16777215)
        self.ops_card.setMinimumHeight(self.ops_card.sizeHint().height())
        self.advanced_card.setMinimumHeight(self.advanced_card.sizeHint().height())
        if not stacked and self.advanced_card.isVisible():
            equal_height = max(self.ops_card.height(), self.advanced_card.height())
            self.ops_card.setMinimumHeight(equal_height)
            self.advanced_card.setMinimumHeight(equal_height)

    def _show_error(self, widget: QTextEdit, title: str, exc: Exception) -> None:
        widget.setPlainText(f"{title}:\n{exc}")
        self.statusBar().showMessage(f"{title}: {exc}")

    def _show_json(self, widget: QTextEdit, payload) -> None:
        widget.setPlainText(json.dumps(payload, indent=2, ensure_ascii=False))

    def _switch_to_tab(self, tab_name: str) -> None:
        wanted = tab_name.strip().lower()
        for idx in range(self.tabs.count()):
            if self.tabs.tabText(idx).strip().lower() == wanted:
                self.tabs.setCurrentIndex(idx)
                return

    def _integration_rows(self, integration_name: str) -> list[dict]:
        exports = self._get("/integrations/telemetry-fabric/exports", timeout=30).json()
        return [
            item for item in exports
            if str(item.get("integration_name", "")).strip().lower() == integration_name.strip().lower()
        ]

    def _incident_rows_for_prefix(self, prefix: str) -> list[dict]:
        incidents = self._get("/history/incidents", timeout=30).json()
        normalized_prefix = prefix.strip().upper()
        return [
            item for item in incidents
            if str(item.get("incident_id", "")).strip().upper().startswith(normalized_prefix)
        ]

    def refresh_whids_workspace(self) -> None:
        if not self.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.whids_table.setRowCount(0)
            self.whids_summary.setHtml(
                "<h3>WHIDS Integration</h3>"
                "<p>Admin access is required for manager sync, reports, artifacts, rules, IoCs, and scheduler controls.</p>"
            )
            self.whids_health_badge.setText("WHIDS: locked")
            self.whids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
            self.whids_detail.setPlainText("WHIDS integration workspace is locked for the current role.")
            return
        try:
            exports = self._integration_rows("whids")
            incidents = self._incident_rows_for_prefix("WHIDS-")
            scheduler = self._get("/integrations/whids/scheduler/status", timeout=15).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS refresh failed", exc)
            return
        dedupe_skips = len([item for item in exports if str(item.get("export_type", "")) == "dedupe_skip"])
        self.whids_table.setRowCount(len(exports))
        for r, item in enumerate(exports):
            values = [item.get("created_at", ""), item.get("export_type", ""), item.get("target", ""), item.get("status", ""), item.get("detail", "")]
            for c, value in enumerate(values):
                self.whids_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.whids_table, r, self._severity_color("high" if str(item.get("status", "")).lower() not in {"success", "ok"} else "low"))
        self.whids_summary.setHtml(
            "<h3>WHIDS Import Status</h3>"
            f"<p><b>Imports logged:</b> {len(exports)}<br>"
            f"<b>WHIDS incidents:</b> {len(incidents)}<br>"
            f"<b>Manager:</b> {html.escape(self.whids_manager_url.text().strip())}<br>"
            f"<b>Current file:</b> {html.escape(self.whids_file_path.text().strip())}<br>"
            f"<b>Endpoint UUID:</b> {html.escape(self.whids_endpoint_uuid.text().strip() or 'all endpoints')}<br>"
            f"<b>Artifacts since:</b> {html.escape(self.whids_artifact_since.text().strip() or 'not set')}<br>"
            f"<b>Scheduler:</b> {html.escape('running' if scheduler.get('running') else 'stopped')}<br>"
            f"<b>Dedupe skips:</b> {dedupe_skips}</p>"
        )
        latest_status = str(exports[0].get("status", "")) if exports else "idle"
        scheduler_running = bool(scheduler.get("running"))
        latest_color = "#2f9e67" if latest_status.lower() in {"success", "ok"} and not scheduler.get("last_error") else "#d64550" if exports and latest_status.lower() not in {"success", "ok"} or scheduler.get("last_error") else "#4a5568"
        self.whids_health_badge.setText(f"WHIDS: {latest_status or 'idle'} | scheduler={'on' if scheduler_running else 'off'}")
        self.whids_health_badge.setStyleSheet(f"background:{latest_color};color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        if exports:
            self.whids_detail.setPlainText(json.dumps(exports[0], indent=2, ensure_ascii=False))
        else:
            self.whids_detail.setPlainText("No WHIDS integration exports yet.")

    def refresh_hids_workspace(self) -> None:
        if not self.auth_context.get("capabilities", {}).get("can_manage_integrations", False):
            self.hids_table.setRowCount(0)
            self.hids_summary.setHtml(
                "<h3>HIDS Integration</h3>"
                "<p>Admin access is required for OSSEC live ingest, orchestration, and provider-native response controls.</p>"
            )
            self.hids_health_badge.setText("HIDS: locked")
            self.hids_health_badge.setStyleSheet("background:#4a5568;color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
            self.hids_detail.setPlainText("HIDS integration workspace is locked for the current role.")
            return
        try:
            exports = self._integration_rows("ossec")
            incidents = self._incident_rows_for_prefix("OSSEC-")
            live_status = self._get("/integrations/ossec/live/status", timeout=15).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS refresh failed", exc)
            return
        dedupe_skips = len([item for item in exports if str(item.get("export_type", "")) == "dedupe_skip"])
        self.hids_table.setRowCount(len(exports))
        for r, item in enumerate(exports):
            values = [item.get("created_at", ""), item.get("export_type", ""), item.get("target", ""), item.get("status", ""), item.get("detail", "")]
            for c, value in enumerate(values):
                self.hids_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.hids_table, r, self._severity_color("high" if str(item.get("status", "")).lower() not in {"success", "ok"} else "low"))
        self.hids_summary.setHtml(
            "<h3>HIDS Import Status</h3>"
            f"<p><b>Imports logged:</b> {len(exports)}<br>"
            f"<b>OSSEC incidents:</b> {len(incidents)}<br>"
            f"<b>Current file:</b> {html.escape(self.hids_file_path.text().strip())}<br>"
            f"<b>Live ingest:</b> {html.escape('running' if live_status.get('running') else 'stopped')}<br>"
            f"<b>Imported live:</b> {html.escape(str(live_status.get('total_imported', 0)))}<br>"
            f"<b>Last error:</b> {html.escape(str(live_status.get('last_error', '') or 'none'))}<br>"
            f"<b>Dedupe skips:</b> {dedupe_skips}</p>"
        )
        live_color = "#2f9e67" if live_status.get("running") and not live_status.get("last_error") else "#d64550" if live_status.get("last_error") else "#4a5568"
        live_label = "running" if live_status.get("running") else "stopped"
        self.hids_health_badge.setText(f"HIDS: {live_label}")
        self.hids_health_badge.setStyleSheet(f"background:{live_color};color:white;padding:6px 10px;border-radius:8px;font-weight:700;")
        if exports:
            self.hids_detail.setPlainText(json.dumps(exports[0], indent=2, ensure_ascii=False))
        else:
            self.hids_detail.setPlainText("No HIDS integration exports yet.")

    def import_whids_file(self) -> None:
        path = self.whids_file_path.text().strip()
        if not path:
            self.statusBar().showMessage("Provide a WHIDS alert file path first")
            return
        try:
            result = self._post("/integrations/whids/import/file", json={"file_path": path, "limit": 500}, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS import failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()
        self.refresh_hosts()
        self.refresh_history()
        self._switch_to_tab("WHIDS")

    def import_whids_manager(self) -> None:
        manager_url = self.whids_manager_url.text().strip()
        api_key = self.whids_manager_api_key.text().strip()
        endpoint_uuid = self.whids_endpoint_uuid.text().strip()
        if not manager_url or not api_key:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "limit": 500,
            "endpoint_uuid": endpoint_uuid,
            "verify_tls": self.whids_verify_tls.isChecked(),
        }
        try:
            result = self._post("/integrations/whids/import/manager", json=payload, timeout=120).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS manager import failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()
        self.refresh_hosts()
        self.refresh_history()
        self._switch_to_tab("WHIDS")

    def import_whids_reports(self) -> None:
        manager_url = self.whids_manager_url.text().strip()
        api_key = self.whids_manager_api_key.text().strip()
        if not manager_url or not api_key:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "limit": 500,
            "endpoint_uuid": self.whids_endpoint_uuid.text().strip(),
            "verify_tls": self.whids_verify_tls.isChecked(),
        }
        try:
            result = self._post("/integrations/whids/reports", json=payload, timeout=120).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS report sync failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()
        self.refresh_history()
        self.refresh_artifacts()
        self._switch_to_tab("WHIDS")

    def import_whids_artifacts(self) -> None:
        manager_url = self.whids_manager_url.text().strip()
        api_key = self.whids_manager_api_key.text().strip()
        endpoint_uuid = self.whids_endpoint_uuid.text().strip()
        if not manager_url or not api_key or not endpoint_uuid:
            self.statusBar().showMessage("Provide WHIDS manager URL, X-Api-Key and Endpoint UUID first")
            return
        payload = {
            "manager_url": manager_url,
            "api_key": api_key,
            "endpoint_uuid": endpoint_uuid,
            "since": self.whids_artifact_since.text().strip(),
            "max_files": self.whids_artifact_limit.value(),
            "verify_tls": self.whids_verify_tls.isChecked(),
        }
        try:
            result = self._post("/integrations/whids/artifacts", json=payload, timeout=180).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS artifact sync failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()
        self.refresh_history()
        self.refresh_artifacts()
        self._switch_to_tab("WHIDS")

    def import_hids_file(self) -> None:
        path = self.hids_file_path.text().strip()
        if not path:
            self.statusBar().showMessage("Provide an OSSEC/HIDS alert file path first")
            return
        try:
            result = self._post("/integrations/ossec/import/file", json={"file_path": path, "limit": 500}, timeout=90).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS import failed", exc)
            return
        self._show_json(self.hids_detail, result)
        self.refresh_hids_workspace()
        self.refresh_hosts()
        self.refresh_history()
        self._switch_to_tab("HIDS")

    def orchestrate_hids_response(self, apply_actions: bool) -> None:
        incident_id = self.hids_incident_id.text().strip()
        if not incident_id:
            row = self.hids_table.currentRow()
            if row >= 0:
                current_detail = self.hids_detail.toPlainText().strip()
                try:
                    payload = json.loads(current_detail)
                    incident_id = str(payload.get("incident_id", "")).strip()
                except Exception:
                    incident_id = ""
        if not incident_id:
            incident_id, ok = QInputDialog.getText(self, "Incident Response", "Incident ID:")
            if not ok or not incident_id.strip():
                self.statusBar().showMessage("Provide an incident ID first")
                return
            incident_id = incident_id.strip()
        try:
            result = self._post(
                f"/integrations/incidents/{incident_id}/response",
                json={"apply_actions": apply_actions},
                timeout=120,
            ).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS response orchestration failed", exc)
            return
        self.hids_incident_id.setText(incident_id)
        self._show_json(self.hids_detail, result)
        self.refresh_history()
        self.refresh_hids_workspace()
        self._switch_to_tab("HIDS")

    def _whids_manager_payload_base(self) -> dict:
        return {
            "manager_url": self.whids_manager_url.text().strip(),
            "api_key": self.whids_manager_api_key.text().strip(),
            "verify_tls": self.whids_verify_tls.isChecked(),
        }

    def load_integration_policy(self) -> None:
        try:
            result = self._get("/integrations/response-policy", timeout=45).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "Integration policy load failed", exc)
            return
        self.integration_policy_payload.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        self._show_json(self.whids_detail, result)

    def save_integration_policy(self) -> None:
        try:
            payload = {"policy": self._parse_json_text(self.integration_policy_payload, {})}
            result = self._post("/integrations/response-policy", json=payload, timeout=60).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "Integration policy save failed", exc)
            return
        self.integration_policy_payload.setPlainText(json.dumps(result, indent=2, ensure_ascii=False))
        self._show_json(self.whids_detail, result)

    def start_whids_scheduler(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload["endpoint_uuid"] = self.whids_endpoint_uuid.text().strip()
        payload["poll_interval"] = self.whids_scheduler_interval.value()
        try:
            result = self._post("/integrations/whids/scheduler/start", json=payload, timeout=60).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS scheduler start failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def stop_whids_scheduler(self) -> None:
        try:
            result = self._post("/integrations/whids/scheduler/stop", timeout=45).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS scheduler stop failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def refresh_whids_scheduler_status(self) -> None:
        try:
            result = self._get("/integrations/whids/scheduler/status", timeout=45).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS scheduler status failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def _parse_json_text(self, widget: QTextEdit, default):
        text = widget.toPlainText().strip()
        if not text:
            return default
        return json.loads(text)

    def query_whids_iocs(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        filters = {}
        if self.whids_rule_name.text().strip():
            filters["value"] = self.whids_rule_name.text().strip()
        payload["filters"] = filters
        try:
            result = self._post("/integrations/whids/iocs/query", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS IoC query failed", exc)
            return
        self._show_json(self.whids_detail, result)

    def add_whids_iocs(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        try:
            payload["items"] = self._parse_json_text(self.whids_ioc_payload, [])
            result = self._post("/integrations/whids/iocs/add", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS IoC add failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def delete_whids_iocs(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        filters = {}
        if self.whids_rule_name.text().strip():
            filters["value"] = self.whids_rule_name.text().strip()
        payload["filters"] = filters
        try:
            result = self._post("/integrations/whids/iocs/delete", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS IoC delete failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def query_whids_rules(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        payload["name_filter"] = self.whids_rule_name.text().strip()
        try:
            result = self._post("/integrations/whids/rules/query", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS rule query failed", exc)
            return
        self._show_json(self.whids_detail, result)

    def add_whids_rules(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"]:
            self.statusBar().showMessage("Provide WHIDS manager URL and X-Api-Key first")
            return
        try:
            payload["rules"] = self._parse_json_text(self.whids_rule_payload, [])
            result = self._post("/integrations/whids/rules/add", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS rule add failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def delete_whids_rules(self) -> None:
        payload = self._whids_manager_payload_base()
        if not payload["manager_url"] or not payload["api_key"] or not self.whids_rule_name.text().strip():
            self.statusBar().showMessage("Provide WHIDS manager URL, X-Api-Key and rule name first")
            return
        payload["rule_name"] = self.whids_rule_name.text().strip()
        try:
            result = self._post("/integrations/whids/rules/delete", json=payload, timeout=90).json()
        except Exception as exc:
            self._show_error(self.whids_detail, "WHIDS rule delete failed", exc)
            return
        self._show_json(self.whids_detail, result)
        self.refresh_whids_workspace()

    def start_hids_live_ingest(self) -> None:
        path = self.hids_file_path.text().strip()
        if not path:
            self.statusBar().showMessage("Provide an OSSEC/HIDS alert file path first")
            return
        payload = {
            "file_path": path,
            "poll_interval": self.hids_live_interval.value(),
            "limit": 500,
            "start_at_end": self.hids_live_start_at_end.isChecked(),
        }
        try:
            result = self._post("/integrations/ossec/live/start", json=payload, timeout=45).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS live ingest start failed", exc)
            return
        self._show_json(self.hids_detail, result)
        self.refresh_hids_workspace()
        self.statusBar().showMessage("OSSEC live ingest started")
        self._switch_to_tab("HIDS")

    def stop_hids_live_ingest(self) -> None:
        try:
            result = self._post("/integrations/ossec/live/stop", timeout=45).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS live ingest stop failed", exc)
            return
        self._show_json(self.hids_detail, result)
        self.refresh_hids_workspace()
        self.statusBar().showMessage("OSSEC live ingest stopped")
        self._switch_to_tab("HIDS")

    def refresh_hids_live_status(self) -> None:
        try:
            result = self._get("/integrations/ossec/live/status", timeout=20).json()
        except Exception as exc:
            self._show_error(self.hids_detail, "HIDS live status failed", exc)
            return
        self._show_json(self.hids_detail, result)
        self.refresh_hids_workspace()
        self._switch_to_tab("HIDS")

    def show_selected_whids_export(self) -> None:
        row = self.whids_table.currentRow()
        if row < 0:
            return
        values = {
            "created_at": self.whids_table.item(row, 0).text() if self.whids_table.item(row, 0) else "",
            "export_type": self.whids_table.item(row, 1).text() if self.whids_table.item(row, 1) else "",
            "target": self.whids_table.item(row, 2).text() if self.whids_table.item(row, 2) else "",
            "status": self.whids_table.item(row, 3).text() if self.whids_table.item(row, 3) else "",
            "detail": self.whids_table.item(row, 4).text() if self.whids_table.item(row, 4) else "",
        }
        self.whids_detail.setPlainText(json.dumps(values, indent=2, ensure_ascii=False))

    def show_selected_hids_export(self) -> None:
        row = self.hids_table.currentRow()
        if row < 0:
            return
        values = {
            "created_at": self.hids_table.item(row, 0).text() if self.hids_table.item(row, 0) else "",
            "export_type": self.hids_table.item(row, 1).text() if self.hids_table.item(row, 1) else "",
            "target": self.hids_table.item(row, 2).text() if self.hids_table.item(row, 2) else "",
            "status": self.hids_table.item(row, 3).text() if self.hids_table.item(row, 3) else "",
            "detail": self.hids_table.item(row, 4).text() if self.hids_table.item(row, 4) else "",
        }
        self.hids_detail.setPlainText(json.dumps(values, indent=2, ensure_ascii=False))

    def open_selected_whids_target(self) -> None:
        row = self.whids_table.currentRow()
        if row < 0:
            self.statusBar().showMessage("Select a WHIDS export first")
            return
        target = self.whids_table.item(row, 2).text() if self.whids_table.item(row, 2) else ""
        self._open_local_target(target)

    def open_selected_hids_target(self) -> None:
        row = self.hids_table.currentRow()
        if row < 0:
            self.statusBar().showMessage("Select a HIDS export first")
            return
        target = self.hids_table.item(row, 2).text() if self.hids_table.item(row, 2) else ""
        self._open_local_target(target)

    def _open_local_target(self, target: str) -> None:
        candidate = str(target or "").strip()
        if not candidate:
            self.statusBar().showMessage("No local target is attached to this export")
            return
        path = Path(candidate)
        if path.exists():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))
            return
        self.statusBar().showMessage(f"Target not found locally: {candidate}")

    def open_enterprise_case_for_incident(self, *, prefix: str = "") -> None:
        incident_id = self.hids_incident_id.text().strip()
        if prefix.upper().startswith("WHIDS"):
            current_detail = self.whids_detail.toPlainText().strip()
            incident_id = incident_id or self._find_incident_id_in_text(current_detail, "WHIDS-")
        else:
            current_detail = self.hids_detail.toPlainText().strip()
            incident_id = incident_id or self._find_incident_id_in_text(current_detail, "OSSEC-")
        if not incident_id:
            self.statusBar().showMessage("No correlated incident ID found for enterprise case jump")
            return
        try:
            cases = self._get("/enterprise/cases", timeout=20).json()
        except Exception as exc:
            self.statusBar().showMessage(f"Enterprise case lookup failed: {exc}")
            return
        for idx, item in enumerate(cases):
            if str(item.get("incident_id", "")).strip() == incident_id:
                self._switch_to_tab("Enterprise")
                self.refresh_enterprise_workspace()
                self.enterprise_cases_table.selectRow(idx)
                self.load_selected_case_board()
                return
        self.statusBar().showMessage(f"No enterprise case linked to {incident_id}")

    def _find_incident_id_in_text(self, text: str, prefix: str) -> str:
        match = re.search(rf"{re.escape(prefix)}[A-Z0-9-]+", text.upper())
        return match.group(0) if match else ""

    def _render_monitor_brief(self, result: dict, incident: dict) -> str:
        score = result.get("final_score", {}) or {}
        likelihood = score.get("likelihood", "n/a")
        severity = incident.get("severity", "unknown")
        summary = incident.get("summary", "No summary generated.")
        attack_chain = self._ensure_list(incident.get("attack_chain"))
        tactics = self._ensure_list(incident.get("mitre_techniques") or incident.get("mitre_mapping"))
        recommended = self._ensure_list(incident.get("recommended_actions")) or ["No analyst actions suggested yet."]
        notes = self._ensure_list(incident.get("notes"))

        attack_chain_html = "".join(f"<span style='color:#9fc7ff;'>{html.escape(str(item))}</span><br>" for item in attack_chain[:6])
        tactics_html = "".join(f"<span style='color:#a8b8c8;'>{html.escape(str(item))}</span><br>" for item in tactics[:6])
        notes_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in notes[:4])
        actions_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in recommended)
        chain_fallback = '<span style="color:#7e93a8;">No chain built yet.</span>'
        tactics_fallback = '<span style="color:#7e93a8;">No ATT&CK mapping yet.</span>'

        return (
            "<div style='font-family:Segoe UI, Arial, sans-serif;'>"
            "<div style='display:flex;justify-content:space-between;gap:24px;'>"
            "<div>"
            "<div style='font-size:18px;font-weight:700;color:#f4f7fb;'>Monitor Session Complete</div>"
            f"<div style='color:#9fb2c6;margin-top:4px;'>{html.escape(str(summary))}</div>"
            "</div>"
            f"<div style='text-align:right;'><div style='font-size:12px;color:#7e93a8;'>Likelihood</div><div style='font-size:18px;font-weight:700;color:#28a0ff;'>{html.escape(str(likelihood))}</div></div>"
            "</div>"
            "<hr style='border:0;border-top:1px solid #243446;margin:12px 0;'>"
            "<div style='display:flex;gap:22px;flex-wrap:wrap;'>"
            f"<div><div style='font-size:12px;color:#7e93a8;'>Incident</div><div style='font-weight:700;color:#eef4fb;'>{html.escape(str(incident.get('incident_id', '-')))}</div></div>"
            f"<div><div style='font-size:12px;color:#7e93a8;'>Severity</div><div style='font-weight:700;color:{self._severity_color(severity).name()};'>{html.escape(str(severity).upper())}</div></div>"
            f"<div><div style='font-size:12px;color:#7e93a8;'>Telemetry Samples</div><div style='font-weight:700;color:#eef4fb;'>{html.escape(str(result.get('telemetry_count', 0)))}</div></div>"
            "</div>"
            "<div style='display:flex;gap:20px;margin-top:14px;'>"
            "<div style='flex:2;background:#16202c;border:1px solid #243446;border-radius:8px;padding:10px;'>"
            "<div style='font-weight:700;color:#f4f7fb;margin-bottom:8px;'>Recommended Actions</div>"
            f"<ul style='margin:0;padding-left:18px;color:#dfe8f2;'>{actions_html}</ul>"
            "</div>"
            "<div style='flex:1;background:#16202c;border:1px solid #243446;border-radius:8px;padding:10px;'>"
            "<div style='font-weight:700;color:#f4f7fb;margin-bottom:8px;'>Attack Chain</div>"
            f"<div style='color:#dfe8f2;'>{attack_chain_html or chain_fallback}</div>"
            "</div>"
            "<div style='flex:1;background:#16202c;border:1px solid #243446;border-radius:8px;padding:10px;'>"
            "<div style='font-weight:700;color:#f4f7fb;margin-bottom:8px;'>ATT&CK / Notes</div>"
            f"<div style='margin-bottom:8px;color:#dfe8f2;'>{tactics_html or tactics_fallback}</div>"
            f"<ul style='margin:0;padding-left:18px;color:#dfe8f2;'>{notes_html or '<li>No additional notes.</li>'}</ul>"
            "</div>"
            "</div>"
            "</div>"
        )

    def _set_health_badge(self, online: bool) -> None:
        color = "#2f9e67" if online else "#d64550"
        text = "API status: online" if online else "API status: offline"
        self.health.setText(text)
        self.health.setStyleSheet(f"background:{color};color:white;padding:6px 10px;border-radius:8px;font-weight:700;")

    def _apply_auth_context(self, payload: dict) -> None:
        self.auth_context = payload
        role = str(payload.get("role", "viewer") or "viewer")
        capabilities = payload.get("capabilities", {}) if isinstance(payload.get("capabilities"), dict) else {}
        if role == "viewer" and not self.auth_active:
            self.auth_role.setText("Role: viewer")
            self.auth_role.setStyleSheet("color:#f4c26b;font-weight:700;")
            self.auth_summary.setText("Capabilities: read-only preview mode until you press OK")
            self.auth_mode_badge.setText("Mode: viewer")
            self.auth_mode_badge.setStyleSheet("color:#f4c26b;font-weight:700;")
            self.auth_mode_hint.setText("Default mode stays in viewer/read-only. Paste an API key and press OK to switch access level.")
        else:
            enabled = [
                label
                for capability, label in [
                    ("can_run_monitor", "monitor"),
                    ("can_run_hunt", "hunt"),
                    ("can_manage_incidents", "incidents"),
                    ("can_manage_process_actions", "response"),
                    ("can_manage_network_warfare", "network-warfare"),
                    ("can_run_scenarios", "scenarios"),
                ]
                if capabilities.get(capability)
            ]
            summary = ", ".join(enabled[:4]) if enabled else "read-only"
            self.auth_role.setText(f"Role: {role}")
            self.auth_role.setStyleSheet("color:#9fd0ff;font-weight:700;")
            self.auth_summary.setText(f"Capabilities: {summary}")
            accent = "#7fe39d" if role == "admin" else "#9fd0ff" if role == "analyst" else "#f4c26b"
            self.auth_mode_badge.setText(f"Mode: {role}")
            self.auth_mode_badge.setStyleSheet(f"color:{accent};font-weight:700;")
            if role == "admin":
                self.auth_mode_hint.setText("Admin mode is active. All protected workflows and response controls are available.")
            elif role == "analyst":
                self.auth_mode_hint.setText("Analyst mode is active. Hunt, triage and investigation workflows are unlocked.")
            else:
                self.auth_mode_hint.setText("Viewer mode is active. Read-only views stay visible and destructive actions stay hidden.")
        if hasattr(self, "enterprise_role_banner"):
            access_text = "Read-only workspace" if role == "viewer" else "Investigation workspace" if role == "analyst" else "Full response workspace"
            self.enterprise_role_banner.setText(f"Enterprise role: {role} | {access_text}")
            accent = "#f4c26b" if role == "viewer" else "#9fd0ff" if role == "analyst" else "#7fe39d"
            self.enterprise_role_banner.setStyleSheet(f"color:{accent};background:#121b27;border:1px solid #2c4260;border-radius:8px;padding:8px 10px;font-weight:600;")
        self._apply_capabilities(capabilities)
        if hasattr(self, "enterprise_tasks_table"):
            can_edit_tasks = bool(capabilities.get("can_manage_incidents", False))
            triggers = QAbstractItemView.DoubleClicked | QAbstractItemView.SelectedClicked | QAbstractItemView.EditKeyPressed if can_edit_tasks else QAbstractItemView.NoEditTriggers
            self.enterprise_tasks_table.setEditTriggers(triggers)
        if hasattr(self, "dash_auth"):
            self._refresh_dashboard_panels()

    def _viewer_mode_payload(self) -> dict:
        return {"role": "viewer", "capabilities": {}}

    def activate_role_mode(self) -> None:
        if not self.api_key.text().strip():
            self.auth_active = False
            self._apply_auth_context(self._viewer_mode_payload())
            self.statusBar().showMessage("Viewer mode active. Enter an API key and press OK to elevate access.")
            return
        self.auth_active = True
        self.check_api_health()

    def _apply_capabilities(self, capabilities: dict[str, bool]) -> None:
        for widget, capability in self.capability_widgets:
            allowed = bool(capabilities.get(capability, False))
            widget.setVisible(allowed)
            widget.setEnabled(allowed)

    def _ensure_list(self, value) -> list[str]:
        if isinstance(value, list):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, tuple):
            return [str(item) for item in value if str(item).strip()]
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            try:
                parsed = json.loads(stripped)
            except Exception:
                parsed = None
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
            return [line.strip() for line in stripped.splitlines() if line.strip()]
        return []

    def _load_settings(self) -> None:
        raw_buttons = self.settings.value("custom_toolbar_buttons", "[]")
        try:
            self.custom_toolbar_buttons = json.loads(raw_buttons)
        except Exception:
            self.custom_toolbar_buttons = []
        self._rebuild_toolbar()
        self.base.setText(self.settings.value("base", self.base.text()))
        remember_api_key = str(self.settings.value("remember_api_key", "false")).lower() == "true"
        self.remember_api_key.setChecked(remember_api_key)
        self.api_key.setText(self._load_secret("api_key") if remember_api_key else "")
        self.duration.setValue(int(self.settings.value("duration", self.duration.value())))
        self.interval.setValue(float(self.settings.value("interval", self.interval.value())))
        self.vt_key.setText(self._load_secret("vt_key") if remember_api_key else "")
        self.malwarebazaar_key.setText(self._load_secret("malwarebazaar_key") if remember_api_key else "")
        self.yaraify_key.setText(self._load_secret("yaraify_key") if remember_api_key else "")
        self.whids_manager_api_key.setText(self._load_secret("whids_manager_api_key") if remember_api_key else "")
        self.webhook_url.setText(self.settings.value("webhook_url", ""))
        self.hash_input.setText(self.settings.value("hash_input", ""))
        self.ip_input.setText(self.settings.value("ip_input", ""))
        self.persist_filter.setText(self.settings.value("persist_filter", ""))
        self.strings_min_length.setValue(int(self.settings.value("strings_min_length", self.strings_min_length.value())))
        self.strings_patterns.setText(self.settings.value("strings_patterns", self.strings_patterns.text()))
        self.trace_duration.setValue(int(self.settings.value("trace_duration", self.trace_duration.value())))
        self.trace_interval.setValue(float(self.settings.value("trace_interval", self.trace_interval.value())))
        self.honeypot_filename.setText(self.settings.value("honeypot_filename", self.honeypot_filename.text()))
        self.evidence_alert_name.setText(self.settings.value("evidence_alert_name", self.evidence_alert_name.text()))
        self.net_range.setText(self.settings.value("net_range", self.net_range.text()))
        self.block_target.setText(self.settings.value("block_target", ""))
        self.block_gateway.setText(self.settings.value("block_gateway", ""))
        self.approval_id.setText(self.settings.value("approval_id", ""))
        self.whids_manager_url.setText(self.settings.value("whids_manager_url", self.whids_manager_url.text()))
        self.whids_endpoint_uuid.setText(self.settings.value("whids_endpoint_uuid", ""))
        self.whids_artifact_since.setText(self.settings.value("whids_artifact_since", ""))
        self.whids_artifact_limit.setValue(int(self.settings.value("whids_artifact_limit", self.whids_artifact_limit.value())))
        self.whids_scheduler_interval.setValue(float(self.settings.value("whids_scheduler_interval", self.whids_scheduler_interval.value())))
        self.whids_verify_tls.setChecked(str(self.settings.value("whids_verify_tls", "true")).lower() == "true")
        self.whids_file_path.setText(self.settings.value("whids_file_path", self.whids_file_path.text()))
        self.whids_rule_name.setText(self.settings.value("whids_rule_name", ""))
        self.whids_ioc_payload.setPlainText(self.settings.value("whids_ioc_payload", ""))
        self.whids_rule_payload.setPlainText(self.settings.value("whids_rule_payload", ""))
        self.integration_policy_payload.setPlainText(self.settings.value("integration_policy_payload", ""))
        self.hids_file_path.setText(self.settings.value("hids_file_path", self.hids_file_path.text()))
        self.hids_incident_id.setText(self.settings.value("hids_incident_id", ""))
        self.hids_live_interval.setValue(float(self.settings.value("hids_live_interval", self.hids_live_interval.value())))
        self.hids_live_start_at_end.setChecked(str(self.settings.value("hids_live_start_at_end", "true")).lower() == "true")
        advanced_visible = str(self.settings.value("advanced_visible", "true")).lower() == "true"
        self.advanced_card.setVisible(advanced_visible)
        self.toggle_advanced_btn.setText("Hide Advanced Settings" if advanced_visible else "Show Advanced Settings")
        self.enterprise_auto_refresh.setChecked(str(self.settings.value("enterprise_auto_refresh", "true")).lower() == "true")
        self.enterprise_mitre_bundle_path.setText(str(self.settings.value("enterprise_mitre_bundle_path", self.enterprise_mitre_bundle_path.text())))
        self.enterprise_case_filter.setText(str(self.settings.value("enterprise_case_filter", "")))
        self.enterprise_task_filter.setText(str(self.settings.value("enterprise_task_filter", "")))
        self.enterprise_activity_filter.setText(str(self.settings.value("enterprise_activity_filter", "")))
        self.enterprise_selected_case_id = self._safe_int(self.settings.value("enterprise_selected_case_id", ""))
        current_tab = self._safe_int(self.settings.value("current_tab_index", 0))
        if current_tab is not None and 0 <= current_tab < self.tabs.count():
            self.tabs.setCurrentIndex(current_tab)

    def _save_settings(self) -> None:
        self.settings.setValue("custom_toolbar_buttons", json.dumps(self.custom_toolbar_buttons))
        self.settings.setValue("base", self.base.text())
        self.settings.setValue("remember_api_key", self.remember_api_key.isChecked())
        self.settings.remove("api_key")
        self.settings.remove("vt_key")
        self.settings.remove("malwarebazaar_key")
        self.settings.remove("yaraify_key")
        self.settings.remove("whids_manager_api_key")
        if self.remember_api_key.isChecked():
            self._save_secret("api_key", self.api_key.text())
            self._save_secret("vt_key", self.vt_key.text())
            self._save_secret("malwarebazaar_key", self.malwarebazaar_key.text())
            self._save_secret("yaraify_key", self.yaraify_key.text())
            self._save_secret("whids_manager_api_key", self.whids_manager_api_key.text())
        else:
            for key in ["api_key", "vt_key", "malwarebazaar_key", "yaraify_key", "whids_manager_api_key"]:
                self._delete_secret(key)
        self.settings.setValue("duration", self.duration.value())
        self.settings.setValue("interval", self.interval.value())
        self.settings.setValue("webhook_url", self.webhook_url.text())
        self.settings.setValue("hash_input", self.hash_input.text())
        self.settings.setValue("ip_input", self.ip_input.text())
        self.settings.setValue("persist_filter", self.persist_filter.text())
        self.settings.setValue("strings_min_length", self.strings_min_length.value())
        self.settings.setValue("strings_patterns", self.strings_patterns.text())
        self.settings.setValue("trace_duration", self.trace_duration.value())
        self.settings.setValue("trace_interval", self.trace_interval.value())
        self.settings.setValue("honeypot_filename", self.honeypot_filename.text())
        self.settings.setValue("evidence_alert_name", self.evidence_alert_name.text())
        self.settings.setValue("net_range", self.net_range.text())
        self.settings.setValue("block_target", self.block_target.text())
        self.settings.setValue("block_gateway", self.block_gateway.text())
        self.settings.setValue("approval_id", self.approval_id.text().strip())
        self.settings.setValue("whids_manager_url", self.whids_manager_url.text())
        self.settings.setValue("whids_endpoint_uuid", self.whids_endpoint_uuid.text())
        self.settings.setValue("whids_artifact_since", self.whids_artifact_since.text())
        self.settings.setValue("whids_artifact_limit", self.whids_artifact_limit.value())
        self.settings.setValue("whids_scheduler_interval", self.whids_scheduler_interval.value())
        self.settings.setValue("whids_verify_tls", self.whids_verify_tls.isChecked())
        self.settings.setValue("whids_file_path", self.whids_file_path.text())
        self.settings.setValue("whids_rule_name", self.whids_rule_name.text())
        self.settings.setValue("whids_ioc_payload", self.whids_ioc_payload.toPlainText())
        self.settings.setValue("whids_rule_payload", self.whids_rule_payload.toPlainText())
        self.settings.setValue("integration_policy_payload", self.integration_policy_payload.toPlainText())
        self.settings.setValue("hids_file_path", self.hids_file_path.text())
        self.settings.setValue("hids_incident_id", self.hids_incident_id.text())
        self.settings.setValue("hids_live_interval", self.hids_live_interval.value())
        self.settings.setValue("hids_live_start_at_end", self.hids_live_start_at_end.isChecked())
        self.settings.setValue("advanced_visible", self.advanced_card.isVisible())
        self.settings.setValue("current_tab_index", self.tabs.currentIndex())
        self.settings.setValue("enterprise_auto_refresh", self.enterprise_auto_refresh.isChecked())
        self.settings.setValue("enterprise_mitre_bundle_path", self.enterprise_mitre_bundle_path.text())
        self.settings.setValue("enterprise_case_filter", self.enterprise_case_filter.text())
        self.settings.setValue("enterprise_task_filter", self.enterprise_task_filter.text())
        self.settings.setValue("enterprise_activity_filter", self.enterprise_activity_filter.text())
        self.settings.setValue("enterprise_selected_case_id", "" if self.enterprise_selected_case_id is None else self.enterprise_selected_case_id)

    def closeEvent(self, event) -> None:
        self._save_settings()
        super().closeEvent(event)

    def _safe_int(self, value) -> int | None:
        try:
            text = str(value).strip()
            if not text:
                return None
            return int(text)
        except Exception:
            return None

    def _persist_enterprise_ui_state(self) -> None:
        self.settings.setValue("enterprise_auto_refresh", self.enterprise_auto_refresh.isChecked())
        self.settings.setValue("enterprise_mitre_bundle_path", self.enterprise_mitre_bundle_path.text())
        self.settings.setValue("enterprise_case_filter", self.enterprise_case_filter.text())
        self.settings.setValue("enterprise_task_filter", self.enterprise_task_filter.text())
        self.settings.setValue("enterprise_activity_filter", self.enterprise_activity_filter.text())
        self.settings.setValue("enterprise_selected_case_id", "" if self.enterprise_selected_case_id is None else self.enterprise_selected_case_id)

    def toggle_advanced_settings(self) -> None:
        visible = not self.advanced_card.isVisible()
        self.advanced_card.setVisible(visible)
        self.toggle_advanced_btn.setText("Hide Advanced Settings" if visible else "Show Advanced Settings")
        self._update_controls_layout()

    def add_custom_toolbar_button(self) -> None:
        label, ok = QInputDialog.getText(self, "Add Button", "Button label:")
        if not ok or not label.strip():
            return
        target, ok = QInputDialog.getText(self, "Add Button", "Target:\nUse `tab:Threat Intel`, `/health`, or `https://...`")
        if not ok or not target.strip():
            return
        self.custom_toolbar_buttons.append({"label": label.strip(), "target": target.strip()})
        self._rebuild_toolbar()
        self.statusBar().showMessage(f"Added toolbar button: {label.strip()}")

    def run_custom_toolbar_button(self, shortcut: dict[str, str]) -> None:
        target = shortcut.get("target", "")
        if target.startswith("tab:"):
            wanted = target.split(":", 1)[1].strip().lower()
            for idx in range(self.tabs.count()):
                if self.tabs.tabText(idx).lower() == wanted:
                    self.tabs.setCurrentIndex(idx)
                    return
            self.statusBar().showMessage(f"Tab not found: {wanted}")
            return
        if target.startswith("http://") or target.startswith("https://"):
            QDesktopServices.openUrl(QUrl(target))
            return
        if target.startswith("/"):
            try:
                response = self._get(target, timeout=20)
                QMessageBox.information(self, shortcut.get("label", "Shortcut"), response.text[:1200] or "OK")
            except Exception as exc:
                QMessageBox.warning(self, shortcut.get("label", "Shortcut"), str(exc))
            return
        self.statusBar().showMessage("Unsupported shortcut target. Use tab:, /path, or https://")

    def _style_table(self, table: QTableWidget) -> None:
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QTableWidget.SelectRows)
        table.setEditTriggers(QTableWidget.NoEditTriggers)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(30)
        table.horizontalHeader().setStretchLastSection(True)
        table.setShowGrid(False)

    def _severity_color(self, severity: str) -> QColor:
        sev = (severity or "").lower()
        if sev in {"critical", "high"}: return QColor("#d64550")
        if sev == "medium": return QColor("#e0a640")
        if sev == "low": return QColor("#2f9e67")
        return QColor("#96a5b8")

    def _paint_row(self, table: QTableWidget, row: int, color: QColor) -> None:
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item:
                item.setForeground(QBrush(color))

    def check_api_health(self) -> None:
        try:
            self._get("/health", timeout=5)
            self._set_health_badge(True)
            if not self.auth_active:
                self._apply_auth_context(self._viewer_mode_payload())
                self.statusBar().showMessage("Connected to backend. Viewer mode active until you press OK.")
                return
            context_response = self._get("/auth/context", timeout=5, raise_for_status=False)
            if context_response.status_code == 200:
                payload = context_response.json()
                if not bool(payload.get("auth_required", False)):
                    self.auth_active = False
                    self._apply_auth_context(self._viewer_mode_payload())
                    self.statusBar().showMessage("Backend auth is disabled. Enable SHADOWLAB_REQUIRE_AUTH for real role-based API key mode.")
                    return
                self._apply_auth_context(payload)
                role = str(self.auth_context.get("role", "unknown"))
                self.statusBar().showMessage(f"Connected to backend. {role} mode active.")
                self.refresh_overview()
                return
            if context_response.status_code in {401, 403}:
                self.auth_active = False
                self._apply_auth_context(self._viewer_mode_payload())
                self.statusBar().showMessage("API key was rejected. Viewer mode remains active.")
                return
            self._raise_for_api_error(context_response)
        except Exception as exc:
            self._set_health_badge(False); self.auth_active = False; self._apply_auth_context(self._viewer_mode_payload()); self.statusBar().showMessage(f"Backend unavailable: {exc}")

    def refresh_overview(self) -> None:
        self.refresh_history(); self.refresh_artifacts(); self.refresh_network()
        try:
            items = self._get("/processes").json(); self.metric_proc.setText(f"Processes: {len(items)}")
        except Exception: self.metric_proc.setText("Processes: unavailable")
        try:
            self.refresh_entity_graph()
        except Exception:
            pass
        if hasattr(self, "dash_metrics"):
            self._refresh_dashboard_panels()

    def refresh_processes(self) -> None:
        try: items = self._get("/processes").json()
        except Exception as exc: self._show_error(self.proc_detail, "Failed to load processes", exc); return
        self.proc_table.setRowCount(len(items))
        for i, p in enumerate(items):
            for j, value in enumerate([p.get("pid",""), p.get("name",""), p.get("cpu_percent",""), p.get("memory_percent",""), p.get("signature_status","n/a")]):
                self.proc_table.setItem(i, j, QTableWidgetItem(str(value)))
            cpu_val = float(p.get("cpu_percent", 0) or 0)
            mem_val = float(p.get("memory_percent", 0) or 0)
            if cpu_val >= 20 or mem_val >= 5:
                self._paint_row(self.proc_table, i, QColor("#e0a640"))
        self.metric_proc.setText(f"Processes: {len(items)}"); self.statusBar().showMessage(f"Loaded {len(items)} processes")

    def _selected_identity(self):
        row = self.proc_table.currentRow()
        if row < 0: return None
        pid_item = self.proc_table.item(row, 0); name_item = self.proc_table.item(row, 1)
        if not pid_item or not name_item: return None
        return pid_item.text(), name_item.text()

    def _selected_process_or_warn(self):
        ident = self._selected_identity()
        if not ident:
            self.statusBar().showMessage("First select a process from the Processes table")
            return None
        return ident

    def show_selected_process(self) -> None:
        ident = self._selected_identity()
        if not ident: return
        pid, _ = ident
        try: profile = self._get(f"/processes/{pid}").json()
        except Exception as exc: self._show_error(self.proc_detail, "Failed to load process detail", exc); return
        self.selected_process = profile
        lines = [f"{k}: {profile.get(k)}" for k in ["pid","name","username","status","exe","cwd","cmdline","sha256","signature_status"]]
        lines += ["", "Network Connections:"] + (profile.get("network_connections") or ["None"])
        self.proc_detail.setPlainText("\n".join(lines))
        self.hunt_out.setPlainText("Selected process ready for deeper analysis.")

    def process_action(self, action: str) -> None:
        ident = self._selected_identity()
        if not ident: return
        pid, name = ident
        process_profile = self.selected_process or {}
        impact = "high" if any(token in str(name).lower() for token in ["lsass", "wininit", "services", "svchost"]) else "moderate"
        rollback = "low" if action in {"kill", "kill-tree"} else "medium" if action == "quarantine" else "high"
        prompt = (
            f"Run '{action}' on {name} (PID {pid})?\n\n"
            f"Impact preview: {impact}\n"
            f"Reasoning: selected process response action requested by the operator.\n"
            f"Rollback confidence: {rollback}\n"
            f"Executable: {process_profile.get('exe', 'n/a')}"
        )
        if QMessageBox.question(self, "Confirm Action", prompt) != QMessageBox.Yes: return
        try:
            result = self._post(f"/processes/{pid}/actions/{action}", params={"process_name": name}, timeout=20).json()
            self.statusBar().showMessage(result.get("message", action))
            self.refresh_history()
        except Exception as exc: self.statusBar().showMessage(f"{action} failed: {exc}")

    def scan_selected_process(self) -> None:
        ident = self._selected_identity()
        if not ident:
            self.statusBar().showMessage("Select a process first")
            return
        pid, _ = ident
        payload = {
            "virustotal_api_key": self.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": self.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": self.yaraify_key.text().strip() or None,
        }
        if not any(payload.values()):
            self.statusBar().showMessage("Enter at least one threat-intel API key")
            return
        try: result = self._post(f"/processes/{pid}/scan", json=payload, timeout=60).json()
        except Exception as exc: self._show_error(self.threat_out, "Threat scan failed", exc); return
        self._show_json(self.threat_out, result)
        source = "VirusTotal + MalwareBazaar + YARAify"
        value = str(self.selected_process.get("sha256", "-")) if self.selected_process else f"PID {pid}"
        self._record_threat_history("process", value, source, result)
        self._switch_to_tab("Threat Intel")

    def run_memory_analysis(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, name = ident
        try: result = self._get(f"/processes/{pid}/memory-analysis", params={"process_name": name}, timeout=40).json()
        except Exception as exc: self._show_error(self.proc_detail, "Memory analysis failed", exc); return
        self._show_json(self.proc_detail, result)

    def load_selected_internals(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        try:
            result = self._get(f"/processes/{pid}/internals", timeout=40).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "Internals load failed", exc)
            return
        rows = []
        for item in result.get("handles", []):
            rows.append(("Handle", item.get("Path", ""), item.get("Mode", ""), item.get("FD", "")))
        for item in result.get("modules", []):
            rows.append(("Module", item.get("Path", ""), item.get("Perms", ""), item.get("Size", "")))
        self.internals_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, value in enumerate(row):
                self.internals_table.setItem(r, c, QTableWidgetItem(str(value)))
        self._show_json(self.hunt_out, {"summary": {"handles": len(result.get("handles", [])), "modules": len(result.get("modules", []))}})
        self._switch_to_tab("Advanced Hunt")

    def run_strings_analysis(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        payload = {
            "min_length": self.strings_min_length.value(),
            "patterns": [part.strip() for part in self.strings_patterns.text().split(",") if part.strip()],
        }
        try:
            result = self._post(f"/processes/{pid}/strings", json=payload, timeout=60).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "Strings analysis failed", exc)
            return
        sample = result.get("sample", [])[:20]
        hits = result.get("pattern_hits", [])[:20]
        self.hunt_out.setPlainText("\n".join([
            f"Total Strings: {result.get('total_strings', 0)}",
            f"Pattern Hits: {len(result.get('pattern_hits', []))}",
            "",
            "Top Hits:",
            *hits,
            "",
            "Sample:",
            *sample,
        ]))
        self._switch_to_tab("Advanced Hunt")

    def run_yara_scan(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        try:
            result = self._post(
                f"/processes/{pid}/yara",
                json={"yaraify_auth_key": self.yaraify_key.text().strip() or None},
                timeout=40,
            ).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "YARA scan failed", exc)
            return
        lookup = result.get("result", {}) if isinstance(result, dict) else {}
        matches = result.get("matches", [])
        provider = result.get("provider", "YARAify")
        self.hunt_out.setPlainText(
            f"{provider} Lookup\n\n"
            f"Status: {lookup.get('status', 'unknown')}\n"
            f"Rule Count: {lookup.get('yara_rule_count', 0)}\n"
            f"Matches:\n" + ("\n".join(matches) if matches else "None")
        )
        self._switch_to_tab("Advanced Hunt")

    def run_sandbox_trace(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        payload = {"duration": self.trace_duration.value(), "interval": self.trace_interval.value()}
        try:
            result = self._post(f"/processes/{pid}/sandbox-trace", json=payload, timeout=payload["duration"] + 20).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "Sandbox trace failed", exc)
            return
        events = result.get("events", [])
        self.hunt_out.setPlainText("\n".join([f"Collected Events: {len(events)}", ""] + [f"{event.get('time')} | {event.get('type')} | {event.get('detail')}" for event in events[:50]]))
        self._switch_to_tab("Advanced Hunt")

    def load_process_tree(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        try:
            result = self._get(f"/processes/{pid}/tree", timeout=30).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "Process tree failed", exc)
            return
        self.tree_view.clear()
        def add_node(parent, node):
            item = QTreeWidgetItem([str(node.get("name")), str(node.get("pid"))])
            if parent is None:
                self.tree_view.addTopLevelItem(item)
            else:
                parent.addChild(item)
            for child in node.get("children", []):
                add_node(item, child)
        add_node(None, result.get("root", {}))
        self.tree_view.expandAll()
        lineage = "\n".join([f"{item.get('name')} (PID {item.get('pid')}, PPID {item.get('ppid')})" for item in result.get("lineage", [])])
        self.hunt_out.setPlainText(f"Lineage:\n{lineage}")
        self._switch_to_tab("Advanced Hunt")

    def run_ai_analysis(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        try:
            result = self._get(f"/processes/{pid}/ai-analysis", timeout=30).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "AI analysis failed", exc)
            return
        self.hunt_out.setPlainText(f"Risk: {result.get('risk')}\nConfidence: {result.get('confidence')}\n\n{result.get('analysis')}")
        self._switch_to_tab("Advanced Hunt")

    def run_auto_triage(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {
            "virustotal_api_key": self.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": self.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": self.yaraify_key.text().strip() or None,
            "trace_duration": min(10, self.trace_duration.value()),
            "strings_min_length": self.strings_min_length.value(),
            "strings_patterns": [part.strip() for part in self.strings_patterns.text().split(",") if part.strip()],
        }
        try:
            result = self._post(f"/triage/{pid}", json=payload, timeout=120).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "Auto triage failed", exc)
            return
        self._show_json(self.hunt_out, result)
        self._switch_to_tab("Advanced Hunt")

    def run_monitor(self) -> None:
        payload = {"duration": self.duration.value(), "interval": self.interval.value()}
        try:
            response = self._post("/monitor/run", json=payload, timeout=payload["duration"] + 60)
            result = self._json_response(response)
        except Exception as exc: self._show_error(self.monitor_out, "Monitor failed", exc); return
        incident = result.get("incident", {})
        telemetry_rows = result.get("telemetry_rows", [])
        self.latest_monitor_rows = telemetry_rows
        self.latest_monitor_result = result
        self._update_cpu_chart(telemetry_rows)
        self.monitor_out.setHtml(self._render_monitor_brief(result, incident))
        self.metric_tel.setText(f"Telemetry Rows: {result.get('telemetry_count','-')}")
        self.metric_inc.setText(f"Last Incident: {incident.get('incident_id','-')}")
        severity = incident.get("severity", "unknown")
        self.metric_inc.setStyleSheet(f"color:{self._severity_color(severity).name()};font-weight:700;")
        self.metric_inc.setText(f"Last Incident: {incident.get('incident_id','-')} ({severity})")
        self.refresh_history(); self.refresh_artifacts(); self._switch_to_tab("Dashboards")

    def refresh_persistence(self) -> None:
        try: self.persistence_items = self._get("/persistence", timeout=45).json()
        except Exception as exc: self._show_error(self.persist_detail, "Failed to load persistence", exc); return
        self.apply_persistence_filter()

    def apply_persistence_filter(self) -> None:
        filt = self.persist_filter.text().strip().lower()
        items = self.persistence_items if not filt else [i for i in self.persistence_items if filt in json.dumps(i).lower()]
        self.persist_table.setRowCount(len(items))
        for r, item in enumerate(items):
            for c, value in enumerate([item.get("name",""), item.get("type",""), item.get("path",""), item.get("details","")]):
                self.persist_table.setItem(r, c, QTableWidgetItem(str(value)))
            risk_text = json.dumps(item).lower()
            if any(token in risk_text for token in ["runonce", "powershell", "temp", "appdata", "startup"]):
                self._paint_row(self.persist_table, r, QColor("#e0a640"))
        self.persist_detail.setPlainText(f"Showing {len(items)} persistence items.")

    def show_selected_persistence(self) -> None:
        row = self.persist_table.currentRow()
        if row < 0: return
        detail = {}
        for c, key in enumerate(["name","type","path","details"]):
            item = self.persist_table.item(row, c); detail[key] = item.text() if item else ""
        self.persist_detail.setPlainText(json.dumps(detail, indent=2))

    def remediate_selected_persistence(self) -> None:
        row = self.persist_table.currentRow()
        if row < 0:
            return
        name = self.persist_table.item(row, 0).text() if self.persist_table.item(row, 0) else ""
        item_type = self.persist_table.item(row, 1).text() if self.persist_table.item(row, 1) else ""
        path = self.persist_table.item(row, 2).text() if self.persist_table.item(row, 2) else ""
        if QMessageBox.question(self, "Remediate Persistence", f"Remediate {name} ({item_type})?") != QMessageBox.Yes:
            return
        try:
            result = self._post("/persistence/remediate", json={"item_type": item_type, "path": path, "name": name}, timeout=40).json()
        except Exception as exc:
            self._show_error(self.persist_detail, "Persistence remediation failed", exc)
            return
        self._show_json(self.persist_detail, result)
        self.refresh_persistence()

    def lookup_hash(self) -> None:
        if not self.hash_input.text().strip(): return
        payload = {
            "file_hash": self.hash_input.text().strip(),
            "virustotal_api_key": self.vt_key.text().strip() or None,
            "malwarebazaar_auth_key": self.malwarebazaar_key.text().strip() or None,
            "yaraify_auth_key": self.yaraify_key.text().strip() or None,
        }
        if not any([payload["virustotal_api_key"], payload["malwarebazaar_auth_key"], payload["yaraify_auth_key"]]):
            self.statusBar().showMessage("Enter at least one hash lookup API key")
            return
        try: result = self._post("/threat-intel/hash/lookup", json=payload).json()
        except Exception as exc: self._show_error(self.threat_out, "Hash lookup failed", exc); return
        self._show_json(self.threat_out, result)
        self._record_threat_history("hash", self.hash_input.text().strip(), "MalwareBazaar + YARAify + VirusTotal", result)
        self._switch_to_tab("Threat Intel")

    def lookup_ip(self) -> None:
        if not self.ip_input.text().strip(): return
        try: result = self._get(f"/threat-intel/ip/{self.ip_input.text().strip()}").json()
        except Exception as exc: self._show_error(self.threat_out, "IP lookup failed", exc); return
        self._show_json(self.threat_out, result)
        self._record_threat_history("ip", self.ip_input.text().strip(), "AbuseIPDB", result)
        self._switch_to_tab("Threat Intel")

    def use_selected_process_hash(self) -> None:
        if not self.selected_process:
            self.statusBar().showMessage("First select a process to auto-fill its hash")
            return
        hash_value = self.selected_process.get("sha256") or ""
        self.hash_input.setText(hash_value)
        self.ti_last_type.setText("Last Query: process hash prepared")
        self.ti_last_value.setText(f"Value: {hash_value[:20]}..." if hash_value else "Value: unavailable")
        self._switch_to_tab("Threat Intel")

    def use_selected_process_ip(self) -> None:
        if not self.selected_process:
            self.statusBar().showMessage("First select a process to auto-fill its remote IP")
            return
        connections = self.selected_process.get("network_connections") or []
        candidate = ""
        for connection in connections:
            if "->" in connection:
                right = connection.split("->", 1)[1]
                candidate = right.split(":")[0]
                break
        self.ip_input.setText(candidate)
        self.ti_last_type.setText("Last Query: process IP prepared")
        self.ti_last_value.setText(f"Value: {candidate or 'unavailable'}")
        self._switch_to_tab("Threat Intel")

    def _record_threat_history(self, query_type: str, value: str, source: str, payload) -> None:
        self.threat_history.insert(0, {"type": query_type, "value": value, "source": source, "payload": json.dumps(payload, indent=2, ensure_ascii=False)})
        self.threat_history = self.threat_history[:20]
        self._refresh_threat_history_table()
        self.ti_last_type.setText(f"Last Query: {query_type}")
        display_value = value if len(value) <= 28 else value[:28] + "..."
        self.ti_last_value.setText(f"Value: {display_value}")
        self.ti_last_source.setText(f"Source: {source}")

    def _refresh_threat_history_table(self) -> None:
        self.threat_history_table.setRowCount(len(self.threat_history))
        for row, item in enumerate(self.threat_history):
            values = [item.get("type", ""), item.get("value", ""), item.get("source", "")]
            for col, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                self.threat_history_table.setItem(row, col, cell)
            if item.get("type") == "process":
                self._paint_row(self.threat_history_table, row, QColor("#e0a640"))
            elif item.get("type") == "ip":
                self._paint_row(self.threat_history_table, row, QColor("#2f9e67"))

    def show_selected_threat_history(self) -> None:
        row = self.threat_history_table.currentRow()
        if row < 0 or row >= len(self.threat_history):
            return
        self.threat_out.setPlainText(self.threat_history[row].get("payload", ""))

    def refresh_network(self) -> None:
        try: items = self._get("/network/connections").json()
        except Exception as exc: self._show_error(self.net_out, "Failed to load network", exc); return
        self.net_table.setRowCount(len(items))
        for r, item in enumerate(items):
            for c, value in enumerate([item.get("local_addr",""), item.get("remote_addr",""), item.get("status",""), item.get("pid","")]):
                self.net_table.setItem(r, c, QTableWidgetItem(str(value)))
            status = str(item.get("status", "")).upper()
            if "ESTABLISHED" in status:
                self._paint_row(self.net_table, r, QColor("#2f9e67"))
        self.net_out.setPlainText(f"Loaded {len(items)} network connections.")

    def refresh_hosts(self) -> None:
        try:
            hosts = self._get("/hosts", timeout=20).json()
        except Exception as exc:
            self.statusBar().showMessage(f"Hosts load failed: {exc}")
            return
        self.host_table.setRowCount(len(hosts))
        for r, item in enumerate(hosts):
            for c, value in enumerate([item.get("host",""), item.get("platform",""), item.get("boot_time",""), item.get("api_status",""), item.get("role",""), item.get("ip_address",""), item.get("agent_version","")]):
                self.host_table.setItem(r, c, QTableWidgetItem(str(value)))
        if not hosts:
            self.statusBar().showMessage("No fleet hosts registered yet.")

    def refresh_entity_graph(self, pid: int | None = None) -> None:
        endpoint = f"/graph/entity-map?pid={pid}" if pid is not None else "/graph/entity-map"
        try:
            graph = self._get(endpoint, timeout=45).json()
        except Exception as exc:
            self._show_error(self.graph_detail, "Entity graph load failed", exc)
            return
        self.entity_graph = graph
        summary = graph.get("summary", {})
        ad = graph.get("ad_context", {})
        overall_risk = int(float(summary.get("overall_risk", 0) or 0))
        exposure = summary.get("remote_exposure", {}) if isinstance(summary.get("remote_exposure"), dict) else {}
        self.graph_summary.setHtml(
            f"<h2>ShadowLab Attack Surface Graph</h2>"
            f"<p><b>Nodes:</b> {summary.get('node_count', 0)} | <b>Edges:</b> {summary.get('edge_count', 0)}<br>"
            f"<b>Overall Risk:</b> <span style='color:{self._severity_color('high' if overall_risk >= 75 else 'medium' if overall_risk >= 45 else 'low').name()};font-weight:700;'>{overall_risk}</span><br>"
            f"<b>Exposure:</b> {json.dumps(exposure)}<br>"
            f"<b>Domain Joined:</b> {summary.get('domain_joined', False)} | <b>Domain:</b> {summary.get('domain', 'n/a')}<br>"
            f"<b>User:</b> {ad.get('user', 'n/a')} | <b>Logon Server:</b> {ad.get('logon_server', 'n/a')}</p>"
        )
        findings = graph.get("priority_findings", []) or summary.get("priority_findings", [])
        findings_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in findings[:8])
        self.graph_findings.setHtml("<h3>Operator Findings</h3>" f"<ul>{findings_html or '<li>No high-priority graph findings yet.</li>'}</ul>")
        groups = summary.get("groups", {}) if isinstance(summary.get("groups"), dict) else {}
        self.graph_group_table.setRowCount(len(groups))
        for r, (group, count) in enumerate(sorted(groups.items(), key=lambda item: item[1], reverse=True)):
            self.graph_group_table.setItem(r, 0, QTableWidgetItem(str(group)))
            self.graph_group_table.setItem(r, 1, QTableWidgetItem(str(count)))
        top_processes = summary.get("top_processes", []) if isinstance(summary.get("top_processes"), list) else []
        self.graph_focus_table.setRowCount(len(top_processes))
        for r, item in enumerate(top_processes):
            for c, value in enumerate([item.get("name", ""), item.get("pid", ""), item.get("risk_score", 0), item.get("signature_status", "")]):
                self.graph_focus_table.setItem(r, c, QTableWidgetItem(str(value)))
            risk_value = float(item.get("risk_score", 0) or 0)
            if risk_value >= 75:
                self._paint_row(self.graph_focus_table, r, QColor("#d64550"))
            elif risk_value >= 45:
                self._paint_row(self.graph_focus_table, r, QColor("#e0a640"))
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        self.graph_nodes_table.setRowCount(len(nodes))
        for r, node in enumerate(nodes):
            for c, value in enumerate([node.get("label", ""), node.get("group", ""), node.get("cluster", ""), node.get("risk_score", 0), node.get("title", "")]):
                self.graph_nodes_table.setItem(r, c, QTableWidgetItem(str(value)))
            node_risk = float(node.get("risk_score", 0) or 0)
            if node_risk >= 75:
                self._paint_row(self.graph_nodes_table, r, QColor("#d64550"))
            elif node_risk >= 45:
                self._paint_row(self.graph_nodes_table, r, QColor("#e0a640"))
        self.graph_edges_table.setRowCount(len(edges))
        for r, edge in enumerate(edges):
            for c, value in enumerate([edge.get("from", ""), edge.get("to", ""), edge.get("label", ""), edge.get("width", 1)]):
                self.graph_edges_table.setItem(r, c, QTableWidgetItem(str(value)))
            if str(edge.get("label", "")) in {"connects_to", "contributes_to", "auto_starts"}:
                self._paint_row(self.graph_edges_table, r, QColor("#f08c00"))
        self.graph_detail.setPlainText(json.dumps(graph, indent=2))

    def refresh_selected_process_graph(self) -> None:
        if not self.selected_process:
            self.statusBar().showMessage("Select a process first to build a focused graph.")
            return
        self.refresh_entity_graph(int(self.selected_process.get("pid", -1)))

    def open_entity_graph(self) -> None:
        graph = getattr(self, "entity_graph", {})
        html_path = graph.get("html_path")
        if not html_path:
            self.refresh_entity_graph()
            graph = getattr(self, "entity_graph", {})
            html_path = graph.get("html_path")
        if html_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))
        else:
            self.statusBar().showMessage("No graph HTML generated yet.")

    def refresh_timeline(self) -> None:
        try:
            items = self._get("/timeline", timeout=20).json()
            graph = self._get("/timeline/graph", timeout=20).json()
        except Exception as exc:
            self._show_error(self.timeline_detail, "Timeline load failed", exc)
            return
        self.timeline_items = items
        self.timeline_table.setRowCount(len(items))
        for r, item in enumerate(items):
            values = [item.get("time",""), item.get("type",""), item.get("severity",""), item.get("title","")]
            for c, value in enumerate(values):
                self.timeline_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.timeline_table, r, self._severity_color(item.get("severity", "")))
        summary = graph.get("summary", {})
        self.timeline_summary.setHtml(
            f"<h3>Timeline Graph Summary</h3>"
            f"<p>Total events: <b>{summary.get('total_events', 0)}</b><br>"
            f"Latest event: <b>{summary.get('latest_event', 'n/a')}</b><br>"
            f"Severity mix: <b>{json.dumps(summary.get('by_severity', {}))}</b></p>"
        )
        if not items:
            self.timeline_detail.setPlainText("No timeline events captured yet.")

    def show_selected_timeline(self) -> None:
        row = self.timeline_table.currentRow()
        if row < 0:
            return
        items = getattr(self, "timeline_items", [])
        if row >= len(items):
            return
        self._show_json(self.timeline_detail, items[row])

    def scan_network_devices(self) -> None:
        try:
            result = self._post("/network/warfare/scan", json={"ip_range": self.net_range.text().strip() or "192.168.1.0/24"}, timeout=60).json()
        except Exception as exc:
            self._show_error(self.net_out, "ARP discovery failed", exc)
            return
        devices = result.get("devices", [])
        self.device_table.setRowCount(len(devices))
        for r, item in enumerate(devices):
            for c, value in enumerate([item.get("ip", ""), item.get("mac", ""), item.get("vendor", item.get("error", ""))]):
                self.device_table.setItem(r, c, QTableWidgetItem(str(value)))
            if item.get("error"):
                self._paint_row(self.device_table, r, QColor("#d64550"))
        self._show_json(self.net_out, result)

    def start_network_blocker(self) -> None:
        payload = {"target_ip": self.block_target.text().strip(), "gateway_ip": self.block_gateway.text().strip()}
        if not payload["target_ip"] or not payload["gateway_ip"]:
            self.statusBar().showMessage("Enter blocker target and gateway IPs first")
            return
        prompt = f"Start ARP blocker for {payload['target_ip']} via {payload['gateway_ip']}?\n\nUse only on systems and networks you own for lab testing."
        if QMessageBox.question(self, "Confirm Network Blocker", prompt) != QMessageBox.Yes:
            return
        try:
            result = self._post("/network/warfare/block", json=payload, timeout=20).json()
        except Exception as exc:
            self._show_error(self.net_out, "Network blocker failed", exc)
            return
        self._show_json(self.net_out, result)

    def stop_network_blocker(self) -> None:
        try:
            result = self._delete("/network/warfare/block", timeout=20).json()
        except Exception as exc:
            self._show_error(self.net_out, "Stop blocker failed", exc)
            return
        self._show_json(self.net_out, result)

    def run_sniffer(self) -> None:
        try: result = self._post("/network/sniff", json={"duration": self.sniff_duration.value()}, timeout=self.sniff_duration.value() + 30).json()
        except Exception as exc: self._show_error(self.net_out, "Packet capture failed", exc); return
        self._show_json(self.net_out, result)

    def refresh_history(self) -> None:
        try: resp = self._get("/history/responses").json()
        except Exception: resp = []
        self.resp_table.setRowCount(len(resp))
        for r, item in enumerate(resp):
            for c, value in enumerate([item.get("timestamp",""), item.get("action",""), item.get("pid",""), item.get("process_name","")]):
                self.resp_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.resp_table, r, self._severity_color("high" if item.get("action") == "KILL" else "medium"))
        try: tel = self._get("/history/telemetry").json()[-200:]
        except Exception: tel = []
        self.tel_table.setRowCount(len(tel))
        for r, item in enumerate(tel):
            for c, value in enumerate([item.get("ts",""), item.get("cpu",""), item.get("mem_percent",""), item.get("proc_threads",""), item.get("tcp_conns","")]):
                self.tel_table.setItem(r, c, QTableWidgetItem(str(value)))
            cpu = float(item.get("cpu", 0) or 0)
            if cpu >= 30:
                self._paint_row(self.tel_table, r, QColor("#d64550"))
        if self.latest_monitor_rows:
            self.metric_tel.setText(f"Telemetry Rows: {len(self.latest_monitor_rows)}")
            self._update_cpu_chart(self.latest_monitor_rows)
        else:
            self.metric_tel.setText(f"Telemetry Rows: {len(tel)}")
            self._update_cpu_chart(tel)
        if not tel and not self.latest_monitor_rows and not self.monitor_out.toPlainText().strip():
            self.monitor_out.setHtml("<div style='color:#9fb2c6;padding:6px;'>Run a monitor session to populate telemetry trend data.</div>")
        try: incidents = self._get("/incidents").json()
        except Exception: incidents = []
        self.inc_table.setRowCount(len(incidents))
        for r, item in enumerate(incidents):
            values = [item.get("incident_id",""), item.get("severity",""), item.get("status",""), item.get("owner",""), item.get("title","")]
            for c, value in enumerate(values):
                self.inc_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.inc_table, r, self._severity_color(item.get("severity", "")))
        try: alerts = self._get("/history/alerts").json()
        except Exception: alerts = []
        self.alert_table.setRowCount(len(alerts))
        for r, item in enumerate(alerts):
            values = [item.get("created_at",""), item.get("destination_type",""), item.get("severity",""), item.get("status","")]
            for c, value in enumerate(values):
                self.alert_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.alert_table, r, self._severity_color(item.get("severity", "")))
        try: remediations = self._get("/history/remediations").json()
        except Exception: remediations = []
        self.rem_table.setRowCount(len(remediations))
        for r, item in enumerate(remediations):
            values = [item.get("created_at",""), item.get("item_type",""), item.get("target",""), item.get("status","")]
            for c, value in enumerate(values):
                self.rem_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.rem_table, r, self._severity_color("medium" if item.get("status") == "applied" else "high"))
        if self.auth_context.get("capabilities", {}).get("can_manage_integrations"):
            try:
                auth_events = self._get("/history/auth").json()
            except Exception:
                auth_events = []
            self.auth_table.setRowCount(len(auth_events))
            for r, item in enumerate(auth_events):
                values = [item.get("created_at",""), item.get("event_type",""), item.get("outcome",""), item.get("role",""), item.get("path","")]
                for c, value in enumerate(values):
                    self.auth_table.setItem(r, c, QTableWidgetItem(str(value)))
                severity = "high" if item.get("outcome") == "denied" else "low"
                self._paint_row(self.auth_table, r, self._severity_color(severity))
            try:
                anomalies = self._get("/history/auth/anomalies").json()
            except Exception as exc:
                self.auth_anomaly_view.setPlainText(f"Auth anomaly load failed:\n{exc}")
            else:
                self.auth_anomaly_view.setPlainText(json.dumps(anomalies, indent=2, ensure_ascii=False))
        else:
            self.auth_table.setRowCount(0)
            self.auth_anomaly_view.setPlainText("Auth audit and anomaly history is visible to admin users only.")
        self.refresh_timeline()
        if self.auth_context.get("capabilities", {}).get("can_view_quarantine"):
            self.refresh_quarantine()
        self.refresh_hosts()

    def show_selected_incident(self) -> None:
        row = self.inc_table.currentRow()
        if row < 0:
            return
        self.incident_status.setCurrentText(self.inc_table.item(row, 2).text() if self.inc_table.item(row, 2) else "open")
        self.incident_owner.setText(self.inc_table.item(row, 3).text() if self.inc_table.item(row, 3) else "")

    def update_selected_incident(self) -> None:
        row = self.inc_table.currentRow()
        if row < 0:
            return
        incident_id = self.inc_table.item(row, 0).text() if self.inc_table.item(row, 0) else ""
        payload = {"status": self.incident_status.currentText(), "owner": self.incident_owner.text().strip(), "notes": self.incident_notes.text().strip()}
        try:
            result = self._patch(f"/incidents/{incident_id}", json=payload, timeout=20).json()
        except Exception as exc:
            self.statusBar().showMessage(f"Incident update failed: {exc}")
            return
        self.statusBar().showMessage(result.get("status", "updated"))
        self.refresh_history()

    def refresh_artifacts(self) -> None:
        try: self.artifacts = self._get("/artifacts").json()
        except Exception as exc: self._show_error(self.art_detail, "Failed to load artifacts", exc); return
        self.art_list.clear()
        for name in sorted(self.artifacts): self.art_list.addItem(name)
        self.art_detail.setPlainText(json.dumps(self.artifacts, indent=2)); self.metric_art.setText(f"Artifacts: {len(self.artifacts)}")
        self.art_preview.setHtml("<h3>Artifact Preview</h3><p>Select an artifact to inspect local path, URL, and quick preview.</p>")

    def refresh_quarantine(self) -> None:
        try:
            items = self._get("/quarantine", timeout=20).json()
        except Exception as exc:
            self._show_error(self.quarantine_detail, "Quarantine load failed", exc)
            return
        self.quarantine_records = items
        self.quarantine_table.setRowCount(len(items))
        for r, item in enumerate(items):
            values = [item.get("id",""), item.get("process_name",""), item.get("original_path",""), item.get("quarantine_path",""), item.get("status",""), item.get("created_at","")]
            for c, value in enumerate(values):
                self.quarantine_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.quarantine_table, r, self._severity_color("medium" if item.get("status") == "active" else "low"))

    def restore_selected_quarantine(self) -> None:
        row = self.quarantine_table.currentRow()
        if row < 0:
            return
        quarantine_id = self.quarantine_table.item(row, 0).text()
        try:
            result = self._post(f"/quarantine/{quarantine_id}/restore", timeout=30).json()
        except Exception as exc:
            self._show_error(self.quarantine_detail, "Quarantine restore failed", exc)
            return
        self._show_json(self.quarantine_detail, result)
        self.refresh_quarantine()

    def delete_selected_quarantine(self) -> None:
        row = self.quarantine_table.currentRow()
        if row < 0:
            return
        quarantine_id = self.quarantine_table.item(row, 0).text()
        try:
            result = self._delete(f"/quarantine/{quarantine_id}", timeout=30).json()
        except Exception as exc:
            self._show_error(self.quarantine_detail, "Quarantine delete failed", exc)
            return
        self._show_json(self.quarantine_detail, result)
        self.refresh_quarantine()

    def test_alert_webhook(self) -> None:
        if not self.webhook_url.text().strip():
            self.statusBar().showMessage("Enter a webhook URL first")
            return
        try:
            result = self._post("/alerts/test", json={"webhook_url": self.webhook_url.text().strip(), "message": "ShadowLab test alert"}, timeout=20).json()
        except Exception as exc:
            self._show_error(self.quarantine_detail, "Webhook test failed", exc)
            return
        self._show_json(self.quarantine_detail, result)

    def save_alert_webhook(self) -> None:
        if not self.webhook_url.text().strip():
            self.statusBar().showMessage("Enter a webhook URL first")
            return
        try:
            result = self._post("/alerts/configure", json={"webhook_url": self.webhook_url.text().strip(), "message": "ShadowLab configured"}, timeout=20).json()
        except Exception as exc:
            self._show_error(self.quarantine_detail, "Webhook save failed", exc)
            return
        self._show_json(self.quarantine_detail, result)

    def deploy_honeypot(self) -> None:
        try:
            result = self._post("/deception/honeypot/deploy", json={"filename": self.honeypot_filename.text().strip() or "passwords.txt"}, timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Honeypot deploy failed", exc)
            return
        self._show_json(self.deception_out, result)
        self._switch_to_tab("Deception")

    def check_honeypot(self) -> None:
        try:
            result = self._get("/deception/honeypot/status", timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Honeypot status failed", exc)
            return
        self._show_json(self.deception_out, result)
        if result.get("status") == "alert":
            self.deception_out.setStyleSheet("color:#d64550;")
        else:
            self.deception_out.setStyleSheet("")

    def cleanup_honeypot(self) -> None:
        try:
            result = self._delete("/deception/honeypot", timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Honeypot cleanup failed", exc)
            return
        self._show_json(self.deception_out, result)

    def deploy_canary(self) -> None:
        try:
            result = self._post("/deception/canary/deploy", timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Canary deploy failed", exc)
            return
        self._show_json(self.deception_out, result)

    def check_canary(self) -> None:
        try:
            result = self._get("/deception/canary/status", timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Canary status failed", exc)
            return
        self._show_json(self.deception_out, result)
        if result.get("alerts"):
            self.deception_out.setStyleSheet("color:#d64550;")
        else:
            self.deception_out.setStyleSheet("")

    def cleanup_canary(self) -> None:
        try:
            result = self._delete("/deception/canary", timeout=20).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Canary cleanup failed", exc)
            return
        self._show_json(self.deception_out, result)

    def capture_evidence(self) -> None:
        try:
            result = self._post("/evidence/capture", json={"alert_name": self.evidence_alert_name.text().strip() or "incident"}, timeout=40).json()
        except Exception as exc:
            self._show_error(self.deception_out, "Evidence capture failed", exc)
            return
        self._show_json(self.deception_out, result)
        self.refresh_evidence()

    def refresh_evidence(self) -> None:
        try:
            result = self._get("/evidence", timeout=20).json()
        except Exception as exc:
            self._show_error(self.evidence_detail, "Evidence list failed", exc)
            return
        self.evidence_items = result.get("items", [])
        self.evidence_list.clear()
        for item in self.evidence_items:
            self.evidence_list.addItem(item.split("\\")[-1].split("/")[-1])
        self.evidence_detail.setPlainText(json.dumps(result, indent=2))

    def show_selected_evidence(self) -> None:
        items = self.evidence_list.selectedItems()
        if not items:
            return
        name = items[0].text()
        match = next((item for item in self.evidence_items if item.endswith(name)), None)
        self.evidence_detail.setPlainText(f"Evidence: {name}\nPath: {match or ''}")

    def open_selected_evidence(self) -> None:
        items = self.evidence_list.selectedItems()
        if not items:
            return
        name = items[0].text()
        match = next((item for item in self.evidence_items if item.endswith(name)), None)
        if match:
            QDesktopServices.openUrl(QUrl.fromLocalFile(match))

    def delete_selected_evidence(self) -> None:
        items = self.evidence_list.selectedItems()
        if not items:
            return
        name = items[0].text()
        try:
            result = self._delete(f"/evidence/{name}", timeout=20).json()
        except Exception as exc:
            self._show_error(self.evidence_detail, "Evidence delete failed", exc)
            return
        self._show_json(self.evidence_detail, result)
        self.refresh_evidence()

    def show_selected_artifact(self) -> None:
        items = self.art_list.selectedItems()
        if not items: return
        name = items[0].text()
        path = self.artifacts.get(name, "")
        self.art_detail.setPlainText(f"Artifact: {name}\nLocal Path: {path}\nDownload URL: {self._url('/artifacts/' + name)}")
        suffix = Path(path).suffix.lower()
        if suffix == ".html" and Path(path).exists():
            self.art_preview.setHtml(Path(path).read_text(encoding="utf-8", errors="ignore")[:6000])
        elif suffix == ".json" and Path(path).exists():
            self.art_preview.setPlainText(Path(path).read_text(encoding="utf-8", errors="ignore")[:4000])
        else:
            self.art_preview.setHtml(f"<h3>{name}</h3><p>No inline preview for this file type yet.</p>")

    def open_selected_artifact(self) -> None:
        items = self.art_list.selectedItems()
        if not items: return
        name = items[0].text(); path = self.artifacts.get(name)
        if path: QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def run_scenario(self) -> None:
        payload = {"profile": self.scenario.currentText(), "duration": self.scenario_duration.value()}
        try: result = self._post("/scenario/run", json=payload).json()
        except Exception as exc: self._show_error(self.scenario_out, "Scenario failed", exc); return
        self._show_json(self.scenario_out, result)

    def refresh_enterprise_workspace(self) -> None:
        preferred_case_id = self.enterprise_selected_case_id or self._safe_int(self.settings.value("enterprise_selected_case_id", ""))
        self.enterprise_live_status.setText("Live sync loading enterprise workspace...")
        try:
            triage = self._get("/enterprise/triage", timeout=10).json()
            assets = self._get("/enterprise/assets", timeout=10).json()
            cases = self._get("/enterprise/cases", timeout=10).json()
            detections = self._get("/enterprise/detections/lifecycle", timeout=10).json()
            mitre_status = self._get("/enterprise/mitre/status", timeout=10).json()
            mitre_summary = self._get("/enterprise/mitre/summary", timeout=10).json()
            mitre_discover = self._get("/enterprise/mitre/discover", timeout=10).json()
            mitre_compare = self._post("/enterprise/mitre/compare", json={"file_path": self.enterprise_mitre_bundle_path.text().strip()}, timeout=20).json() if self.enterprise_mitre_bundle_path.text().strip() else {}
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Enterprise workspace failed", exc)
            self.enterprise_live_status.setText("Live sync failed")
            return
        attention = "".join(f"<li>{html.escape(str(item))}</li>" for item in triage.get("what_needs_attention_now", []))
        self.enterprise_summary.setHtml(
            f"<h3>Triage First</h3><ul>{attention or '<li>No immediate triage items.</li>'}</ul>"
            f"<p><b>Open cases:</b> {len(cases)}<br><b>Top auth anomalies:</b> {len(triage.get('auth_anomalies', []))}</p>"
        )
        self._set_metric_label(self.enterprise_open_cases_value, str(len(cases)))
        self._set_metric_label(self.enterprise_high_risk_value, str(len([item for item in assets.get('top_assets', []) if float(item.get('criticality_score', 0) or 0) >= 85])))
        self.enterprise_cases_data = cases
        self._populate_enterprise_cases_table(cases)
        top_assets = assets.get("top_assets", [])
        self.enterprise_assets_table.setRowCount(len(top_assets))
        for r, item in enumerate(top_assets):
            values = [item.get("pid", ""), item.get("name", ""), item.get("criticality_score", ""), item.get("rationale", "")]
            for c, value in enumerate(values):
                self.enterprise_assets_table.setItem(r, c, QTableWidgetItem(str(value)))
            sev = "critical" if float(item.get("criticality_score", 0) or 0) >= 85 else "medium"
            self._paint_row(self.enterprise_assets_table, r, self._severity_color(sev))
        rules = detections.get("rules", [])
        self.enterprise_detections_table.setRowCount(len(rules))
        for r, item in enumerate(rules):
            values = [item.get("rule_id", ""), item.get("version", ""), item.get("status", ""), item.get("notes", "")]
            for c, value in enumerate(values):
                self.enterprise_detections_table.setItem(r, c, QTableWidgetItem(str(value)))
        story = {
            "title": "Enterprise triage narrative",
            "severity": "medium",
            "attack_chain": ["prioritize", "investigate", "approve", "contain"],
        }
        try:
            story = self._get("/incidents", timeout=8).json()[0]
        except Exception:
            pass
        self.enterprise_narrative.setHtml(
            "<h3>Progressive Disclosure</h3>"
            f"<p><b>Summary:</b> {html.escape(str(story.get('title', 'Prioritize high-criticality assets and pending approvals.')))}</p>"
            f"<p><b>Severity:</b> {html.escape(str(story.get('severity', 'medium')))}"
            f"<br><b>Attack chain:</b> {html.escape(', '.join(story.get('attack_chain', [])) if isinstance(story.get('attack_chain', []), list) else str(story.get('attack_chain', 'ready')))}</p>"
            "<p><b>Raw detail:</b> use the left-side tables, case board, and notification inbox for operational depth. Run <b>Replay Artifact</b> only when you explicitly want replay analysis.</p>"
        )
        self.enterprise_mitre_summary.setHtml(self._render_enterprise_mitre_summary(mitre_status, mitre_summary, mitre_compare, mitre_discover))
        self._show_json(self.enterprise_detail, {"triage": triage, "assets": assets, "detections": detections, "mitre_status": mitre_status, "mitre_summary": mitre_summary, "mitre_discover": mitre_discover, "mitre_compare": mitre_compare, "story": story})
        if cases:
            selected_row = next((idx for idx, item in enumerate(cases) if int(item.get("id", 0) or 0) == preferred_case_id), 0)
            self.enterprise_cases_table.selectRow(selected_row)
            self.load_selected_case_board()
            self.enterprise_loaded_once = True
            self.enterprise_live_status.setText(f"Live sync updated {time.strftime('%H:%M:%S')}")
        else:
            self._clear_enterprise_case_views()
            self.enterprise_warning_banner.setText("No enterprise cases yet. Create a case to start the investigation workflow.")
            self.enterprise_live_status.setText("Live sync idle - no active cases")

    def create_enterprise_case(self) -> None:
        payload = {
            "title": self.enterprise_case_title.text().strip() or "Suspicious activity case",
            "owner": self.enterprise_case_owner.text().strip(),
            "priority": self.enterprise_case_priority.currentText(),
            "narrative": "Created from the enterprise triage-first workflow.",
            "asset_criticality": 75,
        }
        try:
            result = self._post("/enterprise/cases", json=payload, timeout=30).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Create case failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.refresh_enterprise_workspace()

    def _selected_enterprise_case_id(self) -> int | None:
        row = self.enterprise_cases_table.currentRow()
        if row < 0:
            return None
        item = self.enterprise_cases_table.item(row, 0)
        if item is None:
            return None
        try:
            return int(item.text())
        except Exception:
            return None

    def _on_enterprise_case_selection_changed(self) -> None:
        self.enterprise_selected_case_id = self._selected_enterprise_case_id()
        self._persist_enterprise_ui_state()
        self.load_selected_case_board()

    def _selected_enterprise_task_id(self) -> int | None:
        case_id = self._selected_enterprise_case_id()
        row = self.enterprise_tasks_table.currentRow()
        if case_id is None or row < 0:
            return None
        tasks = getattr(self, "enterprise_filtered_tasks_data", getattr(self, "enterprise_tasks_data", []))
        if row >= len(tasks):
            return None
        try:
            return int(tasks[row].get("id", 0) or 0)
        except Exception:
            return None

    def load_selected_case_board(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self._clear_enterprise_case_views()
            return
        self.enterprise_live_status.setText(f"Loading case {case_id}...")
        try:
            board = self._get(f"/enterprise/cases/{case_id}/board", timeout=20).json()
            assignments = self._get(f"/enterprise/cases/{case_id}/assignments", timeout=20).json()
            tasks = self._get(f"/enterprise/cases/{case_id}/tasks", timeout=20).json()
            activity = self._get(f"/enterprise/cases/{case_id}/activity", timeout=20).json()
            notes = self._get("/enterprise/investigations/notes", params={"case_id": case_id}, timeout=20).json()
            stories = self._get("/enterprise/investigations/stories", params={"case_id": case_id}, timeout=20).json()
            mitre = self._get(f"/enterprise/cases/{case_id}/mitre", timeout=20).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Case board load failed", exc)
            self.enterprise_live_status.setText("Live sync failed")
            return
        self.enterprise_case_board_data = board
        self.enterprise_assignments_data = assignments
        self.enterprise_tasks_data = tasks
        self.enterprise_activity_data = activity
        self.enterprise_notes_data = notes
        self.enterprise_stories_data = stories
        self.enterprise_case_mitre_data = mitre
        queue = board.get("queue", {}) if isinstance(board, dict) else {}
        kpis = board.get("kpis", {}) if isinstance(board, dict) else {}
        self.enterprise_timeline_data = board.get("timeline", []) if isinstance(board.get("timeline", []), list) else []
        entity_links = board.get("entity_links", {}) if isinstance(board.get("entity_links", {}), dict) else {}
        self.enterprise_entity_links_data = entity_links.get("items", []) if isinstance(entity_links.get("items", []), list) else []
        self.enterprise_notifications_data = self._build_enterprise_notifications(case_id, queue, kpis, tasks, activity)
        next_steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in board.get("recommended_next_steps", []))
        self.enterprise_case_board.setHtml(
            "<h3>Case Board</h3>"
            f"<p><b>Open tasks:</b> {queue.get('open_tasks', 0)}"
            f"<br><b>Overdue tasks:</b> {queue.get('overdue_tasks', 0)}"
            f"<br><b>Pins:</b> {queue.get('pinned', 0)}"
            f"<br><b>Stories:</b> {queue.get('stories', 0)}</p>"
            f"<p><b>KPI summary:</b> {html.escape(json.dumps(kpis))}"
            f"<br><b>Linked entities:</b> {len(self.enterprise_entity_links_data)}</p>"
            f"<h4>Next Steps</h4><ul>{next_steps or '<li>No recommended next steps.</li>'}</ul>"
        )
        self.enterprise_case_mitre.setHtml(self._render_enterprise_case_mitre(mitre))
        self._set_metric_label(self.enterprise_overdue_value, str(queue.get("overdue_tasks", 0)))
        self._set_metric_label(self.enterprise_assignments_value, str(queue.get("assignments", 0)))
        self._apply_enterprise_filters()
        warnings: list[str] = []
        if int(queue.get("overdue_tasks", 0) or 0) > 0:
            warnings.append(f"{queue.get('overdue_tasks', 0)} overdue tasks")
        if int(queue.get("open_tasks", 0) or 0) > 6:
            warnings.append(f"{queue.get('open_tasks', 0)} open tasks")
        if int(kpis.get("high_or_critical_events", 0) or 0) > 0:
            warnings.append(f"{kpis.get('high_or_critical_events', 0)} high-risk events")
        warning_text = " | ".join(warnings) if warnings else "No urgent warnings for the selected case."
        if self.enterprise_notifications_data:
            warning_text = f"{warning_text} | Inbox: {len(self.enterprise_notifications_data)} items"
        self.enterprise_warning_banner.setText(warning_text)
        self.load_enterprise_case_graph(board=board)
        self._refresh_enterprise_kpi_chart(queue, kpis, len(notes), len(stories))
        self._refresh_enterprise_timeline_table()
        self._refresh_enterprise_entity_links_table()
        self.enterprise_live_status.setText(f"Live sync updated {time.strftime('%H:%M:%S')}")
        self._show_json(self.enterprise_detail, {"board": board, "assignments": assignments, "tasks": tasks, "activity": activity, "notes": notes, "stories": stories, "mitre": mitre, "notifications": self.enterprise_notifications_data})

    def _clear_enterprise_case_views(self) -> None:
        self.enterprise_case_board.setHtml(
            "<h3>Case Board</h3><p>No case selected yet. Pick a case on the left or create a new one.</p>"
        )
        self.enterprise_mitre_summary.setHtml(
            "<h3>ATT&CK Coverage</h3><p>Load a MITRE ATT&CK bundle to see enterprise coverage, tactics, mitigations, and software overlap.</p>"
        )
        self.enterprise_case_mitre.setHtml(
            "<h3>Case ATT&CK</h3><p>Select a case to review mapped techniques, mitigations, and actor context.</p>"
        )
        self.enterprise_graph_summary.setHtml(
            "<h3>Case Correlation View</h3><p>No active case context yet.</p>"
        )
        self.enterprise_narrative.setHtml(
            "<h3>Progressive Disclosure</h3><p>No case narrative yet. Once a case is selected, the analyst story will appear here.</p>"
        )
        self.enterprise_detail.setPlainText("No case selected.")
        self.enterprise_timeline_data = []
        self.enterprise_entity_links_data = []
        self.enterprise_notifications_data = []
        self.enterprise_assignments_data = []
        self.enterprise_tasks_data = []
        self.enterprise_activity_data = []
        self.enterprise_notes_data = []
        self.enterprise_stories_data = []
        self.enterprise_case_mitre_data = {}
        self.enterprise_graph_focus.setRowCount(0)
        self.enterprise_assignments_table.setRowCount(0)
        self.enterprise_tasks_table.setRowCount(0)
        self.enterprise_activity_table.setRowCount(0)
        self.enterprise_notes_table.setRowCount(0)
        self.enterprise_stories_table.setRowCount(0)
        self.enterprise_notifications_table.setRowCount(0)
        self.enterprise_case_timeline.setRowCount(0)
        self.enterprise_entity_links.setRowCount(0)

    def _render_enterprise_mitre_summary(self, status: dict[str, Any], summary: dict[str, Any], compare: dict[str, Any], discover: list[dict[str, Any]]) -> str:
        loaded = bool(status.get("loaded"))
        top_tactics = "".join(
            f"<li>{html.escape(str(item.get('name', '')))}: {html.escape(str(item.get('count', 0)))}</li>"
            for item in summary.get("top_tactics", [])[:6]
        )
        top_techniques = "".join(
            f"<li>{html.escape(str(item.get('technique_id', '')))} - {html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>"
            for item in summary.get("top_mapped_techniques", [])[:6]
        )
        tactic_heat = "".join(
            f"<li>{html.escape(str(item.get('name', '')))} score {html.escape(str(item.get('score', 0)))}</li>"
            for item in summary.get("tactic_heat", [])[:6]
        )
        discovered_html = "".join(
            f"<li>{html.escape(Path(str(item.get('path', ''))).name)}"
            f" | v{html.escape(str(item.get('version', 'unknown')))}"
            f" | techniques {html.escape(str(item.get('technique_count', 0)))}</li>"
            for item in discover[:5]
        )
        diff_html = "".join(
            f"<li>{html.escape(str(item.get('technique_id', '')))} updated to {html.escape(str(item.get('candidate_modified', '')))}</li>"
            for item in compare.get("modified_techniques", [])[:5]
        )
        bundle_path = html.escape(str(status.get("bundle_path", "") or ""))
        return (
            "<h3>ATT&CK Enterprise Coverage</h3>"
            f"<p><b>Bundle loaded:</b> {'yes' if loaded else 'no'}"
            f"<br><b>Techniques indexed:</b> {html.escape(str(status.get('technique_count', 0)))}"
            f"<br><b>Tactics indexed:</b> {html.escape(str(status.get('tactic_count', 0)))}"
            f"<br><b>Recent incidents reviewed:</b> {html.escape(str(summary.get('recent_incident_count', 0)))}</p>"
            f"<p><b>Bundle path:</b> {bundle_path or 'not loaded'}</p>"
            f"<h4>Top Tactics</h4><ul>{top_tactics or '<li>No mapped tactics yet.</li>'}</ul>"
            f"<h4>Top Techniques</h4><ul>{top_techniques or '<li>No mapped techniques yet.</li>'}</ul>"
            f"<h4>Tactic Heat</h4><ul>{tactic_heat or '<li>No tactic heat yet.</li>'}</ul>"
            f"<h4>Lifecycle Diff</h4><ul>{diff_html or '<li>No bundle diff found for the selected path.</li>'}</ul>"
            f"<h4>Known Bundles</h4><ul>{discovered_html or '<li>No ATT&CK bundles discovered.</li>'}</ul>"
        )

    def _render_enterprise_case_mitre(self, coverage: dict[str, Any]) -> str:
        summary = coverage.get("coverage_summary", {}) if isinstance(coverage, dict) else {}
        techniques = coverage.get("techniques", []) if isinstance(coverage.get("techniques", []), list) else []
        technique_rows = "".join(
            f"<li>{html.escape(str(item.get('attack_id', '')))} - {html.escape(str(item.get('name', '')))}"
            f" | tactics: {html.escape(', '.join(item.get('tactics', [])) if isinstance(item.get('tactics', []), list) else '')}</li>"
            for item in techniques[:8]
        )
        mitigations = "".join(
            f"<li>{html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>"
            for item in summary.get("top_mitigations", [])[:5]
        )
        software = "".join(
            f"<li>{html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>"
            for item in summary.get("top_software", [])[:5]
        )
        rollup = "".join(
            f"<li>{html.escape(str(item.get('attack_id', '')))} ({html.escape(str(item.get('count', 0)))})</li>"
            for item in summary.get("parent_technique_rollup", [])[:5]
        )
        cues = "".join(
            f"<li>{html.escape(str(item.get('cue', '')))} ({html.escape(str(item.get('count', 0)))})</li>"
            for item in summary.get("telemetry_cue_hotspots", [])[:6]
        )
        return (
            "<h3>Case ATT&CK</h3>"
            f"<p><b>Incident scope:</b> {html.escape(', '.join(coverage.get('incident_ids', [])) if isinstance(coverage.get('incident_ids', []), list) else '')}"
            f"<br><b>Mapped techniques:</b> {html.escape(str(summary.get('technique_count', 0)))}"
            f"<br><b>Sub-techniques:</b> {html.escape(str(summary.get('subtechnique_count', 0)))}"
            f"<br><b>Tactic progression:</b> {html.escape(' -> '.join(summary.get('tactic_progression', [])) if isinstance(summary.get('tactic_progression', []), list) else '')}</p>"
            f"<h4>Observed Techniques</h4><ul>{technique_rows or '<li>No ATT&CK techniques mapped yet.</li>'}</ul>"
            f"<h4>Top Mitigations</h4><ul>{mitigations or '<li>No mitigations linked yet.</li>'}</ul>"
            f"<h4>Top Software</h4><ul>{software or '<li>No software overlap yet.</li>'}</ul>"
            f"<h4>Parent Rollup</h4><ul>{rollup or '<li>No parent/sub-technique rollup yet.</li>'}</ul>"
            f"<h4>Telemetry Cues</h4><ul>{cues or '<li>No telemetry cues captured yet.</li>'}</ul>"
        )

    def export_enterprise_mitre_layer(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        payload = {
            "case_id": case_id,
            "layer_name": f"ShadowLab Case {case_id} ATT&CK Coverage",
            "description": "Navigator layer exported from the enterprise investigation workspace.",
        }
        try:
            result = self._post("/enterprise/mitre/navigator/export", json=payload, timeout=45).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "ATT&CK layer export failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        saved_path = str(result.get("saved_path", "") or "")
        if saved_path:
            self.statusBar().showMessage(f"Navigator layer exported to {saved_path}")

    def export_enterprise_mitre_workbench(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        try:
            result = self._post("/enterprise/mitre/workbench/export", json={"case_id": case_id}, timeout=45).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Workbench export failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        saved_path = str(result.get("saved_path", "") or "")
        if saved_path:
            self.statusBar().showMessage(f"Workbench coverage exported to {saved_path}")

    def _refresh_enterprise_kpi_chart(self, queue: dict, kpis: dict, note_count: int, story_count: int) -> None:
        load_set = QBarSet("Load")
        load_set.setColor(QColor("#8ec5ff"))
        load_values = [
            float(queue.get("open_tasks", 0) or 0),
            float(queue.get("overdue_tasks", 0) or 0),
            float(note_count or 0),
            float(story_count or 0),
            float(kpis.get("high_or_critical_events", 0) or 0),
        ]
        for value in load_values:
            load_set.append(value)
        trend_series = QLineSeries()
        trend_series.setColor(QColor("#ffd166"))
        for idx, value in enumerate(load_values):
            trend_series.append(idx, value)
        bar_series = QBarSeries()
        bar_series.append(load_set)
        chart = QChart()
        chart.setBackgroundVisible(False)
        chart.legend().setLabelColor(QColor("#96a5b8"))
        chart.addSeries(bar_series)
        chart.addSeries(trend_series)
        axis_x = QBarCategoryAxis()
        axis_x.append(["Open", "Overdue", "Notes", "Stories", "HighRisk"])
        axis_y = QValueAxis()
        axis_y.setRange(0, max(5, max(load_values) + 1 if load_values else 5))
        axis_y.setTickCount(6)
        axis_y.setGridLineColor(QColor("#243446"))
        axis_y.setLabelsColor(QColor("#96a5b8"))
        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        bar_series.attachAxis(axis_x)
        bar_series.attachAxis(axis_y)
        trend_series.attachAxis(axis_x)
        trend_series.attachAxis(axis_y)
        chart.setTitle("Case Load and Evidence Snapshot")
        chart.setTitleBrush(QBrush(QColor("#eef4fb")))
        self.enterprise_kpi_chart.setChart(chart)

    def _show_enterprise_cached_item(self, cache_name: str, table: QTableWidget) -> None:
        row = table.currentRow()
        if row < 0:
            return
        items = getattr(self, cache_name, [])
        if row >= len(items):
            return
        self._show_json(self.enterprise_detail, items[row])

    def show_selected_enterprise_assignment(self) -> None:
        self._show_enterprise_cached_item("enterprise_assignments_data", self.enterprise_assignments_table)

    def show_selected_enterprise_task(self) -> None:
        self._show_enterprise_cached_item("enterprise_tasks_data", self.enterprise_tasks_table)

    def show_selected_enterprise_activity(self) -> None:
        self._show_enterprise_cached_item("enterprise_activity_data", self.enterprise_activity_table)

    def show_selected_enterprise_notification(self) -> None:
        self._show_enterprise_cached_item("enterprise_notifications_data", self.enterprise_notifications_table)

    def show_selected_enterprise_timeline(self) -> None:
        self._show_enterprise_cached_item("enterprise_timeline_data", self.enterprise_case_timeline)

    def show_selected_enterprise_link(self) -> None:
        self._show_enterprise_cached_item("enterprise_entity_links_data", self.enterprise_entity_links)

    def show_selected_enterprise_note(self) -> None:
        self._show_enterprise_cached_item("enterprise_notes_data", self.enterprise_notes_table)

    def show_selected_enterprise_story(self) -> None:
        self._show_enterprise_cached_item("enterprise_stories_data", self.enterprise_stories_table)

    def _populate_enterprise_cases_table(self, cases: list[dict]) -> None:
        self.enterprise_cases_table.blockSignals(True)
        self.enterprise_cases_table.setRowCount(len(cases))
        for r, item in enumerate(cases):
            values = [item.get("id", ""), item.get("title", ""), item.get("priority", ""), item.get("stage", ""), item.get("owner", ""), item.get("status", "")]
            for c, value in enumerate(values):
                self.enterprise_cases_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.enterprise_cases_table, r, self._severity_color(item.get("priority", "")))
        self.enterprise_cases_table.blockSignals(False)

    def _apply_enterprise_filters(self) -> None:
        self._enterprise_table_updating = True
        case_filter = self.enterprise_case_filter.text().strip().lower() if hasattr(self, "enterprise_case_filter") else ""
        task_filter = self.enterprise_task_filter.text().strip().lower() if hasattr(self, "enterprise_task_filter") else ""
        activity_filter = self.enterprise_activity_filter.text().strip().lower() if hasattr(self, "enterprise_activity_filter") else ""

        filtered_cases = [
            item for item in getattr(self, "enterprise_cases_data", [])
            if not case_filter or case_filter in json.dumps(item).lower()
        ]
        self._populate_enterprise_cases_table(filtered_cases)
        self.enterprise_filtered_cases_data = filtered_cases

        assignments = getattr(self, "enterprise_assignments_data", [])
        self.enterprise_assignments_table.setRowCount(len(assignments))
        for r, item in enumerate(assignments):
            values = [item.get("analyst", ""), item.get("role", ""), item.get("status", ""), item.get("assigned_by", "")]
            for c, value in enumerate(values):
                self.enterprise_assignments_table.setItem(r, c, QTableWidgetItem(str(value)))

        notes = [
            item for item in getattr(self, "enterprise_notes_data", [])
            if not activity_filter or activity_filter in json.dumps(item).lower()
        ]
        self.enterprise_notes_table.setRowCount(len(notes))
        for r, item in enumerate(notes):
            values = [item.get("author", ""), item.get("item_type", ""), item.get("note_text", "")]
            for c, value in enumerate(values):
                self.enterprise_notes_table.setItem(r, c, QTableWidgetItem(str(value)))

        stories = [
            item for item in getattr(self, "enterprise_stories_data", [])
            if not activity_filter or activity_filter in json.dumps(item).lower()
        ]
        self.enterprise_stories_table.setRowCount(len(stories))
        for r, item in enumerate(stories):
            values = [item.get("title", ""), item.get("confidence", ""), item.get("created_by", "")]
            for c, value in enumerate(values):
                self.enterprise_stories_table.setItem(r, c, QTableWidgetItem(str(value)))

        tasks = [
            item for item in getattr(self, "enterprise_tasks_data", [])
            if not task_filter or task_filter in json.dumps(item).lower()
        ]
        self.enterprise_filtered_tasks_data = tasks
        self.enterprise_tasks_table.blockSignals(True)
        self.enterprise_tasks_table.setRowCount(len(tasks))
        for r, item in enumerate(tasks):
            values = [item.get("title", ""), item.get("status", ""), item.get("priority", ""), item.get("assigned_to", "")]
            for c, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, int(item.get("id", 0) or 0))
                if c == 0:
                    cell.setFlags(cell.flags() & ~Qt.ItemIsEditable)
                self.enterprise_tasks_table.setItem(r, c, cell)
            due_at = float(item.get("due_at", 0) or 0)
            is_overdue = due_at > 0 and due_at < time.time() and str(item.get("status", "")).lower() not in {"done", "closed"}
            sev = "high" if is_overdue else item.get("priority", "")
            self._paint_row(self.enterprise_tasks_table, r, self._severity_color(str(sev)))
        self.enterprise_tasks_table.blockSignals(False)

        activity = [
            item for item in getattr(self, "enterprise_activity_data", [])
            if not activity_filter or activity_filter in json.dumps(item).lower()
        ]
        self.enterprise_activity_table.setRowCount(len(activity))
        for r, item in enumerate(activity):
            values = [item.get("created_at", ""), item.get("event_type", ""), item.get("actor", ""), item.get("summary", "")]
            for c, value in enumerate(values):
                self.enterprise_activity_table.setItem(r, c, QTableWidgetItem(str(value)))
        notifications = [
            item for item in getattr(self, "enterprise_notifications_data", [])
            if not activity_filter or activity_filter in json.dumps(item).lower()
        ]
        self.enterprise_notifications_table.setRowCount(len(notifications))
        for r, item in enumerate(notifications):
            values = [item.get("created_at", ""), item.get("severity", ""), item.get("category", ""), item.get("message", "")]
            for c, value in enumerate(values):
                self.enterprise_notifications_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.enterprise_notifications_table, r, self._severity_color(str(item.get("severity", "low"))))
        self._enterprise_table_updating = False
        self._persist_enterprise_ui_state()

    def _refresh_enterprise_timeline_table(self) -> None:
        timeline = getattr(self, "enterprise_timeline_data", [])
        self.enterprise_case_timeline.setRowCount(len(timeline))
        for r, item in enumerate(timeline):
            values = [item.get("time", ""), item.get("kind", ""), item.get("severity", ""), item.get("title", "")]
            for c, value in enumerate(values):
                self.enterprise_case_timeline.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.enterprise_case_timeline, r, self._severity_color(str(item.get("severity", "low"))))

    def _refresh_enterprise_entity_links_table(self) -> None:
        links = getattr(self, "enterprise_entity_links_data", [])
        self.enterprise_entity_links.setRowCount(len(links))
        for r, item in enumerate(links):
            values = [item.get("entity", ""), item.get("kind", ""), item.get("evidence_count", ""), ", ".join(item.get("examples", [])[:2])]
            for c, value in enumerate(values):
                self.enterprise_entity_links.setItem(r, c, QTableWidgetItem(str(value)))

    def _build_enterprise_notifications(self, case_id: int, queue: dict, kpis: dict, tasks: list[dict], activity: list[dict]) -> list[dict]:
        notifications: list[dict] = []
        now = time.time()
        if int(queue.get("overdue_tasks", 0) or 0) > 0:
            notifications.append(
                {
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                    "severity": "high",
                    "category": "task",
                    "message": f"{queue.get('overdue_tasks', 0)} overdue tasks require action.",
                    "case_id": case_id,
                }
            )
        if int(kpis.get("high_or_critical_events", 0) or 0) > 0:
            notifications.append(
                {
                    "created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
                    "severity": "high",
                    "category": "risk",
                    "message": f"{kpis.get('high_or_critical_events', 0)} high-risk events are tied to this case.",
                    "case_id": case_id,
                }
            )
        for task in tasks[:8]:
            due_at = float(task.get("due_at", 0) or 0)
            status = str(task.get("status", "")).lower()
            if due_at > 0 and due_at < now and status not in {"done", "closed", "resolved"}:
                notifications.append(
                    {
                        "created_at": task.get("updated_at", "") or task.get("created_at", ""),
                        "severity": "medium",
                        "category": "task",
                        "message": f"Task overdue: {task.get('title', 'task')}",
                        "task_id": task.get("id", ""),
                        "case_id": case_id,
                    }
                )
        for item in activity[:12]:
            event_type = str(item.get("event_type", "")).lower()
            severity = "low"
            if "approval" in event_type:
                severity = "medium"
            if event_type in {"task_updated", "task_created"}:
                severity = "medium"
            if event_type in {"case_created"}:
                severity = "low"
            notifications.append(
                {
                    "created_at": item.get("created_at", ""),
                    "severity": severity,
                    "category": event_type or "activity",
                    "message": str(item.get("summary", "") or event_type),
                    "actor": item.get("actor", ""),
                    "case_id": case_id,
                }
            )
        notifications.sort(key=lambda entry: str(entry.get("created_at", "")), reverse=True)
        return notifications[:20]

    def _inline_update_enterprise_task(self, item: QTableWidgetItem) -> None:
        if self._enterprise_table_updating or item is None:
            return
        row = item.row()
        column = item.column()
        if row < 0 or column not in {1, 2, 3}:
            return
        case_id = self._selected_enterprise_case_id()
        task_id = self._safe_int(item.data(Qt.UserRole))
        tasks = getattr(self, "enterprise_filtered_tasks_data", getattr(self, "enterprise_tasks_data", []))
        if case_id is None or task_id is None or row >= len(tasks):
            return
        original = tasks[row]
        payload: dict[str, object] = {}
        value = item.text().strip()
        if column == 1 and value and value != str(original.get("status", "")):
            payload["status"] = value
        elif column == 2 and value and value != str(original.get("priority", "")):
            payload["priority"] = value
        elif column == 3 and value != str(original.get("assigned_to", "")):
            payload["assigned_to"] = value
        if not payload:
            return
        try:
            result = self._patch(f"/enterprise/cases/{case_id}/tasks/{task_id}", json=payload, timeout=20).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Inline task update failed", exc)
            self._enterprise_table_updating = True
            self.enterprise_tasks_table.blockSignals(True)
            self.enterprise_tasks_table.item(row, column).setText(str(original.get({1: 'status', 2: 'priority', 3: 'assigned_to'}[column], "")))
            self.enterprise_tasks_table.blockSignals(False)
            self._enterprise_table_updating = False
            return
        self.statusBar().showMessage(f"Task {task_id} updated inline.")
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def load_enterprise_case_graph(self, checked: bool = False, board: dict | None = None) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            return
        board_data = board or getattr(self, "enterprise_case_board_data", {})
        try:
            graph = self._get(f"/enterprise/cases/{case_id}/graph", timeout=30).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Graph correlation load failed", exc)
            return
        summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
        findings = graph.get("priority_findings", []) if isinstance(graph.get("priority_findings", []), list) else []
        case_scope = graph.get("case_context", {}) if isinstance(graph.get("case_context", {}), dict) else {}
        top_processes = summary.get("top_processes", []) if isinstance(summary.get("top_processes", []), list) else []
        focus_items = board_data.get("focus_items", []) if isinstance(board_data, dict) else []
        focus_titles = [str(item.get("title", "")).lower() for item in focus_items if isinstance(item, dict)]
        matched_processes = [
            proc for proc in top_processes
            if any(token and token in str(proc.get("name", "")).lower() for token in focus_titles)
        ]
        display_processes = matched_processes or top_processes[:8]
        exposure = summary.get("remote_exposure", {}) if isinstance(summary.get("remote_exposure", {}), dict) else {}
        self.enterprise_graph_summary.setHtml(
            "<h3>Case Correlation View</h3>"
            f"<p><b>Case ID:</b> {case_id}"
            f"<br><b>Overall Graph Risk:</b> {html.escape(str(summary.get('overall_risk', 0)))}"
            f"<br><b>Exposure:</b> {html.escape(json.dumps(exposure))}"
            f"<br><b>Matched Focus Processes:</b> {len(matched_processes)}"
            f"<br><b>Focus PID Count:</b> {html.escape(str(case_scope.get('focus_pid_count', 0)))}"
            f"<br><b>Scoped Notes / Pins:</b> {html.escape(str(case_scope.get('notes', 0)))} / {html.escape(str(case_scope.get('pins', 0)))}</p>"
            f"<p><b>Priority Findings:</b></p><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in findings[:5]) or '<li>No graph findings.</li>'}</ul>"
        )
        self.enterprise_graph_focus.setRowCount(len(display_processes))
        for r, item in enumerate(display_processes):
            values = [item.get("name", ""), item.get("pid", ""), item.get("risk_score", ""), item.get("signature_status", "")]
            for c, value in enumerate(values):
                self.enterprise_graph_focus.setItem(r, c, QTableWidgetItem(str(value)))
            risk_value = float(item.get("risk_score", 0) or 0)
            self._paint_row(self.enterprise_graph_focus, r, self._severity_color("high" if risk_value >= 75 else "medium" if risk_value >= 45 else "low"))

    def assign_enterprise_case(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        analyst, ok = QInputDialog.getText(self, "Assign Analyst", "Analyst:")
        if not ok or not analyst.strip():
            return
        try:
            result = self._post(
                f"/enterprise/cases/{case_id}/assignments",
                json={"analyst": analyst.strip(), "role": "owner", "assigned_by": self.enterprise_case_owner.text().strip() or "desktop"},
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Assign analyst failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def create_enterprise_task(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        title, ok = QInputDialog.getText(self, "Create Task", "Task title:")
        if not ok or not title.strip():
            return
        try:
            result = self._post(
                f"/enterprise/cases/{case_id}/tasks",
                json={"title": title.strip(), "assigned_to": self.enterprise_case_owner.text().strip(), "created_by": "desktop"},
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Create task failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def update_enterprise_task_status(self, forced_status: str | None = None) -> None:
        case_id = self._selected_enterprise_case_id()
        task_id = self._selected_enterprise_task_id()
        if case_id is None or task_id is None:
            self.statusBar().showMessage("Select a case and a task first")
            return
        status = forced_status
        if not status:
            status, ok = QInputDialog.getItem(self, "Update Task Status", "Status:", ["todo", "in_progress", "blocked", "done"], 1, False)
            if not ok or not status:
                return
        try:
            result = self._patch(
                f"/enterprise/cases/{case_id}/tasks/{task_id}",
                json={"status": status},
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Task update failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def add_enterprise_note(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        note_text, ok = QInputDialog.getMultiLineText(self, "Add Note", "Analyst note:")
        if not ok or not note_text.strip():
            return
        try:
            result = self._post(
                "/enterprise/investigations/notes",
                json={
                    "case_id": case_id,
                    "note_text": note_text.strip(),
                    "item_type": "case",
                    "item_title": self.enterprise_case_title.text().strip() or "case note",
                    "author": self.enterprise_case_owner.text().strip() or "desktop",
                },
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Add note failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def add_enterprise_story(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        title, ok = QInputDialog.getText(self, "Add Story", "Story title:")
        if not ok or not title.strip():
            return
        hypothesis, ok = QInputDialog.getMultiLineText(self, "Add Story", "Hypothesis:")
        if not ok:
            return
        try:
            result = self._post(
                "/enterprise/investigations/stories",
                json={
                    "case_id": case_id,
                    "title": title.strip(),
                    "hypothesis": hypothesis.strip(),
                    "summary": "Created from desktop enterprise workflow.",
                    "confidence": "medium",
                    "created_by": self.enterprise_case_owner.text().strip() or "desktop",
                },
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Add story failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def pin_enterprise_event(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        title = ""
        item_type = "case"
        severity = "medium"
        timeline_row = self.timeline_table.currentRow() if hasattr(self, "timeline_table") else -1
        timeline_items = getattr(self, "timeline_items", [])
        if timeline_row >= 0 and timeline_row < len(timeline_items):
            item = timeline_items[timeline_row]
            title = str(item.get("title", "") or "")
            item_type = str(item.get("type", "timeline") or "timeline")
            severity = str(item.get("severity", "medium") or "medium")
            item_time = float(item.get("time", 0) or 0)
            payload = item
        else:
            title = self.enterprise_case_title.text().strip() or "Pinned case event"
            item_time = time.time()
            payload = {"source": "desktop"}
        rationale, ok = QInputDialog.getText(self, "Pin Event", "Rationale:")
        if not ok or not rationale.strip():
            return
        try:
            result = self._post(
                "/enterprise/investigations/pins",
                json={
                    "case_id": case_id,
                    "item_time": item_time,
                    "item_type": item_type,
                    "item_title": title,
                    "item_severity": severity,
                    "item_payload": payload,
                    "rationale": rationale.strip(),
                    "pinned_by": self.enterprise_case_owner.text().strip() or "desktop",
                },
                timeout=20,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Pin event failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.load_selected_case_board()

    def export_selected_case_report(self) -> None:
        case_id = self._selected_enterprise_case_id()
        if case_id is None:
            self.statusBar().showMessage("Select a case first")
            return
        try:
            result = self._post(f"/enterprise/cases/{case_id}/investigation-report/export", timeout=45).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Case report export failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        pdf_path = str(result.get("pdf_path", "") or "")
        if pdf_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))

    def load_enterprise_mitre_bundle(self) -> None:
        bundle_path = self.enterprise_mitre_bundle_path.text().strip()
        if not bundle_path:
            self.statusBar().showMessage("Provide an ATT&CK STIX bundle path first")
            return
        try:
            result = self._post(
                "/enterprise/mitre/load-bundle",
                json={"file_path": bundle_path, "source": "desktop"},
                timeout=60,
            ).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "ATT&CK bundle load failed", exc)
            return
        self._show_json(self.enterprise_detail, result)
        self.statusBar().showMessage("ATT&CK bundle loaded")
        self.refresh_enterprise_workspace()

    def request_enterprise_approval(self) -> None:
        row = self.enterprise_cases_table.currentRow()
        if row < 0:
            self.statusBar().showMessage("Select an enterprise case first")
            return
        case_id = int(self.enterprise_cases_table.item(row, 0).text())
        payload = {"case_id": case_id, "action": "containment", "requested_by": self.enterprise_case_owner.text().strip(), "approver": "admin", "reason": "High impact response requires approval."}
        try:
            result = self._post("/enterprise/approvals", json=payload, timeout=30).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Approval request failed", exc)
            return
        approval_value = result.get("approval_id")
        if approval_value is not None:
            self.approval_id.setText(str(approval_value))
            self.statusBar().showMessage(f"Approval {approval_value} created and attached to Primary Controls.")
        self._show_json(self.enterprise_detail, result)

    def run_web_inspection(self) -> None:
        try:
            result = self._get("/enterprise/web/inspection", timeout=45).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Web inspection failed", exc)
            return
        self._show_json(self.enterprise_detail, result)

    def run_enterprise_network_assessment(self) -> None:
        try:
            result = self._post("/enterprise/network/assessment", json={"ip_range": self.enterprise_network_range.text().strip()}, timeout=90).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Network assessment failed", exc)
            return
        self._show_json(self.enterprise_detail, result)

    def run_purple_replay(self) -> None:
        try:
            result = self._post("/enterprise/purple/replay", json={"artifact_path": self.enterprise_replay_path.text().strip()}, timeout=30).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Purple replay failed", exc)
            return
        self._show_json(self.enterprise_detail, result)

    def load_telemetry_gaps(self) -> None:
        try:
            result = self._get("/enterprise/telemetry/gaps", timeout=30).json()
        except Exception as exc:
            self._show_error(self.enterprise_detail, "Telemetry gap analysis failed", exc)
            return
        self._show_json(self.enterprise_detail, result)

    def refresh_security_ops_workspace(self) -> None:
        try:
            report = self._get("/enterprise/report/security-ops", timeout=45).json()
            observability = self._get("/observability/summary", timeout=30).json()
        except Exception as exc:
            self._show_error(self.security_ops_detail, "Security Ops refresh failed", exc)
            return
        integrity = report.get("integrity", {})
        abuse = report.get("abuse", {})
        database = report.get("database", {})
        counts = integrity.get("counts", {}) if isinstance(integrity.get("counts"), dict) else {}
        self.security_ops_summary.setHtml(
            "<h3>Security Ops Posture</h3>"
            f"<p><b>Integrity status:</b> {html.escape(str(integrity.get('status', 'unknown')))}"
            f"<br><b>Signature valid:</b> {html.escape(str(integrity.get('signature_valid', False)))}"
            f"<br><b>Dead letters:</b> {html.escape(str(abuse.get('dead_letters', 0)))}"
            f"<br><b>Observability events:</b> {html.escape(str(observability.get('event_count', 0)))}</p>"
        )
        integrity_rows = [
            ("verified", counts.get("verified", 0)),
            ("modified", counts.get("modified", 0)),
            ("missing", counts.get("missing", 0)),
            ("untracked", counts.get("untracked", 0)),
        ]
        self.security_integrity_table.setRowCount(len(integrity_rows))
        for r, item in enumerate(integrity_rows):
            self.security_integrity_table.setItem(r, 0, QTableWidgetItem(str(item[0])))
            self.security_integrity_table.setItem(r, 1, QTableWidgetItem(str(item[1])))
        platform_rows = [
            ("database backend", ((database.get("database") or {}).get("backend", "unknown") if isinstance(database, dict) else "unknown")),
            ("database mode", ((database.get("database") or {}).get("mode", "unknown") if isinstance(database, dict) else "unknown")),
            ("migrations", len((database.get("migrations") or {}).get("applied", [])) if isinstance(database, dict) else 0),
            ("abuse anomalies", len(abuse.get("anomalies", [])) if isinstance(abuse, dict) else 0),
        ]
        self.security_platform_table.setRowCount(len(platform_rows))
        for r, item in enumerate(platform_rows):
            self.security_platform_table.setItem(r, 0, QTableWidgetItem(str(item[0])))
            self.security_platform_table.setItem(r, 1, QTableWidgetItem(str(item[1])))
        self._show_json(self.security_ops_detail, {"report": report, "observability": observability})

    def refresh_integrity_manifest(self) -> None:
        try:
            result = self._post("/integrity/refresh", timeout=30).json()
        except Exception as exc:
            self._show_error(self.security_ops_detail, "Integrity refresh failed", exc)
            return
        self._show_json(self.security_ops_detail, result)
        self.refresh_security_ops_workspace()

    def rotate_security_secrets(self) -> None:
        try:
            result = self._post("/enterprise/secrets/rotate", json={"rotate_integrity_signing_key": True, "reencrypt_webhook_secret": True, "reencrypt_connector_secrets": True, "clear_alert_webhook": False}, timeout=45).json()
        except Exception as exc:
            self._show_error(self.security_ops_detail, "Secret rotation failed", exc)
            return
        self._show_json(self.security_ops_detail, result)
        self.refresh_security_ops_workspace()

    def clear_alert_webhook_secret(self) -> None:
        try:
            result = self._post("/enterprise/secrets/rotate", json={"rotate_integrity_signing_key": False, "reencrypt_webhook_secret": False, "reencrypt_connector_secrets": False, "clear_alert_webhook": True}, timeout=30).json()
        except Exception as exc:
            self._show_error(self.security_ops_detail, "Webhook clearing failed", exc)
            return
        self.webhook_url.clear()
        self._show_json(self.security_ops_detail, result)
        self.refresh_security_ops_workspace()

    def export_security_ops_report(self) -> None:
        try:
            result = self._post("/enterprise/report/security-ops/export", timeout=45).json()
        except Exception as exc:
            self._show_error(self.security_ops_detail, "Security Ops export failed", exc)
            return
        self._show_json(self.security_ops_detail, result)
        html_path = str(result.get("html_path", "") or "")
        if html_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))

    def _update_cpu_chart(self, rows) -> None:
        self.cpu_series.clear()
        if rows:
            recent = self._sanitize_telemetry_rows(rows[-60:])
            for idx, item in enumerate(recent):
                self.cpu_series.append(idx, float(item.get("cpu", 0) or 0))
            self.cpu_axis_x.setRange(0, max(1, len(recent) - 1))
            max_cpu = max(float(item.get("cpu", 0) or 0) for item in recent)
            self.cpu_axis_y.setRange(0, max(25, min(100, max_cpu + 10)))
            avg_cpu = sum(float(item.get("cpu", 0) or 0) for item in recent) / max(1, len(recent))
            self.cpu_chart.setTitle(f"Telemetry CPU Trend - {len(recent)} samples | avg {avg_cpu:.1f}%")
        else:
            self.cpu_axis_x.setRange(0, 1)
            self.cpu_axis_y.setRange(0, 100)
            self.cpu_chart.setTitle("Telemetry CPU Trend - no telemetry collected yet")

    def _sanitize_telemetry_rows(self, rows) -> list[dict]:
        cleaned: list[dict] = []
        cpu_values: list[float] = []
        for item in rows:
            value = float(item.get("cpu", 0) or 0)
            cpu_values.append(max(0.0, min(100.0, value)))
        for index, item in enumerate(rows):
            value = cpu_values[index]
            if 0 < index < len(cpu_values) - 1:
                prev_value = cpu_values[index - 1]
                next_value = cpu_values[index + 1]
                if value <= 1.0 and prev_value >= 8.0 and next_value >= 8.0:
                    value = (prev_value + next_value) / 2.0
                elif abs(value - prev_value) >= 20 and abs(value - next_value) >= 20 and abs(prev_value - next_value) <= 8:
                    value = (prev_value + next_value) / 2.0
            normalized = dict(item)
            normalized["cpu"] = round(value, 2)
            cleaned.append(normalized)
        return cleaned


def main() -> int:
    app = QApplication(sys.argv)
    window = ShadowLabDesktop()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
