from __future__ import annotations

import html
import json
import sys
import time
from pathlib import Path

from PySide6.QtCore import QMargins, QSettings, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QBrush, QColor, QDesktopServices, QIcon, QKeySequence, QPen, QPixmap, QShortcut
from PySide6.QtCharts import QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtWidgets import (
    QApplication, QAbstractItemView, QBoxLayout, QComboBox, QDoubleSpinBox, QFormLayout, QGridLayout, QHBoxLayout, QLabel,
    QCheckBox, QInputDialog, QLineEdit, QListWidget, QMainWindow, QMessageBox, QMenu, QPushButton, QSpinBox,
    QDialog,
    QFileDialog,
    QFrame, QScrollArea, QSplitter, QSizePolicy, QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QTextEdit,
    QToolButton,
    QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

try:
    from auth_api import ShadowLabApiClient
except ImportError:
    from desktop.auth_api import ShadowLabApiClient
try:
    from integrations_ops import IntegrationsWorkspaceController
except ImportError:
    from desktop.integrations_ops import IntegrationsWorkspaceController
try:
    import artifacts_ops
except ImportError:
    from desktop import artifacts_ops
try:
    from antivirus_ops import AntivirusWorkspaceController
except ImportError:
    from desktop.antivirus_ops import AntivirusWorkspaceController
try:
    from timeline_ops import TimelineWorkspaceController
except ImportError:
    from desktop.timeline_ops import TimelineWorkspaceController
try:
    from enterprise_ops import EnterpriseWorkspaceController
except ImportError:
    from desktop.enterprise_ops import EnterpriseWorkspaceController
try:
    from process_hunt_ops import ProcessHuntWorkspaceController
except ImportError:
    from desktop.process_hunt_ops import ProcessHuntWorkspaceController
try:
    from network_graph_ops import NetworkGraphWorkspaceController
except ImportError:
    from desktop.network_graph_ops import NetworkGraphWorkspaceController
try:
    from history_ops import HistoryWorkspaceController
except ImportError:
    from desktop.history_ops import HistoryWorkspaceController
try:
    from security_ops import SecurityOpsWorkspaceController
except ImportError:
    from desktop.security_ops import SecurityOpsWorkspaceController
try:
    from intel_ops import IntelWorkspaceController
except ImportError:
    from desktop.intel_ops import IntelWorkspaceController
try:
    from dashboard_ops import DashboardWorkspaceController
except ImportError:
    from desktop.dashboard_ops import DashboardWorkspaceController
try:
    from monitor_ops import MonitorWorkspaceController
except ImportError:
    from desktop.monitor_ops import MonitorWorkspaceController
try:
    from shell_ops import DesktopShellController
except ImportError:
    from desktop.shell_ops import DesktopShellController

try:
    import win32cred  # type: ignore
except Exception:
    win32cred = None

# Encrypted-at-rest fallback for the API key when `win32cred` is not
# available (e.g. PyInstaller build with pywin32 stripped, or pre-Windows
# Vista hosts). Uses the same DPAPI-on-Windows / AES-GCM-elsewhere
# helper as the server-side secret store so the operator gets a single
# threat model instead of an "is it on disk in plaintext?" surprise.
try:
    import sys as _sys
    from pathlib import Path as _Path
    # Append rather than insert(0): we want to fall through to the
    # stdlib first so that a stray `json.py` / `ssl.py` / `pathlib.py`
    # dropped at repo root (supply-chain footgun) cannot hijack the
    # import graph for the rest of the process. The desktop modules
    # already importable via the parent path stay reachable because
    # they're imported by absolute name (`services.secret_store`).
    _repo_root = str(_Path(__file__).resolve().parent.parent)
    if _repo_root not in _sys.path:
        _sys.path.append(_repo_root)
    from services.secret_store import secret_store as _secret_store, is_encrypted_secret as _is_encrypted_secret
except Exception:
    _secret_store = None
    _is_encrypted_secret = None


class ShadowLabDesktop(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("ShadowLab")
        # Product-grade window sizing:
        #  * Minimum 1280×760 — below this Antivirus / Network / Enterprise
        #    consoles can't fit their command-bar buttons or KPI strips.
        #    Setting an explicit minimum lets Qt's default chrome decline
        #    a resize that would clip critical controls instead of
        #    silently letting them overflow off-screen.
        #  * Default 1600×960 — comfortable on a 1080p screen, still has
        #    room for the right-hand status badges. Bigger than the old
        #    1900×980 default which forced every screen-share session
        #    into "scrunch the window" mode.
        self.setMinimumSize(1280, 760)
        self.resize(1600, 960)
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
        self.latest_history_telemetry_rows: list[dict] = []
        self.threat_history: list[dict[str, str]] = []
        self.custom_toolbar_buttons: list[dict[str, str]] = []
        self.auth_context: dict = {}
        self.discovered_auth_context: dict = {}
        self.capability_widgets: list[tuple[QWidget, str]] = []
        self.panel_windows: list[QDialog] = []
        self.auth_active = False
        self.auth_session_ready = False
        self.local_role_mode_active = False
        self._enterprise_table_updating = False
        self.enterprise_selected_case_id: int | None = None
        self.enterprise_loaded_once = False
        self.api_client = ShadowLabApiClient(
            base_url_getter=lambda: self.base.text() if hasattr(self, "base") else "http://127.0.0.1:8000",
            api_key_getter=lambda: self.api_key.text() if hasattr(self, "api_key") else "",
            workspace_id_getter=lambda: self.workspace_id.text() if hasattr(self, "workspace_id") else "default",
            actor_getter=lambda: self.actor_name.text() if hasattr(self, "actor_name") else "",
            approval_id_getter=lambda: self.approval_id.text() if hasattr(self, "approval_id") else "",
        )
        self.integrations_controller = IntegrationsWorkspaceController(self)
        self.antivirus_controller = AntivirusWorkspaceController(self)
        self.timeline_controller = TimelineWorkspaceController(self)
        self.enterprise_controller = EnterpriseWorkspaceController(self)
        self.process_hunt_controller = ProcessHuntWorkspaceController(self)
        self.network_graph_controller = NetworkGraphWorkspaceController(self)
        self.history_controller = HistoryWorkspaceController(self)
        self.security_ops_controller = SecurityOpsWorkspaceController(self)
        self.intel_controller = IntelWorkspaceController(self)
        self.dashboard_controller = DashboardWorkspaceController(self)
        self.monitor_controller = MonitorWorkspaceController(self)
        self.shell_controller = DesktopShellController(self)
        self._whids_tab = self.integrations_controller.build_whids_tab
        self._hids_tab = self.integrations_controller.build_hids_tab
        self.refresh_whids_workspace = self.integrations_controller.refresh_whids_workspace
        self.refresh_hids_workspace = self.integrations_controller.refresh_hids_workspace
        self.import_whids_file = self.integrations_controller.import_whids_file
        self.import_whids_manager = self.integrations_controller.import_whids_manager
        self.import_whids_reports = self.integrations_controller.import_whids_reports
        self.import_whids_artifacts = self.integrations_controller.import_whids_artifacts
        self.import_hids_file = self.integrations_controller.import_hids_file
        self.orchestrate_hids_response = self.integrations_controller.orchestrate_hids_response
        self._whids_manager_payload_base = self.integrations_controller.whids_manager_payload_base
        self.load_integration_policy = self.integrations_controller.load_integration_policy
        self.save_integration_policy = self.integrations_controller.save_integration_policy
        self.start_whids_scheduler = self.integrations_controller.start_whids_scheduler
        self.stop_whids_scheduler = self.integrations_controller.stop_whids_scheduler
        self.refresh_whids_scheduler_status = self.integrations_controller.refresh_whids_scheduler_status
        self._parse_json_text = self.integrations_controller.parse_json_text
        self.query_whids_iocs = self.integrations_controller.query_whids_iocs
        self.add_whids_iocs = self.integrations_controller.add_whids_iocs
        self.delete_whids_iocs = self.integrations_controller.delete_whids_iocs
        self.query_whids_rules = self.integrations_controller.query_whids_rules
        self.add_whids_rules = self.integrations_controller.add_whids_rules
        self.delete_whids_rules = self.integrations_controller.delete_whids_rules
        self.start_hids_live_ingest = self.integrations_controller.start_hids_live_ingest
        self.stop_hids_live_ingest = self.integrations_controller.stop_hids_live_ingest
        self.refresh_hids_live_status = self.integrations_controller.refresh_hids_live_status
        self.show_selected_whids_export = self.integrations_controller.show_selected_whids_export
        self.show_selected_hids_export = self.integrations_controller.show_selected_hids_export
        self.open_selected_whids_target = self.integrations_controller.open_selected_whids_target
        self.open_selected_hids_target = self.integrations_controller.open_selected_hids_target
        self._open_local_target = self.integrations_controller.open_local_target
        self.open_enterprise_case_for_incident = self.integrations_controller.open_enterprise_case_for_incident
        self._find_incident_id_in_text = self.integrations_controller.find_incident_id_in_text
        self._enterprise_tab = self.enterprise_controller.build_tab
        self._process_tab = self.process_hunt_controller.build_tab
        self._network_tab = self.network_graph_controller.build_network_tab
        self._hosts_tab = self.network_graph_controller.build_hosts_tab
        self._graph_tab = self.network_graph_controller.build_graph_tab
        self._quarantine_tab = self.history_controller.build_quarantine_tab
        self._history_tab = self.history_controller.build_history_tab
        self._artifacts_tab = self.history_controller.build_artifacts_tab
        self._security_ops_tab = self.security_ops_controller.build_tab
        self._persistence_tab = self.intel_controller.build_persistence_tab
        self._threat_tab = self.intel_controller.build_threat_tab
        self._malware_analyst_tab = self.intel_controller.build_malware_analyst_tab
        self._dashboard_hub_tab = self.dashboard_controller.build_dashboard_tab
        self._overview_tab = self.dashboard_controller.build_overview_tab
        self.refresh_network = self.network_graph_controller.refresh_network
        self.refresh_hosts = self.network_graph_controller.refresh_hosts
        self.refresh_entity_graph = self.network_graph_controller.refresh_entity_graph
        self.refresh_selected_process_graph = self.network_graph_controller.refresh_selected_process_graph
        self.open_entity_graph = self.network_graph_controller.open_entity_graph
        self.scan_network_devices = self.network_graph_controller.scan_network_devices
        self.start_network_blocker = self.network_graph_controller.start_network_blocker
        self.stop_network_blocker = self.network_graph_controller.stop_network_blocker
        self.run_sniffer = self.network_graph_controller.run_sniffer
        self.refresh_history = self.history_controller.refresh_history
        self.show_selected_incident = self.history_controller.show_selected_incident
        self.update_selected_incident = self.history_controller.update_selected_incident
        self.refresh_artifacts = self.history_controller.refresh_artifacts
        self._render_html_source_preview = self.history_controller.render_html_source_preview
        self.refresh_quarantine = self.history_controller.refresh_quarantine
        self.restore_selected_quarantine = self.history_controller.restore_selected_quarantine
        self.delete_selected_quarantine = self.history_controller.delete_selected_quarantine
        self.test_alert_webhook = self.history_controller.test_alert_webhook
        self.save_alert_webhook = self.history_controller.save_alert_webhook
        self.show_selected_artifact = self.history_controller.show_selected_artifact
        self.open_selected_artifact = self.history_controller.open_selected_artifact
        self.refresh_security_ops_workspace = self.security_ops_controller.refresh_security_ops_workspace
        self.refresh_yara_ops_workspace = self.security_ops_controller.refresh_yara_ops_workspace
        self.load_local_yara_policy = self.security_ops_controller.load_local_yara_policy
        self.save_local_yara_policy = self.security_ops_controller.save_local_yara_policy
        self.load_local_yara_errors = self.security_ops_controller.load_local_yara_errors
        self.refresh_integrity_manifest = self.security_ops_controller.refresh_integrity_manifest
        self.rotate_security_secrets = self.security_ops_controller.rotate_security_secrets
        self.clear_alert_webhook_secret = self.security_ops_controller.clear_alert_webhook_secret
        self.export_security_ops_report = self.security_ops_controller.export_security_ops_report
        self.refresh_persistence = self.intel_controller.refresh_persistence
        self.apply_persistence_filter = self.intel_controller.apply_persistence_filter
        self.show_selected_persistence = self.intel_controller.show_selected_persistence
        self.remediate_selected_persistence = self.intel_controller.remediate_selected_persistence
        self.lookup_hash = self.intel_controller.lookup_hash
        self.lookup_ip = self.intel_controller.lookup_ip
        self.use_selected_process_hash = self.intel_controller.use_selected_process_hash
        self.use_selected_process_ip = self.intel_controller.use_selected_process_ip
        self.pick_malware_analyst_file = self.intel_controller.pick_malware_analyst_file
        self.use_selected_process_for_malware_analysis = self.intel_controller.use_selected_process_for_malware_analysis
        self.refresh_malware_analyst_status = self.intel_controller.refresh_malware_analyst_status
        self.run_malware_analyst_file_scan = self.intel_controller.run_malware_analyst_file_scan
        self.run_malware_analyst_process_scan = self.intel_controller.run_malware_analyst_process_scan
        self._render_malware_analyst_result = self.intel_controller.render_malware_analyst_result
        self._record_threat_history = self.intel_controller.record_threat_history
        self._refresh_threat_history_table = self.intel_controller.refresh_threat_history_table
        self.show_selected_threat_history = self.intel_controller.show_selected_threat_history
        self._copy_cpu_chart = self.dashboard_controller.copy_cpu_chart
        self._open_overview_chart_panel = self.dashboard_controller.open_overview_chart_panel
        self._open_overview_brief_panel = self.dashboard_controller.open_overview_brief_panel
        self._open_hunt_tree_panel = self.dashboard_controller.open_hunt_tree_panel
        self._open_hunt_internals_panel = self.dashboard_controller.open_hunt_internals_panel
        self._open_hunt_output_panel = self.dashboard_controller.open_hunt_output_panel
        self._open_threat_history_panel = self.dashboard_controller.open_threat_history_panel
        self._open_threat_output_panel = self.dashboard_controller.open_threat_output_panel
        self._open_dashboard_metrics_panel = self.dashboard_controller.open_dashboard_metrics_panel
        self._open_dashboard_threat_panel = self.dashboard_controller.open_dashboard_threat_panel
        self._open_dashboard_auth_panel = self.dashboard_controller.open_dashboard_auth_panel
        self._open_dashboard_timeline_panel = self.dashboard_controller.open_dashboard_timeline_panel
        self._open_dashboard_actions_panel = self.dashboard_controller.open_dashboard_actions_panel
        self._refresh_dashboard_panels = self.dashboard_controller.refresh_dashboard_panels
        self.refresh_overview = self.monitor_controller.refresh_overview
        self.run_monitor = self.monitor_controller.run_monitor
        self._update_cpu_chart = self.monitor_controller.update_cpu_chart
        self._sanitize_telemetry_rows = self.monitor_controller.sanitize_telemetry_rows
        self.refresh_processes = self.process_hunt_controller.refresh_processes
        self._checked_process_rows = self.process_hunt_controller.checked_process_rows
        self._selected_process_rows = self.process_hunt_controller.selected_process_rows
        self._selected_identity = self.process_hunt_controller.selected_identity
        self._selected_process_or_warn = self.process_hunt_controller.selected_process_or_warn
        self.show_selected_process = self.process_hunt_controller.show_selected_process
        self.process_action = self.process_hunt_controller.process_action
        self.scan_selected_process = self.process_hunt_controller.scan_selected_process
        self._selected_process_ids = self.process_hunt_controller.selected_process_ids
        self._scan_payload = self.process_hunt_controller.scan_payload
        self._scan_process_ids_bulk = self.process_hunt_controller.scan_process_ids_bulk
        self.scan_selected_processes_vt = self.process_hunt_controller.scan_selected_processes_vt
        self.scan_all_processes_vt = self.process_hunt_controller.scan_all_processes_vt
        self.run_memory_analysis = self.process_hunt_controller.run_memory_analysis
        self.load_selected_internals = self.process_hunt_controller.load_selected_internals
        self.run_strings_analysis = self.process_hunt_controller.run_strings_analysis
        self.run_yara_scan = self.process_hunt_controller.run_yara_scan
        self.run_sandbox_trace = self.process_hunt_controller.run_sandbox_trace
        self.load_process_tree = self.process_hunt_controller.load_process_tree
        self.run_ai_analysis = self.process_hunt_controller.run_ai_analysis
        self.run_auto_triage = self.process_hunt_controller.run_auto_triage
        self.run_triage_response = self.process_hunt_controller.run_triage_response
        self.refresh_enterprise_workspace = self.enterprise_controller.refresh_workspace
        self.create_enterprise_case = self.enterprise_controller.create_case
        self._selected_enterprise_case_id = self.enterprise_controller.selected_case_id
        self._on_enterprise_case_selection_changed = self.enterprise_controller.on_case_selection_changed
        self._selected_enterprise_task_id = self.enterprise_controller.selected_task_id
        self.load_selected_case_board = self.enterprise_controller.load_selected_case_board
        self._clear_enterprise_case_views = self.enterprise_controller.clear_case_views
        self._render_enterprise_mitre_summary = self.enterprise_controller.render_mitre_summary
        self._render_enterprise_case_mitre = self.enterprise_controller.render_case_mitre
        self.export_enterprise_mitre_layer = self.enterprise_controller.export_mitre_layer
        self.export_enterprise_mitre_workbench = self.enterprise_controller.export_mitre_workbench
        self._refresh_enterprise_kpi_chart = self.enterprise_controller.refresh_kpi_chart
        self._show_enterprise_cached_item = self.enterprise_controller.show_cached_item
        self.show_selected_enterprise_assignment = self.enterprise_controller.show_selected_assignment
        self.show_selected_enterprise_task = self.enterprise_controller.show_selected_task
        self.show_selected_enterprise_activity = self.enterprise_controller.show_selected_activity
        self.show_selected_enterprise_notification = self.enterprise_controller.show_selected_notification
        self.show_selected_enterprise_timeline = self.enterprise_controller.show_selected_timeline
        self.show_selected_enterprise_link = self.enterprise_controller.show_selected_link
        self.show_selected_enterprise_note = self.enterprise_controller.show_selected_note
        self.show_selected_enterprise_story = self.enterprise_controller.show_selected_story
        self._populate_enterprise_cases_table = self.enterprise_controller.populate_cases_table
        self._apply_enterprise_filters = self.enterprise_controller.apply_filters
        self._refresh_enterprise_timeline_table = self.enterprise_controller.refresh_timeline_table
        self._refresh_enterprise_entity_links_table = self.enterprise_controller.refresh_entity_links_table
        self._build_enterprise_notifications = self.enterprise_controller.build_notifications
        self._inline_update_enterprise_task = self.enterprise_controller.inline_update_task
        self.load_enterprise_case_graph = self.enterprise_controller.load_case_graph
        self.assign_enterprise_case = self.enterprise_controller.assign_case
        self.create_enterprise_task = self.enterprise_controller.create_task
        self.update_enterprise_task_status = self.enterprise_controller.update_task_status
        self.add_enterprise_note = self.enterprise_controller.add_note
        self.add_enterprise_story = self.enterprise_controller.add_story
        self.pin_enterprise_event = self.enterprise_controller.pin_event
        self.export_selected_case_report = self.enterprise_controller.export_selected_case_report
        self.load_enterprise_mitre_bundle = self.enterprise_controller.load_mitre_bundle
        self.request_enterprise_approval = self.enterprise_controller.request_approval
        self.run_web_inspection = self.enterprise_controller.run_web_inspection
        self.run_enterprise_network_assessment = self.enterprise_controller.run_network_assessment
        self.run_purple_replay = self.enterprise_controller.run_purple_replay
        self.load_telemetry_gaps = self.enterprise_controller.load_telemetry_gaps
        self._get = self.shell_controller.get
        self._post = self.shell_controller.post
        self._show_error = self.shell_controller.show_error
        self._show_json = self.shell_controller.show_json
        self._style_table = self.shell_controller.style_table
        self._severity_color = self.shell_controller.severity_color
        self._paint_row = self.shell_controller.paint_row
        self._tab_header = self.shell_controller.tab_header
        self._metric_card = self.shell_controller.metric_card
        self._set_metric_label = self.shell_controller.set_metric_label
        self._switch_to_tab = self.shell_controller.switch_to_tab
        self._json_response = self.shell_controller.json_response
        self._put = self.shell_controller.put
        self._patch = self.shell_controller.patch
        self._delete = self.shell_controller.delete
        self._safe_int = self.shell_controller.safe_int
        self._render_monitor_brief = self.shell_controller.render_monitor_brief
        self._format_yara_summary = self.shell_controller.format_yara_summary
        self._format_triage_summary = self.shell_controller.format_triage_summary
        self._format_response_execution = self.shell_controller.format_response_execution
        self._malware_analyst_runtime_status = self.shell_controller.malware_analyst_runtime_status
        self._integration_rows = self.shell_controller.integration_rows
        self._incident_rows_for_prefix = self.shell_controller.incident_rows_for_prefix
        self._persist_enterprise_ui_state = self.shell_controller.persist_enterprise_ui_state
        self._field_block = self.shell_controller.field_block
        self._scrollable_tab = self.shell_controller.scrollable_tab
        self._timeline_tab = self.shell_controller.build_timeline_tab
        self._antivirus_tab = self.shell_controller.build_antivirus_tab
        # Scenario tab removed - see shell_ops.SCENARIO_PROFILES comment.
        self._about_tab = self.shell_controller.build_about_tab
        self._bind_capability = self.shell_controller.bind_capability
        self.activate_role_mode = self.shell_controller.activate_role_mode
        self.check_api_health = self.shell_controller.check_api_health
        self.toggle_advanced_settings = self.shell_controller.toggle_advanced_settings
        self._update_controls_layout = self.shell_controller.update_controls_layout
        self._update_tab_bar_layout = self.shell_controller.update_tab_bar_layout
        self._on_tab_changed = self.shell_controller.on_tab_changed
        self._auto_refresh_active_tab = self.shell_controller.auto_refresh_active_tab
        self._load_settings = self.shell_controller.load_settings
        self._save_settings = self.shell_controller.save_settings
        self._theme = self.shell_controller.apply_theme
        self._toolbar = self.shell_controller.build_toolbar
        self._rebuild_toolbar = self.shell_controller.rebuild_toolbar
        self._panel_card = self.shell_controller.panel_card
        self._open_panel_window = self.shell_controller.open_panel_window
        self._clone_table = self.shell_controller.clone_table
        self._clone_text_view = self.shell_controller.clone_text_view
        self._enterprise_action_button = self.shell_controller.enterprise_action_button
        self._enterprise_menu_button = self.shell_controller.enterprise_menu_button
        self._style_enterprise_compact_control = self.shell_controller.style_enterprise_compact_control
        self._open_process_table_panel = self.shell_controller.open_process_table_panel
        self._open_process_detail_panel = self.shell_controller.open_process_detail_panel
        self.refresh_timeline = self.shell_controller.refresh_timeline
        self.show_selected_timeline = self.shell_controller.show_selected_timeline
        self.refresh_antivirus_workspace = self.shell_controller.refresh_antivirus_workspace
        self.refresh_antivirus_status = self.shell_controller.refresh_antivirus_status
        self.scan_antivirus_validation_sample = self.shell_controller.scan_antivirus_validation_sample
        self.scan_antivirus_target = self.shell_controller.scan_antivirus_target
        self.scan_antivirus_selected_process = self.shell_controller.scan_antivirus_selected_process
        self.show_selected_antivirus_result = self.shell_controller.show_selected_antivirus_result
        self.quarantine_selected_antivirus_result = self.shell_controller.quarantine_selected_antivirus_result
        self.show_selected_antivirus_quarantine = self.shell_controller.show_selected_antivirus_quarantine
        self.open_selected_antivirus_quarantine = self.shell_controller.open_selected_antivirus_quarantine
        # `run_scenario` removed alongside the Scenario tab.
        self._theme()
        self._toolbar()
        self._ui()
        self.shell_controller.apply_auth_context({"role": "locked", "auth_required": True, "capabilities": {}})
        self.setStatusBar(QStatusBar())
        self.live_refresh_timer = QTimer(self)
        self.live_refresh_timer.setInterval(10000)
        self.live_refresh_timer.timeout.connect(self._auto_refresh_active_tab)
        self.live_refresh_timer.start()
        self.check_api_health()

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
        # Compact product header — logo + product name only. Author
        # credit lives in About / FAQ; an EDR console doesn't carry a
        # vanity tagline in chrome.
        title_logo = QLabel()
        if self.logo_path.exists():
            title_logo.setPixmap(QPixmap(str(self.logo_path)).scaled(36, 36, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        title = QLabel("ShadowLab")
        title.setStyleSheet("font-size:18px;font-weight:700;padding:2px 6px;color:#f4f7fb;")
        hero_row.addWidget(title_logo)
        hero_row.addWidget(title)
        hero_row.addStretch(1)
        self.base = QLineEdit("http://127.0.0.1:8000")
        self.api_key = QLineEdit()
        self.api_key.setEchoMode(QLineEdit.Password)
        self.remember_api_key = QCheckBox("Remember API key on this machine")
        self.api_key.setPlaceholderText("Paste viewer / analyst / admin API key")
        self.api_key.returnPressed.connect(self.activate_role_mode)
        self.activate_role_btn = QPushButton("OK")
        self.activate_role_btn.clicked.connect(self.activate_role_mode)
        self.auth_mode_badge = QLabel("Mode: locked")
        self.auth_mode_badge.setStyleSheet("color:#f4c26b;font-weight:700;")
        self.auth_mode_hint = QLabel("")
        self.auth_mode_hint.setWordWrap(False)
        self.auth_mode_hint.setStyleSheet("color:#96a5b8;font-size:12px;")
        self.approval_id = QLineEdit()
        self.approval_id.setPlaceholderText("Optional: approved change ID for corp/prod actions")
        self.actor_name = QLineEdit()
        self.actor_name.setPlaceholderText("Operator / actor ID")
        self.workspace_id = QLineEdit("default")
        self.workspace_id.setPlaceholderText("Workspace ID (required for corp/prod)")
        self.duration = QSpinBox(); self.duration.setRange(5, 600); self.duration.setValue(30)
        self.interval = QDoubleSpinBox(); self.interval.setRange(0.1, 10.0); self.interval.setValue(1.0)
        self.vt_key = QLineEdit(); self.vt_key.setEchoMode(QLineEdit.Password)
        self.vt_key.setPlaceholderText("Pushed to backend on focus-out (used by cloud_intel provider)")
        self.malwarebazaar_key = QLineEdit(); self.malwarebazaar_key.setEchoMode(QLineEdit.Password)
        self.malwarebazaar_key.setPlaceholderText("Pushed to backend on focus-out (cloud_intel provider)")
        self.yaraify_key = QLineEdit(); self.yaraify_key.setEchoMode(QLineEdit.Password)
        self.yaraify_key.setPlaceholderText("Pushed to backend on focus-out (cloud_intel provider)")
        self.hybrid_analysis_key = QLineEdit(); self.hybrid_analysis_key.setEchoMode(QLineEdit.Password)
        self.hybrid_analysis_key.setPlaceholderText("Pushed to backend on focus-out (cloud_sandbox provider)")
        # Wire focus-out events on each cloud-credential field to push the
        # value into /antivirus/credentials. The backend stores it
        # encrypted in app_settings AND in the in-process credential
        # cache, so the next scan picks it up without a server restart.
        for widget, slot_name in [
            (self.vt_key, "virustotal"),
            (self.malwarebazaar_key, "malwarebazaar"),
            (self.yaraify_key, "yaraify"),
            (self.hybrid_analysis_key, "hybrid_analysis"),
        ]:
            widget.editingFinished.connect(lambda w=widget, n=slot_name: self._push_av_credential(n, w.text()))
            # P2 — explain the focus-out push semantics so the operator
            # knows the secret has been sent (and not merely typed).
            widget.setToolTip(
                f"Pushes to PUT /antivirus/credentials ({slot_name}) on focus-out. "
                "Stored encrypted in the backend credential vault. "
                "Empty value clears the slot."
            )
        self.hash_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.persist_filter = QLineEdit()
        self.strings_min_length = QSpinBox(); self.strings_min_length.setRange(3, 20); self.strings_min_length.setValue(4)
        self.strings_patterns = QLineEdit("http,powershell,cmd,token,password,api")
        self.trace_duration = QSpinBox(); self.trace_duration.setRange(2, 60); self.trace_duration.setValue(5)
        self.trace_interval = QDoubleSpinBox(); self.trace_interval.setRange(0.1, 5.0); self.trace_interval.setValue(0.5)
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
        ops_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        ops_layout = QVBoxLayout(ops_card)
        ops_layout.setContentsMargins(10, 8, 10, 8)
        ops_layout.setSpacing(1)
        ops_title = QLabel("Primary Controls")
        ops_title.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;")
        ops_sub = QLabel("Base access, fast lookups and day-to-day operator controls")
        ops_sub.setStyleSheet("color:#96a5b8;font-size:10px;")
        ops_form = QGridLayout()
        ops_form.setContentsMargins(0, 2, 0, 0)
        ops_form.setHorizontalSpacing(8)
        ops_form.setVerticalSpacing(4)
        ops_form.setColumnStretch(0, 1)
        ops_form.setColumnStretch(1, 1)
        ops_form.setColumnStretch(2, 1)
        # NOTE: the grid is populated once, below (after auth_row /
        # access_status are built). A stray duplicate
        # `addWidget(_field_block("API Base URL", self.base), 0, 0)`
        # used to sit here — it created an orphan label-only block and,
        # because `self.base` gets reparented into the second
        # field_block, left two overlapping widgets in cell (0,0). That
        # threw off every grid row height and made the last cell
        # (Persistence Filter at 3,2) render shifted and without its
        # input box. Removed; the single population is lines below.
        auth_row = QWidget()
        auth_row_layout = QHBoxLayout(auth_row)
        auth_row_layout.setContentsMargins(0, 0, 0, 0)
        auth_row_layout.setSpacing(8)
        auth_row_layout.addWidget(self.api_key, 1)
        auth_row_layout.addWidget(self.activate_role_btn)
        access_status = QWidget()
        access_status.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        access_status_layout = QVBoxLayout(access_status)
        access_status_layout.setContentsMargins(0, 0, 0, 0)
        access_status_layout.setSpacing(0)
        access_status_layout.setAlignment(Qt.AlignTop)
        self.auth_mode_badge.setStyleSheet("color:#f4c26b;font-weight:700;font-size:10px;")
        self.auth_mode_hint.setStyleSheet("color:#96a5b8;font-size:8px;")
        self.auth_mode_hint.setMinimumHeight(12)
        self.auth_mode_hint.setMaximumHeight(12)
        self.auth_mode_hint.setVisible(False)
        self.remember_api_key.setStyleSheet("font-size:9px;color:#96a5b8;")
        if win32cred is None:
            self.remember_api_key.setChecked(False)
            self.remember_api_key.setEnabled(False)
            self.remember_api_key.setToolTip("Secure secret storage is unavailable on this host.")
        else:
            # Wire the checkbox to the credential store (P0 fix — was
            # previously dead UI). Toggle persists / clears immediately
            # so the user gets feedback.
            self.remember_api_key.toggled.connect(self._on_remember_api_key_toggled)
            self.remember_api_key.setToolTip(
                "When ticked, the API key is stored in Windows Credential Manager and "
                "auto-loaded on next launch."
            )
        self.remember_api_key.setContentsMargins(0, 0, 0, 0)
        access_status_layout.addWidget(self.auth_mode_badge)
        access_status_layout.addWidget(self.remember_api_key)
        ops_header = QWidget()
        ops_header_row = QHBoxLayout(ops_header)
        ops_header_row.setContentsMargins(0, 0, 0, 0)
        ops_header_row.setSpacing(12)
        ops_header_left = QWidget()
        ops_header_left_layout = QVBoxLayout(ops_header_left)
        ops_header_left_layout.setContentsMargins(0, 0, 0, 0)
        ops_header_left_layout.setSpacing(1)
        ops_header_left_layout.addWidget(ops_title)
        ops_header_left_layout.addWidget(ops_sub)
        ops_header_row.addWidget(ops_header_left, 1)
        ops_header_row.addStretch(1)
        ops_form.addWidget(self._field_block("API Base URL", self.base), 0, 0)
        ops_form.addWidget(self._field_block("Role-Based API Key", auth_row), 0, 1)
        ops_form.addWidget(self._field_block("Access Mode", access_status), 0, 2)
        ops_form.addWidget(self._field_block("Approval ID", self.approval_id), 1, 0)
        ops_form.addWidget(self._field_block("Actor", self.actor_name), 1, 1)
        ops_form.addWidget(self._field_block("Workspace ID", self.workspace_id), 1, 2)
        ops_form.addWidget(self._field_block("Monitor Duration (s)", self.duration), 2, 0)
        ops_form.addWidget(self._field_block("Monitor Interval (s)", self.interval), 2, 1)
        ops_form.addWidget(self._field_block("Webhook URL", self.webhook_url), 2, 2)
        ops_form.addWidget(self._field_block("Threat IP", self.ip_input), 3, 0)
        ops_form.addWidget(self._field_block("Threat Hash", self.hash_input), 3, 1)
        # NOTE: the legacy "Persistence Filter" field was removed here.
        # `self.persist_filter` is the SAME QLineEdit the Persistence
        # tab adds to its own search row (intel_ops.py:
        # `f1.addWidget(app.persist_filter)` — its comment literally
        # says it "replaces the legacy app.persist_filter field"). A Qt
        # widget can only live in one layout, and the Persistence tab is
        # built after Primary Controls, so it reparented the input out
        # of this cell — leaving an orphan "Persistence Filter" label
        # with no box. The control lives on the Persistence tab (and the
        # "Filter Persistence" toolbar button); duplicating its label
        # here only ever rendered broken.
        ops_layout.addWidget(ops_header)
        ops_layout.addSpacing(1)
        ops_layout.addLayout(ops_form)
        ops_layout.addStretch(1)

        adv_card = QFrame(); adv_card.setProperty("card", True); adv_card.setMinimumWidth(520)
        adv_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        adv_layout = QVBoxLayout(adv_card)
        adv_layout.setContentsMargins(10, 8, 10, 8)
        adv_layout.setSpacing(1)
        adv_title = QLabel("Advanced Hunt & Lab Settings")
        adv_title.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;")
        adv_sub = QLabel("Advanced hunt, trace, evidence and network lab inputs")
        adv_sub.setStyleSheet("color:#96a5b8;font-size:10px;")
        adv_form = QGridLayout()
        adv_form.setContentsMargins(0, 2, 0, 0)
        adv_form.setHorizontalSpacing(8)
        adv_form.setVerticalSpacing(4)
        adv_form.setColumnStretch(0, 1)
        adv_form.setColumnStretch(1, 1)
        adv_form.setColumnStretch(2, 1)
        # 4 fields in a row with 3-column siblings forced each cred field
        # into 75 % width and broke the visual rhythm. Re-laid out into a
        # uniform 3-per-row grid so every cell on the card is the same
        # width — credentials still group at the top but flow into the
        # next row instead of cramming.
        adv_form.addWidget(self._field_block("VirusTotal API Key",      self.vt_key),               0, 0)
        adv_form.addWidget(self._field_block("MalwareBazaar Auth-Key",  self.malwarebazaar_key),    0, 1)
        adv_form.addWidget(self._field_block("YARAify Auth-Key",        self.yaraify_key),          0, 2)
        adv_form.addWidget(self._field_block("Hybrid-Analysis Auth-Key", self.hybrid_analysis_key), 1, 0)
        adv_form.addWidget(self._field_block("Strings Min Length",      self.strings_min_length),   1, 1)
        adv_form.addWidget(self._field_block("Trace Duration (s)",      self.trace_duration),       1, 2)
        adv_form.addWidget(self._field_block("Trace Interval (s)",      self.trace_interval),       2, 0)
        adv_form.addWidget(self._field_block("Evidence Alert Name",     self.evidence_alert_name),  2, 1)
        adv_form.addWidget(self._field_block("Network IP Range",        self.net_range),            2, 2)
        adv_form.addWidget(self._field_block("Blocker Target IP",       self.block_target),         3, 0)
        adv_form.addWidget(self._field_block("Blocker Gateway IP",      self.block_gateway),        3, 1)
        adv_form.addWidget(self._field_block("Strings Patterns",        self.strings_patterns),     3, 2)
        adv_layout.addWidget(adv_title)
        adv_layout.addWidget(adv_sub)
        adv_layout.addSpacing(1)
        adv_layout.addLayout(adv_form)
        adv_layout.addStretch(1)
        self.advanced_card = adv_card
        self.health = QLabel("API status: unknown")
        self.health.setStyleSheet(
            "background:#24344a;color:#c8d8ea;border:1px solid #355179;"
            "border-radius:10px;padding:6px 14px;font-weight:700;font-size:12px;"
        )
        self.auth_role = QLabel("Role: -")
        self.auth_summary = QLabel("")
        self.auth_summary.setVisible(False)
        self.auth_role.setStyleSheet(
            "background:#24344a;color:#f4f7fb;border:1px solid #355179;"
            "border-radius:10px;padding:6px 14px;font-weight:700;font-size:12px;"
        )
        self.toggle_advanced_btn = QPushButton("Hide Advanced Settings")
        self.toggle_advanced_btn.clicked.connect(self.toggle_advanced_settings)
        self.metric_proc = QLabel("Processes: --")
        self.metric_tel = QLabel("Telemetry Rows: --")
        self.metric_inc = QLabel("Last Incident: --")
        self.metric_art = QLabel("Artifacts: --")
        metric_style = (
            "background:#121b27;color:#c8d8ea;border:1px solid #2c4260;"
            "border-radius:10px;padding:6px 10px;font-weight:600;font-size:11px;"
        )
        for metric in [self.metric_proc, self.metric_tel, self.metric_inc, self.metric_art]:
            metric.setStyleSheet(metric_style)
        top_capabilities = {
            "Run Monitor": "can_run_monitor",
            "Filter Persistence": "can_view_persistence",
        }
        hero_tools = QWidget()
        hero_status = QWidget()
        hero_status_row = QHBoxLayout(hero_status)
        hero_status_row.setContentsMargins(0, 0, 0, 0)
        hero_status_row.setSpacing(8)
        hero_status_row.addStretch(1)
        hero_status_row.addWidget(self.metric_proc)
        hero_status_row.addWidget(self.metric_tel)
        hero_status_row.addWidget(self.metric_inc)
        hero_status_row.addWidget(self.metric_art)
        # Stash a ref so the Dashboards-only visibility rule can flip it.
        self.hero_status = hero_status
        hero_actions = QWidget()
        hero_actions_row = QHBoxLayout(hero_actions)
        hero_actions_row.setContentsMargins(0, 0, 0, 0)
        hero_actions_row.setSpacing(8)
        hero_actions_row.addWidget(self.toggle_advanced_btn)
        # The operator action buttons (Run Monitor, Load Processes,
        # Lookup Hash, Lookup IP, Filter Persistence) were moved OUT of
        # this global header into the Process Hunt console (Processes
        # tab) where they belong — they're per-investigation actions,
        # not header chrome. `dashboard_only_action_buttons` stays as an
        # empty list so the shell's per-tab visibility loop
        # (shell_ops.py) remains a harmless no-op without a code change.
        self.dashboard_only_action_buttons = []
        hero_actions_row.addStretch(1)
        hero_actions_row.addWidget(self.health, 0, Qt.AlignRight)
        hero_actions_row.addWidget(self.auth_role, 0, Qt.AlignRight)
        hero_tools_layout = QVBoxLayout(hero_tools)
        hero_tools_layout.setContentsMargins(0, 0, 0, 0)
        hero_tools_layout.setSpacing(6)
        hero_tools_layout.addWidget(hero_status)
        hero_tools_layout.addWidget(hero_actions)
        hero_row.addWidget(hero_tools, 0, Qt.AlignRight | Qt.AlignTop)
        layout.addWidget(hero)

        controls = QWidget()
        controls.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.controls = controls
        self.controls_row = QHBoxLayout(controls)
        self.controls_row.setContentsMargins(0, 0, 0, 0)
        self.controls_row.setSpacing(10)
        self.ops_card = ops_card
        self.controls_row.addWidget(ops_card, 1)
        self.controls_row.addWidget(adv_card, 1)
        layout.addWidget(controls)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._scrollable_tab(self._dashboard_hub_tab()), "Dashboards")
        self.tabs.addTab(self._whids_tab(), "WHIDS")
        self.tabs.addTab(self._hids_tab(), "HIDS")
        self.tabs.addTab(self._scrollable_tab(self._overview_tab()), "Overview")
        self.tabs.addTab(self._scrollable_tab(self._process_tab(), allow_horizontal=True), "Processes")
        self.tabs.addTab(self._scrollable_tab(self._persistence_tab(), allow_horizontal=True), "Persistence")
        self.tabs.addTab(self._malware_analyst_tab(), "File Analysis")
        self.tabs.addTab(self._network_tab(), "Network")
        self.tabs.addTab(self._graph_tab(), "Graph")
        self.tabs.addTab(self._timeline_tab(), "Timeline")
        self.tabs.addTab(self._antivirus_tab(), "Antivirus")
        self.tabs.addTab(self._scrollable_tab(self._history_tab(), allow_horizontal=True), "History")
        self.tabs.addTab(self._artifacts_tab(), "Artifacts")
        self.tabs.addTab(self._enterprise_tab(), "Enterprise")
        self.tabs.addTab(self._security_ops_tab(), "Security Ops")
        # Scenario tab + helpers removed in 2026-05. CI smoke test is
        # served by `python scripts/perf_stability_probe.py`.
        self.tabs.addTab(self._scrollable_tab(self._about_tab()), "About / FAQ")
        self.tabs.setDocumentMode(True)
        self.tabs.setUsesScrollButtons(True)
        self.tabs.tabBar().setExpanding(False)
        self.tabs.tabBar().setElideMode(Qt.ElideRight)
        self.tabs.tabBar().setUsesScrollButtons(True)
        self.tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tabs, 1)
        self.setCentralWidget(content)
        self._load_settings()
        self._update_controls_layout()
        QTimer.singleShot(0, self._update_tab_bar_layout)
        # After settings load — push any persisted cloud-credential
        # values into the API so the cloud_intel + cloud_sandbox
        # providers see them on the very first scan, not after the
        # operator clicks back into the field.
        QTimer.singleShot(0, self._sync_av_credentials_to_backend)
        # Try to auto-populate the API key from Windows Credential
        # Manager if the operator previously ticked "Remember".  The
        # toggle signal must be silenced while we initialise so the load
        # itself doesn't trigger a duplicate write.
        QTimer.singleShot(0, self._restore_remembered_api_key)
        # Install Ctrl+K global search shortcut (P0-6)
        self._install_search_shortcut()

    # ------------------------------------------------------------------ #
    # Remember API key — Windows Credential Manager wiring (win32cred)
    # ------------------------------------------------------------------ #
    #
    # When the operator ticks "Remember API key on this machine", the key
    # is stored in the Windows credential vault keyed by base_url, so
    # different environments (dev / lab / prod) keep distinct keys.
    # Unticking the box clears the stored credential.

    _CRED_TARGET_PREFIX = "ShadowLab/api_key/"

    def _credential_target(self) -> str:
        base = (self.base.text().strip() if hasattr(self, "base") else "") or "default"
        return f"{self._CRED_TARGET_PREFIX}{base}"

    def _settings_key(self) -> str:
        return f"shadowlab/api_key/{self.base.text().strip() or 'default'}"

    def _store_remembered_api_key(self, value: str) -> bool:
        if not value:
            return False
        if win32cred is not None:
            try:
                win32cred.CredWrite(
                    {
                        "Type": win32cred.CRED_TYPE_GENERIC,
                        "TargetName": self._credential_target(),
                        "UserName": "shadowlab-desktop",
                        "CredentialBlob": value,
                        "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                    },
                    0,
                )
                return True
            except Exception:
                # fall through to encrypted-QSettings fallback
                pass
        # Fallback: encrypt with DPAPI (Windows) or AES-GCM (other) via
        # the shared secret_store so the key never sits in QSettings as
        # plaintext when Credential Manager is unavailable.
        if _secret_store is None:
            return False
        try:
            ciphertext = _secret_store.encrypt_text(value)
        except Exception:
            return False
        try:
            QSettings("ShadowLab", "Desktop").setValue(self._settings_key(), ciphertext)
            return True
        except Exception:
            return False

    def _load_remembered_api_key(self) -> str:
        if win32cred is not None:
            try:
                cred = win32cred.CredRead(self._credential_target(), win32cred.CRED_TYPE_GENERIC, 0)
            except Exception:
                cred = None
            if isinstance(cred, dict):
                blob = cred.get("CredentialBlob")
                if isinstance(blob, bytes):
                    for enc in ("utf-16-le", "utf-8"):
                        try:
                            return blob.decode(enc).rstrip("\x00")
                        except UnicodeDecodeError:
                            continue
                    return ""
                if blob is not None:
                    return str(blob)
        # Fallback: encrypted blob in QSettings.
        if _secret_store is None or _is_encrypted_secret is None:
            return ""
        try:
            stored = str(QSettings("ShadowLab", "Desktop").value(self._settings_key(), "") or "")
        except Exception:
            return ""
        if not stored:
            return ""
        if not _is_encrypted_secret(stored):
            # Pre-fix plaintext value — re-encrypt opportunistically.
            try:
                self._store_remembered_api_key(stored)
            except Exception:
                pass
            return stored
        try:
            return _secret_store.decrypt_text(stored)
        except Exception:
            return ""

    def _clear_remembered_api_key(self) -> None:
        if win32cred is not None:
            try:
                win32cred.CredDelete(self._credential_target(), win32cred.CRED_TYPE_GENERIC, 0)
            except Exception:
                pass
        try:
            QSettings("ShadowLab", "Desktop").remove(self._settings_key())
        except Exception:
            return

    def _on_remember_api_key_toggled(self, checked: bool) -> None:
        """Persist or clear the API key based on the checkbox state.

        Works even when `win32cred` is unavailable — the fallback path
        encrypts the value at rest via the shared secret store.
        """
        if checked:
            value = self.api_key.text().strip()
            if value:
                ok = self._store_remembered_api_key(value)
                if ok:
                    self.statusBar().showMessage("API key saved (encrypted at rest).", 4000)
                else:
                    self.statusBar().showMessage("Failed to persist API key — no Credential Manager and no secret store available.", 5000)
        else:
            self._clear_remembered_api_key()
            self.statusBar().showMessage("API key cleared from local storage.", 4000)

    def _persist_api_key_after_activate(self) -> None:
        """Refresh the stored credential after a successful activation.

        No-op when the checkbox is unticked. Falls back to the encrypted
        QSettings store if Credential Manager isn't wired in.
        """
        if not getattr(self, "remember_api_key", None):
            return
        if not self.remember_api_key.isChecked():
            return
        value = self.api_key.text().strip()
        if value:
            self._store_remembered_api_key(value)

    def closeEvent(self, event):  # type: ignore[override]
        """Persist operator workflow inputs on exit so the next launch
        restores the last-used values (Monitor duration, Trace timing,
        AV intel patterns, Network ranges, etc.)."""
        try:
            self.shell_controller.save_settings()
        except Exception:
            pass
        super().closeEvent(event)

    # ------------------------------------------------------------------ #
    # Search omnibar (P0-6) — Ctrl+K opens a global pivot dialog
    # ------------------------------------------------------------------ #

    def _install_search_shortcut(self) -> None:
        try:
            shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
            shortcut.activated.connect(self._open_search_omnibar)
            self._search_shortcut = shortcut
        except Exception:
            return

    def _detect_search_kind(self, query: str) -> str:
        """Heuristic dispatcher used by the omnibar to route a query."""
        import re
        q = query.strip()
        if not q:
            return "empty"
        # Hash: 32 (MD5), 40 (SHA1), 64 (SHA256) hex chars
        if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", q):
            return "hash"
        # IPv4
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", q):
            return "ip"
        # IPv6 (very loose)
        if ":" in q and re.fullmatch(r"[0-9A-Fa-f:]{3,}", q):
            return "ip"
        # Process / executable name
        if q.lower().endswith((".exe", ".dll", ".sys", ".ps1", ".bat", ".vbs", ".msi")):
            return "process"
        # Otherwise treat as host or process search
        return "host"

    def _open_search_omnibar(self) -> None:
        """Modal pivot bar — type any indicator and the dialog auto-routes
        it to the right ShadowLab workflow:

          - SHA256/SHA1/MD5 hash -> Threat Intel hash lookup
          - IPv4 / IPv6          -> Threat Intel IP lookup
          - *.exe / *.dll / etc. -> Processes tab + filter
          - everything else      -> Persistence filter / generic search
        """
        dialog = QDialog(self)
        dialog.setWindowTitle("ShadowLab — Quick search (Ctrl+K)")
        dialog.setModal(True)
        dialog.resize(640, 200)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)
        prompt = QLabel(
            "Type a hash, IP, host, or process name and press Enter.\n"
            "ShadowLab auto-detects the indicator type and pivots to the right surface."
        )
        prompt.setStyleSheet("color:#96a5b8;font-size:11px;")
        prompt.setWordWrap(True)
        layout.addWidget(prompt)

        line = QLineEdit()
        line.setPlaceholderText("hash / ip / host / process name ...")
        line.setStyleSheet(
            "background:#0e1622;border:1px solid #2c4260;border-radius:8px;"
            "padding:10px 12px;color:#f4f7fb;font-size:14px;"
        )
        layout.addWidget(line)

        hint = QLabel("Detected: —")
        hint.setStyleSheet("color:#7fd7ff;font-size:11px;font-weight:600;")
        layout.addWidget(hint)

        def _refresh_hint(_text=""):
            kind = self._detect_search_kind(line.text())
            label = {
                "hash": "hash → Threat Intel lookup",
                "ip": "IP → Threat Intel lookup",
                "process": "process → Processes tab",
                "host": "host / generic → search",
                "empty": "—",
            }.get(kind, "—")
            hint.setText(f"Detected: {label}")

        line.textChanged.connect(_refresh_hint)

        def _dispatch():
            query = line.text().strip()
            if not query:
                dialog.reject()
                return
            kind = self._detect_search_kind(query)
            dialog.accept()
            try:
                self._dispatch_omnibar(kind, query)
            except Exception as exc:
                try:
                    self.statusBar().showMessage(f"Quick search failed: {exc}", 5000)
                except Exception:
                    pass

        line.returnPressed.connect(_dispatch)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        btn_row.addWidget(cancel_btn)
        go_btn = QPushButton("Pivot")
        go_btn.setDefault(True)
        go_btn.clicked.connect(_dispatch)
        btn_row.addWidget(go_btn)
        layout.addLayout(btn_row)

        line.setFocus()
        dialog.exec()

    def _dispatch_omnibar(self, kind: str, query: str) -> None:
        if kind == "hash":
            self.hash_input.setText(query)
            self._switch_to_tab("Threat Intel")  # may not exist by that name
            try:
                self.lookup_hash()
            except Exception:
                pass
            return
        if kind == "ip":
            self.ip_input.setText(query)
            try:
                self.lookup_ip()
            except Exception:
                pass
            return
        if kind == "process":
            self._switch_to_tab("Processes")
            # Persist filter is the closest free-text filter we surface today
            self.persist_filter.setText(query)
            try:
                self.apply_persistence_filter()
            except Exception:
                pass
            return
        # host / generic — set as persistence filter and switch tab
        self.persist_filter.setText(query)
        self._switch_to_tab("Persistence")
        try:
            self.apply_persistence_filter()
        except Exception:
            pass

    def _restore_remembered_api_key(self) -> None:
        """Auto-populate `self.api_key` from Windows Credential Manager
        on startup if a credential exists.  Called once after settings
        load.  We also tick the checkbox so the operator sees the state.
        """
        if win32cred is None or not getattr(self, "remember_api_key", None):
            return
        stored = self._load_remembered_api_key()
        if not stored:
            return
        self.api_key.setText(stored)
        # Block the toggled-signal while we set the check state so that
        # `_on_remember_api_key_toggled` doesn't re-write the credential
        # (which is harmless but spams the status bar).
        self.remember_api_key.blockSignals(True)
        self.remember_api_key.setChecked(True)
        self.remember_api_key.blockSignals(False)
        # Trigger role activation automatically — it's the obvious next
        # step after the key is restored.
        try:
            self.activate_role_mode()
        except Exception:
            pass

    def _base_url_is_secure_for_credentials(self) -> bool:
        """True when the configured backend URL is safe to receive secrets.

        VT / MalwareBazaar / YARAify / Hybrid-Analysis keys are long-
        lived third-party credentials. Allowing them to traverse a
        plaintext `http://` link to a non-loopback host quietly leaks
        the keys to anyone on the network path. We accept HTTPS
        unconditionally and HTTP only when the destination is the
        operator's own loopback.
        """
        from urllib.parse import urlparse
        raw = (self.base.text() if hasattr(self, "base") else "") or ""
        try:
            parsed = urlparse(raw.strip())
        except ValueError:
            return False
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if scheme == "https":
            return True
        if scheme == "http" and host in {"127.0.0.1", "localhost", "::1"}:
            return True
        return False

    def _push_av_credential(self, slot: str, value: str) -> None:
        """Send a single VT/MalwareBazaar/YARAify/Hybrid-Analysis key to
        `PUT /antivirus/credentials`. Empty string clears the slot."""
        if not getattr(self, "auth_session_ready", False):
            return
        if not self._base_url_is_secure_for_credentials():
            try:
                self.statusBar().showMessage(
                    f"Refusing to push {slot} credential over plaintext HTTP to a "
                    "non-loopback host. Switch the API base to https:// first.",
                    8000,
                )
            except Exception:
                pass
            return
        try:
            self.api_client.put("/antivirus/credentials", json={slot: (value or "").strip()}, timeout=10)
        except Exception:
            try:
                self.statusBar().showMessage(f"⚠ Failed to push {slot} credential — backend may not be reachable.", 5000)
            except Exception:
                pass

    def _sync_av_credentials_to_backend(self) -> None:
        """One-shot bulk push of every populated cred field. Called on
        startup after settings restore so the persisted desktop values
        re-hydrate the backend even if the operator never re-focused
        the input."""
        if not getattr(self, "auth_session_ready", False):
            return
        payload: dict[str, str] = {}
        for widget, slot in [
            (getattr(self, "vt_key", None), "virustotal"),
            (getattr(self, "malwarebazaar_key", None), "malwarebazaar"),
            (getattr(self, "yaraify_key", None), "yaraify"),
            (getattr(self, "hybrid_analysis_key", None), "hybrid_analysis"),
        ]:
            if widget is None:
                continue
            text = (widget.text() or "").strip()
            if text:
                payload[slot] = text
        if not payload:
            return
        if not self._base_url_is_secure_for_credentials():
            try:
                self.statusBar().showMessage(
                    "Refusing to sync AV credentials over plaintext HTTP to a "
                    "non-loopback host. Switch the API base to https:// first.",
                    8000,
                )
            except Exception:
                pass
            return
        try:
            self.api_client.put("/antivirus/credentials", json=payload, timeout=10)
        except Exception:
            pass

def main() -> int:
    app = QApplication(sys.argv)
    window = ShadowLabDesktop()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())








