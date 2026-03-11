from __future__ import annotations

import json
import sys
from pathlib import Path

import requests
from PySide6.QtCore import QSettings, Qt, QUrl
from PySide6.QtGui import QAction, QBrush, QColor, QDesktopServices, QIcon, QPixmap
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtWidgets import (
    QApplication, QBoxLayout, QComboBox, QDoubleSpinBox, QFormLayout, QGridLayout, QHBoxLayout, QLabel,
    QInputDialog, QLineEdit, QListWidget, QMainWindow, QMessageBox, QPushButton, QSpinBox,
    QFrame, QScrollArea, QSplitter, QStatusBar, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QTextEdit,
    QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)


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
        self.threat_history: list[dict[str, str]] = []
        self.custom_toolbar_buttons: list[dict[str, str]] = []
        self._theme()
        self._toolbar()
        self._ui()
        self.setStatusBar(QStatusBar())
        self.check_api_health()

    def _theme(self) -> None:
        self.setStyleSheet(
            "QMainWindow,QWidget{background:#10151d;color:#e5edf5;}"
            "QLineEdit,QTextEdit,QSpinBox,QDoubleSpinBox,QComboBox,QTableWidget,QListWidget{background:#16202c;color:#eef4fb;border:1px solid #243446;border-radius:6px;padding:4px;}"
            "QPushButton{background:#1d7df2;color:white;border:none;border-radius:6px;padding:8px 12px;} QPushButton:hover{background:#3b8ff3;}"
            "QTabWidget::pane{border:1px solid #243446;} QTabBar::tab{background:#16202c;color:#d7e2ef;padding:10px 16px;} QTabBar::tab:selected{background:#1d7df2;color:white;}"
            "QHeaderView::section{background:#16202c;color:#d7e2ef;border:1px solid #243446;padding:6px;}"
            "QTableWidget{gridline-color:#243446;alternate-background-color:#12202c;}"
            "QFrame[card='true']{background:#121b27;border:1px solid #243446;border-radius:10px;}"
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
        layout = QVBoxLayout(content)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(10)
        hero = QWidget()
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(0, 0, 0, 0)
        hero_row.setSpacing(14)
        title_logo = QLabel()
        if self.logo_path.exists():
            title_logo.setPixmap(QPixmap(str(self.logo_path)).scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        title = QLabel("ShadowLab")
        title.setStyleSheet("font-size:28px;font-weight:700;padding:8px;color:#f4f7fb;")
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
        self.controls_row = QHBoxLayout(controls)
        self.controls_row.setContentsMargins(0, 0, 0, 0)
        self.controls_row.setSpacing(18)
        self.base = QLineEdit("http://127.0.0.1:8000")
        self.duration = QSpinBox(); self.duration.setRange(5, 600); self.duration.setValue(30)
        self.interval = QDoubleSpinBox(); self.interval.setRange(0.1, 10.0); self.interval.setValue(1.0)
        self.vt_key = QLineEdit(); self.vt_key.setEchoMode(QLineEdit.Password)
        self.hash_input = QLineEdit()
        self.ip_input = QLineEdit()
        self.persist_filter = QLineEdit()
        self.strings_min_length = QSpinBox(); self.strings_min_length.setRange(3, 20); self.strings_min_length.setValue(4)
        self.strings_patterns = QLineEdit("http,powershell,cmd,token,password,api")
        self.yara_pack = QComboBox(); self.yara_pack.addItems(["hybrid", "curated", "basic"])
        self.trace_duration = QSpinBox(); self.trace_duration.setRange(2, 60); self.trace_duration.setValue(5)
        self.trace_interval = QDoubleSpinBox(); self.trace_interval.setRange(0.1, 5.0); self.trace_interval.setValue(0.5)
        self.honeypot_filename = QLineEdit("passwords.txt")
        self.evidence_alert_name = QLineEdit("incident")
        self.net_range = QLineEdit("192.168.1.0/24")
        self.block_target = QLineEdit()
        self.block_gateway = QLineEdit()
        self.webhook_url = QLineEdit()

        ops_card = QFrame(); ops_card.setProperty("card", True); ops_card.setMinimumWidth(620)
        ops_layout = QVBoxLayout(ops_card)
        ops_layout.setContentsMargins(18, 18, 18, 18)
        ops_layout.setSpacing(10)
        ops_title = QLabel("Primary Controls")
        ops_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        ops_sub = QLabel("Daily operations, monitor and fast lookups")
        ops_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        ops_form = QGridLayout()
        ops_form.setContentsMargins(0, 4, 0, 0)
        ops_form.setHorizontalSpacing(16)
        ops_form.setVerticalSpacing(12)
        ops_form.addWidget(self._field_block("API Base URL", self.base), 0, 0, 1, 2)
        ops_form.addWidget(self._field_block("Monitor Duration (s)", self.duration), 1, 0)
        ops_form.addWidget(self._field_block("Monitor Interval (s)", self.interval), 1, 1)
        ops_form.addWidget(self._field_block("VirusTotal API Key", self.vt_key), 2, 0, 1, 2)
        ops_form.addWidget(self._field_block("Threat Hash", self.hash_input), 3, 0)
        ops_form.addWidget(self._field_block("Threat IP", self.ip_input), 3, 1)
        ops_form.addWidget(self._field_block("Persistence Filter", self.persist_filter), 4, 0)
        ops_form.addWidget(self._field_block("Webhook URL", self.webhook_url), 4, 1)
        ops_layout.addWidget(ops_title)
        ops_layout.addWidget(ops_sub)
        ops_layout.addLayout(ops_form)

        adv_card = QFrame(); adv_card.setProperty("card", True); adv_card.setMinimumWidth(720)
        adv_layout = QVBoxLayout(adv_card)
        adv_layout.setContentsMargins(18, 18, 18, 18)
        adv_layout.setSpacing(10)
        adv_title = QLabel("Advanced Hunt & Lab Settings")
        adv_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        adv_sub = QLabel("Strings, sandbox, deception and network-warfare inputs")
        adv_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        adv_form = QGridLayout()
        adv_form.setContentsMargins(0, 4, 0, 0)
        adv_form.setHorizontalSpacing(16)
        adv_form.setVerticalSpacing(12)
        adv_form.addWidget(self._field_block("Strings Min Length", self.strings_min_length), 0, 0)
        adv_form.addWidget(self._field_block("Strings Patterns", self.strings_patterns), 0, 1)
        adv_form.addWidget(self._field_block("YARA Rule Pack", self.yara_pack), 0, 2)
        adv_form.addWidget(self._field_block("Trace Duration (s)", self.trace_duration), 1, 0)
        adv_form.addWidget(self._field_block("Trace Interval (s)", self.trace_interval), 1, 1)
        adv_form.addWidget(self._field_block("Honeypot Filename", self.honeypot_filename), 1, 2)
        adv_form.addWidget(self._field_block("Evidence Alert Name", self.evidence_alert_name), 2, 0)
        adv_form.addWidget(self._field_block("Network IP Range", self.net_range), 2, 1)
        adv_form.addWidget(self._field_block("Blocker Target IP", self.block_target), 2, 2)
        adv_form.addWidget(self._field_block("Blocker Gateway IP", self.block_gateway), 3, 0, 1, 3)
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
        self.health = QLabel("API status: unknown")
        top_row.addWidget(self.health)
        self.toggle_advanced_btn = QPushButton("Hide Advanced Settings")
        self.toggle_advanced_btn.clicked.connect(self.toggle_advanced_settings)
        top_row.addWidget(self.toggle_advanced_btn)
        top_row.addStretch(1)
        for btn_text, fn in [
            ("Run Monitor", self.run_monitor),
            ("Load Processes", self.refresh_processes),
            ("Lookup Hash", self.lookup_hash),
            ("Lookup IP", self.lookup_ip),
            ("Filter Persistence", self.apply_persistence_filter),
        ]:
            btn = QPushButton(btn_text); btn.clicked.connect(fn); top_row.addWidget(btn)
        layout.addWidget(top)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._overview_tab(), "Overview")
        self.tabs.addTab(self._process_tab(), "Processes")
        self.tabs.addTab(self._hunt_tab(), "Advanced Hunt")
        self.tabs.addTab(self._persistence_tab(), "Persistence")
        self.tabs.addTab(self._threat_tab(), "Threat Intel")
        self.tabs.addTab(self._deception_tab(), "Deception")
        self.tabs.addTab(self._network_tab(), "Network")
        self.tabs.addTab(self._hosts_tab(), "Hosts")
        self.tabs.addTab(self._timeline_tab(), "Timeline")
        self.tabs.addTab(self._quarantine_tab(), "Quarantine")
        self.tabs.addTab(self._history_tab(), "History")
        self.tabs.addTab(self._artifacts_tab(), "Artifacts")
        self.tabs.addTab(self._scenario_tab(), "Scenarios")
        self.tabs.addTab(self._about_tab(), "About / FAQ")
        layout.addWidget(self.tabs)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setWidget(content)
        self.setCentralWidget(scroll)
        self._load_settings()
        self._update_controls_layout()

    def _overview_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        row = QWidget(); r = QHBoxLayout(row)
        self.metric_proc = QLabel("Processes: -"); self.metric_tel = QLabel("Telemetry Rows: -")
        self.metric_inc = QLabel("Last Incident: -"); self.metric_art = QLabel("Artifacts: -")
        for label in [self.metric_proc, self.metric_tel, self.metric_inc, self.metric_art]: r.addWidget(label)
        r.addStretch(1); l.addWidget(row)
        self.cpu_series = QLineSeries()
        self.cpu_chart = QChart()
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
        self.cpu_chart_view.setMinimumHeight(260)
        l.addWidget(self.cpu_chart_view)
        self.monitor_out = QTextEdit(); self.monitor_out.setReadOnly(True); l.addWidget(self.monitor_out)
        return w

    def _process_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); s = QSplitter(Qt.Horizontal)
        self.proc_table = QTableWidget(0, 5); self.proc_table.setHorizontalHeaderLabels(["PID","Name","CPU %","Memory %","Signature"]); self.proc_table.itemSelectionChanged.connect(self.show_selected_process); self._style_table(self.proc_table)
        right = QWidget(); rl = QVBoxLayout(right); self.proc_detail = QTextEdit(); self.proc_detail.setReadOnly(True); rl.addWidget(self.proc_detail)
        actions = QWidget(); ar = QHBoxLayout(actions)
        for text, fn in [("Auto Triage", self.run_auto_triage),("Threat Scan", self.scan_selected_process),("Memory Analysis", self.run_memory_analysis),("Internals", self.load_selected_internals),("Strings", self.run_strings_analysis),("YARA", self.run_yara_scan),("Sandbox", self.run_sandbox_trace),("Process Tree", self.load_process_tree),("AI Analyst", self.run_ai_analysis),("Suspend", lambda: self.process_action("suspend")),("Resume", lambda: self.process_action("resume")),("Kill", lambda: self.process_action("kill")),("Kill Tree", lambda: self.process_action("kill-tree")),("Quarantine", lambda: self.process_action("quarantine"))]:
            b = QPushButton(text); b.clicked.connect(fn); ar.addWidget(b)
        rl.addWidget(actions); s.addWidget(self.proc_table); s.addWidget(right); s.setStretchFactor(0, 2); s.setStretchFactor(1, 3); l.addWidget(s); return w

    def _hunt_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        actions = QWidget(); ar = QHBoxLayout(actions)
        for text, fn in [("Load Internals", self.load_selected_internals),("Extract Strings", self.run_strings_analysis),("Run YARA", self.run_yara_scan),("Sandbox Trace", self.run_sandbox_trace),("Process Tree", self.load_process_tree),("AI Analyst", self.run_ai_analysis)]:
            btn = QPushButton(text); btn.clicked.connect(fn); ar.addWidget(btn)
        ar.addStretch(1)
        l.addWidget(actions)
        self.tree_view = QTreeWidget()
        self.tree_view.setHeaderLabels(["Process Tree", "PID"])
        self.tree_view.setMinimumHeight(180)
        self.internals_table = QTableWidget(0, 4)
        self.internals_table.setHorizontalHeaderLabels(["Kind", "Path / Detail", "Mode / Perms", "FD / Size"])
        self._style_table(self.internals_table)
        self.hunt_out = QTextEdit(); self.hunt_out.setReadOnly(True)
        l.addWidget(self.tree_view)
        l.addWidget(self.internals_table)
        l.addWidget(self.hunt_out)
        return w

    def _persistence_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        self.persist_table = QTableWidget(0, 4); self.persist_table.setHorizontalHeaderLabels(["Name","Type","Path","Details"]); self.persist_table.itemSelectionChanged.connect(self.show_selected_persistence); self._style_table(self.persist_table)
        remediate = QPushButton("Remediate Selected Persistence"); remediate.clicked.connect(self.remediate_selected_persistence)
        self.persist_detail = QTextEdit(); self.persist_detail.setReadOnly(True)
        l.addWidget(self.persist_table); l.addWidget(remediate); l.addWidget(self.persist_detail); return w

    def _threat_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        summary = QWidget(); sr = QHBoxLayout(summary)
        self.ti_last_type = QLabel("Last Query: -")
        self.ti_last_value = QLabel("Value: -")
        self.ti_last_source = QLabel("Source: -")
        for item in [self.ti_last_type, self.ti_last_value, self.ti_last_source]:
            sr.addWidget(item)
        sr.addStretch(1)
        l.addWidget(summary)

        controls = QWidget(); cr = QHBoxLayout(controls)
        auto_hash = QPushButton("Use Selected Process Hash"); auto_hash.clicked.connect(self.use_selected_process_hash)
        auto_ip = QPushButton("Use Selected Process IP"); auto_ip.clicked.connect(self.use_selected_process_ip)
        hash_btn = QPushButton("Lookup Hash"); hash_btn.clicked.connect(self.lookup_hash)
        ip_btn = QPushButton("Lookup IP"); ip_btn.clicked.connect(self.lookup_ip)
        scan_btn = QPushButton("Scan Selected Process"); scan_btn.clicked.connect(self.scan_selected_process)
        for btn in [auto_hash, auto_ip, hash_btn, ip_btn, scan_btn]:
            cr.addWidget(btn)
        cr.addStretch(1)
        l.addWidget(controls)

        split = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        self.threat_history_table = QTableWidget(0, 3)
        self.threat_history_table.setHorizontalHeaderLabels(["Type", "Value", "Source"])
        self.threat_history_table.itemSelectionChanged.connect(self.show_selected_threat_history)
        self._style_table(self.threat_history_table)
        ll.addWidget(self.threat_history_table)
        self.threat_out = QTextEdit(); self.threat_out.setReadOnly(True)
        split.addWidget(left)
        split.addWidget(self.threat_out)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 3)
        l.addWidget(split)
        return w

    def _deception_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        top = QWidget(); tr = QHBoxLayout(top)
        for text, fn in [("Deploy Honeypot", self.deploy_honeypot),("Check Honeypot", self.check_honeypot),("Cleanup Honeypot", self.cleanup_honeypot),("Deploy Canary", self.deploy_canary),("Check Canary", self.check_canary),("Cleanup Canary", self.cleanup_canary),("Capture Evidence", self.capture_evidence),("Refresh Evidence", self.refresh_evidence),("Delete Evidence", self.delete_selected_evidence)]:
            btn = QPushButton(text); btn.clicked.connect(fn); tr.addWidget(btn)
        tr.addStretch(1)
        l.addWidget(top)
        split = QSplitter(Qt.Horizontal)
        self.evidence_list = QListWidget(); self.evidence_list.itemSelectionChanged.connect(self.show_selected_evidence)
        right = QWidget(); rl = QVBoxLayout(right)
        self.deception_out = QTextEdit(); self.deception_out.setReadOnly(True)
        self.evidence_detail = QTextEdit(); self.evidence_detail.setReadOnly(True)
        open_evidence_btn = QPushButton("Open Selected Evidence"); open_evidence_btn.clicked.connect(self.open_selected_evidence)
        rl.addWidget(self.deception_out); rl.addWidget(self.evidence_detail)
        rl.addWidget(open_evidence_btn)
        split.addWidget(self.evidence_list); split.addWidget(right)
        split.setStretchFactor(0, 1); split.setStretchFactor(1, 3)
        l.addWidget(split)
        return w

    def _network_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        row = QWidget(); r = QHBoxLayout(row); self.sniff_duration = QSpinBox(); self.sniff_duration.setRange(5, 60); self.sniff_duration.setValue(10); sniff = QPushButton("Start Packet Capture"); sniff.clicked.connect(self.run_sniffer); scan = QPushButton("ARP Discovery"); scan.clicked.connect(self.scan_network_devices); start_block = QPushButton("Start Blocker"); start_block.clicked.connect(self.start_network_blocker); stop_block = QPushButton("Stop Blocker"); stop_block.clicked.connect(self.stop_network_blocker); r.addWidget(QLabel("Capture Duration")); r.addWidget(self.sniff_duration); r.addWidget(sniff); r.addWidget(scan); r.addWidget(start_block); r.addWidget(stop_block); r.addStretch(1); l.addWidget(row)
        s = QSplitter(Qt.Horizontal)
        left = QWidget(); ll = QVBoxLayout(left)
        self.net_table = QTableWidget(0, 4); self.net_table.setHorizontalHeaderLabels(["Local","Remote","Status","PID"]); self._style_table(self.net_table)
        self.device_table = QTableWidget(0, 3); self.device_table.setHorizontalHeaderLabels(["IP","MAC","Vendor"]); self._style_table(self.device_table)
        ll.addWidget(self.net_table); ll.addWidget(self.device_table)
        self.net_out = QTextEdit(); self.net_out.setReadOnly(True)
        s.addWidget(left); s.addWidget(self.net_out); s.setStretchFactor(0, 2); s.setStretchFactor(1, 3); l.addWidget(s); return w

    def _hosts_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        btn = QPushButton("Refresh Hosts"); btn.clicked.connect(self.refresh_hosts); l.addWidget(btn)
        self.host_table = QTableWidget(0, 5); self.host_table.setHorizontalHeaderLabels(["Host","Platform","Boot Time","API Status","Role"]); self._style_table(self.host_table)
        l.addWidget(self.host_table)
        return w

    def _timeline_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        btn = QPushButton("Refresh Timeline"); btn.clicked.connect(self.refresh_timeline); l.addWidget(btn)
        self.timeline_table = QTableWidget(0, 4); self.timeline_table.setHorizontalHeaderLabels(["Time","Type","Severity","Title"]); self.timeline_table.itemSelectionChanged.connect(self.show_selected_timeline); self._style_table(self.timeline_table)
        self.timeline_detail = QTextEdit(); self.timeline_detail.setReadOnly(True)
        l.addWidget(self.timeline_table); l.addWidget(self.timeline_detail)
        return w

    def _quarantine_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w)
        row = QWidget(); r = QHBoxLayout(row)
        for text, fn in [("Refresh Quarantine", self.refresh_quarantine), ("Restore Selected", self.restore_selected_quarantine), ("Delete Selected", self.delete_selected_quarantine), ("Test Webhook", self.test_alert_webhook), ("Save Webhook", self.save_alert_webhook)]:
            b = QPushButton(text); b.clicked.connect(fn); r.addWidget(b)
        r.addStretch(1); l.addWidget(row)
        self.quarantine_table = QTableWidget(0, 6); self.quarantine_table.setHorizontalHeaderLabels(["ID","Process","Original Path","Quarantine Path","Status","Created"]); self._style_table(self.quarantine_table)
        self.quarantine_detail = QTextEdit(); self.quarantine_detail.setReadOnly(True)
        l.addWidget(self.quarantine_table); l.addWidget(self.quarantine_detail)
        return w

    def _history_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); s = QSplitter(Qt.Horizontal)
        controls = QWidget(); cr = QHBoxLayout(controls)
        self.incident_status = QComboBox(); self.incident_status.addItems(["open","investigating","contained","closed"])
        self.incident_owner = QLineEdit()
        self.incident_notes = QLineEdit()
        save_incident = QPushButton("Update Incident"); save_incident.clicked.connect(self.update_selected_incident)
        cr.addWidget(QLabel("Status")); cr.addWidget(self.incident_status)
        cr.addWidget(QLabel("Owner")); cr.addWidget(self.incident_owner)
        cr.addWidget(QLabel("Notes")); cr.addWidget(self.incident_notes)
        cr.addWidget(save_incident); cr.addStretch(1)
        l.addWidget(controls)
        self.resp_table = QTableWidget(0, 4); self.resp_table.setHorizontalHeaderLabels(["Timestamp","Action","PID","Process"]); self._style_table(self.resp_table)
        self.tel_table = QTableWidget(0, 5); self.tel_table.setHorizontalHeaderLabels(["ts","cpu","mem","threads","tcp"]); self._style_table(self.tel_table)
        self.inc_table = QTableWidget(0, 5); self.inc_table.setHorizontalHeaderLabels(["Incident ID","Severity","Status","Owner","Title"]); self.inc_table.itemSelectionChanged.connect(self.show_selected_incident); self._style_table(self.inc_table)
        s.addWidget(self.resp_table); s.addWidget(self.tel_table); s.addWidget(self.inc_table); l.addWidget(s); return w

    def _artifacts_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); s = QSplitter(Qt.Horizontal)
        self.art_list = QListWidget(); self.art_list.itemSelectionChanged.connect(self.show_selected_artifact)
        right = QWidget(); rl = QVBoxLayout(right); self.art_detail = QTextEdit(); self.art_detail.setReadOnly(True); open_btn = QPushButton("Open Selected Artifact"); open_btn.clicked.connect(self.open_selected_artifact); rl.addWidget(self.art_detail); rl.addWidget(open_btn)
        s.addWidget(self.art_list); s.addWidget(right); s.setStretchFactor(0, 1); s.setStretchFactor(1, 3); l.addWidget(s); return w

    def _scenario_tab(self) -> QWidget:
        w = QWidget(); l = QVBoxLayout(w); row = QWidget(); r = QHBoxLayout(row)
        self.scenario = QComboBox(); self.scenario.addItems(["balanced","cpu-heavy","network-heavy","file-heavy","memory-heavy"])
        self.scenario_duration = QSpinBox(); self.scenario_duration.setRange(5, 300); self.scenario_duration.setValue(30)
        btn = QPushButton("Run Scenario"); btn.clicked.connect(self.run_scenario); r.addWidget(QLabel("Scenario")); r.addWidget(self.scenario); r.addWidget(QLabel("Duration")); r.addWidget(self.scenario_duration); r.addWidget(btn); r.addStretch(1)
        self.scenario_out = QTextEdit(); self.scenario_out.setReadOnly(True); l.addWidget(row); l.addWidget(self.scenario_out); return w

    def _about_tab(self) -> QWidget:
        w = QWidget(); root = QHBoxLayout(w)
        left_card = QFrame(); left_card.setProperty("card", True); l = QVBoxLayout(left_card)
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
        right_layout = QVBoxLayout(right_card)
        photo_title = QLabel("Creator Profile")
        photo_title.setStyleSheet("font-size:16px;font-weight:700;color:#f4f7fb;")
        photo_sub = QLabel("Ulfat Ibadov")
        photo_sub.setStyleSheet("color:#96a5b8;font-size:12px;")
        profile_image = QLabel()
        image_path = Path(__file__).resolve().parent.parent / "static" / "ulfat-profile.jpg"
        pixmap = QPixmap(str(image_path))
        if not pixmap.isNull():
            profile_image.setPixmap(pixmap.scaled(320, 420, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        profile_image.setAlignment(Qt.AlignCenter)
        right_layout.addWidget(photo_title)
        right_layout.addWidget(photo_sub)
        right_layout.addWidget(profile_image, 1)

        root.addWidget(left_card, 3)
        root.addWidget(right_card, 2)
        return w

    def _url(self, path: str) -> str: return self.base.text().rstrip("/") + path
    def _get(self, path: str, **kwargs): return requests.get(self._url(path), timeout=kwargs.pop("timeout", 20), **kwargs)
    def _post(self, path: str, **kwargs): return requests.post(self._url(path), timeout=kwargs.pop("timeout", 20), **kwargs)
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

    def _field_block(self, label_text: str, widget: QWidget) -> QWidget:
        block = QWidget()
        layout = QVBoxLayout(block)
        layout.setContentsMargins(0, 0, 0, 6)
        layout.setSpacing(5)
        label = QLabel(label_text)
        label.setStyleSheet("color:#d7e2ef;font-size:12px;font-weight:600;")
        if hasattr(widget, "setMinimumHeight"):
            widget.setMinimumHeight(44)
        layout.addWidget(label)
        layout.addWidget(widget)
        return block

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._update_controls_layout()

    def _update_controls_layout(self) -> None:
        available_width = self.width()
        stacked = available_width < 1680
        self.controls_row.setDirection(QBoxLayout.TopToBottom if stacked else QBoxLayout.LeftToRight)
        self.controls_row.setSpacing(14 if stacked else 18)
        self.ops_card.setMinimumWidth(0 if stacked else 620)
        self.advanced_card.setMinimumWidth(0 if stacked else 720)

    def _show_error(self, widget: QTextEdit, title: str, exc: Exception) -> None:
        widget.setPlainText(f"{title}:\n{exc}")
        self.statusBar().showMessage(f"{title}: {exc}")

    def _show_json(self, widget: QTextEdit, payload) -> None:
        widget.setPlainText(json.dumps(payload, indent=2, ensure_ascii=False))

    def _set_health_badge(self, online: bool) -> None:
        color = "#2f9e67" if online else "#d64550"
        text = "API status: online" if online else "API status: offline"
        self.health.setText(text)
        self.health.setStyleSheet(f"background:{color};color:white;padding:6px 10px;border-radius:8px;font-weight:700;")

    def _load_settings(self) -> None:
        raw_buttons = self.settings.value("custom_toolbar_buttons", "[]")
        try:
            self.custom_toolbar_buttons = json.loads(raw_buttons)
        except Exception:
            self.custom_toolbar_buttons = []
        self._rebuild_toolbar()
        self.base.setText(self.settings.value("base", self.base.text()))
        self.duration.setValue(int(self.settings.value("duration", self.duration.value())))
        self.interval.setValue(float(self.settings.value("interval", self.interval.value())))
        self.vt_key.setText(self.settings.value("vt_key", ""))
        self.webhook_url.setText(self.settings.value("webhook_url", ""))
        self.hash_input.setText(self.settings.value("hash_input", ""))
        self.ip_input.setText(self.settings.value("ip_input", ""))
        self.persist_filter.setText(self.settings.value("persist_filter", ""))
        self.strings_min_length.setValue(int(self.settings.value("strings_min_length", self.strings_min_length.value())))
        self.strings_patterns.setText(self.settings.value("strings_patterns", self.strings_patterns.text()))
        saved_pack = self.settings.value("yara_pack", self.yara_pack.currentText())
        idx = self.yara_pack.findText(str(saved_pack))
        if idx >= 0:
            self.yara_pack.setCurrentIndex(idx)
        self.trace_duration.setValue(int(self.settings.value("trace_duration", self.trace_duration.value())))
        self.trace_interval.setValue(float(self.settings.value("trace_interval", self.trace_interval.value())))
        self.honeypot_filename.setText(self.settings.value("honeypot_filename", self.honeypot_filename.text()))
        self.evidence_alert_name.setText(self.settings.value("evidence_alert_name", self.evidence_alert_name.text()))
        self.net_range.setText(self.settings.value("net_range", self.net_range.text()))
        self.block_target.setText(self.settings.value("block_target", ""))
        self.block_gateway.setText(self.settings.value("block_gateway", ""))
        advanced_visible = str(self.settings.value("advanced_visible", "true")).lower() == "true"
        self.advanced_card.setVisible(advanced_visible)
        self.toggle_advanced_btn.setText("Hide Advanced Settings" if advanced_visible else "Show Advanced Settings")

    def _save_settings(self) -> None:
        self.settings.setValue("custom_toolbar_buttons", json.dumps(self.custom_toolbar_buttons))
        self.settings.setValue("base", self.base.text())
        self.settings.setValue("duration", self.duration.value())
        self.settings.setValue("interval", self.interval.value())
        self.settings.setValue("vt_key", self.vt_key.text())
        self.settings.setValue("webhook_url", self.webhook_url.text())
        self.settings.setValue("hash_input", self.hash_input.text())
        self.settings.setValue("ip_input", self.ip_input.text())
        self.settings.setValue("persist_filter", self.persist_filter.text())
        self.settings.setValue("strings_min_length", self.strings_min_length.value())
        self.settings.setValue("strings_patterns", self.strings_patterns.text())
        self.settings.setValue("yara_pack", self.yara_pack.currentText())
        self.settings.setValue("trace_duration", self.trace_duration.value())
        self.settings.setValue("trace_interval", self.trace_interval.value())
        self.settings.setValue("honeypot_filename", self.honeypot_filename.text())
        self.settings.setValue("evidence_alert_name", self.evidence_alert_name.text())
        self.settings.setValue("net_range", self.net_range.text())
        self.settings.setValue("block_target", self.block_target.text())
        self.settings.setValue("block_gateway", self.block_gateway.text())
        self.settings.setValue("advanced_visible", self.advanced_card.isVisible())

    def closeEvent(self, event) -> None:
        self._save_settings()
        super().closeEvent(event)

    def toggle_advanced_settings(self) -> None:
        visible = not self.advanced_card.isVisible()
        self.advanced_card.setVisible(visible)
        self.toggle_advanced_btn.setText("Hide Advanced Settings" if visible else "Show Advanced Settings")

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
        table.horizontalHeader().setStretchLastSection(True)

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
            self._get("/health", timeout=5).raise_for_status()
            self._set_health_badge(True); self.statusBar().showMessage("Connected to backend"); self.refresh_overview()
        except Exception as exc:
            self._set_health_badge(False); self.statusBar().showMessage(f"Backend unavailable: {exc}")

    def refresh_overview(self) -> None:
        self.refresh_history(); self.refresh_artifacts()
        try:
            items = self._get("/processes").json(); self.metric_proc.setText(f"Processes: {len(items)}")
        except Exception: self.metric_proc.setText("Processes: unavailable")

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
        if QMessageBox.question(self, "Confirm Action", f"Run '{action}' on {name} (PID {pid})?") != QMessageBox.Yes: return
        try:
            result = self._post(f"/processes/{pid}/actions/{action}", params={"process_name": name}, timeout=20).json()
            self.statusBar().showMessage(result.get("message", action))
            self.refresh_history()
        except Exception as exc: self.statusBar().showMessage(f"{action} failed: {exc}")

    def scan_selected_process(self) -> None:
        ident = self._selected_identity()
        if not ident or not self.vt_key.text().strip(): self.statusBar().showMessage("Select process and enter VT key"); return
        pid, _ = ident
        try: result = self._post(f"/processes/{pid}/scan", json={"api_key": self.vt_key.text().strip()}, timeout=60).json()
        except Exception as exc: self._show_error(self.threat_out, "Threat scan failed", exc); return
        self._show_json(self.threat_out, result)
        source = "VirusTotal + MalwareBazaar"
        value = str(self.selected_process.get("sha256", "-")) if self.selected_process else f"PID {pid}"
        self._record_threat_history("process", value, source, result)
        self.tabs.setCurrentIndex(4)

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
        self.tabs.setCurrentIndex(2)

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
        self.tabs.setCurrentIndex(2)

    def run_yara_scan(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident: return
        pid, _ = ident
        try:
            result = self._get(f"/processes/{pid}/yara", params={"pack": self.yara_pack.currentText()}, timeout=40).json()
        except Exception as exc:
            self._show_error(self.hunt_out, "YARA scan failed", exc)
            return
        matches = result.get("matches", [])
        self.hunt_out.setPlainText(f"{'MATCHES FOUND' if matches else 'No YARA matches'}\n\nMatches:\n" + ("\n".join(matches) if matches else "None"))
        self.tabs.setCurrentIndex(2)

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
        self.tabs.setCurrentIndex(2)

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
        self.tabs.setCurrentIndex(2)

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
        self.tabs.setCurrentIndex(2)

    def run_auto_triage(self) -> None:
        ident = self._selected_process_or_warn()
        if not ident:
            return
        pid, _ = ident
        payload = {
            "virustotal_api_key": self.vt_key.text().strip() or None,
            "yara_pack": self.yara_pack.currentText(),
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
        self.tabs.setCurrentIndex(2)

    def run_monitor(self) -> None:
        payload = {"duration": self.duration.value(), "interval": self.interval.value()}
        try: result = self._post("/monitor/run", json=payload, timeout=payload["duration"] + 60).json()
        except Exception as exc: self._show_error(self.monitor_out, "Monitor failed", exc); return
        incident = result.get("incident", {})
        self._show_json(self.monitor_out, result)
        self.metric_tel.setText(f"Telemetry Rows: {result.get('telemetry_count','-')}")
        self.metric_inc.setText(f"Last Incident: {incident.get('incident_id','-')}")
        severity = incident.get("severity", "unknown")
        self.metric_inc.setStyleSheet(f"color:{self._severity_color(severity).name()};font-weight:700;")
        self.metric_inc.setText(f"Last Incident: {incident.get('incident_id','-')} ({severity})")
        self.refresh_history(); self.refresh_artifacts(); self.tabs.setCurrentIndex(0)

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
        try: result = self._get(f"/threat-intel/hash/{self.hash_input.text().strip()}").json()
        except Exception as exc: self._show_error(self.threat_out, "Hash lookup failed", exc); return
        self._show_json(self.threat_out, result)
        self._record_threat_history("hash", self.hash_input.text().strip(), "MalwareBazaar", result)
        self.tabs.setCurrentIndex(4)

    def lookup_ip(self) -> None:
        if not self.ip_input.text().strip(): return
        try: result = self._get(f"/threat-intel/ip/{self.ip_input.text().strip()}").json()
        except Exception as exc: self._show_error(self.threat_out, "IP lookup failed", exc); return
        self._show_json(self.threat_out, result)
        self._record_threat_history("ip", self.ip_input.text().strip(), "AbuseIPDB", result)
        self.tabs.setCurrentIndex(4)

    def use_selected_process_hash(self) -> None:
        if not self.selected_process:
            self.statusBar().showMessage("First select a process to auto-fill its hash")
            return
        hash_value = self.selected_process.get("sha256") or ""
        self.hash_input.setText(hash_value)
        self.ti_last_type.setText("Last Query: process hash prepared")
        self.ti_last_value.setText(f"Value: {hash_value[:20]}..." if hash_value else "Value: unavailable")
        self.tabs.setCurrentIndex(4)

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
        self.tabs.setCurrentIndex(4)

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
            for c, value in enumerate([item.get("host",""), item.get("platform",""), item.get("boot_time",""), item.get("api_status",""), item.get("role","")]):
                self.host_table.setItem(r, c, QTableWidgetItem(str(value)))

    def refresh_timeline(self) -> None:
        try:
            items = self._get("/timeline", timeout=20).json()
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
            result = requests.delete(self._url("/network/warfare/block"), timeout=20).json()
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
        self.metric_tel.setText(f"Telemetry Rows: {len(tel)}")
        self.cpu_series.clear()
        for idx, item in enumerate(tel[-60:]):
            self.cpu_series.append(idx, float(item.get("cpu", 0) or 0))
        self.cpu_axis_x.setRange(0, max(1, min(60, len(tel[-60:]))))
        try: incidents = self._get("/incidents").json()
        except Exception: incidents = []
        self.inc_table.setRowCount(len(incidents))
        for r, item in enumerate(incidents):
            values = [item.get("incident_id",""), item.get("severity",""), item.get("status",""), item.get("owner",""), item.get("title","")]
            for c, value in enumerate(values):
                self.inc_table.setItem(r, c, QTableWidgetItem(str(value)))
            self._paint_row(self.inc_table, r, self._severity_color(item.get("severity", "")))
        self.refresh_timeline()
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
            result = requests.patch(self._url(f"/incidents/{incident_id}"), json=payload, timeout=20).json()
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
            result = requests.delete(self._url(f"/quarantine/{quarantine_id}"), timeout=30).json()
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
        self.tabs.setCurrentIndex(5)

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
            result = requests.delete(self._url("/deception/honeypot"), timeout=20).json()
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
            result = requests.delete(self._url("/deception/canary"), timeout=20).json()
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
            result = requests.delete(self._url(f"/evidence/{name}"), timeout=20).json()
        except Exception as exc:
            self._show_error(self.evidence_detail, "Evidence delete failed", exc)
            return
        self._show_json(self.evidence_detail, result)
        self.refresh_evidence()

    def show_selected_artifact(self) -> None:
        items = self.art_list.selectedItems()
        if not items: return
        name = items[0].text()
        self.art_detail.setPlainText(f"Artifact: {name}\nLocal Path: {self.artifacts.get(name,'')}\nDownload URL: {self._url('/artifacts/' + name)}")

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


def main() -> int:
    app = QApplication(sys.argv)
    window = ShadowLabDesktop()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
