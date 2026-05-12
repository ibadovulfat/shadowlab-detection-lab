from __future__ import annotations

import html
import ipaddress
import json
import time
from pathlib import Path

from PySide6.QtCore import QObject, QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

try:
    from _audit_log import AuditLogStore, actor_workspace_pair
except ImportError:  # pragma: no cover
    from desktop._audit_log import AuditLogStore, actor_workspace_pair

try:
    from _audit_mirror import install_backend_mirror as _install_audit_mirror
except ImportError:  # pragma: no cover
    from desktop._audit_mirror import install_backend_mirror as _install_audit_mirror

try:
    from _action_common import ActionGate, ReasonCapture, submit_async_call
except ImportError:  # pragma: no cover
    from desktop._action_common import ActionGate, ReasonCapture, submit_async_call

try:
    from process_hunt_jobs import ProcessWorker as _NetworkWorker
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker as _NetworkWorker


# Server-side accepted network actions. Mirrored client-side so a stray
# button or typo can't reach an undocumented endpoint.
NETWORK_ACTION_ALLOWLIST: frozenset[str] = frozenset({
    "sniff", "arp-scan", "block-start", "block-stop", "hosts-refresh",
    "connections-refresh",
})

# Actions that require a structured reason (ticket + category + narrative).
# ARP scan is intentionally excluded - it's a discovery probe, not a
# state-change.
NETWORK_REASON_REQUIRED: frozenset[str] = frozenset({
    "sniff", "block-start", "block-stop",
})

# Per-action debounce. Network blocker actions are non-idempotent
# (calling Start twice with different gateways would chain the host
# behind two different blockers).
NETWORK_DEBOUNCE_SECONDS = 1.5

NETWORK_AUDIT_RETENTION = 500

# CIDR safety threshold. Anything broader than /16 (65k addresses)
# pegs the backend ARP scanner for hours. Operators almost always
# want /24 (256 addresses) - a /16 default cap is generous.
ARP_SCAN_MIN_PREFIX = 16

# Default sniff duration in seconds when the operator hasn't picked
# one. The legacy default of 1 second was visually misleading
# (capturing nothing useful) and required an extra click before the
# capture button became actionable.
DEFAULT_SNIFF_DURATION = 15
MAX_SNIFF_DURATION = 60

NETWORK_BUTTON_CAPABILITIES: dict[str, str] = {
    "sniff": "can_run_sniffer",
    "arp-scan": "can_run_hunt",
    "block-start": "can_manage_network_warfare",
    "block-stop": "can_manage_network_warfare",
}


class NetworkGraphWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        # Shared audit store (paylaşılan model with Antivirus / Enterprise
        # / Intel / History) - distinct path so Network audit chain
        # is grep-able alone.
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=NETWORK_AUDIT_RETENTION,
        )
        _install_audit_mirror(self._audit_store, app, source_slug="network")
        # Shared action plumbing - same gate/reason/async helpers all
        # consoles will eventually use. Public methods on this controller
        # remain thin facades so existing call sites keep working.
        self._gate = ActionGate(
            allowlist=NETWORK_ACTION_ALLOWLIST,
            debounce_seconds=NETWORK_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        self._reason = ReasonCapture(
            reason_required=NETWORK_REASON_REQUIRED,
            parent=app,
            on_cancel=lambda action: app.statusBar().showMessage(
                f"`{action}` cancelled - structured reason required."
            ),
        )
        # Legacy mirror - tests still touch `_last_action_click` directly.
        # The gate is the source of truth; the dict shadows the gate's
        # internal state for the small number of tests that haven't
        # migrated yet.
        self._last_action_click: dict[str, float] = {}
        self._async_jobs: list[tuple[QThread, _NetworkWorker]] = []
        # Live session state - drives the status banner so the operator
        # can see at a glance "currently sniffing" / "currently blocking".
        self._sniffer_running: bool = False
        self._sniffer_started_at: float = 0.0
        self._sniffer_duration: int = 0
        self._blocker_active: bool = False
        self._blocker_target: str = ""
        self._blocker_gateway: str = ""

    # ------------------------------------------------------------------ #
    # Audit + reason capture (paylaşılan model)
    # ------------------------------------------------------------------ #

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "network-audit-log.json"

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def _capture_reason(self, action: str) -> dict | None:
        # Delegate to the shared `ReasonCapture`. Network always
        # requires a reason for the actions it captures one for, so
        # an empty dict from the helper (action not in
        # NETWORK_REASON_REQUIRED) means the caller decided no reason
        # is needed - which we surface as a sentinel `{}` here too.
        return self._reason.capture(action)

    def _check_action_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. The gate is the source
        # of truth; `_last_action_click` is kept as a legacy mirror
        # for tests that haven't migrated to the gate API yet.
        ok = self._gate.check(action)
        if ok:
            self._last_action_click[action] = time.time()
        return ok

    def _record_audit(
        self,
        *,
        action: str,
        target: str,
        severity: str,
        status: str,
        payload,
        reason: dict | None = None,
    ) -> dict:
        actor, workspace = actor_workspace_pair(self.app)
        return self._audit_store.append(
            category="network",
            action=action,
            target=target,
            severity=severity,
            status=status,
            payload=payload,
            actor=actor,
            workspace=workspace,
            reason=reason,
        )

    def _submit_async(
        self,
        *,
        label: str,
        work,
        on_success,
        on_failure,
        timeout_seconds: int = 60,
    ) -> None:
        """Delegate to the shared `submit_async_call`.

        The job registry threading-safety dance lives in the shared
        helper now. Pass our own list as `job_registry` so PySide
        keeps the (thread, worker) pair alive until the work
        completes - same semantic the inline implementation had.
        """
        submit_async_call(
            parent=self.app,
            label=label,
            work=work,
            on_success=on_success,
            on_failure=on_failure,
            timeout_seconds=timeout_seconds,
            job_registry=self._async_jobs,
        )

    def _update_session_status(self) -> None:
        """Refresh the live session banner labels."""
        app = self.app
        if hasattr(app, "network_sniffer_status"):
            if self._sniffer_running:
                elapsed = max(0, int(time.time() - self._sniffer_started_at))
                remaining = max(0, self._sniffer_duration - elapsed)
                app.network_sniffer_status.setText(f"Sniffer: capturing · {remaining}s left")
                app.network_sniffer_status.setStyleSheet(
                    "background:#2c1f3a;color:#bda4ff;border:1px solid #5d3f8a;"
                    "border-radius:8px;padding:4px 10px;font-size:10px;font-weight:800;"
                )
            else:
                app.network_sniffer_status.setText("Sniffer: idle")
                app.network_sniffer_status.setStyleSheet(
                    "background:#101a24;color:#96a5b8;border:1px solid #243446;"
                    "border-radius:8px;padding:4px 10px;font-size:10px;font-weight:800;"
                )
        if hasattr(app, "network_blocker_status"):
            if self._blocker_active and self._blocker_target:
                app.network_blocker_status.setText(
                    f"Blocker: ACTIVE · {self._blocker_target} via {self._blocker_gateway}"
                )
                app.network_blocker_status.setStyleSheet(
                    "background:#3a1f2c;color:#ff9ab0;border:1px solid #8c2d44;"
                    "border-radius:8px;padding:4px 10px;font-size:10px;font-weight:800;"
                )
            else:
                app.network_blocker_status.setText("Blocker: idle")
                app.network_blocker_status.setStyleSheet(
                    "background:#101a24;color:#96a5b8;border:1px solid #243446;"
                    "border-radius:8px;padding:4px 10px;font-size:10px;font-weight:800;"
                )

    def build_network_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(l, "Network Workspace", "Capture packets, discover ARP devices, inspect connections and control the network blocker.")

        # ------------------------------------------------------------------
        # Live session status banner - sniffer + blocker state. Operator
        # always sees "what's running right now" without scrolling
        # through the network output text. Replaces the previous design
        # where a packet capture in progress was completely invisible.
        # ------------------------------------------------------------------
        status_banner = QFrame(); status_banner.setProperty("card", True)
        status_banner.setStyleSheet(
            "QFrame[card='true']{background:#0e1720;border:1px solid #243446;border-radius:7px;padding:2px 6px;}"
        )
        sb_layout = QHBoxLayout(status_banner)
        sb_layout.setContentsMargins(8, 4, 8, 4); sb_layout.setSpacing(8)
        status_label = QLabel("Live State")
        status_label.setStyleSheet("color:#96a5b8;font-size:9px;font-weight:800;letter-spacing:0.5px;")
        sb_layout.addWidget(status_label)
        app.network_sniffer_status = QLabel("Sniffer: idle")
        app.network_blocker_status = QLabel("Blocker: idle")
        app.network_capture_clock = QLabel("")
        sb_layout.addWidget(app.network_sniffer_status)
        sb_layout.addWidget(app.network_blocker_status)
        sb_layout.addStretch(1)
        l.addWidget(status_banner)
        # Initial paint - sets the idle styles via the helper.
        self._update_session_status()

        # Live ticker for the sniffer countdown - fires every 500 ms
        # while a capture is in flight, no-op when idle.
        app.network_status_timer = QTimer(w)
        app.network_status_timer.setInterval(500)
        app.network_status_timer.timeout.connect(self._update_session_status)
        app.network_status_timer.start()

        # ------------------------------------------------------------------
        # Capture duration + colour-coded action button groups. Same
        # pattern used in Antivirus / Enterprise for visual category
        # affordance.
        # ------------------------------------------------------------------
        controls_row = QWidget(); row = QHBoxLayout(controls_row)
        row.setContentsMargins(0, 0, 0, 0); row.setSpacing(8)
        app.sniff_duration = QSpinBox()
        app.sniff_duration.setRange(5, MAX_SNIFF_DURATION)
        app.sniff_duration.setValue(DEFAULT_SNIFF_DURATION)
        app.sniff_duration.setSuffix(" s")
        app.sniff_duration.setMinimumWidth(80)
        app.sniff_duration.setToolTip("Packet capture duration in seconds. Range 5-60s. Capture is async and writes to the audit chain.")

        sniff = QPushButton("Start Packet Capture"); sniff.clicked.connect(app.run_sniffer)
        scan = QPushButton("ARP Discovery"); scan.clicked.connect(app.scan_network_devices)
        start_block = QPushButton("Start Blocker"); start_block.clicked.connect(app.start_network_blocker)
        stop_block = QPushButton("Stop Blocker"); stop_block.clicked.connect(app.stop_network_blocker)
        refresh_hosts_btn = QPushButton("Refresh Hosts"); refresh_hosts_btn.clicked.connect(app.refresh_hosts)
        refresh_conn_btn = QPushButton("Refresh Connections"); refresh_conn_btn.clicked.connect(app.refresh_network)
        for button, capability in [
            (sniff, NETWORK_BUTTON_CAPABILITIES["sniff"]),
            (scan, NETWORK_BUTTON_CAPABILITIES["arp-scan"]),
            (start_block, NETWORK_BUTTON_CAPABILITIES["block-start"]),
            (stop_block, NETWORK_BUTTON_CAPABILITIES["block-stop"]),
        ]:
            app._bind_capability(button, capability)

        row.addWidget(QLabel("Capture Duration"))
        row.addWidget(app.sniff_duration)
        row.addStretch(1)

        action_row = QWidget()
        action_layout = QHBoxLayout(action_row)
        action_layout.setContentsMargins(0, 0, 0, 0); action_layout.setSpacing(8)
        action_groups: list[tuple[str, str, list]] = [
            ("Capture",    "#5d3f8a", [sniff]),                             # privacy-event purple
            ("Discovery",  "#3a6ea8", [scan]),                              # case-blue
            ("Block",      "#a83a4f", [start_block, stop_block]),           # danger-red
            ("Workspace",  "#5e7493", [refresh_hosts_btn, refresh_conn_btn]),
        ]
        for label_text, accent, buttons in action_groups:
            if not buttons:
                continue
            group = QFrame(); group.setProperty("card", True)
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

        l.addWidget(controls_row)
        l.addWidget(action_row)

        # ------------------------------------------------------------------
        # Connection / Discovery / Output panels (top row) + Host
        # Inventory (bottom). Tables get Expanding policy so the cards
        # fill the panel - same fix Intel needed for QTabWidget.
        # ------------------------------------------------------------------
        app.net_table = QTableWidget(0, 4); app.net_table.setHorizontalHeaderLabels(["Local","Remote","Status","PID"]); app._style_table(app.net_table)
        app.net_table.setMinimumHeight(120)
        app.net_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Right-click on a remote endpoint → "Block this remote IP" so
        # the operator doesn't have to copy/paste into the blocker
        # inputs in Primary Controls.
        app.net_table.setContextMenuPolicy(Qt.CustomContextMenu)
        app.net_table.customContextMenuRequested.connect(self._show_connection_context_menu)
        app.device_table = QTableWidget(0, 3); app.device_table.setHorizontalHeaderLabels(["IP","MAC","Vendor"]); app._style_table(app.device_table)
        app.device_table.setMinimumHeight(120)
        app.device_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.network_host_table = QTableWidget(0, 7); app.network_host_table.setHorizontalHeaderLabels(["Host","Platform","Boot Time","API Status","Role","IP","Version"]); app._style_table(app.network_host_table)
        app.network_host_table.setMinimumHeight(120)
        app.network_host_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.net_out = QTextEdit(); app.net_out.setReadOnly(True); app.net_out.setMinimumHeight(120)
        app.net_out.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        app.net_out.setPlainText("Network actions, packet capture output, ARP discovery, and blocker results will appear here.")

        top_cards = QWidget()
        top_cards_layout = QHBoxLayout(top_cards)
        top_cards_layout.setContentsMargins(0, 0, 0, 0)
        top_cards_layout.setSpacing(8)
        top_cards_layout.addWidget(app._panel_card("Connection Table", app.net_table, lambda: app._open_panel_window("Connection Table", app._clone_table(app.net_table))), 1)
        top_cards_layout.addWidget(app._panel_card("Discovered Devices", app.device_table, lambda: app._open_panel_window("Discovered Devices", app._clone_table(app.device_table))), 1)
        top_cards_layout.addWidget(app._panel_card("Network Output", app.net_out, lambda: app._open_panel_window("Network Output", app._clone_text_view(app.net_out))), 1)
        l.addWidget(top_cards, 1)

        bottom_cards = QWidget()
        bottom_cards_layout = QHBoxLayout(bottom_cards)
        bottom_cards_layout.setContentsMargins(0, 0, 0, 0)
        bottom_cards_layout.setSpacing(8)
        bottom_cards_layout.addWidget(app._panel_card("Host Inventory", app.network_host_table, lambda: app._open_panel_window("Host Inventory", app._clone_table(app.network_host_table))), 1)
        l.addWidget(bottom_cards, 1)

        # ------------------------------------------------------------------
        # Keyboard shortcuts - owned by the tab so they only fire while
        # the analyst is on Network.
        # ------------------------------------------------------------------
        QShortcut(QKeySequence("Ctrl+P"), w).activated.connect(app.run_sniffer)
        QShortcut(QKeySequence("Ctrl+D"), w).activated.connect(app.scan_network_devices)
        QShortcut(QKeySequence("Ctrl+B"), w).activated.connect(app.start_network_blocker)
        QShortcut(QKeySequence("Ctrl+Shift+B"), w).activated.connect(app.stop_network_blocker)
        QShortcut(QKeySequence("Ctrl+R"), w).activated.connect(app.refresh_hosts)
        QShortcut(QKeySequence("Ctrl+L"), w).activated.connect(app.refresh_network)

        return w

    def _show_connection_context_menu(self, point) -> None:
        """Right-click a connection row → Block this remote IP."""
        from PySide6.QtWidgets import QMenu
        app = self.app
        table = app.net_table
        row = table.indexAt(point).row()
        if row < 0:
            return
        table.selectRow(row)
        remote_item = table.item(row, 1)
        remote = remote_item.text() if remote_item else ""
        # Strip port - `1.2.3.4:443` → `1.2.3.4`. IPv6 (with `[::1]:80`)
        # keeps the brackets stripped too.
        remote_ip = remote.split(":")[0].strip("[]") if remote else ""
        if not remote_ip:
            return

        menu = QMenu(table)
        title = menu.addAction(f"Connection · {remote}")
        title.setEnabled(False)
        menu.addSeparator()
        copy_action = menu.addAction(f"Copy remote IP ({remote_ip})")
        prefill_action = menu.addAction("Prefill blocker target with this IP")

        chosen = menu.exec(table.viewport().mapToGlobal(point))
        if chosen is None:
            return
        if chosen is copy_action:
            try:
                from PySide6.QtGui import QGuiApplication
                QGuiApplication.clipboard().setText(remote_ip)
                app.statusBar().showMessage(f"Copied {remote_ip} to clipboard.")
            except Exception:
                pass
        elif chosen is prefill_action and hasattr(app, "block_target"):
            app.block_target.setText(remote_ip)
            app.statusBar().showMessage(f"Blocker target prefilled with {remote_ip}.")

    def build_hosts_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(l, "Fleet Host Inventory", "View and refresh all registered ShadowLab agents and fleet hosts.")
        top = QWidget(); row = QHBoxLayout(top)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        btn = QPushButton("Refresh Hosts"); btn.clicked.connect(app.refresh_hosts); row.addWidget(btn); row.addStretch(1)
        app.host_inventory_table = QTableWidget(0, 7); app.host_inventory_table.setHorizontalHeaderLabels(["Host","Platform","Boot Time","API Status","Role","IP","Version"]); app._style_table(app.host_inventory_table)
        l.addWidget(app._panel_card("Host Actions", top, lambda: app._open_panel_window("Host Actions", QLabel("Use refresh from main workspace."))))
        l.addWidget(app._panel_card("Host Inventory", app.host_inventory_table, lambda: app._open_panel_window("Host Inventory", app._clone_table(app.host_inventory_table))), 1)
        return w

    def build_graph_tab(self) -> QWidget:
        """Product-grade Entity Graph console.

        Layout (matches Security Ops / History posture for consistency):

          1. Tab header.
          2. Header strip - last refreshed timestamp + Refresh All
             shortcut (Ctrl+R).
          3. KPI strip - 5 equal-width chips covering Nodes / Edges /
             Overall Risk / High-Risk Procs / Public Exposure.
          4. Controls row - primary actions grouped by intent.
          5. 3+3 panel grid - overview row + drill-down row.

        Replaces the previous design where the Refresh button was the
        only feedback signal during a 45s graph build, the dashboard
        showed every metric as plain text, and tables exposed no
        sortable/clickable affordances.
        """
        # Import lazily so the build_tab path doesn't choke when this
        # module is loaded for non-graph workflows (e.g. headless tests).
        try:
            from _panel_kit import build_kpi_strip, BusyController, install_empty_table_placeholder
        except ImportError:
            from desktop._panel_kit import build_kpi_strip, BusyController, install_empty_table_placeholder
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(
            l,
            "Entity Graph Workspace",
            "Build and inspect the attack surface entity graph - nodes, edges, exposure, AD context, and process-focused views.",
        )

        # --- (1) Header strip - last-refreshed, workspace badge,
        #          time-window, auto-refresh, Refresh All shortcut.
        from PySide6.QtGui import QKeySequence as _QKeySeq
        from PySide6.QtWidgets import QCheckBox as _QCheck, QComboBox as _QCombo
        header_row = QWidget()
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        self._graph_last_refresh_label = QLabel("Last refreshed: never")
        self._graph_last_refresh_label.setStyleSheet("color:#9aa5b1; font-size:12px;")
        header_layout.addWidget(self._graph_last_refresh_label)

        # Workspace badge — surfaces which tenant the entity graph is
        # being built for. Multi-tenant admins must not silently read
        # tenant-A nodes while logged into tenant-B.
        self._graph_workspace_badge = QLabel("workspace: —")
        self._graph_workspace_badge.setStyleSheet(
            "color:#cbd5e0; background:#1f2933; padding:4px 10px; border-radius:8px;"
            " font-size:11px; font-weight:600;"
        )
        self._graph_workspace_badge.setToolTip("Active workspace for the entity graph build.")
        header_layout.addWidget(self._graph_workspace_badge)

        header_layout.addStretch(1)

        # Time-window selector — affects which slice of telemetry feeds
        # into the graph build. Backends that ignore the parameter keep
        # working as before.
        self._graph_window = _QCombo()
        self._graph_window.addItems(["1h", "24h", "7d", "All"])
        self._graph_window.setCurrentText("24h")
        self._graph_window.setToolTip(
            "Restrict telemetry sources to this rolling window when rebuilding the graph."
        )
        self._graph_window.currentTextChanged.connect(lambda _: app.refresh_entity_graph())
        window_label = QLabel("Window:")
        window_label.setStyleSheet("color:#9aa5b1;font-size:11px;")
        header_layout.addWidget(window_label)
        header_layout.addWidget(self._graph_window)

        # Auto-refresh toggle — opt-in 30s polling, off by default so
        # 45-second graph builds don't pile up.
        self._graph_auto_refresh = _QCheck("Auto-refresh 30s")
        self._graph_auto_refresh.setStyleSheet("color:#cbd5e0;font-size:11px;")
        self._graph_auto_refresh.toggled.connect(self._toggle_graph_auto_refresh)
        header_layout.addWidget(self._graph_auto_refresh)

        refresh_all_btn = QPushButton("Refresh All (Ctrl+R)")
        refresh_all_btn.setShortcut(_QKeySeq("Ctrl+R"))
        refresh_all_btn.clicked.connect(app.refresh_entity_graph)
        app._bind_capability(refresh_all_btn, "can_run_hunt")
        header_layout.addWidget(refresh_all_btn)
        l.addWidget(header_row)

        # --- (2) KPI strip - rendered directly into the tab layout
        #     (no wrapping posture card) so the 80+ px chrome the old
        #     framed surface added is reclaimed for the insight rows
        #     below. Each chip already carries its own "awaiting refresh"
        #     hint, so the separate posture-card title became redundant.
        # Keep the hint label as a private attribute so refresh
        # callbacks that previously cleared `_graph_hint_label` stay
        # no-ops instead of raising AttributeError.
        self._graph_hint_label = QLabel("")
        self._graph_hint_label.setVisible(False)

        kpi_strip, self._graph_kpis = build_kpi_strip(
            w, ("Nodes", "Edges", "Overall Risk", "High-Risk Procs", "Public Exposure")
        )
        l.addWidget(kpi_strip)

        # --- (2b) AD context strip — surfaces server-side _collect_ad_context
        #          which used to be discarded by the UI. Hidden until the
        #          first refresh lands real data so it doesn't take screen
        #          real-estate up-front.
        from PySide6.QtWidgets import QLineEdit, QSpinBox, QSlider, QCheckBox
        self._ad_context_strip = QFrame()
        self._ad_context_strip.setObjectName("adStrip")
        self._ad_context_strip.setStyleSheet(
            "#adStrip { background:#0e1720; border:1px solid #243446; border-radius:8px;"
            " padding:6px 10px; }"
        )
        ad_layout = QHBoxLayout(self._ad_context_strip)
        ad_layout.setContentsMargins(8, 4, 8, 4)
        ad_layout.setSpacing(14)
        ad_title = QLabel("AD CONTEXT")
        ad_title.setStyleSheet(
            "color:#cbd5e0; font-size:11px; letter-spacing:1.2px; font-weight:700;"
        )
        ad_layout.addWidget(ad_title)
        self._ad_domain_label = QLabel("Domain: —")
        self._ad_logon_label = QLabel("Logon Server: —")
        self._ad_user_label = QLabel("User: —")
        self._ad_dc_label = QLabel("DC list: —")
        for lbl in (self._ad_domain_label, self._ad_logon_label, self._ad_user_label, self._ad_dc_label):
            lbl.setStyleSheet("color:#cbd5e0; font-size:12px;")
            ad_layout.addWidget(lbl)
        ad_layout.addStretch(1)
        self._ad_context_strip.setVisible(False)
        l.addWidget(self._ad_context_strip)

        # --- (3) Filter row — search bar, group filter chips, risk
        #          threshold slider, manual PID input. All client-side
        #          so they slice the local copy of the graph without
        #          extra HTTP round-trips.
        filter_card = QFrame()
        filter_card.setObjectName("filterCard")
        filter_card.setStyleSheet(
            "#filterCard { background:#0e1720; border:1px solid #243446; border-radius:8px;"
            " padding:6px 10px; }"
        )
        filter_outer = QVBoxLayout(filter_card)
        filter_outer.setContentsMargins(8, 6, 8, 6)
        filter_outer.setSpacing(6)

        # Row 1: search + risk threshold + PID input.
        filter_row1 = QWidget()
        f1 = QHBoxLayout(filter_row1)
        f1.setContentsMargins(0, 0, 0, 0)
        f1.setSpacing(8)

        search_lbl = QLabel("🔍")
        search_lbl.setStyleSheet("color:#9aa5b1; font-size:12px;")
        self._graph_search = QLineEdit()
        self._graph_search.setPlaceholderText("filter Entity Nodes / Edges / Hot Processes by label, group, or title…")
        self._graph_search.setClearButtonEnabled(True)
        self._graph_search.textChanged.connect(self._apply_graph_filters)
        f1.addWidget(search_lbl)
        f1.addWidget(self._graph_search, 2)

        risk_lbl = QLabel("Risk ≥")
        risk_lbl.setStyleSheet("color:#9aa5b1; font-size:12px;")
        self._risk_threshold = QSpinBox()
        self._risk_threshold.setRange(0, 100)
        self._risk_threshold.setValue(0)
        self._risk_threshold.setSuffix(" pts")
        self._risk_threshold.setToolTip(
            "Hide Entity Nodes / Hot Processes whose risk score falls below this threshold."
        )
        self._risk_threshold.valueChanged.connect(self._apply_graph_filters)
        f1.addWidget(risk_lbl)
        f1.addWidget(self._risk_threshold)

        pid_lbl = QLabel("Focus PID:")
        pid_lbl.setStyleSheet("color:#9aa5b1; font-size:12px;")
        self._focus_pid_input = QSpinBox()
        self._focus_pid_input.setRange(0, 999999)
        self._focus_pid_input.setValue(0)
        self._focus_pid_input.setToolTip(
            "Type a PID and click Focus to rebuild the graph centred on that process."
        )
        focus_pid_btn = QPushButton("Focus")
        focus_pid_btn.setMaximumWidth(70)
        focus_pid_btn.setToolTip("Rebuild the entity graph focused on the PID typed to the left.")
        focus_pid_btn.clicked.connect(self._on_focus_pid_clicked)
        app._bind_capability(focus_pid_btn, "can_run_hunt")
        f1.addWidget(pid_lbl)
        f1.addWidget(self._focus_pid_input)
        f1.addWidget(focus_pid_btn)
        filter_outer.addWidget(filter_row1)

        # Row 2: group filter chips (process / host / domain / connection / persistence).
        filter_row2 = QWidget()
        f2 = QHBoxLayout(filter_row2)
        f2.setContentsMargins(0, 0, 0, 0)
        f2.setSpacing(6)
        group_lbl = QLabel("GROUPS")
        group_lbl.setStyleSheet("color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;")
        f2.addWidget(group_lbl)
        self._group_filter_chips: dict[str, QCheckBox] = {}
        for slug in ("process", "host", "domain", "connection", "persistence", "incident"):
            chk = QCheckBox(slug.title())
            chk.setChecked(True)
            chk.setStyleSheet(
                "QCheckBox { color:#cbd5e0; font-size:11px; padding:2px 6px; }"
                "QCheckBox::indicator { width:12px; height:12px; }"
            )
            chk.toggled.connect(self._apply_graph_filters)
            self._group_filter_chips[slug] = chk
            f2.addWidget(chk)
        f2.addStretch(1)
        clear_filters_btn = QPushButton("Reset Filters")
        clear_filters_btn.setMaximumWidth(110)
        clear_filters_btn.clicked.connect(self._reset_graph_filters)
        f2.addWidget(clear_filters_btn)
        filter_outer.addWidget(filter_row2)

        l.addWidget(filter_card)

        # --- (4) Controls row.
        top = QWidget(); row = QHBoxLayout(top)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        top.setMinimumHeight(36)
        top.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        refresh_btn = QPushButton("Refresh Entity Graph"); refresh_btn.clicked.connect(app.refresh_entity_graph)
        focus_btn = QPushButton("Build From Selected Process"); focus_btn.clicked.connect(app.refresh_selected_process_graph)
        # "Open Interactive Graph" routes through the embedded
        # QWebEngineView drawer first; the helper falls back to the
        # external browser if QtWebEngine isn't installed.
        open_btn = QPushButton("Open Interactive Graph")
        open_btn.setToolTip(
            "Render the pyvis interactive graph in an embedded drawer. "
            "Falls back to the external browser if QtWebEngine is unavailable."
        )
        open_btn.clicked.connect(self.open_embedded_interactive_graph)
        # Snapshot lifecycle — save the live graph to disk so two refreshes
        # can be diffed without an external scripting harness.
        snapshot_save_btn = QPushButton("Save Snapshot")
        snapshot_save_btn.setToolTip("Persist the current entity graph (with redacted secrets) to disk for later diff.")
        snapshot_save_btn.clicked.connect(self._save_graph_snapshot)
        snapshot_diff_btn = QPushButton("Diff vs Snapshot")
        snapshot_diff_btn.setToolTip("Show added / removed nodes and edges between a saved snapshot and the live graph.")
        snapshot_diff_btn.clicked.connect(self._diff_graph_snapshot)
        for btn in [refresh_btn, focus_btn, open_btn, snapshot_save_btn, snapshot_diff_btn]:
            app._bind_capability(btn, "can_run_hunt")
            btn.setMaximumWidth(220)
            row.addWidget(btn)
        row.addStretch(1)
        l.addWidget(top)
        # Centralised busy controller so the next refresh disables the
        # whole action row + Refresh-All + per-row interactions in unison.
        self._graph_busy = BusyController(
            app, [refresh_all_btn, refresh_btn, focus_btn, open_btn, snapshot_save_btn, snapshot_diff_btn],
        )

        # --- (4) Panels.
        # Minimum-height values are tuned so the full 3-row insight grid
        # (Summary/Findings/Detail + Hot/Nodes/Edges + Group/Legend)
        # fits inside a single 1080p viewport without scrolling. The
        # rows below still stretch to fill any extra space on bigger
        # displays via the addWidget stretch factor.
        app.graph_summary = QTextBrowser(); app.graph_summary.setMinimumHeight(120)
        app.graph_summary.setHtml(
            "<div style='padding:6px'>"
            "<h3 style='margin:0 0 6px 0;color:#cbd5e0'>Attack Surface Graph</h3>"
            "<p style='color:#9aa5b1;line-height:1.45;margin:0'>"
            "Press <b>Refresh All</b> (Ctrl+R) to build the entity graph from live telemetry. "
            "Once nodes, edges, exposure, and AD context have been collected, this card surfaces "
            "the headline summary; the KPI strip above will fill in too."
            "</p></div>"
        )
        app.graph_findings = QTextBrowser(); app.graph_findings.setMinimumHeight(120)
        app.graph_findings.setHtml(
            "<div style='padding:6px'>"
            "<h3 style='margin:0 0 6px 0;color:#cbd5e0'>Priority Findings</h3>"
            "<p style='color:#9aa5b1;margin:0'>No findings yet - refresh to surface attack-surface anomalies, exposed services, and high-risk parent chains.</p>"
            "</div>"
        )
        app.graph_focus_table = QTableWidget(0, 4); app.graph_focus_table.setHorizontalHeaderLabels(["Process","PID","Risk","Signature"]); app._style_table(app.graph_focus_table)
        app.graph_focus_table.setMinimumHeight(130)
        app.graph_focus_table.setSortingEnabled(True)
        # Double-click on a hot process row → rebuild focused graph for that PID.
        app.graph_focus_table.cellDoubleClicked.connect(self._on_focus_table_double_click)
        app.graph_focus_table.setToolTip("Double-click any row to rebuild a process-focused graph for that PID")
        install_empty_table_placeholder(
            app.graph_focus_table,
            "No hot processes yet - refresh the graph to compute risk scores.",
        )
        app.graph_group_table = QTableWidget(0, 2); app.graph_group_table.setHorizontalHeaderLabels(["Group","Count"]); app._style_table(app.graph_group_table)
        app.graph_group_table.setMinimumHeight(110)
        app.graph_group_table.setMaximumHeight(160)
        app.graph_group_table.setSortingEnabled(True)
        app.graph_nodes_table = QTableWidget(0, 6)
        app.graph_nodes_table.setHorizontalHeaderLabels(["Label","Group","Cluster","Risk","MITRE","Title"])
        app._style_table(app.graph_nodes_table)
        app.graph_nodes_table.setSortingEnabled(True)
        # Row-click on Entity Nodes pops the risk-score breakdown so the
        # operator doesn't have to scroll through raw JSON to learn why
        # a node is rated where it is.
        app.graph_nodes_table.cellDoubleClicked.connect(self._on_entity_node_double_click)
        app.graph_nodes_table.setToolTip("Double-click any node to see its risk-score breakdown.")
        app.graph_edges_table = QTableWidget(0, 4); app.graph_edges_table.setHorizontalHeaderLabels(["From","To","Label","Width"]); app._style_table(app.graph_edges_table)
        app.graph_edges_table.setSortingEnabled(True)
        app.graph_nodes_table.setMinimumHeight(130)
        app.graph_edges_table.setMinimumHeight(130)
        install_empty_table_placeholder(
            app.graph_nodes_table,
            "No entity nodes yet - refresh to populate.",
        )
        install_empty_table_placeholder(
            app.graph_edges_table,
            "No edges yet - refresh to populate.",
        )
        app.graph_detail = QTextEdit(); app.graph_detail.setReadOnly(True); app.graph_detail.setMinimumHeight(120)
        app.graph_detail.setPlainText("Raw graph JSON will appear here after Refresh - secrets in the payload are auto-redacted.")

        summary_row = QWidget()
        summary_row_layout = QHBoxLayout(summary_row)
        summary_row_layout.setContentsMargins(0, 0, 0, 0)
        summary_row_layout.setSpacing(8)
        summary_row_layout.addWidget(app._panel_card("Graph Summary", app.graph_summary, lambda: app._open_panel_window("Graph Summary", app._clone_text_view(app.graph_summary))), 1)
        summary_row_layout.addWidget(app._panel_card("Priority Findings", app.graph_findings, lambda: app._open_panel_window("Priority Findings", app._clone_text_view(app.graph_findings))), 1)
        summary_row_layout.addWidget(app._panel_card("Graph Detail", app.graph_detail, lambda: app._open_panel_window("Graph Detail", app._clone_text_view(app.graph_detail))), 1)
        l.addWidget(summary_row, 1)

        # Render the previously-orphaned group counts table — `graph_group_table`
        # used to be instantiated but never wired into a card, so the
        # process / host / domain counts the server returned were thrown
        # away on every refresh.
        install_empty_table_placeholder(
            app.graph_group_table,
            "No group counts yet - refresh to populate.",
        )

        insights_row = QWidget()
        insights_row_layout = QHBoxLayout(insights_row)
        insights_row_layout.setContentsMargins(0, 0, 0, 0)
        insights_row_layout.setSpacing(8)
        insights_row_layout.addWidget(app._panel_card("Hot Processes", app.graph_focus_table, lambda: app._open_panel_window("Hot Processes", app._clone_table(app.graph_focus_table))), 1)
        insights_row_layout.addWidget(app._panel_card("Entity Nodes", app.graph_nodes_table, lambda: app._open_panel_window("Entity Nodes", app._clone_table(app.graph_nodes_table))), 1)
        insights_row_layout.addWidget(app._panel_card("Entity Edges", app.graph_edges_table, lambda: app._open_panel_window("Entity Edges", app._clone_table(app.graph_edges_table))), 1)
        l.addWidget(insights_row, 1)

        # Third row — group counts (revived) + cluster legend, side by
        # side. Keeps the previous 3+3 grid intact while exposing the
        # second insight surface.
        third_row = QWidget()
        third_row_layout = QHBoxLayout(third_row)
        third_row_layout.setContentsMargins(0, 0, 0, 0)
        third_row_layout.setSpacing(8)
        third_row_layout.addWidget(
            app._panel_card("Group Counts", app.graph_group_table,
                            lambda: app._open_panel_window("Group Counts", app._clone_table(app.graph_group_table))),
            1,
        )
        third_row_layout.addWidget(self._build_cluster_legend(), 2)
        l.addWidget(third_row, 0)
        return w

    # ------------------------------------------------------------------ #
    # P1 helpers: skeleton, anomaly flash, percentile, graph age
    # ------------------------------------------------------------------ #

    def _render_graph_skeleton_rows(self) -> None:
        """Replace empty placeholders with shimmer rows during refresh.

        Without this, the four insight tables look identical to the
        empty-state placeholders the operator just left, so a 45-second
        graph build feels stuck. Skeleton rows are non-selectable grey
        dots; real data overwrites them on render.
        """
        app = self.app
        for table, cols in (
            (app.graph_focus_table, 4),
            (app.graph_nodes_table, 6),
            (app.graph_edges_table, 4),
            (app.graph_group_table, 2),
        ):
            try:
                table.clearSpans()
                table.setSortingEnabled(False)
                table.setRowCount(3)
                for r in range(3):
                    for c in range(cols):
                        item = QTableWidgetItem("· · ·")
                        item.setForeground(QColor("#3a4452"))
                        item.setFlags(item.flags() & ~Qt.ItemIsEditable & ~Qt.ItemIsSelectable)
                        table.setItem(r, c, item)
            except Exception:
                continue

    def _flash_anomaly(self, labels: set[str]) -> None:
        """Briefly paint newly-appeared high-risk node rows yellow."""
        if not labels:
            return
        table = self.app.graph_nodes_table
        rows_to_flash: list[int] = []
        for r in range(table.rowCount()):
            item = table.item(r, 0)
            if item and item.text() in labels:
                rows_to_flash.append(r)
        if not rows_to_flash:
            return
        original_colors: list[tuple[int, list]] = []
        from PySide6.QtGui import QBrush as _QBrush
        flash_brush = _QBrush(QColor("#f6e05e"))
        for r in rows_to_flash:
            row_originals = []
            for c in range(table.columnCount()):
                cell = table.item(r, c)
                if cell is None:
                    row_originals.append(None)
                    continue
                row_originals.append(cell.background())
                cell.setBackground(flash_brush)
            original_colors.append((r, row_originals))

        def _restore():
            for r, originals in original_colors:
                for c, brush in enumerate(originals):
                    cell = table.item(r, c)
                    if cell is not None and brush is not None:
                        cell.setBackground(brush)
        QTimer.singleShot(1200, _restore)
        # Status banner pings the operator about the anomaly.
        self.app.statusBar().showMessage(
            f"⚠ New high-risk node(s) detected: {', '.join(sorted(labels)[:3])}", 6000,
        )

    def _risk_percentile_hint(self, overall_risk: int) -> str:
        """Approximate percentile placement for the overall risk score.

        Calibrated against the integer 0-100 surface the server emits.
        Three coarse bands match how SOC dashboards routinely describe
        risk: 'low / typical', 'elevated', 'critical'. Exact percentile
        ranking would require a per-tenant baseline endpoint; this
        approximation is honest about its origin in its label.
        """
        if overall_risk < 25:
            return "low band (≈ bottom 30%)"
        if overall_risk < 45:
            return "typical band (≈ middle 40%)"
        if overall_risk < 75:
            return "elevated (≈ top 25%)"
        return "critical (≈ top 10%)"

    def _format_graph_age(self, built_at) -> str:
        """`13s ago` / `4m ago` for the server-supplied build timestamp."""
        if not built_at:
            return "just now"
        try:
            seconds = max(0, int(time.time() - float(built_at)))
        except (TypeError, ValueError):
            return ""
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"

    def open_embedded_interactive_graph(self) -> None:
        """Render the pyvis interactive graph inside an in-app drawer.

        Falls back to `app.open_entity_graph()` (external browser) when
        `PySide6.QtWebEngineWidgets` isn't installed in the runtime.
        Keeping the embedded view in a separate `QDialog` (vs. a panel
        on the tab) means the Graph tab stays scrollable on smaller
        screens and the operator can pop the chart side-by-side with
        the underlying tables.
        """
        app = self.app
        graph = getattr(app, "entity_graph", {}) or {}
        html_path = graph.get("html_path")
        if not html_path:
            # No live graph yet — trigger a refresh, then re-enter.
            app.statusBar().showMessage("Building entity graph first…", 4000)
            app.refresh_entity_graph()
            graph = getattr(app, "entity_graph", {}) or {}
            html_path = graph.get("html_path")
            if not html_path:
                app.statusBar().showMessage("Graph HTML still unavailable - check Refresh output.", 6000)
                return
        try:
            from PySide6.QtWebEngineWidgets import QWebEngineView
            from PySide6.QtCore import QUrl as _QUrl
        except ImportError:
            # Graceful degradation — open in the system browser the
            # operator already has policy controls around.
            app.statusBar().showMessage("QtWebEngine missing — opening in external browser.", 5000)
            app.open_entity_graph()
            return
        # Reuse the dialog across opens so an existing window flashes to
        # the foreground instead of stacking ten copies on top.
        existing = getattr(self, "_embedded_graph_dialog", None)
        if existing is not None and existing.isVisible():
            existing.raise_()
            existing.activateWindow()
            existing.findChild(QWebEngineView).load(_QUrl.fromLocalFile(html_path))
            return
        from PySide6.QtWidgets import QDialog as _QDialog, QVBoxLayout as _QV, QHBoxLayout as _QH, QPushButton as _QBtn
        dlg = _QDialog(app)
        dlg.setWindowTitle("Entity Graph — Interactive")
        dlg.setModal(False)
        dlg.resize(1280, 820)
        layout = _QV(dlg)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        # Toolbar above the embedded view: Reload, Open Externally.
        toolbar = _QH()
        toolbar.setContentsMargins(0, 0, 0, 0)
        toolbar.setSpacing(8)
        view = QWebEngineView(dlg)
        view.load(_QUrl.fromLocalFile(html_path))
        reload_btn = _QBtn("Rebuild + Reload")
        reload_btn.setToolTip("Run Refresh Entity Graph again and reload the embedded view.")

        def _reload():
            app.refresh_entity_graph()
            new_path = (getattr(app, "entity_graph", {}) or {}).get("html_path") or html_path
            view.load(_QUrl.fromLocalFile(new_path))
        reload_btn.clicked.connect(_reload)
        toolbar.addWidget(reload_btn)
        external_btn = _QBtn("Open Externally")
        external_btn.clicked.connect(app.open_entity_graph)
        toolbar.addWidget(external_btn)
        toolbar.addStretch(1)
        info = QLabel(f"Source: {html_path}")
        info.setStyleSheet("color:#9aa5b1;font-size:11px;")
        toolbar.addWidget(info)
        layout.addLayout(toolbar)
        layout.addWidget(view, 1)
        dlg.show()
        self._embedded_graph_dialog = dlg

    def _save_graph_snapshot(self) -> None:
        """Persist the current entity graph to a JSON file the operator picks."""
        app = self.app
        graph = getattr(app, "entity_graph", None)
        if not graph:
            app._show_error(app.graph_detail, "Snapshot failed", Exception("No entity graph in memory — refresh first."))
            return
        from PySide6.QtWidgets import QFileDialog
        default_path = f"shadowlab_out/graph_snapshot_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(app, "Save Entity Graph Snapshot", default_path, "JSON (*.json)")
        if not path:
            return
        try:
            from _panel_kit import redact_payload as _redact
        except ImportError:
            from desktop._panel_kit import redact_payload as _redact
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(_redact(graph), handle, indent=2, ensure_ascii=False, default=str)
            app.statusBar().showMessage(f"Snapshot saved: {path}", 6000)
        except Exception as exc:
            app._show_error(app.graph_detail, "Snapshot save failed", exc)

    def _diff_graph_snapshot(self) -> None:
        """Compare the live graph against a previously-saved snapshot file."""
        app = self.app
        live = getattr(app, "entity_graph", None)
        if not live:
            app._show_error(app.graph_detail, "Diff failed", Exception("Refresh the graph first."))
            return
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(app, "Open Snapshot for Diff", "shadowlab_out/", "JSON (*.json)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                snapshot = json.load(handle)
        except Exception as exc:
            app._show_error(app.graph_detail, "Snapshot load failed", exc)
            return
        live_nodes = {str(n.get("label", "")): n for n in live.get("nodes", [])}
        snap_nodes = {str(n.get("label", "")): n for n in snapshot.get("nodes", [])}
        added = sorted(set(live_nodes) - set(snap_nodes))
        removed = sorted(set(snap_nodes) - set(live_nodes))
        risk_deltas: list[tuple[str, float, float]] = []
        for label in set(live_nodes) & set(snap_nodes):
            try:
                live_risk = float(live_nodes[label].get("risk_score", 0) or 0)
                snap_risk = float(snap_nodes[label].get("risk_score", 0) or 0)
            except (TypeError, ValueError):
                continue
            if abs(live_risk - snap_risk) >= 5:  # only surface meaningful drift
                risk_deltas.append((label, snap_risk, live_risk))
        live_edges = {
            f"{e.get('from','?')}|{e.get('to','?')}|{e.get('label','')}": e
            for e in live.get("edges", [])
        }
        snap_edges = {
            f"{e.get('from','?')}|{e.get('to','?')}|{e.get('label','')}": e
            for e in snapshot.get("edges", [])
        }
        edges_added = sorted(set(live_edges) - set(snap_edges))
        edges_removed = sorted(set(snap_edges) - set(live_edges))

        # Render readable summary into graph_detail.
        lines = [
            "═══ Entity Graph Diff ═══",
            f"Snapshot:   {path}",
            f"Snapshot at: {self._format_graph_age(snapshot.get('built_at', 0)) or 'unknown'}",
            "",
            f"Nodes added   ({len(added):3d}):",
            *[f"  + {item}" for item in added[:25]],
            (f"  … (+{len(added) - 25} more)" if len(added) > 25 else ""),
            "",
            f"Nodes removed ({len(removed):3d}):",
            *[f"  - {item}" for item in removed[:25]],
            (f"  … (+{len(removed) - 25} more)" if len(removed) > 25 else ""),
            "",
            f"Risk drift    ({len(risk_deltas):3d}):",
            *[f"  ~ {label}: {old:.0f} -> {new:.0f} (Δ {new - old:+.0f})"
              for label, old, new in sorted(risk_deltas, key=lambda x: -abs(x[2] - x[1]))[:15]],
            "",
            f"Edges added   ({len(edges_added):3d}):",
            *[f"  + {item}" for item in edges_added[:15]],
            "",
            f"Edges removed ({len(edges_removed):3d}):",
            *[f"  - {item}" for item in edges_removed[:15]],
        ]
        app.graph_detail.setPlainText("\n".join(l for l in lines if l is not None))
        app.statusBar().showMessage(
            f"Diff: +{len(added)} nodes / -{len(removed)} nodes / {len(risk_deltas)} risk drift",
            8000,
        )

    def _render_empty_state_cta(self) -> None:
        """Replace the Priority Findings card with a step-by-step CTA when
        the graph build returned no nodes. Pre-existing copy was a single
        sentence; an analyst landing here cold needs a concrete recipe."""
        self.app.graph_findings.setHtml(
            "<div style='padding:6px'>"
            "<h3 style='margin:0 0 6px 0;color:#cbd5e0'>How to populate this view</h3>"
            "<ol style='color:#cbd5e0; line-height:1.6; padding-left:18px; margin:0'>"
            "<li>Open the <b>Processes</b> tab and pick a process row.</li>"
            "<li>Return here and click <b>Build From Selected Process</b>.</li>"
            "<li>Or type a PID in the Focus PID box and press <b>Focus</b>.</li>"
            "<li>For the unfocused workspace view, click <b>Refresh Entity Graph</b>.</li>"
            "</ol>"
            "<p style='color:#9aa5b1;margin-top:8px;font-size:11px;font-style:italic'>"
            "Telemetry, history, and persistence rows feed the graph; collect them first if this stays empty.</p>"
            "</div>"
        )

    # ------------------------------------------------------------------ #
    # Header helpers (workspace badge, auto-refresh, time window)
    # ------------------------------------------------------------------ #

    def _toggle_graph_auto_refresh(self, checked: bool) -> None:
        """Start / stop a 30s polling timer for the entity graph."""
        if not hasattr(self, "_graph_auto_refresh_timer"):
            self._graph_auto_refresh_timer = QTimer(self.app)
            self._graph_auto_refresh_timer.setInterval(30000)
            self._graph_auto_refresh_timer.timeout.connect(self.app.refresh_entity_graph)
        if checked:
            self._graph_auto_refresh_timer.start()
            self.app.statusBar().showMessage("Graph auto-refresh enabled (30s)", 4000)
        else:
            self._graph_auto_refresh_timer.stop()
            self.app.statusBar().showMessage("Graph auto-refresh disabled", 4000)

    def _update_graph_workspace_badge(self) -> None:
        try:
            workspace_id = ""
            if hasattr(self.app, "workspace_id") and hasattr(self.app.workspace_id, "text"):
                workspace_id = self.app.workspace_id.text().strip()
            workspace_id = workspace_id or (
                getattr(self.app, "current_auth_context", {}) or {}
            ).get("workspace_id", "default")
            self._graph_workspace_badge.setText(f"workspace: {workspace_id}")
        except Exception:
            self._graph_workspace_badge.setText("workspace: default")

    def _current_graph_window(self) -> str:
        try:
            return self._graph_window.currentText()
        except AttributeError:
            return "24h"

    # ------------------------------------------------------------------ #
    # Filter + drill-down helpers (P0 upgrades)
    # ------------------------------------------------------------------ #

    def _apply_graph_filters(self) -> None:
        """Hide/show rows in Entity Nodes, Hot Processes, and Entity Edges
        according to the live filter row state (search text, risk threshold,
        group checkboxes). Client-side only — no extra HTTP round-trip."""
        app = self.app
        needle = (self._graph_search.text() if hasattr(self, "_graph_search") else "").strip().lower()
        threshold = int(self._risk_threshold.value()) if hasattr(self, "_risk_threshold") else 0
        active_groups = {
            slug for slug, chk in getattr(self, "_group_filter_chips", {}).items()
            if chk.isChecked()
        }

        def _row_matches(text_cols: list[str], risk_val: float, group_val: str) -> bool:
            if needle and not any(needle in t.lower() for t in text_cols):
                return False
            if risk_val < threshold:
                return False
            if active_groups and group_val and group_val.lower() not in active_groups:
                return False
            return True

        # Entity Nodes — columns: Label, Group, Cluster, Risk, MITRE, Title.
        nt = app.graph_nodes_table
        for r in range(nt.rowCount()):
            label = nt.item(r, 0).text() if nt.item(r, 0) else ""
            group = nt.item(r, 1).text() if nt.item(r, 1) else ""
            try:
                risk = float(nt.item(r, 3).text()) if nt.item(r, 3) else 0.0
            except (ValueError, AttributeError):
                risk = 0.0
            mitre = nt.item(r, 4).text() if nt.item(r, 4) else ""
            title = nt.item(r, 5).text() if nt.item(r, 5) else ""
            nt.setRowHidden(r, not _row_matches([label, group, mitre, title], risk, group))

        # Hot Processes — columns: Process, PID, Risk, Signature.
        ft = app.graph_focus_table
        for r in range(ft.rowCount()):
            proc = ft.item(r, 0).text() if ft.item(r, 0) else ""
            pid = ft.item(r, 1).text() if ft.item(r, 1) else ""
            sig = ft.item(r, 3).text() if ft.item(r, 3) else ""
            try:
                risk = float(ft.item(r, 2).text()) if ft.item(r, 2) else 0.0
            except (ValueError, AttributeError):
                risk = 0.0
            # Hot Processes are inherently the "process" group.
            ft.setRowHidden(r, not _row_matches([proc, pid, sig], risk, "process"))

        # Entity Edges — search-only (no risk column).
        et = app.graph_edges_table
        for r in range(et.rowCount()):
            cols = [et.item(r, c).text() if et.item(r, c) else "" for c in range(et.columnCount())]
            if needle and not any(needle in t.lower() for t in cols):
                et.setRowHidden(r, True)
            else:
                et.setRowHidden(r, False)

    def _reset_graph_filters(self) -> None:
        """Wipe search text, drop risk threshold to 0, re-check every group."""
        if hasattr(self, "_graph_search"):
            self._graph_search.clear()
        if hasattr(self, "_risk_threshold"):
            self._risk_threshold.setValue(0)
        for chk in getattr(self, "_group_filter_chips", {}).values():
            chk.setChecked(True)
        self._apply_graph_filters()

    def _on_focus_pid_clicked(self) -> None:
        """Handler for the manual 'Focus PID' button — rebuild graph for typed PID."""
        try:
            pid = int(self._focus_pid_input.value())
        except Exception:
            return
        if pid <= 0:
            self.app.statusBar().showMessage("Enter a PID > 0 to focus the graph.", 4000)
            return
        self.app.statusBar().showMessage(f"Rebuilding graph focused on PID {pid}…", 4000)
        self.app.refresh_entity_graph(pid)

    def _on_entity_node_double_click(self, row: int, _col: int) -> None:
        """Surface the risk-score breakdown for the double-clicked node.

        Reads the latest `app.entity_graph` payload to find the node by
        its label, then composes a readable summary of every input that
        contributed to its risk score (signature, parent chain, network
        exposure, cluster, MITRE techniques where present).
        """
        app = self.app
        try:
            label = app.graph_nodes_table.item(row, 0).text()
        except AttributeError:
            return
        graph = getattr(app, "entity_graph", {}) or {}
        node = next((n for n in graph.get("nodes", []) if str(n.get("label", "")) == label), None)
        if node is None:
            return
        # Compose the breakdown text.
        lines: list[str] = [f"<h3>{html.escape(str(node.get('label', label)))}</h3>"]
        lines.append("<table cellpadding='3' style='font-size:12px;color:#cbd5e0'>")
        for key in ("group", "cluster", "risk_score", "title", "signature_status", "remote_exposure"):
            if key in node:
                lines.append(
                    f"<tr><td><b>{html.escape(key)}</b></td><td>{html.escape(str(node[key]))[:240]}</td></tr>"
                )
        lines.append("</table>")
        contributors = node.get("risk_breakdown") or node.get("risk_contributors") or []
        if isinstance(contributors, list) and contributors:
            lines.append("<h4 style='margin-top:8px'>Risk contributors</h4><ul>")
            for item in contributors[:20]:
                lines.append(f"<li>{html.escape(str(item))}</li>")
            lines.append("</ul>")
        mitre = node.get("mitre_techniques") or []
        if mitre:
            lines.append(
                "<h4 style='margin-top:8px'>MITRE ATT&amp;CK</h4><p>" +
                ", ".join(html.escape(str(t)) for t in mitre[:12]) + "</p>"
            )
        # Edges touching this node.
        related = [
            edge for edge in graph.get("edges", [])
            if str(edge.get("from", "")) == label or str(edge.get("to", "")) == label
        ]
        if related:
            lines.append("<h4 style='margin-top:8px'>Connected edges</h4><ul>")
            for edge in related[:15]:
                arrow = f"{edge.get('from')} → {edge.get('to')}"
                lines.append(f"<li>{html.escape(arrow)} ({html.escape(str(edge.get('label', '')))})</li>")
            lines.append("</ul>")
        dlg = QMessageBox(self.app)
        dlg.setWindowTitle(f"Risk Breakdown — {label}")
        dlg.setTextFormat(Qt.RichText)
        dlg.setIcon(QMessageBox.Information)
        dlg.setText("\n".join(lines))
        dlg.setStandardButtons(QMessageBox.Close)
        dlg.exec()

    def _build_cluster_legend(self) -> QWidget:
        """Static colour-key card so operators can read the node palette."""
        from PySide6.QtWidgets import QFrame as _QFrame
        card = _QFrame()
        card.setObjectName("legendCard")
        card.setStyleSheet(
            "#legendCard { background:#0e1720; border:1px solid #243446; border-radius:8px; padding:6px 10px; }"
        )
        card.setMaximumHeight(160)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(6, 4, 6, 6)
        layout.setSpacing(2)
        title = QLabel("CLUSTER LEGEND")
        title.setStyleSheet("color:#cbd5e0; font-size:11px; letter-spacing:1.2px; font-weight:700;")
        layout.addWidget(title)
        entries = [
            ("#5c7cfa", "Domain / Logon servers"),
            ("#748ffc", "Domain controllers"),
            ("#a83a4f", "High-risk processes (≥75)"),
            ("#e0a640", "Medium-risk processes (45-74)"),
            ("#3a6ea8", "Hosts / Endpoints"),
            ("#f08c00", "Active network edges"),
            ("#5d3f8a", "Persistence anchors"),
            ("#bda4ff", "Incident links"),
        ]
        legend_row = QHBoxLayout()
        legend_row.setContentsMargins(0, 0, 0, 0)
        legend_row.setSpacing(8)
        from PySide6.QtWidgets import QGridLayout as _QGrid
        grid = _QGrid()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)
        for idx, (colour, label_text) in enumerate(entries):
            dot = QLabel("●")
            dot.setStyleSheet(f"color:{colour}; font-size:14px;")
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color:#cbd5e0; font-size:11px;")
            r, c = divmod(idx, 4)
            grid.addWidget(dot, r, c * 2)
            grid.addWidget(lbl, r, c * 2 + 1)
        layout.addLayout(grid)
        return card

    def _update_ad_context_strip(self, ad: dict, summary: dict) -> None:
        """Reveal + populate the AD context strip from server payload."""
        domain = str(summary.get("domain") or ad.get("domain") or "n/a")
        logon = str(ad.get("logon_server") or "n/a")
        user = str(ad.get("user") or "n/a")
        dcs = ad.get("domain_controllers", []) or []
        dc_text = ", ".join(str(d) for d in dcs[:3]) + (f" (+{len(dcs)-3} more)" if len(dcs) > 3 else "")
        self._ad_domain_label.setText(f"Domain: {domain}")
        self._ad_logon_label.setText(f"Logon Server: {logon}")
        self._ad_user_label.setText(f"User: {user}")
        self._ad_dc_label.setText(f"DC list: {dc_text or '—'}")
        # Show only when at least one field is populated meaningfully.
        meaningful = any(v not in {"n/a", "", "—"} for v in (domain, logon, user, dc_text))
        self._ad_context_strip.setVisible(meaningful)

    def _on_focus_table_double_click(self, row: int, _col: int) -> None:
        """Rebuild a focused graph for the PID in the double-clicked row."""
        app = self.app
        try:
            pid_item = app.graph_focus_table.item(row, 1)
            if pid_item is None:
                return
            pid_text = pid_item.text().strip()
            if not pid_text.isdigit():
                return
            pid_int = int(pid_text)
        except Exception:
            return
        app.statusBar().showMessage(f"Rebuilding graph focused on PID {pid_int}…")
        self.refresh_entity_graph_for_pid(pid_int)

    def refresh_entity_graph_for_pid(self, pid: int) -> None:
        """Convenience wrapper around the existing refresh path that
        accepts an explicit PID without depending on `app.selected_process`."""
        self.app.refresh_entity_graph(pid)

    def refresh_network(self) -> None:
        app = self.app
        try: items = app._get("/network/connections").json()
        except Exception as exc: app._show_error(app.net_out, "Failed to load network", exc); return
        app.net_table.setRowCount(len(items))
        for row, item in enumerate(items):
            for col, value in enumerate([item.get("local_addr",""), item.get("remote_addr",""), item.get("status",""), item.get("pid","")]):
                app.net_table.setItem(row, col, QTableWidgetItem(str(value)))
            status = str(item.get("status", "")).upper()
            if "ESTABLISHED" in status:
                app._paint_row(app.net_table, row, QColor("#2f9e67"))
        if items:
            established = sum(1 for item in items if "ESTABLISHED" in str(item.get("status", "")).upper())
            app.net_out.setPlainText(
                f"Loaded {len(items)} network connections.\nEstablished sessions: {established}\nSelect Network, Hosts, or Graph actions to continue investigation."
            )
        else:
            app.net_out.setPlainText("No live network connections were returned. Refresh hosts or run packet capture to build context.")

    def refresh_hosts(self) -> None:
        app = self.app
        try:
            hosts = app._get("/hosts", timeout=20).json()
        except Exception as exc:
            app.statusBar().showMessage(f"Hosts load failed: {exc}")
            return
        tables = [table for table in [getattr(app, "network_host_table", None), getattr(app, "host_inventory_table", None)] if table is not None]
        for table in tables:
            table.setRowCount(len(hosts))
        for row, item in enumerate(hosts):
            values = [item.get("host",""), item.get("platform",""), item.get("boot_time",""), item.get("api_status",""), item.get("role",""), item.get("ip_address",""), item.get("agent_version","")]
            for table in tables:
                for col, value in enumerate(values):
                    table.setItem(row, col, QTableWidgetItem(str(value)))
        if not hosts:
            app.statusBar().showMessage("No fleet hosts registered yet.")
            if hasattr(app, "net_out"):
                app.net_out.setPlainText("No fleet hosts registered yet. Agent enrollment is required before network inventory will populate.")
        elif hasattr(app, "net_out") and not app.net_out.toPlainText().strip():
            app.net_out.setPlainText(f"Loaded {len(hosts)} registered hosts.")

    def refresh_entity_graph(self, pid: int | None = None) -> None:
        app = self.app
        # Forward the active time-window selector so backends that read
        # it can scope their telemetry slice. Unknown query params are
        # ignored by the existing endpoint so legacy servers stay happy.
        params = [f"pid={pid}"] if pid is not None else []
        try:
            window = self._current_graph_window()
            if window and window != "All":
                params.append(f"window={window}")
        except AttributeError:
            pass
        endpoint = "/graph/entity-map" + (f"?{'&'.join(params)}" if params else "")
        # Busy lock - the graph build is async server-side but the client
        # still blocks on the HTTP roundtrip; without this the analyst
        # can fire multiple refreshes and the last one wins silently.
        if hasattr(self, "_graph_busy"):
            self._graph_busy.set_busy(True, "Building entity graph…")
        # Drop shimmer rows into every insight table so the dashboard
        # reads as "working" instead of holding stale empty-state copy.
        try:
            self._render_graph_skeleton_rows()
        except AttributeError:
            pass
        try:
            graph = app._get(endpoint, timeout=45).json()
        except Exception as exc:
            if hasattr(self, "_graph_busy"):
                self._graph_busy.set_busy(False)
            app._show_error(app.graph_detail, "Entity graph load failed", exc)
            return
        finally:
            if hasattr(self, "_graph_busy"):
                self._graph_busy.set_busy(False)
        app.entity_graph = graph
        summary = graph.get("summary", {})
        ad = graph.get("ad_context", {})
        overall_risk = int(float(summary.get("overall_risk", 0) or 0))
        exposure = summary.get("remote_exposure", {}) if isinstance(summary.get("remote_exposure"), dict) else {}
        # KPI strip - five chips matching the strip we instantiated in
        # build_graph_tab(). Tone scales tighten as numbers grow so a
        # 200-node graph doesn't render the same as a 5-node one.
        try:
            node_count = int(summary.get("node_count", 0) or 0)
            edge_count = int(summary.get("edge_count", 0) or 0)
            top_processes = summary.get("top_processes", []) if isinstance(summary.get("top_processes"), list) else []
            high_risk_proc_count = sum(1 for p in top_processes if float(p.get("risk_score", 0) or 0) >= 75)
            public_exposure = int(exposure.get("public", 0) or 0)
            self._graph_kpis["nodes"].update(
                str(node_count),
                "ok" if node_count else "neutral",
                "entity nodes",
            )
            self._graph_kpis["edges"].update(
                str(edge_count),
                "ok" if edge_count else "neutral",
                "relationships",
            )
            risk_tone = "ok" if overall_risk < 45 else ("warn" if overall_risk < 75 else "crit")
            self._graph_kpis["overall_risk"].update(
                str(overall_risk),
                risk_tone,
                self._risk_percentile_hint(overall_risk),
            )
            self._graph_kpis["high_risk_procs"].update(
                str(high_risk_proc_count),
                "ok" if high_risk_proc_count == 0 else ("warn" if high_risk_proc_count < 3 else "crit"),
                "risk ≥ 75",
            )
            self._graph_kpis["public_exposure"].update(
                str(public_exposure),
                "ok" if public_exposure == 0 else ("warn" if public_exposure < 3 else "crit"),
                "public IP hops",
            )
        except (AttributeError, KeyError):
            pass
        # Last-refreshed timestamp on the header strip, including the
        # server's `built_at` graph age when the payload includes it.
        if hasattr(self, "_graph_last_refresh_label"):
            built_at = graph.get("built_at") or summary.get("built_at") or 0
            age_hint = self._format_graph_age(built_at) if built_at else ""
            stamp = f"Last refreshed: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            if age_hint:
                stamp += f"  ·  graph built {age_hint}"
            if pid is not None:
                stamp += f"  ·  focused PID {pid}"
            self._graph_last_refresh_label.setText(stamp)
        # Hide the "press Refresh to populate" hint now that data is in.
        if hasattr(self, "_graph_hint_label"):
            self._graph_hint_label.setText("")
        # Workspace badge update so a multi-tenant operator can see the
        # tenant context for the metrics on screen.
        try:
            self._update_graph_workspace_badge()
        except AttributeError:
            pass
        # Empty-state CTA — replace the static "no findings" copy with
        # a step-by-step recipe when nodes came back empty.
        if not nodes:
            try:
                self._render_empty_state_cta()
            except AttributeError:
                pass
        # Populate the AD context strip from the server payload.
        try:
            self._update_ad_context_strip(ad or {}, summary or {})
        except AttributeError:
            pass
        # Re-apply the active filter set so a refresh respects the
        # operator's pre-set risk threshold / group toggles.
        try:
            self._apply_graph_filters()
        except AttributeError:
            pass
        app.graph_summary.setHtml(
            f"<h2>ShadowLab Attack Surface Graph</h2>"
            f"<p><b>Nodes:</b> {summary.get('node_count', 0)} | <b>Edges:</b> {summary.get('edge_count', 0)}<br>"
            f"<b>Overall Risk:</b> <span style='color:{app._severity_color('high' if overall_risk >= 75 else 'medium' if overall_risk >= 45 else 'low').name()};font-weight:700;'>{overall_risk}</span><br>"
            f"<b>Exposure:</b> {json.dumps(exposure)}<br>"
            f"<b>Domain Joined:</b> {summary.get('domain_joined', False)} | <b>Domain:</b> {summary.get('domain', 'n/a')}<br>"
            f"<b>User:</b> {ad.get('user', 'n/a')} | <b>Logon Server:</b> {ad.get('logon_server', 'n/a')}</p>"
        )
        findings = graph.get("priority_findings", []) or summary.get("priority_findings", [])
        findings_html = "".join(f"<li>{html.escape(str(item))}</li>" for item in findings[:8])
        app.graph_findings.setHtml("<h3>Operator Findings</h3>" f"<ul>{findings_html or '<li>No high-priority graph findings yet.</li>'}</ul>")
        # Disable sorting before bulk-loading rows so item indices stay
        # stable (re-enabled after each table is populated).
        for tbl in (app.graph_group_table, app.graph_focus_table, app.graph_nodes_table, app.graph_edges_table):
            tbl.clearSpans()
            tbl.setSortingEnabled(False)
        groups = summary.get("groups", {}) if isinstance(summary.get("groups"), dict) else {}
        app.graph_group_table.setRowCount(len(groups))
        for row, (group, count) in enumerate(sorted(groups.items(), key=lambda item: item[1], reverse=True)):
            app.graph_group_table.setItem(row, 0, QTableWidgetItem(str(group)))
            app.graph_group_table.setItem(row, 1, QTableWidgetItem(str(count)))
        top_processes = summary.get("top_processes", []) if isinstance(summary.get("top_processes"), list) else []
        app.graph_focus_table.setRowCount(len(top_processes))
        for row, item in enumerate(top_processes):
            for col, value in enumerate([item.get("name", ""), item.get("pid", ""), item.get("risk_score", 0), item.get("signature_status", "")]):
                app.graph_focus_table.setItem(row, col, QTableWidgetItem(str(value)))
            risk_value = float(item.get("risk_score", 0) or 0)
            if risk_value >= 75:
                app._paint_row(app.graph_focus_table, row, QColor("#d64550"))
            elif risk_value >= 45:
                app._paint_row(app.graph_focus_table, row, QColor("#e0a640"))
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        # Track every newly-seen high-risk node so we can flash them at
        # the end of the render — gives the operator a visual hook
        # when a fresh anomaly appears between two refreshes.
        previous_high_risk = set(getattr(self, "_previous_high_risk_labels", set()))
        new_high_risk: set[str] = set()
        app.graph_nodes_table.setRowCount(len(nodes))
        for row, node in enumerate(nodes):
            mitre_value = node.get("mitre_techniques") or node.get("mitre") or []
            if isinstance(mitre_value, list):
                mitre_str = ", ".join(str(t) for t in mitre_value[:5])
                if len(mitre_value) > 5:
                    mitre_str += f" (+{len(mitre_value) - 5})"
            else:
                mitre_str = str(mitre_value)
            for col, value in enumerate([
                node.get("label", ""),
                node.get("group", ""),
                node.get("cluster", ""),
                node.get("risk_score", 0),
                mitre_str,
                node.get("title", ""),
            ]):
                app.graph_nodes_table.setItem(row, col, QTableWidgetItem(str(value)))
            node_risk = float(node.get("risk_score", 0) or 0)
            if node_risk >= 75:
                app._paint_row(app.graph_nodes_table, row, QColor("#d64550"))
                label = str(node.get("label", ""))
                if label:
                    new_high_risk.add(label)
            elif node_risk >= 45:
                app._paint_row(app.graph_nodes_table, row, QColor("#e0a640"))
        app.graph_edges_table.setRowCount(len(edges))
        for row, edge in enumerate(edges):
            for col, value in enumerate([edge.get("from", ""), edge.get("to", ""), edge.get("label", ""), edge.get("width", 1)]):
                app.graph_edges_table.setItem(row, col, QTableWidgetItem(str(value)))
            if str(edge.get("label", "")) in {"connects_to", "contributes_to", "auto_starts"}:
                app._paint_row(app.graph_edges_table, row, QColor("#f08c00"))
        if not nodes:
            app.graph_findings.setHtml("<h3>Operator Findings</h3><ul><li>No entity graph data returned yet. Refresh after telemetry, history, or process analysis.</li></ul>")

        # Anomaly highlight — labels that crossed into the high-risk band
        # between the previous refresh and this one get a brief yellow
        # border so the operator's eye lands on the change.
        newly_appeared = new_high_risk - previous_high_risk
        if newly_appeared and previous_high_risk:  # skip on the first ever render
            self._flash_anomaly(newly_appeared)
        self._previous_high_risk_labels = new_high_risk

        # Re-enable sorting now that bulk-load is done.
        for tbl in (app.graph_group_table, app.graph_focus_table, app.graph_nodes_table, app.graph_edges_table):
            tbl.setSortingEnabled(True)
        # Pipe through the shared show_json helper so the redaction layer
        # masks any signing material that bled into the entity payload.
        app._show_json(app.graph_detail, graph)

    def refresh_selected_process_graph(self) -> None:
        app = self.app
        if not app.selected_process:
            app.statusBar().showMessage("Select a process first to build a focused graph.")
            return
        self.refresh_entity_graph(int(app.selected_process.get("pid", -1)))

    def open_entity_graph(self) -> None:
        app = self.app
        graph = getattr(app, "entity_graph", {})
        html_path = graph.get("html_path")
        if not html_path:
            self.refresh_entity_graph()
            graph = getattr(app, "entity_graph", {})
            html_path = graph.get("html_path")
        if html_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))
        else:
            app.statusBar().showMessage("No graph HTML generated yet.")

    def scan_network_devices(self) -> None:
        app = self.app
        if not self._check_action_gate("arp-scan"):
            return
        ip_range = app.net_range.text().strip() if hasattr(app, "net_range") else ""
        ip_range = ip_range or "192.168.1.0/24"
        # P0: client-side CIDR validation. The previous build accepted
        # any string and the backend would happily start scanning
        # 0.0.0.0/0 (~4 billion addresses). Block anything broader
        # than /16 (~65k addresses).
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError as exc:
            app._show_error(app.net_out, "ARP discovery blocked", Exception(f"`{ip_range}` is not a valid CIDR ({exc})"))
            return
        if network.prefixlen < ARP_SCAN_MIN_PREFIX:
            app._show_error(
                app.net_out,
                "ARP discovery blocked",
                Exception(
                    f"CIDR /{network.prefixlen} is too broad ({network.num_addresses} addresses). "
                    f"Refusing to scan ranges wider than /{ARP_SCAN_MIN_PREFIX}. "
                    "Narrow the range to /24 (256 addresses) or scan a focused subnet."
                ),
            )
            self._record_audit(
                action="arp-scan",
                target=ip_range,
                severity="medium",
                status="blocked",
                payload={"reason": "cidr-too-broad", "prefix": network.prefixlen, "num_addresses": network.num_addresses},
            )
            return

        app.net_out.setPlainText(f"ARP discovery running on {ip_range} ({network.num_addresses} addresses) - async capture, UI stays responsive...")

        def _on_ok(result: dict) -> None:
            devices = result.get("devices", []) if isinstance(result, dict) else []
            app.device_table.setRowCount(len(devices))
            for row, item in enumerate(devices):
                for col, value in enumerate([item.get("ip", ""), item.get("mac", ""), item.get("vendor", item.get("error", ""))]):
                    app.device_table.setItem(row, col, QTableWidgetItem(str(value)))
                if item.get("error"):
                    app._paint_row(app.device_table, row, QColor("#d64550"))
            app._show_json(app.net_out, result)
            self._record_audit(
                action="arp-scan",
                target=ip_range,
                severity="low",
                status="ok",
                payload={"num_addresses": network.num_addresses, "devices_found": len(devices)},
            )

        def _on_err(message: str) -> None:
            app._show_error(app.net_out, "ARP discovery failed", Exception(message))
            self._record_audit(
                action="arp-scan",
                target=ip_range,
                severity="low",
                status="failed",
                payload={"error": message},
            )

        self._submit_async(
            label=f"arp-scan ({ip_range})",
            work=lambda: app._post("/network/warfare/scan", json={"ip_range": ip_range}, timeout=60).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=75,
        )

    def start_network_blocker(self) -> None:
        app = self.app
        if not self._check_action_gate("block-start"):
            return
        target_raw = app.block_target.text().strip() if hasattr(app, "block_target") else ""
        gateway_raw = app.block_gateway.text().strip() if hasattr(app, "block_gateway") else ""
        if not target_raw or not gateway_raw:
            app.statusBar().showMessage("Enter blocker target and gateway IPs first")
            return
        # P0: client-side IP validation. A typo in the gateway field
        # could silently mis-route traffic - backend takes whatever
        # it's given.
        try:
            ipaddress.ip_address(target_raw)
            ipaddress.ip_address(gateway_raw)
        except ValueError as exc:
            app._show_error(app.net_out, "Network blocker blocked", Exception(f"Invalid IP address ({exc})"))
            return
        # Refuse to block local-only / loopback / multicast - those
        # are infrastructure addresses and almost certainly a typo.
        for label, value in (("target", target_raw), ("gateway", gateway_raw)):
            ip = ipaddress.ip_address(value)
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
                app._show_error(
                    app.net_out,
                    "Network blocker blocked",
                    Exception(f"{label} `{value}` is loopback/multicast/unspecified - refusing to send to ARP blocker."),
                )
                return

        prompt = (
            f"Start ARP blocker for {target_raw} via {gateway_raw}?\n\n"
            "Severs the target's network plane until you click Stop Blocker. "
            "A structured reason is required next."
        )
        if QMessageBox.question(app, "Confirm Network Blocker", prompt) != QMessageBox.Yes:
            return
        reason = self._capture_reason(f"network-block ({target_raw})")
        if reason is None:
            return

        payload = {"target_ip": target_raw, "gateway_ip": gateway_raw}
        app.net_out.setPlainText(f"Network blocker request running for {target_raw} via {gateway_raw} (async)...")

        def _on_ok(result: dict) -> None:
            app._show_json(app.net_out, result)
            status = str(result.get("status", "")).lower() if isinstance(result, dict) else ""
            ok = bool(isinstance(result, dict) and (status in {"ok", "started"} or result.get("ok") is True))
            if ok:
                self._blocker_active = True
                self._blocker_target = target_raw
                self._blocker_gateway = gateway_raw
                self._update_session_status()
            self._record_audit(
                action="block-start",
                target=f"{target_raw} via {gateway_raw}",
                severity="critical",
                status="ok" if ok else "failed",
                payload={"request": payload, "response": result},
                reason=reason,
            )

        def _on_err(message: str) -> None:
            app._show_error(app.net_out, "Network blocker failed", Exception(message))
            self._record_audit(
                action="block-start",
                target=f"{target_raw} via {gateway_raw}",
                severity="critical",
                status="failed",
                payload={"request": payload, "error": message},
                reason=reason,
            )

        self._submit_async(
            label=f"network-block ({target_raw})",
            work=lambda: app._post("/network/warfare/block", json=payload, timeout=20).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=25,
        )

    def stop_network_blocker(self) -> None:
        app = self.app
        if not self._check_action_gate("block-stop"):
            return
        # Stop is a recovery action - capture a reason because the
        # blocker was started with one. Pairing the two reasons in
        # the audit chain makes incident timeline clean.
        reason = self._capture_reason("network-block-stop")
        if reason is None:
            return
        app.net_out.setPlainText("Network blocker stop request running (async)...")

        def _on_ok(result: dict) -> None:
            app._show_json(app.net_out, result)
            status = str(result.get("status", "")).lower() if isinstance(result, dict) else ""
            ok = bool(isinstance(result, dict) and (status in {"ok", "stopped"} or result.get("ok") is True))
            if ok:
                self._blocker_active = False
                self._blocker_target = ""
                self._blocker_gateway = ""
                self._update_session_status()
            self._record_audit(
                action="block-stop",
                target=self._blocker_target or "all",
                severity="high",
                status="ok" if ok else "failed",
                payload=result,
                reason=reason,
            )

        def _on_err(message: str) -> None:
            app._show_error(app.net_out, "Stop blocker failed", Exception(message))
            self._record_audit(
                action="block-stop",
                target=self._blocker_target or "all",
                severity="high",
                status="failed",
                payload={"error": message},
                reason=reason,
            )

        self._submit_async(
            label="network-block-stop",
            work=lambda: app._delete("/network/warfare/block", timeout=20).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=25,
        )

    def run_sniffer(self) -> None:
        app = self.app
        if not self._check_action_gate("sniff"):
            return
        if self._sniffer_running:
            app.statusBar().showMessage("Packet capture already running.")
            return
        duration = int(app.sniff_duration.value())
        # P0: packet capture is a privacy event - analyst can see
        # user-plane traffic. Capture a structured reason so the
        # forensic chain explains why this was authorised.
        reason = self._capture_reason(f"packet-sniff ({duration}s)")
        if reason is None:
            return

        self._sniffer_running = True
        self._sniffer_started_at = time.time()
        self._sniffer_duration = duration
        self._update_session_status()
        app.net_out.setPlainText(f"Packet capture running for {duration}s - async, UI remains responsive. Audit chain captures the reason.")

        def _on_ok(result: dict) -> None:
            self._sniffer_running = False
            self._update_session_status()
            app._show_json(app.net_out, result)
            self._record_audit(
                action="sniff",
                target=f"duration={duration}s",
                severity="medium",
                status="ok",
                payload=result if isinstance(result, dict) else {"raw": str(result)[:200]},
                reason=reason,
            )

        def _on_err(message: str) -> None:
            self._sniffer_running = False
            self._update_session_status()
            app._show_error(app.net_out, "Packet capture failed", Exception(message))
            self._record_audit(
                action="sniff",
                target=f"duration={duration}s",
                severity="medium",
                status="failed",
                payload={"error": message},
                reason=reason,
            )

        self._submit_async(
            label=f"packet-sniff ({duration}s)",
            work=lambda: app._post("/network/sniff", json={"duration": duration}, timeout=duration + 30).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=duration + 45,
        )
