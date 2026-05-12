from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any

from PySide6.QtCharts import QBarCategoryAxis, QBarSeries, QBarSet, QChart, QLineSeries, QValueAxis
from PySide6.QtCore import QObject, QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QBrush, QColor, QCursor, QDesktopServices, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QCheckBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QComboBox,
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
    from _action_common import ActionGate, ReasonCapture
except ImportError:  # pragma: no cover
    from desktop._action_common import ActionGate, ReasonCapture

try:
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason

try:
    from process_hunt_jobs import ProcessWorker as _EnterpriseWorker
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker as _EnterpriseWorker


# Server-side accepted state for enterprise case work. Mirrored
# client-side so a stray button can't POST an unsupported value and
# get a 400 back as feedback.
CASE_PRIORITY_ALLOWLIST: frozenset[str] = frozenset({"low", "medium", "high", "critical"})

# Case actions that change forensic state and therefore require a
# structured reason (ticket + category + narrative). Echoes the
# Antivirus / Process / History pattern so SOC operators see the same
# audit prompt across consoles.
ENTERPRISE_REASON_REQUIRED_ACTIONS: frozenset[str] = frozenset({
    "assign", "approval", "export-report", "export-mitre-layer",
    "export-mitre-workbench", "purple-replay",
})

# Per-action click debounce. Several enterprise endpoints write
# evidence (notes, stories, pinned events) that re-render in the
# activity feed — a double-click would generate duplicate rows.
ENTERPRISE_DEBOUNCE_SECONDS = 1.0

ENTERPRISE_AUDIT_RETENTION = 500


def _default_mitre_bundle_path() -> Path:
    """Resolve a sane default for the ATT&CK STIX bundle.

    The previous build hard-coded `C:/Users/ulfat/Documents/...` which
    breaks on every machine that isn't `ulfat`. We probe the most
    likely locations relative to the repo root and fall back to an
    obviously-empty placeholder so the operator sees they need to
    pick a file rather than getting a silent 404 on Load ATT&CK.
    """
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / "config" / "mitre" / "enterprise-bundle.json",
        repo_root / "shadowlab_out" / "enterprise-bundle.json",
        repo_root / "data" / "mitreattack" / "enterprise-bundle.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    # Last-resort placeholder — operator picks via "Load ATT&CK".
    return repo_root / "config" / "mitre" / "enterprise-bundle.json"


class EnterpriseWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        # Shared audit store — same class Antivirus / History use.
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=ENTERPRISE_AUDIT_RETENTION,
        )
        # Wire backend mirror via the shared helper so every console
        # uses identical throttling + thread semantics.
        _install_audit_mirror(self._audit_store, app, source_slug="enterprise")
        self._audit_inventory: list[dict] = []
        # Shared action plumbing — gate + reason. Enterprise-specific
        # `_check_action_gate` and `_capture_reason` below delegate
        # to these instances. The legacy `_last_action_click` dict is
        # kept as a mirror for tests that touch it directly.
        self._gate = ActionGate(
            allowlist=frozenset({
                "assign", "approval", "export-report", "export-mitre-layer",
                "export-mitre-workbench", "purple-replay", "create-case",
                "create-task", "update-task", "add-note", "add-story", "pin-event",
                "web-surface", "network-assessment", "telemetry-gaps",
            }),
            debounce_seconds=ENTERPRISE_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        self._reason = ReasonCapture(
            reason_required=ENTERPRISE_REASON_REQUIRED_ACTIONS,
            parent=app,
            on_cancel=lambda action: app.statusBar().showMessage(
                f"`{action}` cancelled — structured reason required."
            ),
        )
        self._last_action_click: dict[str, float] = {}
        self._async_jobs: list[tuple[QThread, "_EnterpriseWorker"]] = []
        # Token for the latest case-board load — drops responses from
        # superseded clicks so a fast row-flip doesn't render a stale
        # board on top of the freshly-selected one.
        self._board_load_token: int = 0
        # Approval poller state — set up in build_tab.
        self._approval_poll_timer = None
        # Mirror failure throttle so a backend that doesn't expose
        # /audit/desktop doesn't spam the status bar with errors.
        self._mirror_warned_until: float = 0.0

    # ------------------------------------------------------------------ #
    # Audit + reason capture (shared with Antivirus / History / Process)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _style_splitter(splitter) -> None:
        """Style every splitter in the Enterprise tab the same way.

        The default Qt splitter handle is 1 px wide and the same colour
        as the panel border — operators don't realise the panels are
        drag-resizable. Bumping the handle to 8 px with a faint accent
        gives a visible affordance without being noisy. Resizing
        works out-of-the-box; this just makes the handle discoverable.
        """
        splitter.setHandleWidth(8)
        splitter.setStyleSheet(
            "QSplitter::handle{background:#1a2b3f;border:1px solid #243446;border-radius:3px;margin:2px;}"
            "QSplitter::handle:hover{background:#2a4666;border-color:#3a5680;}"
            "QSplitter::handle:pressed{background:#365a82;}"
        )

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "enterprise-audit-log.json"

    # ------------------------------------------------------------------ #
    # Backend audit mirror — fires off a fire-and-forget POST to
    # `/audit/desktop` after every successful append. The local file
    # remains the source of truth; this is purely a SOC convenience so
    # the audit chain shows up in the central store. If the backend
    # doesn't yet expose this endpoint, the failure is silent — the
    # operator already saw the action succeed in the UI.
    # ------------------------------------------------------------------ #

    def _poll_pending_approvals(self) -> None:
        """Refresh just the Pending Approvals KPI off the UI thread.

        Avoids a full `refresh_workspace` round-trip every 30s — that
        would reshuffle the cases table under the operator's cursor.
        Only the KPI label updates; everything else stays put.
        """
        app = self.app
        if not hasattr(app, "auth_context"):
            return
        if str(app.auth_context.get("role", "locked") or "locked") == "locked":
            return
        if not hasattr(app, "enterprise_pending_approvals_value"):
            return

        def _work() -> int:
            try:
                approvals = app._get("/enterprise/approvals", timeout=8).json()
            except Exception:
                return -1
            if not isinstance(approvals, list):
                return -1
            return sum(1 for item in approvals if isinstance(item, dict) and str(item.get("status", "")).lower() in {"pending", "open"})

        thread = QThread(app)
        worker = _EnterpriseWorker(_work)
        worker.moveToThread(thread)

        def _on_done(value) -> None:
            try:
                if isinstance(value, int) and value >= 0:
                    app._set_metric_label(app.enterprise_pending_approvals_value, str(value))
            finally:
                try:
                    self._async_jobs.remove((thread, worker))
                except ValueError:
                    pass
                thread.quit()
                thread.wait(1500)
                worker.deleteLater()
                thread.deleteLater()

        thread.started.connect(worker.run)
        worker.finished.connect(_on_done)
        worker.failed.connect(lambda _msg: _on_done(-1))
        self._async_jobs.append((thread, worker))
        thread.start()

    def _mirror_audit_to_backend(self, entry: dict) -> None:
        app = self.app
        if not hasattr(app, "_post"):
            return

        # Snapshot the entry for the worker — the cache slot may shift
        # before the network call completes.
        payload = {"source": "desktop:enterprise", "entry": entry}

        def _work() -> None:
            try:
                app._post("/audit/desktop", json=payload, timeout=5)
            except Exception as exc:
                # Throttle the warning to once per 5 minutes so a
                # missing endpoint doesn't spam the status bar after
                # every action.
                now = time.time()
                if now < self._mirror_warned_until:
                    return
                self._mirror_warned_until = now + 300
                try:
                    app.statusBar().showMessage(
                        f"Audit mirror to /audit/desktop unavailable ({exc.__class__.__name__}); local log still authoritative.",
                        6000,
                    )
                except Exception:
                    pass

        thread = QThread(app)
        worker = _EnterpriseWorker(_work)
        worker.moveToThread(thread)

        def _cleanup(*_args) -> None:
            try:
                self._async_jobs.remove((thread, worker))
            except ValueError:
                pass
            thread.quit()
            thread.wait(1500)
            worker.deleteLater()
            thread.deleteLater()

        thread.started.connect(worker.run)
        worker.finished.connect(_cleanup)
        worker.failed.connect(_cleanup)
        self._async_jobs.append((thread, worker))
        thread.start()

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def _capture_reason(self, action: str) -> dict | None:
        # Delegate to the shared `ReasonCapture`. Actions outside
        # ENTERPRISE_REASON_REQUIRED_ACTIONS get an empty-dict sentinel.
        # The previous implementation always opened the modal — this
        # is a behaviour-preserving change because every Enterprise
        # action that calls `_capture_reason` is in the required set.
        return self._reason.capture(action)

    def _check_action_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. The legacy mirror dict
        # is updated so tests that read it directly still see the
        # expected state.
        ok = self._gate.check(action)
        if ok:
            self._last_action_click[action] = time.time()
        return ok

    def _record_audit(
        self,
        *,
        category: str,
        action: str,
        target: str,
        severity: str,
        status: str,
        payload: Any,
        reason: dict | None = None,
    ) -> dict:
        actor, workspace = actor_workspace_pair(self.app)
        entry = self._audit_store.append(
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
        if not isinstance(self._audit_inventory, list):
            self._audit_inventory = []
        self._audit_inventory.insert(0, entry)
        del self._audit_inventory[ENTERPRISE_AUDIT_RETENTION:]
        self._render_audit_panel()
        return entry

    def _render_audit_panel(self) -> None:
        """Render the local audit chain into the Audit tab text browser.

        Same severity-coloured-chip style as the History console — a SOC
        operator on Enterprise sees the same forensic chain shape they
        see on the History tab, no mental context-switch.
        """
        app = self.app
        if not hasattr(app, "enterprise_audit_view"):
            return
        all_entries = list(self._audit_inventory or self._audit_store.entries() or [])
        # Apply audit filter chips if they exist (the redesigned layout
        # adds them; legacy code paths that call this method during
        # startup may still hit it before the combos are constructed).
        cat_choice = "all"
        if hasattr(app, "enterprise_audit_category_filter"):
            raw = app.enterprise_audit_category_filter.currentText().strip().lower()
            if raw and not raw.startswith("all"):
                cat_choice = raw
        status_choice = "all"
        if hasattr(app, "enterprise_audit_status_filter"):
            raw = app.enterprise_audit_status_filter.currentText().strip().lower()
            if raw and not raw.startswith("all"):
                status_choice = raw

        def _passes(item: dict) -> bool:
            if cat_choice != "all" and str(item.get("category", "")).lower() != cat_choice:
                return False
            if status_choice != "all" and str(item.get("status", "")).lower() != status_choice:
                return False
            return True

        entries = [item for item in all_entries if _passes(item)][:60]
        if not entries:
            empty_message = (
                "No enterprise audit activity yet. Case assignments, approvals, "
                "exports, and replay actions will appear here with ticket / category / narrative."
                if not all_entries
                else f"No audit rows match the current filters (category={cat_choice}, status={status_choice})."
            )
            app.enterprise_audit_view.setHtml(
                f"<p style='color:#96a5b8;'>{html.escape(empty_message)}</p>"
            )
            return

        def _status_color(status: str) -> str:
            return {
                "ok": "#7fe39d", "blocked": "#ffcf7a", "failed": "#ff6b8a",
                "cancelled": "#f4c26b", "partial": "#ffcf7a",
            }.get(str(status).lower(), "#7fd7ff")

        rows = []
        for entry in entries:
            ticket = str(entry.get("ticket_id", "") or "")
            category = str(entry.get("reason_category", "") or "")
            reason_text = str(entry.get("reason_text", "") or "")
            reason_block = ""
            if ticket or category or reason_text:
                reason_block = (
                    "<br><span style='color:#96a5b8;'>"
                    f"<b>Ticket:</b> {html.escape(ticket or '-')} &nbsp;"
                    f"<b>Category:</b> {html.escape(category or '-')} &nbsp;"
                    f"<b>Reason:</b> {html.escape(reason_text[:160])}"
                    "</span>"
                )
            rows.append(
                "<tr>"
                f"<td style='color:#96a5b8;'>{html.escape(str(entry.get('timestamp', '-')))}</td>"
                f"<td><b>{html.escape(str(entry.get('action', '-')))}</b>"
                f" <span style='color:#7fd7ff;'>·</span> "
                f"{html.escape(str(entry.get('category', '-')))}</td>"
                f"<td>{html.escape(str(entry.get('target', '-'))[:80])}</td>"
                f"<td>{html.escape(str(entry.get('actor', '-')))}</td>"
                f"<td><span style='color:{_status_color(entry.get('status', ''))};font-weight:800;'>"
                f"{html.escape(str(entry.get('status', '-')))}</span>"
                f"{reason_block}</td>"
                "</tr>"
            )
        app.enterprise_audit_view.setHtml(
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

    def _set_enterprise_detail_message(self, title: str, body: str) -> None:
        self.app.enterprise_detail.setPlainText(f"{title}\n\n{body}")

    def _set_enterprise_locked_state(self) -> None:
        app = self.app
        app.enterprise_summary.setHtml(
            "<h3>Triage First</h3><p>Authentication is required before enterprise triage, approvals, case workflow, and ATT&CK coverage can be loaded.</p>"
        )
        app.enterprise_role_banner.setText("Role context: locked")
        app.enterprise_warning_banner.setText("Enterprise workflow is locked until a valid API key is applied.")
        app.enterprise_live_status.setText("Live sync locked")
        app.enterprise_cases_data = []
        app._populate_enterprise_cases_table([])
        app._clear_enterprise_case_views()
        app._set_metric_label(app.enterprise_open_cases_value, "0")
        app._set_metric_label(app.enterprise_high_risk_value, "0")
        app._set_metric_label(app.enterprise_auth_anomalies_value, "0")
        app._set_metric_label(app.enterprise_pending_approvals_value, "0")
        self._set_enterprise_detail_message(
            "Enterprise Workspace Locked",
            "Apply a valid API key to load enterprise triage, assignments, approvals, and case correlation.",
        )

    def build_tab(self) -> QWidget:
        app = self.app
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(8, 8, 8, 8)
        l.setSpacing(8)
        overview_section = QFrame()
        overview_section.setProperty("card", True)
        overview_layout = QVBoxLayout(overview_section)
        overview_layout.setContentsMargins(12, 10, 12, 12)
        overview_layout.setSpacing(8)
        controls_card = QFrame()
        controls_card.setProperty("card", True)
        controls_inner = QVBoxLayout(controls_card)
        controls_inner.setContentsMargins(12, 8, 12, 8)
        controls_inner.setSpacing(4)
        controls_lbl = QLabel("Case &amp; Operations Controls")
        controls_lbl.setStyleSheet("font-size:12px;font-weight:700;color:#96a5b8;")
        controls_inner.addWidget(controls_lbl)
        controls_top = QWidget()
        controls_top_layout = QVBoxLayout(controls_top)
        controls_top_layout.setContentsMargins(0, 0, 0, 0)
        controls_top_layout.setSpacing(6)
        controls_status_row = QHBoxLayout()
        controls_status_row.setContentsMargins(0, 0, 0, 0)
        controls_status_row.setSpacing(8)
        app.enterprise_warning_banner = QLabel("Warnings will appear here when cases need attention.")
        app.enterprise_warning_banner.setStyleSheet("color:#ffd166;background:#1a2230;border:1px solid #2c4260;border-radius:8px;padding:8px 10px;font-weight:600;")
        app.enterprise_role_banner = QLabel("Role context will appear here.")
        app.enterprise_role_banner.setStyleSheet("color:#9fd0ff;background:#121b27;border:1px solid #2c4260;border-radius:8px;padding:8px 10px;font-weight:600;")
        app.enterprise_live_status = QLabel("Live sync idle")
        app.enterprise_live_status.setStyleSheet("color:#96a5b8;font-size:11px;")
        app.enterprise_auto_refresh = QCheckBox("Auto refresh")
        app.enterprise_auto_refresh.setChecked(True)
        app.enterprise_case_filter = QLineEdit()
        app.enterprise_case_filter.setPlaceholderText("Filter cases")
        app.enterprise_case_filter.setFixedWidth(150)
        app.enterprise_case_filter.textChanged.connect(app._apply_enterprise_filters)
        app.enterprise_case_filter.textChanged.connect(app._persist_enterprise_ui_state)
        app.enterprise_task_filter = QLineEdit()
        app.enterprise_task_filter.setPlaceholderText("Filter tasks")
        app.enterprise_task_filter.setFixedWidth(150)
        app.enterprise_task_filter.textChanged.connect(app._apply_enterprise_filters)
        app.enterprise_task_filter.textChanged.connect(app._persist_enterprise_ui_state)
        app.enterprise_activity_filter = QLineEdit()
        app.enterprise_activity_filter.setPlaceholderText("Filter activity")
        app.enterprise_activity_filter.setFixedWidth(150)
        app.enterprise_activity_filter.textChanged.connect(app._apply_enterprise_filters)
        app.enterprise_activity_filter.textChanged.connect(app._persist_enterprise_ui_state)
        app.enterprise_auto_refresh.toggled.connect(app._persist_enterprise_ui_state)
        # Structured filters — priority + status — operate on the
        # cached case inventory (no backend round-trip on flip).
        app.enterprise_case_priority_filter = QComboBox()
        app.enterprise_case_priority_filter.addItems(["All priority", "critical", "high", "medium", "low"])
        app.enterprise_case_priority_filter.currentTextChanged.connect(app._apply_enterprise_filters)
        app.enterprise_case_priority_filter.currentTextChanged.connect(app._persist_enterprise_ui_state)
        app.enterprise_case_status_filter = QComboBox()
        # Status set is a superset of common backend values — operators
        # can extend without a desktop redeploy.
        app.enterprise_case_status_filter.addItems([
            "All status", "open", "investigating", "contained", "closed", "blocked",
        ])
        app.enterprise_case_status_filter.currentTextChanged.connect(app._apply_enterprise_filters)
        app.enterprise_case_status_filter.currentTextChanged.connect(app._persist_enterprise_ui_state)
        controls_status_row.addWidget(app.enterprise_warning_banner, 2)
        controls_status_row.addWidget(app.enterprise_role_banner, 1)
        controls_status_row.addWidget(app.enterprise_live_status)
        controls_status_row.addWidget(app.enterprise_auto_refresh)
        controls_status_row.addWidget(app.enterprise_case_filter)
        controls_status_row.addWidget(app.enterprise_case_priority_filter)
        controls_status_row.addWidget(app.enterprise_case_status_filter)
        controls_status_row.addWidget(app.enterprise_task_filter)
        controls_status_row.addWidget(app.enterprise_activity_filter)
        controls_status_row.addStretch(1)
        controls_top_layout.addLayout(controls_status_row)
        controls_inner.addWidget(controls_top)

        controls = QWidget()
        cr = QVBoxLayout(controls)
        cr.setContentsMargins(0, 0, 0, 0)
        cr.setSpacing(6)
        app.enterprise_case_title = QLineEdit("Suspicious activity case")
        app.enterprise_case_title.setPlaceholderText("Case title")
        app.enterprise_case_owner = QLineEdit()
        app.enterprise_case_owner.setPlaceholderText("Owner")
        app.enterprise_case_priority = QComboBox()
        app.enterprise_case_priority.addItems(["low", "medium", "high", "critical"])
        # P0 fix: previously hard-coded to `C:/Users/ulfat/Documents/...`
        # which is broken on every machine that isn't `ulfat`.
        # `_default_mitre_bundle_path()` probes the repo for a sane
        # default and falls back to a placeholder under `config/mitre/`
        # so the operator can pick one via Load ATT&CK.
        app.enterprise_mitre_bundle_path = QLineEdit(str(_default_mitre_bundle_path()))
        app.enterprise_mitre_bundle_path.setPlaceholderText("ATT&CK STIX bundle path")
        app.enterprise_replay_path = QLineEdit(str((Path(__file__).resolve().parent.parent / "shadowlab_out" / "incident_bundle.json")))
        app.enterprise_network_range = QLineEdit("127.0.0.1")
        refresh_btn = app._enterprise_action_button("Refresh", app.refresh_enterprise_workspace, "can_run_hunt")
        create_case_btn = app._enterprise_action_button("Create Case", app.create_enterprise_case, "can_manage_incidents")
        assign_btn = app._enterprise_action_button("Assign", app.assign_enterprise_case, "can_manage_incidents")
        update_task_btn = app._enterprise_action_button("Update Task", app.update_enterprise_task_status, "can_manage_incidents")
        mark_done_btn = app._enterprise_action_button("Mark Done", lambda: app.update_enterprise_task_status("done"), "can_manage_incidents")
        graph_btn = app._enterprise_action_button("Correlation", app.load_enterprise_case_graph, "can_run_hunt")
        board_btn = app._enterprise_action_button("Case Board", app.load_selected_case_board, "can_manage_incidents")
        export_case_btn = app._enterprise_action_button("Export Report", app.export_selected_case_report, "can_manage_integrations")
        export_mitre_btn = app._enterprise_action_button("ATT&CK Layer", app.export_enterprise_mitre_layer, "can_run_hunt")
        export_workbench_btn = app._enterprise_action_button("Workbench", app.export_enterprise_mitre_workbench, "can_run_hunt")
        approval_btn = app._enterprise_action_button("Approval", app.request_enterprise_approval, "can_manage_incidents")
        web_btn = app._enterprise_action_button("Web Surface", app.run_web_inspection, "can_run_hunt")
        net_btn = app._enterprise_action_button("Network", app.run_enterprise_network_assessment, "can_run_hunt")
        replay_btn = app._enterprise_action_button("Replay", app.run_purple_replay, "can_run_hunt")
        gaps_btn = app._enterprise_action_button("Gaps", app.load_telemetry_gaps, "can_run_hunt")
        load_mitre_btn = app._enterprise_action_button("Load ATT&CK", app.load_enterprise_mitre_bundle, "can_manage_integrations")
        add_btn = app._enterprise_menu_button(
            "Add",
            [
                ("Task", app.create_enterprise_task, "can_manage_incidents"),
                ("Note", app.add_enterprise_note, "can_manage_incidents"),
                ("Story", app.add_enterprise_story, "can_manage_incidents"),
                ("Pin Event", app.pin_enterprise_event, "can_manage_incidents"),
            ],
        )
        for widget in [
            refresh_btn,
            create_case_btn,
            assign_btn,
            update_task_btn,
            mark_done_btn,
            graph_btn,
            board_btn,
            export_case_btn,
            export_mitre_btn,
            export_workbench_btn,
            approval_btn,
            web_btn,
            net_btn,
            replay_btn,
            gaps_btn,
            load_mitre_btn,
            add_btn,
        ]:
            app._style_enterprise_compact_control(widget)
        fields_row = QWidget()
        fields_layout = QHBoxLayout(fields_row)
        fields_layout.setContentsMargins(0, 0, 0, 0)
        fields_layout.setSpacing(6)
        fields_layout.addWidget(QLabel("Case"))
        fields_layout.addWidget(app.enterprise_case_title, 3)
        fields_layout.addWidget(QLabel("Owner"))
        fields_layout.addWidget(app.enterprise_case_owner, 2)
        fields_layout.addWidget(QLabel("Priority"))
        fields_layout.addWidget(app.enterprise_case_priority, 1)
        fields_layout.addWidget(QLabel("ATT&CK"))
        fields_layout.addWidget(app.enterprise_mitre_bundle_path, 5)
        fields_layout.addStretch(1)
        # Action buttons grouped by intent + colour-coded so the operator
        # finds the right button by category, not by row scan. Groups:
        #   Workspace (slate)  — Refresh, Load ATT&CK
        #   Case (blue)        — Create, Add, Assign, Board, Correlation,
        #                        Update Task, Mark Done
        #   Hunt (cyan)        — Web Surface, Network, Replay, Gaps
        #   Export (green)     — Export Report, ATT&CK Layer, Workbench
        #   Danger (red)       — Approval (high-impact gate)
        # Each group renders as its own micro-card on the action row,
        # separated by a faint vertical bar so the eye lands on
        # boundaries instead of a wall of identical buttons.
        actions_row = QWidget()
        actions_layout = QHBoxLayout(actions_row)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(8)

        action_groups: list[tuple[str, str, list]] = [
            ("Workspace", "#5e7493", [refresh_btn, load_mitre_btn]),
            ("Case",      "#3a6ea8", [create_case_btn, add_btn, assign_btn, board_btn, graph_btn, update_task_btn, mark_done_btn]),
            ("Hunt",      "#3a8aa8", [web_btn, net_btn, replay_btn, gaps_btn]),
            ("Export",    "#3a8a64", [export_case_btn, export_mitre_btn, export_workbench_btn]),
            ("Danger",    "#a83a4f", [approval_btn]),
        ]

        for label_text, accent, buttons in action_groups:
            if not buttons:
                continue
            group = QFrame()
            group.setProperty("card", True)
            group.setStyleSheet(
                "QFrame[card='true']{"
                f"background:#0e1720;border:1px solid {accent};border-radius:7px;"
                "padding:2px 4px;"
                "}"
            )
            group_layout = QHBoxLayout(group)
            group_layout.setContentsMargins(6, 2, 6, 2)
            group_layout.setSpacing(3)
            cap = QLabel(label_text)
            cap.setStyleSheet(f"color:{accent};font-size:9px;font-weight:800;letter-spacing:0.5px;")
            group_layout.addWidget(cap)
            for btn in buttons:
                group_layout.addWidget(btn)
            actions_layout.addWidget(group)
        actions_layout.addStretch(1)
        cr.addWidget(fields_row)
        cr.addWidget(actions_row)
        controls_inner.addWidget(controls)
        overview_layout.addWidget(controls_card)

        app.enterprise_summary = QTextBrowser()
        app.enterprise_summary.setMinimumHeight(110)
        app.enterprise_summary.setProperty("role", "brief")
        app.enterprise_summary.setHtml("<h3>Triage First</h3><p>Refresh enterprise workspace to load open cases, approvals, case pressure, ATT&CK posture, and narrative guidance.</p>")
        context_metrics = QWidget()
        cmr = QHBoxLayout(context_metrics)
        cmr.setContentsMargins(0, 0, 0, 0)
        cmr.setSpacing(8)
        selected_case_card, app.enterprise_selected_case_value = app._metric_card("Selected Case", "#c9d7e8")
        auth_anomalies_card, app.enterprise_auth_anomalies_value = app._metric_card("Auth Anomalies", "#ff9f6b")
        approvals_card, app.enterprise_pending_approvals_value = app._metric_card("Pending Approvals", "#ffd166")
        event_pressure_card, app.enterprise_event_pressure_value = app._metric_card("High-Risk Events", "#ff7f96")
        for card in [selected_case_card, auth_anomalies_card, approvals_card, event_pressure_card]:
            cmr.addWidget(card, 1)
        metrics = QWidget()
        mr = QHBoxLayout(metrics)
        mr.setContentsMargins(0, 0, 0, 0)
        mr.setSpacing(8)
        open_cases_card, app.enterprise_open_cases_value = app._metric_card("Open Cases", "#8ec5ff")
        overdue_card, app.enterprise_overdue_value = app._metric_card("Overdue Tasks", "#ff8b8b")
        assignments_card, app.enterprise_assignments_value = app._metric_card("Assignments", "#ffd166")
        high_risk_card, app.enterprise_high_risk_value = app._metric_card("High Risk Assets", "#7bd389")
        for card in [open_cases_card, overdue_card, assignments_card, high_risk_card]:
            mr.addWidget(card, 1)
        app.enterprise_kpi_chart = app.enterprise_kpi_chart if hasattr(app, "enterprise_kpi_chart") else None
        from PySide6.QtCharts import QChartView
        from PySide6.QtGui import QPainter
        app.enterprise_kpi_chart = QChartView()
        app.enterprise_kpi_chart.setMinimumHeight(110)
        app.enterprise_kpi_chart.setRenderHint(QPainter.Antialiasing)
        # Pre-seed an empty themed chart so the panel does NOT render as
        # a stark white rectangle while waiting for `refresh_kpi_chart`
        # to populate it. Previously the QChartView default surface
        # made the Operations Snapshot panel look broken / unstyled.
        _placeholder_chart = QChart()
        _placeholder_chart.setBackgroundBrush(QBrush(QColor("#0e1720")))
        _placeholder_chart.setPlotAreaBackgroundBrush(QBrush(QColor("#0e1720")))
        _placeholder_chart.setPlotAreaBackgroundVisible(True)
        _placeholder_chart.setBackgroundRoundness(8)
        _placeholder_chart.setTitle("Refresh enterprise workspace to populate the KPI chart.")
        _placeholder_chart.setTitleBrush(QBrush(QColor("#96a5b8")))
        _placeholder_chart.legend().setVisible(False)
        app.enterprise_kpi_chart.setChart(_placeholder_chart)
        app.enterprise_kpi_chart.setStyleSheet(
            "QChartView{background:#0e1720;border:1px solid #243446;border-radius:9px;}"
        )
        # The summary, KPI rows and chart used to live ABOVE the inner
        # tab widget — that pushed the actual workspace several hundred
        # pixels down on every screen. They've been migrated into a
        # dedicated "Snapshot" sub-tab, built later in this method, so
        # only the input/controls/actions stay on top.
        summary_row = QWidget()
        summary_row_layout = QHBoxLayout(summary_row)
        summary_row_layout.setContentsMargins(0, 0, 0, 0)
        summary_row_layout.setSpacing(8)
        summary_row_layout.addWidget(
            app._panel_card(
                "What Needs Attention Now",
                app.enterprise_summary,
                lambda: app._open_panel_window("What Needs Attention Now", app._clone_text_view(app.enterprise_summary)),
            ),
            6,
        )
        summary_row_layout.addWidget(
            app._panel_card(
                "Operational Snapshot",
                app.enterprise_kpi_chart,
                lambda: app._open_panel_window(
                    "Operational Snapshot",
                    QLabel("Use the main Enterprise tab for the live KPI chart."),
                ),
            ),
            5,
        )

        enterprise_sections = QTabWidget()
        enterprise_sections.setDocumentMode(True)
        enterprise_sections.setUsesScrollButtons(False)

        # Widget definitions follow. Layouts that consume them are built
        # AFTER all widgets exist (the redesigned 3-tab layout below)
        # so we can wire them into a denser splitter structure without
        # forward-declaring placeholder containers.
        app.enterprise_cases_table = QTableWidget(0, 6)
        app.enterprise_cases_table.setHorizontalHeaderLabels(["ID", "Title", "Priority", "Stage", "Owner", "Status"])
        app._style_table(app.enterprise_cases_table)
        app.enterprise_cases_table.itemSelectionChanged.connect(app._on_enterprise_case_selection_changed)
        # Click any column header to sort. Default click on Priority would
        # otherwise sort lexically ("critical" < "high" < "low" < "medium")
        # which is wrong — `populate_cases_table` writes a hidden numeric
        # rank into Qt.UserRole on the priority cell so the sort key
        # respects the operational severity order.
        app.enterprise_cases_table.setSortingEnabled(True)
        app.enterprise_cases_table.horizontalHeader().setSortIndicatorShown(True)
        app.enterprise_cases_table.setContextMenuPolicy(Qt.CustomContextMenu)
        app.enterprise_cases_table.customContextMenuRequested.connect(self._show_cases_context_menu)
        app.enterprise_assets_table = QTableWidget(0, 4)
        app.enterprise_assets_table.setHorizontalHeaderLabels(["PID", "Name", "Criticality", "Rationale"])
        app._style_table(app.enterprise_assets_table)
        app.enterprise_detections_table = QTableWidget(0, 4)
        app.enterprise_detections_table.setHorizontalHeaderLabels(["Rule", "Version", "Status", "Notes"])
        app._style_table(app.enterprise_detections_table)
        app.enterprise_notes_table = QTableWidget(0, 3)
        app.enterprise_notes_table.setHorizontalHeaderLabels(["Author", "Type", "Note"])
        app._style_table(app.enterprise_notes_table)
        app.enterprise_notes_table.itemSelectionChanged.connect(app.show_selected_enterprise_note)
        app.enterprise_stories_table = QTableWidget(0, 3)
        app.enterprise_stories_table.setHorizontalHeaderLabels(["Title", "Confidence", "Author"])
        app._style_table(app.enterprise_stories_table)
        app.enterprise_stories_table.itemSelectionChanged.connect(app.show_selected_enterprise_story)
        app.enterprise_narrative = QTextBrowser()
        app.enterprise_narrative.setProperty("role", "brief")
        app.enterprise_narrative.setMinimumHeight(90)
        app.enterprise_narrative.setHtml("<h3>Progressive Disclosure</h3><p>No case narrative yet. Select or create a case to begin investigation storytelling.</p>")
        app.enterprise_case_board = QTextBrowser()
        app.enterprise_case_board.setProperty("role", "brief")
        app.enterprise_case_board.setMinimumHeight(80)
        app.enterprise_case_board.setHtml("<h3>Case Board</h3><p>No case selected yet. Pick a case on the left or create a new one.</p>")
        app.enterprise_case_timeline = QTableWidget(0, 4)
        app.enterprise_case_timeline.setHorizontalHeaderLabels(["Time", "Kind", "Severity", "Title"])
        app._style_table(app.enterprise_case_timeline)
        app.enterprise_case_timeline.itemSelectionChanged.connect(app.show_selected_enterprise_timeline)
        app.enterprise_entity_links = QTableWidget(0, 4)
        app.enterprise_entity_links.setHorizontalHeaderLabels(["Entity", "Kind", "Evidence", "Examples"])
        app._style_table(app.enterprise_entity_links)
        app.enterprise_entity_links.itemSelectionChanged.connect(app.show_selected_enterprise_link)
        app.enterprise_graph_summary = QTextBrowser()
        app.enterprise_graph_summary.setProperty("role", "brief")
        app.enterprise_graph_summary.setMinimumHeight(80)
        app.enterprise_graph_summary.setHtml("<h3>Case Correlation View</h3><p>No active case context yet.</p>")
        app.enterprise_mitre_summary = QTextBrowser()
        app.enterprise_mitre_summary.setProperty("role", "brief")
        app.enterprise_mitre_summary.setMinimumHeight(80)
        app.enterprise_mitre_summary.setHtml("<h3>ATT&CK Coverage</h3><p>Load or refresh enterprise coverage to review tactics, techniques, mitigations, and telemetry cues.</p>")
        app.enterprise_case_mitre = QTextBrowser()
        app.enterprise_case_mitre.setProperty("role", "brief")
        app.enterprise_case_mitre.setMinimumHeight(80)
        app.enterprise_case_mitre.setHtml("<h3>Case ATT&CK</h3><p>Select a case to review mapped techniques, mitigations, and actor context.</p>")
        app.enterprise_graph_focus = QTableWidget(0, 4)
        app.enterprise_graph_focus.setHorizontalHeaderLabels(["Process", "PID", "Risk", "Signature"])
        app._style_table(app.enterprise_graph_focus)
        app.enterprise_assignments_table = QTableWidget(0, 4)
        app.enterprise_assignments_table.setHorizontalHeaderLabels(["Analyst", "Role", "Status", "Assigned By"])
        app._style_table(app.enterprise_assignments_table)
        app.enterprise_assignments_table.itemSelectionChanged.connect(app.show_selected_enterprise_assignment)
        app.enterprise_tasks_table = QTableWidget(0, 4)
        app.enterprise_tasks_table.setHorizontalHeaderLabels(["Title", "Status", "Priority", "Assigned"])
        app._style_table(app.enterprise_tasks_table)
        app.enterprise_tasks_table.itemSelectionChanged.connect(app.show_selected_enterprise_task)
        app.enterprise_tasks_table.itemChanged.connect(app._inline_update_enterprise_task)
        app.enterprise_activity_table = QTableWidget(0, 4)
        app.enterprise_activity_table.setHorizontalHeaderLabels(["Time", "Event", "Actor", "Summary"])
        app._style_table(app.enterprise_activity_table)
        app.enterprise_activity_table.itemSelectionChanged.connect(app.show_selected_enterprise_activity)
        app.enterprise_notifications_cases_table = QTableWidget(0, 4)
        app.enterprise_notifications_cases_table.setHorizontalHeaderLabels(["Time", "Severity", "Category", "Message"])
        app._style_table(app.enterprise_notifications_cases_table)
        app.enterprise_notifications_cases_table.setMinimumHeight(90)
        app.enterprise_notifications_cases_table.itemSelectionChanged.connect(app.show_selected_enterprise_notification)
        app.enterprise_notifications_table = QTableWidget(0, 4)
        app.enterprise_notifications_table.setHorizontalHeaderLabels(["Time", "Severity", "Category", "Message"])
        app._style_table(app.enterprise_notifications_table)
        app.enterprise_notifications_table.setMinimumHeight(90)
        app.enterprise_notifications_table.itemSelectionChanged.connect(app.show_selected_enterprise_notification)
        app.enterprise_detail = QTextEdit()
        app.enterprise_detail.setReadOnly(True)
        app.enterprise_detail.setPlainText("Enterprise case JSON, workflow results, exports, and correlation detail will appear here.")
        # ==================================================================
        # Redesigned 3-tab layout (was 6 sub-tabs with sparse panels):
        #   1. Operations  — Cases left rail + tabbed right pane
        #                    (Board · Tasks · Activity · Notes & Stories)
        #   2. Intel & Graph — ATT&CK coverage + assets/detections + graph
        #   3. Audit Chain — full-width audit log with action filter row
        # The Overview block (KPI cards + summary) lives ABOVE the inner
        # tab widget so it stays visible regardless of which sub-tab the
        # operator is on. That kills the "Overview" tab without losing
        # any of the metrics it surfaced.
        # ==================================================================

        # ------------------------------------------------------------------
        # Tab 1: Operations
        # ------------------------------------------------------------------
        ops_page = QWidget()
        ops_layout = QHBoxLayout(ops_page)
        ops_layout.setContentsMargins(0, 0, 0, 0)
        ops_layout.setSpacing(8)
        ops_split = QSplitter(Qt.Horizontal)
        ops_split.setChildrenCollapsible(False)
        self._style_splitter(ops_split)

        # Left rail — Cases (persistent across all right-pane sub-tabs).
        ops_left = QWidget()
        ops_left_layout = QVBoxLayout(ops_left)
        ops_left_layout.setContentsMargins(0, 0, 0, 0)
        ops_left_layout.setSpacing(8)
        ops_left_layout.addWidget(
            app._panel_card(
                "Cases",
                app.enterprise_cases_table,
                lambda: app._open_panel_window("Enterprise Cases", app._clone_table(app.enterprise_cases_table)),
            ),
            3,
        )
        ops_left_layout.addWidget(
            app._panel_card(
                "Assignments",
                app.enterprise_assignments_table,
                lambda: app._open_panel_window("Assignments", app._clone_table(app.enterprise_assignments_table)),
            ),
            2,
        )

        # Right pane — inner QTabWidget. Sub-tabs collapse the previous
        # six sparse panels into four task-focused workspaces.
        ops_right_tabs = QTabWidget()
        ops_right_tabs.setDocumentMode(True)

        # Sub-tab: Board — 3 panels side-by-side (narrative + case board
        # + JSON detail). Horizontal splitter keeps the operator's eyes
        # at the same scroll height instead of forcing a vertical scan
        # through stacked text browsers.
        board_page = QWidget()
        board_split = QSplitter(Qt.Horizontal)
        board_split.setChildrenCollapsible(False)
        self._style_splitter(board_split)
        board_split.addWidget(
            app._panel_card(
                "Narrative",
                app.enterprise_narrative,
                lambda: app._open_panel_window("Enterprise Narrative", app._clone_text_view(app.enterprise_narrative)),
            )
        )
        board_split.addWidget(
            app._panel_card(
                "Case Board",
                app.enterprise_case_board,
                lambda: app._open_panel_window("Case Board", app._clone_text_view(app.enterprise_case_board)),
            )
        )
        board_split.addWidget(
            app._panel_card(
                "Case JSON Detail",
                app.enterprise_detail,
                lambda: app._open_panel_window("Case JSON Detail", app._clone_text_view(app.enterprise_detail)),
            )
        )
        board_split.setStretchFactor(0, 1)
        board_split.setStretchFactor(1, 1)
        board_split.setStretchFactor(2, 1)
        board_layout = QVBoxLayout(board_page)
        board_layout.setContentsMargins(0, 0, 0, 0)
        board_layout.addWidget(board_split)

        # Sub-tab: Tasks (full-height tasks table — primary surface for
        # multi-step investigation workflow).
        tasks_page = QWidget()
        tasks_layout = QVBoxLayout(tasks_page)
        tasks_layout.setContentsMargins(0, 0, 0, 0)
        tasks_layout.addWidget(
            app._panel_card(
                "Tasks",
                app.enterprise_tasks_table,
                lambda: app._open_panel_window("Tasks", app._clone_table(app.enterprise_tasks_table)),
            ),
            1,
        )

        # Sub-tab: Activity (feed + notifications side-by-side; was two
        # separate sub-tabs Ops Cases / Ops Activity).
        activity_page = QWidget()
        activity_split = QSplitter(Qt.Horizontal)
        activity_split.setChildrenCollapsible(False)
        self._style_splitter(activity_split)
        activity_split.addWidget(
            app._panel_card(
                "Activity Feed",
                app.enterprise_activity_table,
                lambda: app._open_panel_window("Activity Feed", app._clone_table(app.enterprise_activity_table)),
            )
        )
        activity_split.addWidget(
            app._panel_card(
                "Notifications",
                app.enterprise_notifications_table,
                lambda: app._open_panel_window("Notifications", app._clone_table(app.enterprise_notifications_table)),
            )
        )
        activity_split.setStretchFactor(0, 3)
        activity_split.setStretchFactor(1, 2)
        activity_layout = QVBoxLayout(activity_page)
        activity_layout.setContentsMargins(0, 0, 0, 0)
        activity_layout.addWidget(activity_split)

        # The legacy "Notifications (Ops Cases)" table was the same data
        # rendered twice — keep it hidden but bound so existing
        # selection-handler code that expects the table to exist
        # doesn't crash. Its row population still runs in
        # `apply_filters()`.
        app.enterprise_notifications_cases_table.setVisible(False)

        # Sub-tab: Notes & Stories — 3 panels side-by-side (notes,
        # stories, case timeline). Forensic narrative surface — every
        # column is a different lens on the same investigation.
        notes_page = QWidget()
        notes_split = QSplitter(Qt.Horizontal)
        notes_split.setChildrenCollapsible(False)
        self._style_splitter(notes_split)
        notes_split.addWidget(
            app._panel_card(
                "Investigation Notes",
                app.enterprise_notes_table,
                lambda: app._open_panel_window("Investigation Notes", app._clone_table(app.enterprise_notes_table)),
            )
        )
        notes_split.addWidget(
            app._panel_card(
                "Investigation Stories",
                app.enterprise_stories_table,
                lambda: app._open_panel_window("Investigation Stories", app._clone_table(app.enterprise_stories_table)),
            )
        )
        notes_split.addWidget(
            app._panel_card(
                "Case Timeline",
                app.enterprise_case_timeline,
                lambda: app._open_panel_window("Case Timeline", app._clone_table(app.enterprise_case_timeline)),
            )
        )
        notes_split.setStretchFactor(0, 1)
        notes_split.setStretchFactor(1, 1)
        notes_split.setStretchFactor(2, 1)
        notes_layout = QVBoxLayout(notes_page)
        notes_layout.setContentsMargins(0, 0, 0, 0)
        notes_layout.addWidget(notes_split)

        ops_right_tabs.addTab(board_page, "Board")
        ops_right_tabs.addTab(tasks_page, "Tasks")
        ops_right_tabs.addTab(activity_page, "Activity")
        ops_right_tabs.addTab(notes_page, "Notes & Stories")

        ops_split.addWidget(ops_left)
        ops_split.addWidget(ops_right_tabs)
        ops_split.setStretchFactor(0, 2)
        ops_split.setStretchFactor(1, 3)
        ops_layout.addWidget(ops_split)

        # ------------------------------------------------------------------
        # Tab 2: Intel & Graph (was Intel Coverage + Intel Graph)
        # ------------------------------------------------------------------
        intel_page = QWidget()
        intel_layout = QHBoxLayout(intel_page)
        intel_layout.setContentsMargins(0, 0, 0, 0)
        intel_layout.setSpacing(8)
        intel_split = QSplitter(Qt.Horizontal)
        intel_split.setChildrenCollapsible(False)
        self._style_splitter(intel_split)

        intel_left = QWidget()
        intel_left_layout = QVBoxLayout(intel_left)
        intel_left_layout.setContentsMargins(0, 0, 0, 0)
        intel_left_layout.setSpacing(8)
        intel_left_layout.addWidget(
            app._panel_card(
                "ATT&CK Coverage",
                app.enterprise_mitre_summary,
                lambda: app._open_panel_window("ATT&CK Coverage", app._clone_text_view(app.enterprise_mitre_summary)),
            ),
            1,
        )
        intel_left_layout.addWidget(
            app._panel_card(
                "Case ATT&CK",
                app.enterprise_case_mitre,
                lambda: app._open_panel_window("Case ATT&CK", app._clone_text_view(app.enterprise_case_mitre)),
            ),
            1,
        )

        intel_right_tabs = QTabWidget()
        intel_right_tabs.setDocumentMode(True)

        # Sub-tab: Assets & Detections — 2 panels side-by-side. Horizontal
        # splitter keeps the asset criticality and the detection lifecycle
        # at the same eye height so the analyst can correlate without
        # scrolling.
        ad_page = QWidget()
        ad_split = QSplitter(Qt.Horizontal)
        ad_split.setChildrenCollapsible(False)
        self._style_splitter(ad_split)
        ad_split.addWidget(
            app._panel_card(
                "Critical Assets",
                app.enterprise_assets_table,
                lambda: app._open_panel_window("Enterprise Assets", app._clone_table(app.enterprise_assets_table)),
            )
        )
        ad_split.addWidget(
            app._panel_card(
                "Detection Lifecycle",
                app.enterprise_detections_table,
                lambda: app._open_panel_window("Enterprise Detections", app._clone_table(app.enterprise_detections_table)),
            )
        )
        ad_split.setStretchFactor(0, 1)
        ad_split.setStretchFactor(1, 1)
        ad_layout = QVBoxLayout(ad_page)
        ad_layout.setContentsMargins(0, 0, 0, 0)
        ad_layout.addWidget(ad_split)

        # Sub-tab: Graph — 3 panels side-by-side (correlation summary,
        # focus processes, entity links). Each panel is one slice of
        # the same correlation context — keeping them at the same eye
        # height makes pivoting between them faster than scrolling
        # vertically.
        graph_page = QWidget()
        graph_split = QSplitter(Qt.Horizontal)
        graph_split.setChildrenCollapsible(False)
        self._style_splitter(graph_split)
        graph_split.addWidget(
            app._panel_card(
                "Graph Correlation",
                app.enterprise_graph_summary,
                lambda: app._open_panel_window("Graph Correlation", app._clone_text_view(app.enterprise_graph_summary)),
            )
        )
        graph_split.addWidget(
            app._panel_card(
                "Graph Focus Processes",
                app.enterprise_graph_focus,
                lambda: app._open_panel_window("Graph Focus Processes", app._clone_table(app.enterprise_graph_focus)),
            )
        )
        graph_split.addWidget(
            app._panel_card(
                "Entity Links",
                app.enterprise_entity_links,
                lambda: app._open_panel_window("Entity Links", app._clone_table(app.enterprise_entity_links)),
            )
        )
        graph_split.setStretchFactor(0, 1)
        graph_split.setStretchFactor(1, 1)
        graph_split.setStretchFactor(2, 1)
        graph_layout = QVBoxLayout(graph_page)
        graph_layout.setContentsMargins(0, 0, 0, 0)
        graph_layout.addWidget(graph_split)

        intel_right_tabs.addTab(ad_page, "Assets & Detections")
        intel_right_tabs.addTab(graph_page, "Graph")

        intel_split.addWidget(intel_left)
        intel_split.addWidget(intel_right_tabs)
        intel_split.setStretchFactor(0, 1)
        intel_split.setStretchFactor(1, 1)
        intel_layout.addWidget(intel_split)

        # ------------------------------------------------------------------
        # Tab 3: Audit Chain — full-width log + action filter chips
        # ------------------------------------------------------------------
        audit_page = QWidget()
        audit_layout = QVBoxLayout(audit_page)
        audit_layout.setContentsMargins(0, 0, 0, 0)
        audit_layout.setSpacing(8)

        # Audit filter chip row — narrows the view by category / status
        # without re-querying the disk store.
        audit_filter_row = QWidget()
        audit_filter_layout = QHBoxLayout(audit_filter_row)
        audit_filter_layout.setContentsMargins(8, 4, 8, 4)
        audit_filter_layout.setSpacing(8)
        app.enterprise_audit_category_filter = QComboBox()
        app.enterprise_audit_category_filter.addItems(["All categories", "case", "hunt"])
        app.enterprise_audit_status_filter = QComboBox()
        app.enterprise_audit_status_filter.addItems(["All status", "ok", "failed", "blocked", "cancelled", "partial"])
        app.enterprise_audit_category_filter.currentTextChanged.connect(
            lambda _v: self._render_audit_panel()
        )
        app.enterprise_audit_status_filter.currentTextChanged.connect(
            lambda _v: self._render_audit_panel()
        )
        audit_filter_layout.addWidget(QLabel("Filter category"))
        audit_filter_layout.addWidget(app.enterprise_audit_category_filter)
        audit_filter_layout.addWidget(QLabel("status"))
        audit_filter_layout.addWidget(app.enterprise_audit_status_filter)
        audit_filter_layout.addStretch(1)

        app.enterprise_audit_view = QTextBrowser()
        app.enterprise_audit_view.setOpenExternalLinks(False)
        app.enterprise_audit_view.setMinimumHeight(110)
        app.enterprise_audit_view.setStyleSheet(
            "QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;"
            "color:#eef4fb;font-family:Consolas,monospace;font-size:11px;}"
        )
        # Hydrate from disk so the audit chain survives a desktop restart.
        self._audit_inventory = self.load_audit_log()
        self._render_audit_panel()
        audit_layout.addWidget(
            app._panel_card("Audit Filters", audit_filter_row, None),
            0,
        )
        audit_layout.addWidget(
            app._panel_card(
                "Local Enterprise Audit Chain (assignments + approvals + exports + replay)",
                app.enterprise_audit_view,
                lambda: app._open_panel_window(
                    "Enterprise Audit Chain",
                    app._clone_text_view(app.enterprise_audit_view),
                ),
            ),
            1,
        )

        # ------------------------------------------------------------------
        # Tab 0: Snapshot — KPI cards + summary brief + chart, all the
        # pieces that previously consumed several hundred pixels above
        # the workspace. Putting them behind a tab lets the analyst
        # collapse to "just the workspace" with a single click.
        # ------------------------------------------------------------------
        snapshot_page = QWidget()
        snapshot_layout = QVBoxLayout(snapshot_page)
        snapshot_layout.setContentsMargins(0, 0, 0, 0)
        snapshot_layout.setSpacing(8)
        snapshot_layout.addWidget(summary_row, 0)
        snapshot_layout.addWidget(context_metrics, 0)
        snapshot_layout.addWidget(metrics, 0)
        snapshot_layout.addStretch(1)

        enterprise_sections.addTab(snapshot_page, "Snapshot")
        enterprise_sections.addTab(ops_page, "Operations")
        enterprise_sections.addTab(intel_page, "Intel && Graph")
        enterprise_sections.addTab(audit_page, "Audit Chain")

        # Snapshot first-activation auto-refresh — when the operator
        # lands on the Snapshot tab and the workspace hasn't been
        # refreshed yet (KPIs still showing "--"), trigger one
        # `refresh_workspace`. After the first hit the flag stays True
        # so the operator's manual refreshes aren't second-guessed.
        self._snapshot_first_activation_done = False

        def _maybe_auto_refresh_snapshot(index: int) -> None:
            try:
                if enterprise_sections.tabText(index) != "Snapshot":
                    return
                if self._snapshot_first_activation_done:
                    return
                if not hasattr(app, "auth_context"):
                    return
                if str(app.auth_context.get("role", "locked") or "locked") == "locked":
                    return
                self._snapshot_first_activation_done = True
                # One-shot — defer to event loop tick so the tab paint
                # finishes before the network call kicks off.
                QTimer.singleShot(0, app.refresh_enterprise_workspace)
            except Exception:
                pass

        enterprise_sections.currentChanged.connect(_maybe_auto_refresh_snapshot)
        # Compact top — only the input row and action bar (controls_card)
        # live here now. Status badges, filters, KPI cards, and the
        # summary chart have moved into the "Snapshot" sub-tab to
        # reclaim ~280 px of vertical space at the top of the workspace.
        l.addWidget(overview_section, 0)
        l.addWidget(enterprise_sections, 1)

        # ------------------------------------------------------------------
        # Keyboard shortcuts — operator muscle memory matters once the
        # console is in production rotation. Owned by the tab widget
        # (`w`) so they only fire while the analyst is on Enterprise.
        # ------------------------------------------------------------------
        QShortcut(QKeySequence("Ctrl+R"), w).activated.connect(app.refresh_enterprise_workspace)
        QShortcut(QKeySequence("Ctrl+N"), w).activated.connect(app.create_enterprise_case)
        QShortcut(QKeySequence("Ctrl+E"), w).activated.connect(app.export_selected_case_report)
        QShortcut(QKeySequence("Ctrl+M"), w).activated.connect(app.load_enterprise_mitre_bundle)
        QShortcut(QKeySequence("Ctrl+Shift+A"), w).activated.connect(app.assign_enterprise_case)
        QShortcut(QKeySequence("Ctrl+Shift+P"), w).activated.connect(app.request_enterprise_approval)

        # ------------------------------------------------------------------
        # Approval poller — every 30 seconds, refresh just the Pending
        # Approvals KPI tile so a SOC analyst sitting on Enterprise sees
        # a new approval request without manually clicking Refresh. The
        # full workspace refresh stays manual (clicking Refresh) so the
        # cases table doesn't reshuffle under the operator's cursor.
        # ------------------------------------------------------------------
        from PySide6.QtCore import QTimer
        self._approval_poll_timer = QTimer(w)
        self._approval_poll_timer.setInterval(30_000)
        self._approval_poll_timer.timeout.connect(self._poll_pending_approvals)
        self._approval_poll_timer.start()
        return w

    def refresh_workspace(self) -> None:
        app = self.app
        current_role = str(app.auth_context.get("role", "locked") or "locked")
        if current_role == "locked":
            self._set_enterprise_locked_state()
            return
        preferred_case_id = app.enterprise_selected_case_id or app._safe_int(app.settings.value("enterprise_selected_case_id", ""))
        app.enterprise_live_status.setText("Live sync loading enterprise workspace...")
        app.enterprise_role_banner.setText(f"Role context: {current_role}")
        try:
            triage = app._get("/enterprise/triage", timeout=10).json()
            assets = app._get("/enterprise/assets", timeout=10).json()
            cases = app._get("/enterprise/cases", timeout=10).json()
            approvals = app._get("/enterprise/approvals", timeout=10).json()
            detections = app._get("/enterprise/detections/lifecycle", timeout=10).json()
            mitre_status = app._get("/enterprise/mitre/status", timeout=10).json()
            mitre_summary = app._get("/enterprise/mitre/summary", timeout=10).json()
            mitre_discover = app._get("/enterprise/mitre/discover", timeout=10).json()
            mitre_compare = app._post("/enterprise/mitre/compare", json={"file_path": app.enterprise_mitre_bundle_path.text().strip()}, timeout=20).json() if app.enterprise_mitre_bundle_path.text().strip() else {}
        except Exception as exc:
            app.enterprise_cases_data = []
            app._populate_enterprise_cases_table([])
            app._show_error(app.enterprise_detail, "Enterprise workspace failed", exc)
            app.enterprise_live_status.setText("Live sync failed")
            return
        attention = "".join(f"<li>{html.escape(str(item))}</li>" for item in triage.get("what_needs_attention_now", []))
        auth_anomalies = triage.get("auth_anomalies", [])
        auth_items = "".join(
            f"<li>{html.escape(str(item.get('message') or item.get('summary') or item.get('actor') or 'Anomalous authentication pattern detected'))}</li>"
            for item in auth_anomalies[:3]
            if isinstance(item, dict)
        )
        pending_approvals = [item for item in approvals if str(item.get("status", "")).strip().lower() in {"pending", "requested", "open"}] if isinstance(approvals, list) else []
        app.enterprise_summary.setHtml(
            f"<h3>Triage First</h3><ul>{attention or '<li>No immediate triage items.</li>'}</ul>"
            f"<p><b>Open cases:</b> {len(cases)}"
            f"<br><b>Top auth anomalies:</b> {len(auth_anomalies)}"
            f"<br><b>Pending approvals:</b> {len(pending_approvals)}</p>"
            f"<h4>Authentication Watch</h4><ul>{auth_items or '<li>No recent authentication anomalies in focus.</li>'}</ul>"
        )
        app._set_metric_label(app.enterprise_open_cases_value, str(len(cases)))
        app._set_metric_label(app.enterprise_high_risk_value, str(len([item for item in assets.get("top_assets", []) if float(item.get("criticality_score", 0) or 0) >= 85])))
        app._set_metric_label(app.enterprise_selected_case_value, f"#{preferred_case_id}" if preferred_case_id else "None")
        app._set_metric_label(app.enterprise_auth_anomalies_value, str(len(auth_anomalies)))
        app._set_metric_label(app.enterprise_pending_approvals_value, str(len(pending_approvals)))
        app._set_metric_label(app.enterprise_event_pressure_value, "0")
        app.enterprise_cases_data = cases
        app._populate_enterprise_cases_table(cases)
        top_assets = assets.get("top_assets", [])
        app.enterprise_assets_table.setRowCount(len(top_assets))
        for r, item in enumerate(top_assets):
            values = [item.get("pid", ""), item.get("name", ""), item.get("criticality_score", ""), item.get("rationale", "")]
            for c, value in enumerate(values):
                app.enterprise_assets_table.setItem(r, c, QTableWidgetItem(str(value)))
            sev = "critical" if float(item.get("criticality_score", 0) or 0) >= 85 else "medium"
            app._paint_row(app.enterprise_assets_table, r, app._severity_color(sev))
        rules = detections.get("rules", [])
        app.enterprise_detections_table.setRowCount(len(rules))
        for r, item in enumerate(rules):
            values = [item.get("rule_id", ""), item.get("version", ""), item.get("status", ""), item.get("notes", "")]
            for c, value in enumerate(values):
                app.enterprise_detections_table.setItem(r, c, QTableWidgetItem(str(value)))
        story = {"title": "Enterprise triage narrative", "severity": "medium", "attack_chain": ["prioritize", "investigate", "approve", "contain"]}
        try:
            story = app._get("/incidents", timeout=8).json()[0]
        except Exception:
            pass
        app.enterprise_narrative.setHtml(
            "<h3>Progressive Disclosure</h3>"
            f"<p><b>Summary:</b> {html.escape(str(story.get('title', 'Prioritize high-criticality assets and pending approvals.')))}</p>"
            f"<p><b>Severity:</b> {html.escape(str(story.get('severity', 'medium')))}"
            f"<br><b>Attack chain:</b> {html.escape(', '.join(story.get('attack_chain', [])) if isinstance(story.get('attack_chain', []), list) else str(story.get('attack_chain', 'ready')))}</p>"
            "<p><b>Raw detail:</b> use the left-side tables, case board, and notification inbox for operational depth. Run <b>Replay Artifact</b> only when you explicitly want replay analysis.</p>"
        )
        app.enterprise_mitre_summary.setHtml(app._render_enterprise_mitre_summary(mitre_status, mitre_summary, mitre_compare, mitre_discover))
        app._show_json(app.enterprise_detail, {"triage": triage, "assets": assets, "approvals": approvals, "detections": detections, "mitre_status": mitre_status, "mitre_summary": mitre_summary, "mitre_discover": mitre_discover, "mitre_compare": mitre_compare, "story": story})
        if cases:
            selected_row = next((idx for idx, item in enumerate(cases) if int(item.get("id", 0) or 0) == preferred_case_id), 0)
            app.enterprise_cases_table.selectRow(selected_row)
            app.load_selected_case_board()
            app.enterprise_loaded_once = True
            app.enterprise_live_status.setText(f"Live sync updated {time.strftime('%H:%M:%S')}")
        else:
            app._clear_enterprise_case_views()
            app.enterprise_summary.setHtml(
                "<h3>Triage First</h3><p>No enterprise cases yet. Create a case to begin assignments, case board tracking, ATT&CK mapping, and approvals.</p>"
            )
            app.enterprise_warning_banner.setText("No enterprise cases yet. Create a case to start the investigation workflow.")
            app.enterprise_live_status.setText("Live sync idle - no active cases")

    def create_case(self) -> None:
        app = self.app
        if not self._check_action_gate("create-case"):
            return
        payload = {
            "title": app.enterprise_case_title.text().strip() or "Suspicious activity case",
            "owner": app.enterprise_case_owner.text().strip(),
            "priority": app.enterprise_case_priority.currentText(),
            "narrative": "Created from the enterprise triage-first workflow.",
            "asset_criticality": 75,
        }
        try:
            result = app._post("/enterprise/cases", json=payload, timeout=30).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        case_id = result.get("id") if isinstance(result, dict) else None
        # Creation events don't take a structured reason — they're not
        # destructive — but they must show up in the audit chain so a
        # SOC manager can see who opened which case at what time and
        # under whose API key.
        self._record_audit(
            category="case",
            action="create",
            target=f"case={case_id or 'pending'} title={payload['title']}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload={"request": payload, "response": result},
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Create case failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.refresh_enterprise_workspace()

    def selected_case_id(self) -> int | None:
        app = self.app
        row = app.enterprise_cases_table.currentRow()
        if row < 0:
            return None
        item = app.enterprise_cases_table.item(row, 0)
        if item is None:
            return None
        try:
            return int(item.text())
        except Exception:
            return None

    def on_case_selection_changed(self) -> None:
        app = self.app
        app.enterprise_selected_case_id = app._selected_enterprise_case_id()
        app._persist_enterprise_ui_state()
        app.load_selected_case_board()

    def selected_task_id(self) -> int | None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        row = app.enterprise_tasks_table.currentRow()
        if case_id is None or row < 0:
            return None
        tasks = getattr(app, "enterprise_filtered_tasks_data", getattr(app, "enterprise_tasks_data", []))
        if row >= len(tasks):
            return None
        try:
            return int(tasks[row].get("id", 0) or 0)
        except Exception:
            return None

    def load_selected_case_board(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app._clear_enterprise_case_views()
            return
        # Bump the load token — any in-flight worker that finishes
        # *after* the operator has clicked another case will see its
        # token mismatch and drop the response. Stops a stale board
        # rendering on top of the freshly-selected one.
        self._board_load_token += 1
        token = self._board_load_token
        app.enterprise_live_status.setText(f"Loading case {case_id}...")

        def _gather() -> dict:
            # Each call is independent; hold partial results so a single
            # failed sub-fetch (e.g. stories endpoint hiccup) doesn't
            # force the operator to lose the rest of the board.
            partials: dict[str, Any] = {"errors": []}
            calls = [
                ("board", lambda: app._get(f"/enterprise/cases/{case_id}/board", timeout=20).json()),
                ("assignments", lambda: app._get(f"/enterprise/cases/{case_id}/assignments", timeout=20).json()),
                ("tasks", lambda: app._get(f"/enterprise/cases/{case_id}/tasks", timeout=20).json()),
                ("activity", lambda: app._get(f"/enterprise/cases/{case_id}/activity", timeout=20).json()),
                ("notes", lambda: app._get("/enterprise/investigations/notes", params={"case_id": case_id}, timeout=20).json()),
                ("stories", lambda: app._get("/enterprise/investigations/stories", params={"case_id": case_id}, timeout=20).json()),
                ("mitre", lambda: app._get(f"/enterprise/cases/{case_id}/mitre", timeout=20).json()),
            ]
            for key, fn in calls:
                try:
                    partials[key] = fn()
                except Exception as exc:
                    partials[key] = None
                    partials["errors"].append({"endpoint": key, "error": str(exc)})
            return partials

        thread = QThread(app)
        worker = _EnterpriseWorker(_gather)
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

        def _on_partials(partials: dict) -> None:
            if finished["value"]:
                return
            finished["value"] = True
            try:
                if token != self._board_load_token:
                    # Superseded by a newer click — drop silently.
                    return
                board = partials.get("board") or {}
                assignments = partials.get("assignments") or []
                tasks = partials.get("tasks") or []
                activity = partials.get("activity") or []
                notes = partials.get("notes") or []
                stories = partials.get("stories") or []
                mitre = partials.get("mitre") or {}
                errors = partials.get("errors") or []
                if errors and not isinstance(board, dict):
                    # Hard fail — board endpoint itself died, nothing
                    # to render. Surface error and bail.
                    msg = "; ".join(f"{item['endpoint']}: {item['error']}" for item in errors[:3])
                    app._show_error(app.enterprise_detail, "Case board load failed", Exception(msg))
                    app.enterprise_live_status.setText("Live sync failed")
                    return
                self._apply_case_board(case_id, board, assignments, tasks, activity, notes, stories, mitre, errors)
            finally:
                cleanup()

        def _on_failure(message: str) -> None:
            if finished["value"]:
                return
            finished["value"] = True
            try:
                if token != self._board_load_token:
                    return
                app._show_error(app.enterprise_detail, "Case board load failed", Exception(message))
                app.enterprise_live_status.setText("Live sync failed")
            finally:
                cleanup()

        thread.started.connect(worker.run)
        worker.finished.connect(_on_partials)
        worker.failed.connect(_on_failure)
        self._async_jobs.append((thread, worker))
        thread.start()

    def _apply_case_board(
        self,
        case_id: int,
        board: dict,
        assignments: list,
        tasks: list,
        activity: list,
        notes: list,
        stories: list,
        mitre: dict,
        errors: list[dict] | None = None,
    ) -> None:
        app = self.app
        try:
            app.enterprise_case_board_data = board
            app.enterprise_assignments_data = assignments
            app.enterprise_tasks_data = tasks
            app.enterprise_activity_data = activity
            app.enterprise_notes_data = notes
            app.enterprise_stories_data = stories
            app.enterprise_case_mitre_data = mitre
            queue = board.get("queue", {}) if isinstance(board, dict) else {}
            kpis = board.get("kpis", {}) if isinstance(board, dict) else {}
            app.enterprise_timeline_data = board.get("timeline", []) if isinstance(board.get("timeline", []), list) else []
            entity_links = board.get("entity_links", {}) if isinstance(board.get("entity_links", {}), dict) else {}
            app.enterprise_entity_links_data = entity_links.get("items", []) if isinstance(entity_links.get("items", []), list) else []
            app.enterprise_notifications_data = app._build_enterprise_notifications(case_id, queue, kpis, tasks, activity)
            next_steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in board.get("recommended_next_steps", []))
            app.enterprise_case_board.setHtml(
                "<h3>Case Board</h3>"
                f"<p><b>Open tasks:</b> {queue.get('open_tasks', 0)}"
                f"<br><b>Overdue tasks:</b> {queue.get('overdue_tasks', 0)}"
                f"<br><b>Pins:</b> {queue.get('pinned', 0)}"
                f"<br><b>Stories:</b> {queue.get('stories', 0)}</p>"
                f"<p><b>KPI summary:</b> {html.escape(json.dumps(kpis))}"
                f"<br><b>Linked entities:</b> {len(app.enterprise_entity_links_data)}</p>"
                f"<h4>Next Steps</h4><ul>{next_steps or '<li>No recommended next steps.</li>'}</ul>"
            )
            app.enterprise_case_mitre.setHtml(app._render_enterprise_case_mitre(mitre))
            app._set_metric_label(app.enterprise_selected_case_value, f"#{case_id}")
            app._set_metric_label(app.enterprise_event_pressure_value, str(kpis.get("high_or_critical_events", 0)))
            app._set_metric_label(app.enterprise_overdue_value, str(queue.get("overdue_tasks", 0)))
            app._set_metric_label(app.enterprise_assignments_value, str(queue.get("assignments", 0)))
            app._apply_enterprise_filters()
            warnings: list[str] = []
            if int(queue.get("overdue_tasks", 0) or 0) > 0:
                warnings.append(f"{queue.get('overdue_tasks', 0)} overdue tasks")
            if int(queue.get("open_tasks", 0) or 0) > 6:
                warnings.append(f"{queue.get('open_tasks', 0)} open tasks")
            if int(kpis.get("high_or_critical_events", 0) or 0) > 0:
                warnings.append(f"{kpis.get('high_or_critical_events', 0)} high-risk events")
            warning_text = " | ".join(warnings) if warnings else "No urgent warnings for the selected case."
            if app.enterprise_notifications_data:
                warning_text = f"{warning_text} | Inbox: {len(app.enterprise_notifications_data)} items"
            # Surface partial-fetch failures in the warning banner so the
            # operator knows the board is slightly degraded — better than
            # silently rendering missing data.
            if errors:
                bad_endpoints = ", ".join(sorted({str(item.get("endpoint", "?")) for item in errors}))
                warning_text = f"{warning_text} | Partial: {bad_endpoints}"
            app.enterprise_warning_banner.setText(warning_text)
            app.load_enterprise_case_graph(board=board)
            app._refresh_enterprise_kpi_chart(queue, kpis, len(notes), len(stories))
            app._refresh_enterprise_timeline_table()
            app._refresh_enterprise_entity_links_table()
            app.enterprise_live_status.setText(f"Live sync updated {time.strftime('%H:%M:%S')}")
            app._show_json(
                app.enterprise_detail,
                {
                    "board": board,
                    "assignments": assignments,
                    "tasks": tasks,
                    "activity": activity,
                    "notes": notes,
                    "stories": stories,
                    "mitre": mitre,
                    "notifications": app.enterprise_notifications_data,
                    "errors": errors or [],
                },
            )
        except Exception as exc:
            # Render-time exception (UI element gone, JSON shape change,
            # etc.) — degrade gracefully rather than tearing down the
            # case-board worker thread.
            app._show_error(app.enterprise_detail, "Case board render failed", exc)
            app.enterprise_live_status.setText("Live sync render failed")

    def clear_case_views(self) -> None:
        app = self.app
        app.enterprise_case_board.setHtml("<h3>Case Board</h3><p>No case selected yet. Pick a case on the left or create a new one.</p>")
        app._set_metric_label(app.enterprise_selected_case_value, "None")
        app._set_metric_label(app.enterprise_event_pressure_value, "0")
        app._set_metric_label(app.enterprise_overdue_value, "0")
        app._set_metric_label(app.enterprise_assignments_value, "0")
        app.enterprise_mitre_summary.setHtml("<h3>ATT&CK Coverage</h3><p>Load a MITRE ATT&CK bundle to see enterprise coverage, tactics, mitigations, and software overlap.</p>")
        app.enterprise_case_mitre.setHtml("<h3>Case ATT&CK</h3><p>Select a case to review mapped techniques, mitigations, and actor context.</p>")
        app.enterprise_graph_summary.setHtml("<h3>Case Correlation View</h3><p>No active case context yet.</p>")
        app.enterprise_narrative.setHtml("<h3>Progressive Disclosure</h3><p>No case narrative yet. Once a case is selected, the analyst story will appear here.</p>")
        self._set_enterprise_detail_message(
            "No Enterprise Case Selected",
            "Select a case from the Cases table or create a new case to load tasks, assignments, narrative, notifications, and graph correlation.",
        )
        app.enterprise_warning_banner.setText("No active case selected.")
        app.enterprise_timeline_data = []
        app.enterprise_entity_links_data = []
        app.enterprise_notifications_data = []
        app.enterprise_assignments_data = []
        app.enterprise_tasks_data = []
        app.enterprise_activity_data = []
        app.enterprise_notes_data = []
        app.enterprise_stories_data = []
        app.enterprise_case_mitre_data = {}
        app.enterprise_graph_focus.setRowCount(0)
        app.enterprise_assignments_table.setRowCount(0)
        app.enterprise_tasks_table.setRowCount(0)
        app.enterprise_activity_table.setRowCount(0)
        app.enterprise_notes_table.setRowCount(0)
        app.enterprise_stories_table.setRowCount(0)
        app.enterprise_notifications_cases_table.setRowCount(0)
        app.enterprise_notifications_table.setRowCount(0)
        app.enterprise_case_timeline.setRowCount(0)
        app.enterprise_entity_links.setRowCount(0)

    def render_mitre_summary(self, status: dict[str, Any], summary: dict[str, Any], compare: dict[str, Any], discover: list[dict[str, Any]]) -> str:
        loaded = bool(status.get("loaded"))
        top_tactics = "".join(f"<li>{html.escape(str(item.get('name', '')))}: {html.escape(str(item.get('count', 0)))}</li>" for item in summary.get("top_tactics", [])[:6])
        top_techniques = "".join(f"<li>{html.escape(str(item.get('technique_id', '')))} - {html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>" for item in summary.get("top_mapped_techniques", [])[:6])
        tactic_heat = "".join(f"<li>{html.escape(str(item.get('name', '')))} score {html.escape(str(item.get('score', 0)))}</li>" for item in summary.get("tactic_heat", [])[:6])
        discovered_html = "".join(f"<li>{html.escape(Path(str(item.get('path', ''))).name)} | v{html.escape(str(item.get('version', 'unknown')))} | techniques {html.escape(str(item.get('technique_count', 0)))}</li>" for item in discover[:5])
        diff_html = "".join(f"<li>{html.escape(str(item.get('technique_id', '')))} updated to {html.escape(str(item.get('candidate_modified', '')))}</li>" for item in compare.get("modified_techniques", [])[:5])
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

    def render_case_mitre(self, coverage: dict[str, Any]) -> str:
        summary = coverage.get("coverage_summary", {}) if isinstance(coverage, dict) else {}
        techniques = coverage.get("techniques", []) if isinstance(coverage.get("techniques", []), list) else []
        technique_rows = "".join(f"<li>{html.escape(str(item.get('attack_id', '')))} - {html.escape(str(item.get('name', '')))} | tactics: {html.escape(', '.join(item.get('tactics', [])) if isinstance(item.get('tactics', []), list) else '')}</li>" for item in techniques[:8])
        mitigations = "".join(f"<li>{html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>" for item in summary.get("top_mitigations", [])[:5])
        software = "".join(f"<li>{html.escape(str(item.get('name', '')))} ({html.escape(str(item.get('count', 0)))})</li>" for item in summary.get("top_software", [])[:5])
        rollup = "".join(f"<li>{html.escape(str(item.get('attack_id', '')))} ({html.escape(str(item.get('count', 0)))})</li>" for item in summary.get("parent_technique_rollup", [])[:5])
        cues = "".join(f"<li>{html.escape(str(item.get('cue', '')))} ({html.escape(str(item.get('count', 0)))})</li>" for item in summary.get("telemetry_cue_hotspots", [])[:6])
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

    def export_mitre_layer(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("ATT&CK Export Blocked", "Select an enterprise case before exporting a Navigator layer.")
            return
        if not self._check_action_gate("export-mitre-layer"):
            return
        payload = {"case_id": case_id, "layer_name": f"ShadowLab Case {case_id} ATT&CK Coverage", "description": "Navigator layer exported from the enterprise investigation workspace."}
        try:
            result = app._post("/enterprise/mitre/navigator/export", json=payload, timeout=45).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        saved_path = str(result.get("saved_path", "") or "") if isinstance(result, dict) else ""
        self._record_audit(
            category="case",
            action="export-mitre-layer",
            target=f"case={case_id} path={saved_path or 'pending'}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload=result,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "ATT&CK layer export failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        if saved_path:
            app.statusBar().showMessage(f"Navigator layer exported to {saved_path}")

    def export_mitre_workbench(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Workbench Export Blocked", "Select an enterprise case before exporting ATT&CK workbench coverage.")
            return
        if not self._check_action_gate("export-mitre-workbench"):
            return
        try:
            result = app._post("/enterprise/mitre/workbench/export", json={"case_id": case_id}, timeout=45).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        saved_path = str(result.get("saved_path", "") or "") if isinstance(result, dict) else ""
        self._record_audit(
            category="case",
            action="export-mitre-workbench",
            target=f"case={case_id} path={saved_path or 'pending'}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload=result,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Workbench export failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        if saved_path:
            app.statusBar().showMessage(f"Workbench coverage exported to {saved_path}")

    def refresh_kpi_chart(self, queue: dict, kpis: dict, note_count: int, story_count: int) -> None:
        app = self.app
        load_set = QBarSet("Load")
        load_set.setColor(QColor("#8ec5ff"))
        load_values = [float(queue.get("open_tasks", 0) or 0), float(queue.get("overdue_tasks", 0) or 0), float(note_count or 0), float(story_count or 0), float(kpis.get("high_or_critical_events", 0) or 0)]
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
        app.enterprise_kpi_chart.setChart(chart)

    def show_cached_item(self, cache_name: str, table: QTableWidget) -> None:
        app = self.app
        row = table.currentRow()
        if row < 0:
            self._set_enterprise_detail_message(
                "No Item Selected",
                "Select a row in the active enterprise table to inspect its raw record and workflow context.",
            )
            return
        items = getattr(app, cache_name, [])
        if row >= len(items):
            self._set_enterprise_detail_message(
                "Enterprise Detail Unavailable",
                "The selected row no longer maps to cached enterprise data. Refresh the workspace and select the item again.",
            )
            return
        app._show_json(app.enterprise_detail, items[row])

    def show_selected_assignment(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_assignments_data", self.app.enterprise_assignments_table)

    def show_selected_task(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_tasks_data", self.app.enterprise_tasks_table)

    def show_selected_activity(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_activity_data", self.app.enterprise_activity_table)

    def show_selected_notification(self) -> None:
        app = self.app
        table = app.sender() if isinstance(app.sender(), QTableWidget) else app.enterprise_notifications_table
        app._show_enterprise_cached_item("enterprise_notifications_data", table)

    def show_selected_timeline(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_timeline_data", self.app.enterprise_case_timeline)

    def show_selected_link(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_entity_links_data", self.app.enterprise_entity_links)

    def show_selected_note(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_notes_data", self.app.enterprise_notes_table)

    def show_selected_story(self) -> None:
        self.app._show_enterprise_cached_item("enterprise_stories_data", self.app.enterprise_stories_table)

    PRIORITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def _show_cases_context_menu(self, point) -> None:
        """Right-click context menu on a case row.

        Brings the most-used pivot actions (assign, export, approval,
        copy ID) within a single click of where the analyst's eyes
        already are. The action handlers are the same ones the top
        toolbar fires — context menu is purely a discoverability and
        speed shortcut, not a separate code path.
        """
        from PySide6.QtWidgets import QMenu
        app = self.app
        table = app.enterprise_cases_table
        row = table.indexAt(point).row()
        if row < 0:
            return
        # Make sure the right-clicked row is the selected one — without
        # this, the action would target whatever row WAS selected
        # before the right-click, which is confusing.
        table.selectRow(row)

        case_id_item = table.item(row, 0)
        case_id = case_id_item.text() if case_id_item else ""
        priority_item = table.item(row, 2)
        priority = priority_item.text() if priority_item else ""

        menu = QMenu(table)
        title_action = menu.addAction(f"Case #{case_id} ({priority or 'unknown priority'})")
        title_action.setEnabled(False)
        menu.addSeparator()

        assign_action = menu.addAction("Assign analyst…   Ctrl+Shift+A")
        approval_action = menu.addAction("Request approval…   Ctrl+Shift+P")
        export_action = menu.addAction("Export investigation report…   Ctrl+E")
        menu.addSeparator()
        layer_action = menu.addAction("Export ATT&CK Navigator layer")
        workbench_action = menu.addAction("Export ATT&CK workbench coverage")
        menu.addSeparator()
        graph_action = menu.addAction("Load case graph correlation")
        board_action = menu.addAction("Reload case board")
        menu.addSeparator()
        copy_id_action = menu.addAction(f"Copy case ID ({case_id})")
        copy_target_action = menu.addAction("Copy enterprise:cases target")

        chosen = menu.exec(table.viewport().mapToGlobal(point))
        if chosen is None:
            return
        if chosen is assign_action:
            app.assign_enterprise_case()
        elif chosen is approval_action:
            app.request_enterprise_approval()
        elif chosen is export_action:
            app.export_selected_case_report()
        elif chosen is layer_action:
            app.export_enterprise_mitre_layer()
        elif chosen is workbench_action:
            app.export_enterprise_mitre_workbench()
        elif chosen is graph_action:
            app.load_enterprise_case_graph()
        elif chosen is board_action:
            app.load_selected_case_board()
        elif chosen is copy_id_action:
            try:
                from PySide6.QtGui import QGuiApplication
                QGuiApplication.clipboard().setText(case_id)
                app.statusBar().showMessage(f"Copied case ID {case_id} to clipboard.")
            except Exception:
                pass
        elif chosen is copy_target_action:
            try:
                from PySide6.QtGui import QGuiApplication
                QGuiApplication.clipboard().setText(f"enterprise:cases:{case_id}")
                app.statusBar().showMessage(f"Copied target enterprise:cases:{case_id}.")
            except Exception:
                pass

    def populate_cases_table(self, cases: list[dict]) -> None:
        app = self.app
        # Disable sorting while we batch-insert rows so QTableWidget
        # doesn't re-sort after every cell write — that would silently
        # reshuffle the model relative to `cases` and break the
        # `_on_enterprise_case_selection_changed` row-index lookup.
        sorting_was_on = app.enterprise_cases_table.isSortingEnabled()
        app.enterprise_cases_table.setSortingEnabled(False)
        app.enterprise_cases_table.blockSignals(True)
        app.enterprise_cases_table.setRowCount(len(cases))
        for r, item in enumerate(cases):
            values = [item.get("id", ""), item.get("title", ""), item.get("priority", ""), item.get("stage", ""), item.get("owner", ""), item.get("status", "")]
            for c, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                # Stash a sortable numeric / canonical key in UserRole
                # for columns where lexical sort would mislead the
                # operator (Priority: critical>high>medium>low; ID: numeric).
                if c == 0:  # ID
                    try:
                        cell.setData(Qt.UserRole, int(value))
                    except (TypeError, ValueError):
                        cell.setData(Qt.UserRole, 0)
                elif c == 2:  # Priority
                    cell.setData(Qt.UserRole, self.PRIORITY_RANK.get(str(value).lower(), 0))
                app.enterprise_cases_table.setItem(r, c, cell)
            app._paint_row(app.enterprise_cases_table, r, app._severity_color(item.get("priority", "")))
        app.enterprise_cases_table.blockSignals(False)
        if sorting_was_on:
            app.enterprise_cases_table.setSortingEnabled(True)

    def apply_filters(self) -> None:
        app = self.app
        app._enterprise_table_updating = True
        case_filter = app.enterprise_case_filter.text().strip().lower() if hasattr(app, "enterprise_case_filter") else ""
        task_filter = app.enterprise_task_filter.text().strip().lower() if hasattr(app, "enterprise_task_filter") else ""
        activity_filter = app.enterprise_activity_filter.text().strip().lower() if hasattr(app, "enterprise_activity_filter") else ""

        priority_choice = "all"
        if hasattr(app, "enterprise_case_priority_filter"):
            raw = app.enterprise_case_priority_filter.currentText().strip().lower()
            if raw and not raw.startswith("all"):
                priority_choice = raw
        status_choice = "all"
        if hasattr(app, "enterprise_case_status_filter"):
            raw = app.enterprise_case_status_filter.currentText().strip().lower()
            if raw and not raw.startswith("all"):
                status_choice = raw

        def _passes_case(item: dict) -> bool:
            if case_filter and case_filter not in json.dumps(item).lower():
                return False
            if priority_choice != "all" and str(item.get("priority", "")).lower() != priority_choice:
                return False
            if status_choice != "all" and str(item.get("status", "")).lower() != status_choice:
                return False
            return True

        filtered_cases = [item for item in getattr(app, "enterprise_cases_data", []) if _passes_case(item)]
        app._populate_enterprise_cases_table(filtered_cases)
        app.enterprise_filtered_cases_data = filtered_cases
        assignments = getattr(app, "enterprise_assignments_data", [])
        app.enterprise_assignments_table.setRowCount(len(assignments))
        for r, item in enumerate(assignments):
            values = [item.get("analyst", ""), item.get("role", ""), item.get("status", ""), item.get("assigned_by", "")]
            for c, value in enumerate(values):
                app.enterprise_assignments_table.setItem(r, c, QTableWidgetItem(str(value)))
        notes = [item for item in getattr(app, "enterprise_notes_data", []) if not activity_filter or activity_filter in json.dumps(item).lower()]
        app.enterprise_notes_table.setRowCount(len(notes))
        for r, item in enumerate(notes):
            values = [item.get("author", ""), item.get("item_type", ""), item.get("note_text", "")]
            for c, value in enumerate(values):
                app.enterprise_notes_table.setItem(r, c, QTableWidgetItem(str(value)))
        stories = [item for item in getattr(app, "enterprise_stories_data", []) if not activity_filter or activity_filter in json.dumps(item).lower()]
        app.enterprise_stories_table.setRowCount(len(stories))
        for r, item in enumerate(stories):
            values = [item.get("title", ""), item.get("confidence", ""), item.get("created_by", "")]
            for c, value in enumerate(values):
                app.enterprise_stories_table.setItem(r, c, QTableWidgetItem(str(value)))
        tasks = [item for item in getattr(app, "enterprise_tasks_data", []) if not task_filter or task_filter in json.dumps(item).lower()]
        app.enterprise_filtered_tasks_data = tasks
        app.enterprise_tasks_table.blockSignals(True)
        app.enterprise_tasks_table.setRowCount(len(tasks))
        for r, item in enumerate(tasks):
            values = [item.get("title", ""), item.get("status", ""), item.get("priority", ""), item.get("assigned_to", "")]
            for c, value in enumerate(values):
                cell = QTableWidgetItem(str(value))
                cell.setData(Qt.UserRole, int(item.get("id", 0) or 0))
                if c == 0:
                    cell.setFlags(cell.flags() & ~Qt.ItemIsEditable)
                app.enterprise_tasks_table.setItem(r, c, cell)
            due_at = float(item.get("due_at", 0) or 0)
            is_overdue = due_at > 0 and due_at < time.time() and str(item.get("status", "")).lower() not in {"done", "closed"}
            sev = "high" if is_overdue else item.get("priority", "")
            app._paint_row(app.enterprise_tasks_table, r, app._severity_color(str(sev)))
        app.enterprise_tasks_table.blockSignals(False)
        activity = [item for item in getattr(app, "enterprise_activity_data", []) if not activity_filter or activity_filter in json.dumps(item).lower()]
        app.enterprise_activity_table.setRowCount(len(activity))
        for r, item in enumerate(activity):
            values = [item.get("created_at", ""), item.get("event_type", ""), item.get("actor", ""), item.get("summary", "")]
            for c, value in enumerate(values):
                app.enterprise_activity_table.setItem(r, c, QTableWidgetItem(str(value)))
        notifications = [item for item in getattr(app, "enterprise_notifications_data", []) if not activity_filter or activity_filter in json.dumps(item).lower()]
        for table in [app.enterprise_notifications_cases_table, app.enterprise_notifications_table]:
            table.setRowCount(len(notifications))
            for r, item in enumerate(notifications):
                values = [item.get("created_at", ""), item.get("severity", ""), item.get("category", ""), item.get("message", "")]
                for c, value in enumerate(values):
                    table.setItem(r, c, QTableWidgetItem(str(value)))
                app._paint_row(table, r, app._severity_color(str(item.get("severity", "low"))))
        app._enterprise_table_updating = False
        app._persist_enterprise_ui_state()

    def refresh_timeline_table(self) -> None:
        app = self.app
        timeline = getattr(app, "enterprise_timeline_data", [])
        app.enterprise_case_timeline.setRowCount(len(timeline))
        for r, item in enumerate(timeline):
            values = [item.get("time", ""), item.get("kind", ""), item.get("severity", ""), item.get("title", "")]
            for c, value in enumerate(values):
                app.enterprise_case_timeline.setItem(r, c, QTableWidgetItem(str(value)))
            app._paint_row(app.enterprise_case_timeline, r, app._severity_color(str(item.get("severity", "low"))))

    def refresh_entity_links_table(self) -> None:
        app = self.app
        links = getattr(app, "enterprise_entity_links_data", [])
        app.enterprise_entity_links.setRowCount(len(links))
        for r, item in enumerate(links):
            values = [item.get("entity", ""), item.get("kind", ""), item.get("evidence_count", ""), ", ".join(item.get("examples", [])[:2])]
            for c, value in enumerate(values):
                app.enterprise_entity_links.setItem(r, c, QTableWidgetItem(str(value)))

    def build_notifications(self, case_id: int, queue: dict, kpis: dict, tasks: list[dict], activity: list[dict]) -> list[dict]:
        notifications: list[dict] = []
        now = time.time()
        if int(queue.get("overdue_tasks", 0) or 0) > 0:
            notifications.append({"created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "severity": "high", "category": "task", "message": f"{queue.get('overdue_tasks', 0)} overdue tasks require action.", "case_id": case_id})
        if int(kpis.get("high_or_critical_events", 0) or 0) > 0:
            notifications.append({"created_at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)), "severity": "high", "category": "risk", "message": f"{kpis.get('high_or_critical_events', 0)} high-risk events are tied to this case.", "case_id": case_id})
        for task in tasks[:8]:
            due_at = float(task.get("due_at", 0) or 0)
            status = str(task.get("status", "")).lower()
            if due_at > 0 and due_at < now and status not in {"done", "closed", "resolved"}:
                notifications.append({"created_at": task.get("updated_at", "") or task.get("created_at", ""), "severity": "medium", "category": "task", "message": f"Task overdue: {task.get('title', 'task')}", "task_id": task.get("id", ""), "case_id": case_id})
        for item in activity[:12]:
            event_type = str(item.get("event_type", "")).lower()
            severity = "low"
            if "approval" in event_type or event_type in {"task_updated", "task_created"}:
                severity = "medium"
            notifications.append({"created_at": item.get("created_at", ""), "severity": severity, "category": event_type or "activity", "message": str(item.get("summary", "") or event_type), "actor": item.get("actor", ""), "case_id": case_id})
        notifications.sort(key=lambda entry: str(entry.get("created_at", "")), reverse=True)
        return notifications[:20]

    def inline_update_task(self, item: QTableWidgetItem) -> None:
        app = self.app
        if app._enterprise_table_updating or item is None:
            return
        row = item.row()
        column = item.column()
        if row < 0 or column not in {1, 2, 3}:
            return
        case_id = app._selected_enterprise_case_id()
        task_id = app._safe_int(item.data(Qt.UserRole))
        tasks = getattr(app, "enterprise_filtered_tasks_data", getattr(app, "enterprise_tasks_data", []))
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
            result = app._patch(f"/enterprise/cases/{case_id}/tasks/{task_id}", json=payload, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        # Inline edits hit the same endpoint as the explicit "Update Task"
        # button. Capture in audit so a colleague flipping a task status
        # by accident leaves a trace.
        col_field = {1: "status", 2: "priority", 3: "assigned_to"}.get(column, "?")
        severity = "medium" if (col_field == "status" and str(value).lower() == "done") else "low"
        self._record_audit(
            category="case",
            action=f"task-inline:{col_field}",
            target=f"case={case_id} task={task_id} {col_field}={value}",
            severity=severity,
            status="ok" if ok_flag else "failed",
            payload=result,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Inline task update failed", Exception(error))
            app._enterprise_table_updating = True
            app.enterprise_tasks_table.blockSignals(True)
            app.enterprise_tasks_table.item(row, column).setText(str(original.get(col_field, "")))
            app.enterprise_tasks_table.blockSignals(False)
            app._enterprise_table_updating = False
            return
        app.statusBar().showMessage(f"Task {task_id} updated inline.")
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def load_case_graph(self, checked: bool = False, board: dict | None = None) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.enterprise_graph_summary.setHtml(
                "<h3>Case Correlation View</h3><p>Select a case first to load process-to-entity correlation, exposure hints, and priority findings.</p>"
            )
            app.enterprise_graph_focus.setRowCount(0)
            return
        board_data = board or getattr(app, "enterprise_case_board_data", {})
        try:
            graph = app._get(f"/enterprise/cases/{case_id}/graph", timeout=30).json()
        except Exception as exc:
            app._show_error(app.enterprise_detail, "Graph correlation load failed", exc)
            return
        summary = graph.get("summary", {}) if isinstance(graph, dict) else {}
        findings = graph.get("priority_findings", []) if isinstance(graph.get("priority_findings", []), list) else []
        case_scope = graph.get("case_context", {}) if isinstance(graph.get("case_context", {}), dict) else {}
        top_processes = summary.get("top_processes", []) if isinstance(summary.get("top_processes", []), list) else []
        focus_titles = [str(item.get("title", "")).lower() for item in board_data.get("focus_items", []) if isinstance(item, dict)] if isinstance(board_data, dict) else []
        matched_processes = [proc for proc in top_processes if any(token and token in str(proc.get("name", "")).lower() for token in focus_titles)]
        display_processes = matched_processes or top_processes[:8]
        exposure = summary.get("remote_exposure", {}) if isinstance(summary.get("remote_exposure", {}), dict) else {}
        app.enterprise_graph_summary.setHtml(
            "<h3>Case Correlation View</h3>"
            f"<p><b>Case ID:</b> {case_id}"
            f"<br><b>Overall Graph Risk:</b> {html.escape(str(summary.get('overall_risk', 0)))}"
            f"<br><b>Exposure:</b> {html.escape(json.dumps(exposure))}"
            f"<br><b>Matched Focus Processes:</b> {len(matched_processes)}"
            f"<br><b>Focus PID Count:</b> {html.escape(str(case_scope.get('focus_pid_count', 0)))}"
            f"<br><b>Scoped Notes / Pins:</b> {html.escape(str(case_scope.get('notes', 0)))} / {html.escape(str(case_scope.get('pins', 0)))}</p>"
            f"<p><b>Priority Findings:</b></p><ul>{''.join(f'<li>{html.escape(str(item))}</li>' for item in findings[:5]) or '<li>No graph findings.</li>'}</ul>"
        )
        app.enterprise_graph_focus.setRowCount(len(display_processes))
        for r, item in enumerate(display_processes):
            values = [item.get("name", ""), item.get("pid", ""), item.get("risk_score", ""), item.get("signature_status", "")]
            for c, value in enumerate(values):
                app.enterprise_graph_focus.setItem(r, c, QTableWidgetItem(str(value)))
            risk_value = float(item.get("risk_score", 0) or 0)
            app._paint_row(app.enterprise_graph_focus, r, app._severity_color("high" if risk_value >= 75 else "medium" if risk_value >= 45 else "low"))

    def assign_case(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Assignment Blocked", "Select an enterprise case before assigning an analyst.")
            return
        if not self._check_action_gate("assign"):
            return
        analyst, ok = QInputDialog.getText(app, "Assign Analyst", "Analyst:")
        if not ok or not analyst.strip():
            return
        # Reassigning a case is a state change with regulatory weight —
        # who owned it before, who owns it now, why. Capture a
        # structured reason so the audit chain is actionable.
        reason = self._capture_reason(f"assign (case {case_id} → {analyst.strip()})")
        if reason is None:
            return
        actor, _ws = actor_workspace_pair(app)
        try:
            result = app._post(
                f"/enterprise/cases/{case_id}/assignments",
                json={
                    "analyst": analyst.strip(),
                    "role": "owner",
                    "assigned_by": app.enterprise_case_owner.text().strip() or actor,
                    "reason": {
                        "ticket_id": reason["ticket_id"],
                        "category": reason["reason_category"],
                        "text": reason["reason_text"],
                    },
                },
                timeout=20,
            ).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="case",
            action="assign",
            target=f"case={case_id} → {analyst.strip()}",
            severity="medium",
            status="ok" if ok_flag else "failed",
            payload={"request": {"analyst": analyst.strip()}, "response": result},
            reason=reason,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Assign analyst failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def create_task(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Task Creation Blocked", "Select an enterprise case before creating a task.")
            return
        if not self._check_action_gate("create-task"):
            return
        title, ok = QInputDialog.getText(app, "Create Task", "Task title:")
        if not ok or not title.strip():
            return
        try:
            result = app._post(f"/enterprise/cases/{case_id}/tasks", json={"title": title.strip(), "assigned_to": app.enterprise_case_owner.text().strip(), "created_by": "desktop"}, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="case",
            action="create-task",
            target=f"case={case_id} task={title.strip()}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload=result,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Create task failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def update_task_status(self, forced_status: str | None = None) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        task_id = app._selected_enterprise_task_id()
        if case_id is None or task_id is None:
            app.statusBar().showMessage("Select a case and a task first")
            self._set_enterprise_detail_message(
                "Task Update Blocked",
                "Select both an enterprise case and a task before updating workflow status.",
            )
            return
        if not self._check_action_gate("update-task"):
            return
        status = forced_status
        if not status:
            status, ok = QInputDialog.getItem(app, "Update Task Status", "Status:", ["todo", "in_progress", "blocked", "done"], 1, False)
            if not ok or not status:
                return
        try:
            result = app._patch(f"/enterprise/cases/{case_id}/tasks/{task_id}", json={"status": status}, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        # `done` is a terminal state — bump audit severity so SOC managers
        # can grep the chain for "who closed which task".
        severity = "medium" if str(status).lower() == "done" else "low"
        self._record_audit(
            category="case",
            action=f"task-status:{status}",
            target=f"case={case_id} task={task_id}",
            severity=severity,
            status="ok" if ok_flag else "failed",
            payload=result,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Task update failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def add_note(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Note Creation Blocked", "Select an enterprise case before adding an investigation note.")
            return
        if not self._check_action_gate("add-note"):
            return
        note_text, ok = QInputDialog.getMultiLineText(app, "Add Note", "Analyst note:")
        if not ok or not note_text.strip():
            return
        try:
            result = app._post("/enterprise/investigations/notes", json={"case_id": case_id, "note_text": note_text.strip(), "item_type": "case", "item_title": app.enterprise_case_title.text().strip() or "case note", "author": app.enterprise_case_owner.text().strip() or "desktop"}, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="case",
            action="add-note",
            target=f"case={case_id}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload={"note_preview": note_text.strip()[:120], "response": result},
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Add note failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def add_story(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Story Creation Blocked", "Select an enterprise case before adding an investigation story.")
            return
        if not self._check_action_gate("add-story"):
            return
        title, ok = QInputDialog.getText(app, "Add Story", "Story title:")
        if not ok or not title.strip():
            return
        hypothesis, ok = QInputDialog.getMultiLineText(app, "Add Story", "Hypothesis:")
        if not ok:
            return
        try:
            result = app._post("/enterprise/investigations/stories", json={"case_id": case_id, "title": title.strip(), "hypothesis": hypothesis.strip(), "summary": "Created from desktop enterprise workflow.", "confidence": "medium", "created_by": app.enterprise_case_owner.text().strip() or "desktop"}, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="case",
            action="add-story",
            target=f"case={case_id} story={title.strip()}",
            severity="low",
            status="ok" if ok_flag else "failed",
            payload={"hypothesis_preview": hypothesis.strip()[:120], "response": result},
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Add story failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def pin_event(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Pin Event Blocked", "Select an enterprise case before pinning a timeline or case event.")
            return
        if not self._check_action_gate("pin-event"):
            return
        timeline_row = app.timeline_table.currentRow() if hasattr(app, "timeline_table") else -1
        timeline_items = getattr(app, "timeline_items", [])
        if timeline_row >= 0 and timeline_row < len(timeline_items):
            item = timeline_items[timeline_row]
            title = str(item.get("title", "") or "")
            item_type = str(item.get("type", "timeline") or "timeline")
            severity = str(item.get("severity", "medium") or "medium")
            item_time = float(item.get("time", 0) or 0)
            payload = item
        else:
            title = app.enterprise_case_title.text().strip() or "Pinned case event"
            item_type = "case"
            severity = "medium"
            item_time = time.time()
            payload = {"source": "desktop"}
        rationale, ok = QInputDialog.getText(app, "Pin Event", "Rationale:")
        if not ok or not rationale.strip():
            return
        try:
            result = app._post("/enterprise/investigations/pins", json={"case_id": case_id, "item_time": item_time, "item_type": item_type, "item_title": title, "item_severity": severity, "item_payload": payload, "rationale": rationale.strip(), "pinned_by": app.enterprise_case_owner.text().strip() or "desktop"}, timeout=20).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="case",
            action="pin-event",
            target=f"case={case_id} event={title}",
            severity=severity,
            status="ok" if ok_flag else "failed",
            payload={"rationale": rationale.strip()[:160], "item_type": item_type, "response": result},
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Pin event failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        app.load_selected_case_board()

    def export_selected_case_report(self) -> None:
        app = self.app
        case_id = app._selected_enterprise_case_id()
        if case_id is None:
            app.statusBar().showMessage("Select a case first")
            self._set_enterprise_detail_message("Export Blocked", "Select an enterprise case before exporting an investigation report.")
            return
        if not self._check_action_gate("export-report"):
            return
        # The PDF report leaves the appliance — capture *why* it was
        # exported so the chain-of-custody record matches the evidence
        # bundle.
        reason = self._capture_reason(f"export-report (case {case_id})")
        if reason is None:
            return
        try:
            result = app._post(
                f"/enterprise/cases/{case_id}/investigation-report/export",
                json={
                    "reason": {
                        "ticket_id": reason["ticket_id"],
                        "category": reason["reason_category"],
                        "text": reason["reason_text"],
                    },
                },
                timeout=45,
            ).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        pdf_path = str(result.get("pdf_path", "") or "") if isinstance(result, dict) else ""
        self._record_audit(
            category="case",
            action="export-report",
            target=f"case={case_id} pdf={pdf_path or 'pending'}",
            severity="medium",
            status="ok" if ok_flag else "failed",
            payload=result,
            reason=reason,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Case report export failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)
        if pdf_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(pdf_path))

    def load_mitre_bundle(self) -> None:
        app = self.app
        bundle_path = app.enterprise_mitre_bundle_path.text().strip()
        if not bundle_path:
            app.statusBar().showMessage("Provide an ATT&CK STIX bundle path first")
            return
        try:
            result = app._post("/enterprise/mitre/load-bundle", json={"file_path": bundle_path, "source": "desktop"}, timeout=60).json()
        except Exception as exc:
            app._show_error(app.enterprise_detail, "ATT&CK bundle load failed", exc)
            return
        app._show_json(app.enterprise_detail, result)
        app.statusBar().showMessage("ATT&CK bundle loaded")
        app.refresh_enterprise_workspace()

    def request_approval(self) -> None:
        app = self.app
        row = app.enterprise_cases_table.currentRow()
        if row < 0:
            app.statusBar().showMessage("Select an enterprise case first")
            return
        if not self._check_action_gate("approval"):
            return
        case_id = int(app.enterprise_cases_table.item(row, 0).text())
        # An approval request exists *because* a high-impact response is
        # being staged. Capture a real ticket + reason so the approver
        # has context to act on, instead of the previous boilerplate
        # "High impact response requires approval." string.
        reason = self._capture_reason(f"approval (case {case_id})")
        if reason is None:
            return
        actor, _ws = actor_workspace_pair(app)
        payload = {
            "case_id": case_id,
            "action": "containment",
            "requested_by": app.enterprise_case_owner.text().strip() or actor,
            "approver": "admin",
            "reason": reason["reason_summary"],
            "reason_meta": {
                "ticket_id": reason["ticket_id"],
                "category": reason["reason_category"],
                "text": reason["reason_text"],
            },
        }
        try:
            result = app._post("/enterprise/approvals", json=payload, timeout=30).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        approval_value = result.get("approval_id") if isinstance(result, dict) else None
        self._record_audit(
            category="case",
            action="approval-request",
            target=f"case={case_id} approval={approval_value or 'pending'}",
            severity="high",
            status="ok" if ok_flag else "failed",
            payload={"request": payload, "response": result},
            reason=reason,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Approval request failed", Exception(error))
            return
        if approval_value is not None:
            app.approval_id.setText(str(approval_value))
            app.statusBar().showMessage(f"Approval {approval_value} created and attached to Primary Controls.")
        app._show_json(app.enterprise_detail, result)

    def run_web_inspection(self) -> None:
        app = self.app
        if not self._check_action_gate("web-surface"):
            return
        # Web surface inspection enumerates internet-facing assets in
        # the lab. Async so a slow probe doesn't lock the desktop.
        app.statusBar().showMessage("Web surface inspection running...")

        def _on_ok(result: dict) -> None:
            self._record_audit(
                category="hunt",
                action="web-surface",
                target="enterprise",
                severity="low",
                status="ok",
                payload=result,
            )
            app._show_json(app.enterprise_detail, result)
            app.statusBar().showMessage("Web surface inspection complete.")

        def _on_err(message: str) -> None:
            self._record_audit(
                category="hunt",
                action="web-surface",
                target="enterprise",
                severity="low",
                status="failed",
                payload={"error": message},
            )
            app._show_error(app.enterprise_detail, "Web inspection failed", Exception(message))

        self._submit_async_hunt(
            label="web-surface",
            work=lambda: app._get("/enterprise/web/inspection", timeout=45).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=55,
        )

    def run_network_assessment(self) -> None:
        app = self.app
        if not self._check_action_gate("network-assessment"):
            return
        ip_range = app.enterprise_network_range.text().strip()
        if not ip_range:
            app.statusBar().showMessage("Provide an IP range before running a network assessment.")
            return
        app.statusBar().showMessage(f"Network assessment running for {ip_range}...")

        def _on_ok(result: dict) -> None:
            self._record_audit(
                category="hunt",
                action="network-assessment",
                target=f"range={ip_range}",
                severity="medium",
                status="ok",
                payload=result,
            )
            app._show_json(app.enterprise_detail, result)
            app.statusBar().showMessage(f"Network assessment complete for {ip_range}.")

        def _on_err(message: str) -> None:
            self._record_audit(
                category="hunt",
                action="network-assessment",
                target=f"range={ip_range}",
                severity="medium",
                status="failed",
                payload={"error": message},
            )
            app._show_error(app.enterprise_detail, "Network assessment failed", Exception(message))

        self._submit_async_hunt(
            label="network-assessment",
            work=lambda: app._post("/enterprise/network/assessment", json={"ip_range": ip_range}, timeout=90).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=110,
        )

    def run_purple_replay(self) -> None:
        app = self.app
        if not self._check_action_gate("purple-replay"):
            return
        artifact = app.enterprise_replay_path.text().strip()
        if not artifact:
            app.statusBar().showMessage("Provide a purple-replay artifact path first.")
            return
        # Replay reproduces an attack chain on the lab — operationally
        # the same risk profile as a controlled simulation. Capture
        # the ticket so the audit chain explains what corner of the
        # estate is being re-tested.
        reason = self._capture_reason(f"purple-replay ({artifact})")
        if reason is None:
            return
        try:
            result = app._post(
                "/enterprise/purple/replay",
                json={
                    "artifact_path": artifact,
                    "reason": {
                        "ticket_id": reason["ticket_id"],
                        "category": reason["reason_category"],
                        "text": reason["reason_text"],
                    },
                },
                timeout=30,
            ).json()
            ok_flag = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok_flag = False
            error = str(exc)
        self._record_audit(
            category="hunt",
            action="purple-replay",
            target=artifact,
            severity="medium",
            status="ok" if ok_flag else "failed",
            payload=result,
            reason=reason,
        )
        if not ok_flag:
            app._show_error(app.enterprise_detail, "Purple replay failed", Exception(error))
            return
        app._show_json(app.enterprise_detail, result)

    def load_telemetry_gaps(self) -> None:
        app = self.app
        if not self._check_action_gate("telemetry-gaps"):
            return
        app.statusBar().showMessage("Telemetry gap analysis running...")

        def _on_ok(result: dict) -> None:
            self._record_audit(
                category="hunt",
                action="telemetry-gaps",
                target="enterprise",
                severity="low",
                status="ok",
                payload=result,
            )
            app._show_json(app.enterprise_detail, result)
            app.statusBar().showMessage("Telemetry gap analysis complete.")

        def _on_err(message: str) -> None:
            self._record_audit(
                category="hunt",
                action="telemetry-gaps",
                target="enterprise",
                severity="low",
                status="failed",
                payload={"error": message},
            )
            app._show_error(app.enterprise_detail, "Telemetry gap analysis failed", Exception(message))

        self._submit_async_hunt(
            label="telemetry-gaps",
            work=lambda: app._get("/enterprise/telemetry/gaps", timeout=30).json(),
            on_success=_on_ok,
            on_failure=_on_err,
            timeout_seconds=40,
        )

    def _submit_async_hunt(
        self,
        *,
        label: str,
        work,
        on_success,
        on_failure,
        timeout_seconds: int = 60,
    ) -> None:
        """Lightweight QThread wrapper for hunt-style endpoints.

        Antivirus has its own `_submit_async`; Process has the
        single-slot JobManager. Enterprise hunt actions can fan out in
        parallel (web/network/replay/gaps), so each call gets its own
        thread with a watchdog timeout.
        """
        from PySide6.QtCore import QTimer
        thread = QThread(self.app)
        worker = _EnterpriseWorker(work)
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
            self.app.statusBar().showMessage(f"{label} timed out after {timeout_seconds}s.")
            cleanup()

        thread.started.connect(worker.run)
        worker.finished.connect(handle_success)
        worker.failed.connect(handle_failure)
        self._async_jobs.append((thread, worker))
        QTimer.singleShot(int(max(1, timeout_seconds)) * 1000, watchdog)
        thread.start()
