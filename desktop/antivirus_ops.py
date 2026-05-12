from __future__ import annotations

import html
import ipaddress
import json
import time
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, QThread, Qt, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

try:
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason

try:
    from process_hunt_jobs import ProcessWorker as _BulkWorker, bulk_scan_timeout
except ImportError:  # pragma: no cover
    from desktop.process_hunt_jobs import ProcessWorker as _BulkWorker, bulk_scan_timeout

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


# Server-side response action set, mirrored from
# api/routes/antivirus_response.py — keeping the client allowlist
# explicit so a stray button or typo can't trigger an undocumented
# endpoint.
RESPONSE_ACTION_ALLOWLIST: frozenset[str] = frozenset({
    "kill", "isolate", "release", "quarantine", "vss-restore", "collect-artifacts",
})

# Per-action minimum gap between two consecutive button presses.
# Backend already rate-limits some of these but the desktop debounce
# stops a panicked operator from queueing five "Isolate" clicks while
# the first one is still negotiating the firewall.
RESPONSE_DEBOUNCE_SECONDS = 1.5

# Audit log retention — same as the Process console for parity with
# operator expectations.
ANTIVIRUS_AUDIT_LOG_RETENTION = 500


# ---------------------------------------------------------------------------
# Product-level layout constants. Centralised so the engine palette, KPI
# colour accents, and badge styles stay consistent across every render path.
# ---------------------------------------------------------------------------
ALL_PROVIDERS: list[tuple[str, str, str]] = [
    # (key, display, accent)
    ("aegis_core", "Aegis Core", "#8ec5ff"),
    ("sentinel_cli", "Sentinel CLI", "#7bd389"),
    ("cloud_intel", "Cloud Intel", "#ffd166"),
    ("yara_x", "YARA-X", "#bda4ff"),
    ("behavioural", "Behavioural", "#ff9f6b"),
    ("cloud_sandbox", "Cloud Sandbox", "#5fd4d6"),
]
PROVIDER_KEY_TO_DISPLAY = {key: display for key, display, _ in ALL_PROVIDERS}

VERDICT_COLOUR = {
    "infected": "#ff8b8b",
    "malicious": "#ff8b8b",
    "suspicious": "#f4c26b",
    "degraded": "#9fd0ff",
    "clean": "#7bd389",
    "skipped": "#96a5b8",
    "error": "#ff8b8b",
    "unavailable": "#96a5b8",
}

YARA_PACKS = ["enterprise", "hybrid", "memory", "shadowlab", "rules_master", "signature_base"]


# --- Sparkline widget --------------------------------------------------------


class SparklineWidget(QWidget):
    """Tiny custom sparkline for KPI tiles.

    Pure QPainter — no pyqtgraph / matplotlib dep. Renders a thin polyline
    over a faint baseline. Designed to fit in ~120 × 18 px under a KPI
    value label. `set_data([float, float, ...])` redraws; baseline is the
    minimum value so a flat-zero series shows a flat line at the bottom
    rather than an empty rectangle."""

    def __init__(self, *, accent: str = "#9fd0ff", parent=None) -> None:
        super().__init__(parent)
        self._values: list[float] = []
        self._accent = accent
        self.setMinimumHeight(16)
        self.setMaximumHeight(20)
        self.setMinimumWidth(80)

    def set_data(self, values: list[float]) -> None:
        self._values = [float(v) for v in (values or [])]
        self.update()

    def paintEvent(self, _event) -> None:
        from PySide6.QtGui import QPainter, QPen, QColor
        from PySide6.QtCore import QPointF
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, True)
        rect = self.rect().adjusted(2, 2, -2, -2)
        # Faint baseline.
        baseline_pen = QPen(QColor("#243446"))
        baseline_pen.setWidthF(0.7)
        painter.setPen(baseline_pen)
        painter.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())
        if not self._values or len(self._values) < 2:
            return
        lo = min(self._values); hi = max(self._values)
        rng = max(1e-6, hi - lo)
        n = len(self._values)
        step = rect.width() / max(1, n - 1)
        points = []
        for i, value in enumerate(self._values):
            x = rect.left() + i * step
            y = rect.bottom() - ((value - lo) / rng) * rect.height()
            points.append(QPointF(x, y))
        line_pen = QPen(QColor(self._accent))
        line_pen.setWidthF(1.4)
        painter.setPen(line_pen)
        for a, b in zip(points, points[1:]):
            painter.drawLine(a, b)
        # End-marker dot.
        dot_pen = QPen(QColor(self._accent))
        dot_pen.setWidthF(1.0)
        painter.setPen(dot_pen)
        painter.setBrush(QColor(self._accent))
        last = points[-1]
        painter.drawEllipse(last, 1.8, 1.8)


class AntivirusWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        self.scan_buttons: dict[str, QPushButton] = {}
        self.quarantine_buttons: dict[str, QPushButton] = {}
        self.policy_buttons: dict[str, QPushButton] = {}
        # Per-action click timestamps for the response debounce. Keyed
        # by canonical action token (kill/isolate/...) so each verb has
        # its own cooldown — a Kill cooldown shouldn't block Isolate.
        # Kept as a legacy mirror so a small number of tests that
        # touch this dict directly keep working.
        self._last_response_click: dict[str, float] = {}
        # Shared list of background QThread/Worker pairs we've spawned
        # so PySide doesn't garbage-collect them while running.
        self._async_response_jobs: list[tuple[QThread, _BulkWorker]] = []
        # Shared on-disk audit log — same store class History uses.
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=ANTIVIRUS_AUDIT_LOG_RETENTION,
        )
        # Best-effort backend mirror — POSTs each audit row to
        # /audit/desktop. Local file remains the source of truth.
        _install_audit_mirror(self._audit_store, app, source_slug="antivirus")
        # Shared action plumbing — same gate/reason/async helpers all
        # consoles will eventually use. The thin facades below keep
        # the historical method names so existing call sites work.
        self._gate = ActionGate(
            allowlist=RESPONSE_ACTION_ALLOWLIST,
            debounce_seconds=RESPONSE_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        # Every response action in Antivirus captures a reason (kill,
        # isolate, release, quarantine, vss-restore, collect-artifacts).
        # Treat the entire allowlist as reason-required.
        self._reason = ReasonCapture(
            reason_required=RESPONSE_ACTION_ALLOWLIST,
            parent=app,
            on_cancel=lambda action: app.statusBar().showMessage(
                f"`{action}` cancelled — structured reason required."
            ),
        )

    # ------------------------------------------------------------------ #
    # Audit log persistence — uses the shared `AuditLogStore`. The thin
    # wrappers below preserve the historical method names so any
    # external caller still has the public API it expects.
    # ------------------------------------------------------------------ #

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "antivirus-audit-log.json"

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def save_audit_log(self) -> None:
        # Push the controller's view of the list (which may have been
        # mutated by callers that pre-date the AuditLogStore migration)
        # into the store before flushing to disk.
        self._audit_store.save(getattr(self.app, "antivirus_history_entries", []) or [])

    # ------------------------------------------------------------------ #
    # Response action gates — debounce + allowlist. Always call
    # `_check_response_gate(action)` before issuing a request to a
    # response endpoint. Returns False when the action should be
    # blocked (operator sees a status-bar message).
    # ------------------------------------------------------------------ #

    def _check_response_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. The legacy
        # `_last_response_click` dict is kept as a mirror for any
        # test that touches it directly.
        ok = self._gate.check(action)
        if ok:
            self._last_response_click[action] = time.time()
        return ok

    def _capture_reason(self, action: str) -> dict | None:
        # Delegate to the shared `ReasonCapture`. Antivirus treats the
        # entire allowlist as reason-required; an action outside that
        # set yields the empty-dict sentinel.
        return self._reason.capture(action)

    def _submit_async(self, label: str, work, on_success, on_failure=None, *, timeout_seconds: int = 60) -> None:
        """Delegate to the shared `submit_async_call`.

        Antivirus operators run multiple drawer actions in parallel
        (polling stats while a quarantine is in flight) so each call
        gets its own thread. The `on_failure=None` legacy default
        becomes a status-bar fallback below to preserve the old
        behaviour for callers that don't pass a handler.
        """
        if on_failure is None:
            def _default_failure(message: str) -> None:
                self.app.statusBar().showMessage(f"{label} failed: {message}")
            on_failure = _default_failure
        submit_async_call(
            parent=self.app,
            label=label,
            work=work,
            on_success=on_success,
            on_failure=on_failure,
            timeout_seconds=timeout_seconds,
            job_registry=self._async_response_jobs,
        )
        return

    def _set_scan_empty_state(self, message: str | None = None) -> None:
        app = self.app
        if hasattr(app, "antivirus_result_detail"):
            app.antivirus_result_detail.setHtml(
                "<h3>Fused Verdict</h3><p>"
                + html.escape(message or "No scan selected yet. Run a validation, file, or process scan to review a fused verdict.")
                + "</p>"
            )
        if hasattr(app, "antivirus_provider_hits"):
            app.antivirus_provider_hits.setHtml(
                "<h3>Provider-by-Provider Hits</h3><p>No provider results recorded yet.</p>"
            )
        if hasattr(app, "antivirus_scan_guidance"):
            app.antivirus_scan_guidance.setHtml(
                "<h3>Operator Guidance</h3><p>"
                + html.escape(
                    message
                    or "Start with Refresh Engines to confirm provider health, then run a validation, file, or process scan."
                )
                + "</p>"
            )

    def _set_quarantine_empty_state(self, message: str | None = None) -> None:
        if hasattr(self.app, "antivirus_quarantine_detail"):
            self.app.antivirus_quarantine_detail.setPlainText(
                message
                or "No quarantine item selected.\n\nSelect an item to inspect its record, or trigger containment from the Scan tab."
            )

    def _set_history_empty_state(self, message: str | None = None) -> None:
        if hasattr(self.app, "antivirus_history_detail"):
            self.app.antivirus_history_detail.setPlainText(
                message
                or "No antivirus audit activity recorded yet.\n\nScans, containment actions, report exports, and webhook events will appear here."
            )

    def build_tab(self) -> QWidget:
        """Product-level Antivirus console.

        One viewport, no inner scroll: 48 px command bar, 76 px KPI strip,
        a 2-column engines + MITRE coverage row, then a recent-verdicts
        table at the bottom. Quarantine, History, Detail, and Policy live
        behind buttons that open dedicated drawer windows — keeps the
        primary screen uncluttered the way real EDR consoles do."""
        app = self.app

        # Pre-construct every drawer-only widget up front so existing public
        # methods (refresh_quarantine_inventory, restore_selected_quarantine,
        # show_selected_history, save_policy, etc.) can keep referencing
        # them by attribute even before the user has opened the drawer.
        self._build_drawer_widgets()

        w = QWidget()
        outer = QVBoxLayout(w)
        outer.setContentsMargins(6, 6, 6, 6)
        outer.setSpacing(6)

        outer.addWidget(self._build_command_bar(), 0)
        outer.addWidget(self._build_kpi_strip(), 0)

        # Keyboard shortcuts — analyst muscle memory matters. Ctrl+S
        # fires a scan against the current target, "/" focuses the
        # search field, "?" opens a tiny cheat sheet. Owned by the tab
        # widget so they don't fire while the analyst is on a different
        # tab.
        from PySide6.QtGui import QShortcut, QKeySequence
        QShortcut(QKeySequence("Ctrl+S"), w).activated.connect(lambda: self.handle_scan_kind("full"))
        QShortcut(QKeySequence("/"), w).activated.connect(
            lambda: app.antivirus_target_path.setFocus() if hasattr(app, "antivirus_target_path") else None
        )
        QShortcut(QKeySequence("?"), w).activated.connect(self._show_shortcut_help)
        QShortcut(QKeySequence("Ctrl+Q"), w).activated.connect(self.open_quarantine_drawer)
        QShortcut(QKeySequence("Ctrl+J"), w).activated.connect(self.open_jobs_drawer)
        QShortcut(QKeySequence("Ctrl+R"), w).activated.connect(self.refresh_workspace)
        QShortcut(QKeySequence("Ctrl+L"), w).activated.connect(self.open_lists_drawer)
        QShortcut(QKeySequence("Ctrl+E"), w).activated.connect(self.open_eicar_drawer)

        # Drag-drop file → fill search field + auto-scan. The whole tab
        # accepts drops; we install an event filter on the verdict
        # table because that's where the analyst's eyes already are.
        w.setAcceptDrops(True)
        w.dragEnterEvent = self._handle_drag_enter  # type: ignore[assignment]
        w.dropEvent = self._handle_file_drop       # type: ignore[assignment]

        # Mid row — provider matrix + MITRE heat-map side-by-side.
        mid_row = QWidget()
        mid_layout = QHBoxLayout(mid_row)
        mid_layout.setContentsMargins(0, 0, 0, 0)
        mid_layout.setSpacing(8)
        mid_layout.addWidget(self._build_provider_matrix_card(), 1)
        mid_layout.addWidget(self._build_mitre_heatmap_card(), 1)
        outer.addWidget(mid_row, 1)

        # Bottom row — recent verdicts table (clickable rows open detail drawer).
        outer.addWidget(self._build_verdict_table_card(), 1)

        # Initialise state stores.
        app.antivirus_scan_results = []
        app.antivirus_status_payload = {}
        # Reload audit log from disk so the forensic chain survives an
        # app crash mid-incident. Records are newest-first on disk.
        app.antivirus_history_entries = self.load_audit_log()
        app.quarantine_records = []
        app.antivirus_mitre_techniques = []
        app.antivirus_mitre_coverage = {"total_techniques": 0, "tactics_covered": [], "by_tactic": {}}
        app.antivirus_recent_mitre_payload = {}
        # Open drawers (one window per drawer kind, reused on subsequent opens).
        self._open_drawers: dict[str, QDialog] = {}

        self._set_scan_empty_state()
        self._set_quarantine_empty_state()
        self._set_history_empty_state()
        self._refresh_kpis()
        self._render_provider_matrix({})
        self._render_mitre_heatmap()
        self.apply_role_access()
        # Real-time verdict feed — 2 s polling against
        # /antivirus/scans/recent. Every new server-side scan (including
        # those triggered by the folder watcher or the async job queue)
        # appears in the verdict table without the analyst pressing Refresh.
        from PySide6.QtCore import QTimer
        self._verdict_poll_since: float = 0.0
        self._verdict_poll_timer = QTimer(w)
        self._verdict_poll_timer.setInterval(2000)
        self._verdict_poll_timer.timeout.connect(self._poll_recent_scans)
        self._verdict_poll_timer.start()
        return w

    def _poll_recent_scans(self) -> None:
        """Pull /antivirus/scans/recent since the last poll, merge into the
        verdict table. Honours auto-refresh checkbox so the analyst can
        pause the live feed during deep investigation."""
        app = self.app
        if hasattr(app, "antivirus_auto_refresh") and not app.antivirus_auto_refresh.isChecked():
            return
        if not hasattr(app, "api_client"):
            return
        try:
            resp = app._get(
                "/antivirus/scans/recent",
                params={"since": self._verdict_poll_since, "limit": 100},
                timeout=8,
            ).json()
        except Exception:
            # Auth not yet supplied or transient — keep the live pill amber.
            if hasattr(self, "_verdict_live_pill"):
                self._verdict_live_pill.setText("○ Idle")
                self._verdict_live_pill.setStyleSheet(
                    "color:#96a5b8;background:#121b27;border:1px solid #2c4260;border-radius:7px;"
                    "padding:3px 8px;font-size:10px;font-weight:700;"
                )
            return
        rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
        now = float(resp.get("now", time.time()) or time.time())
        merged = 0
        # Build a dedupe set of payload ids already present (sha256 + created_at).
        existing_keys = {
            (str(item.get("sha256", "") or ""), float(item.get("created_at", 0) or 0))
            for item in getattr(app, "antivirus_scan_results", [])
        }
        for row in sorted(rows, key=lambda r: float(r.get("created_at", 0) or 0)):
            key = (str(row.get("sha256", "") or ""), float(row.get("created_at", 0) or 0))
            if key in existing_keys:
                continue
            verdict = str(row.get("fused_verdict", "") or "unknown").lower()
            severity = str(row.get("severity", "low") or "low")
            sha = str(row.get("sha256", "") or "")
            target = str(row.get("target_path", "") or "")
            engines_text = str(row.get("providers_set", "") or "")
            # The recent endpoint returns audit-row shape, not a full
            # fused result. Reconstruct just enough for the row to render.
            row_payload = {
                "scope": str(row.get("scope", "file")),
                "target": target,
                "severity": severity,
                "verdict": verdict,
                "status": verdict,
                "mitre_text": "—",
                "engines_text": engines_text or "—",
                "timestamp": datetime.fromtimestamp(float(row.get("created_at", 0) or 0)).strftime("%H:%M:%S"),
                "created_at": float(row.get("created_at", 0) or 0),
                "sha256": sha,
                "payload": {
                    "status": verdict,
                    "path": target,
                    "sha256": sha,
                    "summary": {
                        "fused_verdict": verdict,
                        "severity": severity,
                        "score": int(row.get("score", 0) or 0),
                        "confidence": str(row.get("confidence", "") or "low"),
                        "detections": [],
                        "provider_hits": [],
                        "provider_cards": [],
                        "reasons": [f"Surfaced via real-time stream — actor={row.get('actor', '?')}, source={row.get('source', '?')}, duration={row.get('duration_ms', 0)} ms"],
                        "recommended_actions": [],
                    },
                    "policy": {},
                },
            }
            app.antivirus_scan_results.insert(0, row_payload)
            merged += 1
        if merged:
            app.antivirus_scan_results = app.antivirus_scan_results[:200]
            self._render_verdict_table()
            self._refresh_kpis()
        # Advance the cursor regardless so we don't re-pull old rows.
        self._verdict_poll_since = max(self._verdict_poll_since, now)
        if hasattr(self, "_verdict_live_pill"):
            self._verdict_live_pill.setText("● Live")
            self._verdict_live_pill.setStyleSheet(
                "color:#7bd389;background:#121b27;border:1px solid #2c4260;border-radius:7px;"
                "padding:3px 8px;font-size:10px;font-weight:700;"
            )

    # ------------------------------------------------------------------
    # Top-level builders for the product-grade single-viewport layout
    # ------------------------------------------------------------------

    def _build_command_bar(self) -> QWidget:
        """Two-row product-grade command bar.

        Row 1 — primary work surface, NEVER overflows because it has at
        most 7 widgets and the search field is the only flexible one:
            [Title] [Search] [Browse] [Auto] [Status badges] [▸ Scan ▾]
        Row 2 — drawer launchers (operator tools), always visible
        because moving them down to their own row gives them all the
        horizontal real estate they need:
            [⚙ Policy] [Vault] [Signatures] [EICAR] [Stats]
            [Quarantine] [History] [Jobs] [Watcher] [Webhooks] [Refresh]

        The previous single-row layout crammed 14+ widgets into one
        QHBoxLayout — at 1280-px width the right half of the row was
        clipped off-screen and the analyst couldn't see the Scan
        button, the Live status, or the role badge."""
        app = self.app
        bar = QFrame()
        bar.setProperty("card", True)
        bar.setMaximumHeight(96)
        bar.setMinimumHeight(80)
        bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        wrapper = QVBoxLayout(bar)
        wrapper.setContentsMargins(10, 6, 10, 6)
        wrapper.setSpacing(4)

        # ---------------------------------------------------------------- ROW 1
        row1 = QHBoxLayout()
        row1.setContentsMargins(0, 0, 0, 0)
        row1.setSpacing(8)

        title = QLabel("Antivirus & Containment")
        title.setStyleSheet("font-size:14px;font-weight:700;color:#f4f7fb;")
        row1.addWidget(title)
        row1.addSpacing(8)

        # Search — accepts hash or path. Returns to Scan-File semantics.
        app.antivirus_target_path = QLineEdit(str(self.validation_sample_path()))
        app.antivirus_target_path.setPlaceholderText("Hash or absolute file path…")
        app.antivirus_target_path.setMinimumWidth(220)
        app.antivirus_target_path.setMaximumHeight(28)
        # Pressing Enter inside the search field fires a full scan — UX
        # cliché analysts already expect from every browser console.
        app.antivirus_target_path.returnPressed.connect(lambda: self.handle_scan_kind("full"))
        row1.addWidget(app.antivirus_target_path, 4)

        browse_btn = QPushButton("Browse")
        browse_btn.setMaximumHeight(28)
        browse_btn.clicked.connect(self.pick_scan_target_file)
        row1.addWidget(browse_btn)

        # Hidden mirror of webhook URL so legacy save/test paths keep working.
        app.antivirus_webhook_url = QLineEdit(app.webhook_url.text().strip())
        app.antivirus_webhook_url.setVisible(False)
        app.antivirus_webhook_url.textChanged.connect(app.webhook_url.setText)

        # Auto-refresh checkbox (live verdict feed pause toggle).
        app.antivirus_auto_refresh = QCheckBox("Auto")
        app.antivirus_auto_refresh.setChecked(True)
        app.antivirus_auto_refresh.setStyleSheet("font-size:11px;color:#96a5b8;")
        app.antivirus_auto_refresh.setMaximumHeight(28)
        row1.addWidget(app.antivirus_auto_refresh)

        row1.addStretch(1)

        # Status chips — Policy / Live status / Role.
        app.antivirus_policy_badge = QLabel("Policy: loading")
        app.antivirus_policy_badge.setStyleSheet(
            "color:#9fd0ff;background:#121b27;border:1px solid #2c4260;border-radius:7px;padding:3px 10px;font-size:11px;font-weight:600;"
        )
        app.antivirus_policy_badge.setMaximumHeight(28)
        app.antivirus_live_status = QLabel("Engines idle")
        app.antivirus_live_status.setStyleSheet("color:#96a5b8;font-size:11px;")
        app.antivirus_role_badge = QLabel("viewer")
        app.antivirus_role_badge.setStyleSheet(
            "color:#f4c26b;background:#121b27;border:1px solid #2c4260;border-radius:7px;padding:3px 10px;font-size:11px;font-weight:600;"
        )
        app.antivirus_role_badge.setMaximumHeight(28)
        row1.addWidget(app.antivirus_policy_badge)
        row1.addWidget(app.antivirus_live_status)
        row1.addWidget(app.antivirus_role_badge)

        # Scan split-button — primary green CTA, FAR RIGHT so it's always
        # visible regardless of how the analyst resizes the window.
        scan_btn = QToolButton()
        scan_btn.setText("▸ Scan")
        scan_btn.setStyleSheet(
            "QToolButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:7px;"
            "padding:4px 16px;font-weight:700;font-size:12px;}"
            "QToolButton:hover{background:#258759;}"
            "QToolButton:disabled{background:#16202c;color:#5b6d80;border-color:#243446;}"
            "QToolButton::menu-button{border-left:1px solid #2f9c6c;width:18px;}"
            "QToolButton::menu-arrow{image:none;}"
        )
        scan_btn.setPopupMode(QToolButton.MenuButtonPopup)
        scan_menu = QMenu(scan_btn)
        scan_menu.setStyleSheet(
            "QMenu{background:#16202c;color:#eef4fb;border:1px solid #2c4260;}"
            "QMenu::item{padding:5px 18px;}"
            "QMenu::item:selected{background:#1d3a5f;color:#9fd0ff;}"
        )
        for label, kind in [
            ("Full fused scan",     "full"),
            ("YARA-X only",         "yara"),
            ("Behavioural only",    "behavioural"),
            ("Cloud Sandbox only",  "sandbox"),
            ("Selected process",    "process"),
            ("EICAR validation",    "validation"),
        ]:
            act = QAction(label, scan_btn)
            act.triggered.connect(lambda _checked=False, k=kind: self.handle_scan_kind(k))
            scan_menu.addAction(act)
        scan_btn.setMenu(scan_menu)
        scan_btn.clicked.connect(lambda: self.handle_scan_kind("full"))
        scan_btn.setMinimumHeight(28); scan_btn.setMaximumHeight(32)
        scan_btn.setMinimumWidth(110)
        scan_btn.setToolTip("Run a fused scan against the path in the search field. ▾ for engine-specific scans.")
        self.scan_buttons = {"full": scan_btn}
        row1.addWidget(scan_btn)

        wrapper.addLayout(row1)

        # ---------------------------------------------------------------- ROW 2
        row2 = QHBoxLayout()
        row2.setContentsMargins(0, 0, 0, 0)
        row2.setSpacing(6)

        # Settings (gear) leads the row — same alignment with the title above.
        settings_btn = QPushButton("⚙ Policy")
        settings_btn.setMaximumHeight(26)
        settings_btn.setToolTip("Open antivirus policy & engine controls")
        settings_btn.clicked.connect(self.open_settings_drawer)
        row2.addWidget(settings_btn)

        # Drawer launchers — keep the original ordering so muscle memory
        # transfers (Vault first because crypto-grade ops are highest
        # operator value, Refresh last because it's a manual override
        # for the auto-poll). Each one ships a tooltip so the analyst
        # doesn't need to click around to discover what each opens.
        # Sprint-5 additions (Response / Rules / Lists) live alongside
        # the existing Wave-1/2/3 drawers — they're peer operator tools.
        for label, slot, tooltip in [
            ("Vault",      self.open_vault_drawer,         "Cryptographic vault — verify HMAC, unseal sealed samples to disk, purge ciphertext."),
            ("Signatures", self.open_signatures_drawer,    "Trigger freshclam / per-engine signature update + view rolling update history."),
            ("EICAR",      self.open_eicar_drawer,         "Run the EICAR validation sample through the fused pipeline; see which engines caught it."),
            ("Stats",      self.open_stats_drawer,         "Verdict cache + worker pool + vault + signature-updater snapshot."),
            ("Quarantine", self.open_quarantine_drawer,    "Quarantine inventory — restore, delete, or open the sealed copy."),
            ("History",    self.open_history_drawer,       "Antivirus audit history — every scan, containment, export, webhook event."),
            ("Jobs",       self.open_jobs_drawer,          "Async scan job queue — submit long-running scans, watch progress, cancel."),
            ("Watcher",    self.open_folder_watcher_drawer,"On-access folder watcher — point at directories to auto-scan new files."),
            ("Webhooks",   self.open_webhooks_drawer,      "Signed webhook deliveries + DLQ replay + HMAC secret rotation."),
            ("Response",   self.open_response_drawer,      "Live Response — kill PID, isolate network, collect artifacts, VSS rollback."),
            ("Rules",      self.open_rules_drawer,         "Custom YARA rule editor — write, validate, dry-run, deploy bespoke rules."),
            ("Lists",      self.open_lists_drawer,         "Exclusion / blocklist / allowlist management — paths and hashes."),
        ]:
            btn = QPushButton(label)
            btn.setMaximumHeight(26)
            btn.setToolTip(tooltip)
            btn.clicked.connect(slot)
            row2.addWidget(btn)

        row2.addStretch(1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setMaximumHeight(26)
        refresh_btn.setToolTip("Force-refresh provider matrix + verdict feed (auto-poll runs every 2 s)")
        refresh_btn.clicked.connect(self.refresh_workspace)
        row2.addWidget(refresh_btn)

        wrapper.addLayout(row2)
        return bar

    def _build_kpi_strip(self) -> QWidget:
        """4 KPI tiles: Engines, Suspicious, Quarantine, MITRE coverage."""
        app = self.app
        strip = QFrame()
        strip.setProperty("card", True)
        strip.setMaximumHeight(86)
        strip.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        row = QHBoxLayout(strip)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(10)

        def _tile(title: str, accent: str) -> tuple[QWidget, QLabel, QLabel, SparklineWidget]:
            tile = QFrame()
            tile.setProperty("card", True)
            tile.setStyleSheet(
                f"QFrame{{background:#121b27;border:1px solid #2c4260;border-radius:9px;}}"
            )
            tile.setMinimumHeight(80)
            tile.setMaximumHeight(96)
            tile_layout = QVBoxLayout(tile)
            tile_layout.setContentsMargins(12, 6, 12, 6)
            tile_layout.setSpacing(2)
            heading = QLabel(title)
            heading.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:700;letter-spacing:0.5px;")
            value_row = QHBoxLayout(); value_row.setContentsMargins(0, 0, 0, 0); value_row.setSpacing(8)
            value = QLabel("--")
            value.setStyleSheet(f"color:{accent};font-size:20px;font-weight:800;")
            value_row.addWidget(value)
            spark = SparklineWidget(accent=accent)
            value_row.addWidget(spark, 1)
            sub = QLabel("")
            sub.setStyleSheet("color:#7e91a8;font-size:10px;")
            sub.setMinimumHeight(12)
            tile_layout.addWidget(heading)
            tile_layout.addLayout(value_row)
            tile_layout.addWidget(sub)
            return tile, value, sub, spark

        engines_tile, app.antivirus_kpi_engines, app.antivirus_kpi_engines_sub, app.antivirus_kpi_engines_spark = _tile("ENGINES", "#9fd0ff")
        suspicious_tile, app.antivirus_kpi_suspicious, app.antivirus_kpi_suspicious_sub, app.antivirus_kpi_suspicious_spark = _tile("SUSPICIOUS", "#f4c26b")
        quarantine_tile, app.antivirus_kpi_quarantine, app.antivirus_kpi_quarantine_sub, app.antivirus_kpi_quarantine_spark = _tile("QUARANTINE", "#ff9f6b")
        mitre_tile, app.antivirus_kpi_mitre, app.antivirus_kpi_mitre_sub, app.antivirus_kpi_mitre_spark = _tile("MITRE COVERAGE", "#bda4ff")

        # Legacy aliases — older code paths refer to these widget names.
        app.antivirus_aegis_value = app.antivirus_kpi_engines
        app.antivirus_sentinel_value = app.antivirus_kpi_suspicious
        app.antivirus_last_scan_value = app.antivirus_kpi_suspicious_sub
        app.antivirus_quarantine_value = app.antivirus_kpi_quarantine

        row.addWidget(engines_tile, 1)
        row.addWidget(suspicious_tile, 1)
        row.addWidget(quarantine_tile, 1)
        row.addWidget(mitre_tile, 1)
        return strip

    def _build_provider_matrix_card(self) -> QWidget:
        """6-engine readiness matrix with per-row inline ops — left
        half of mid row.

        Sprint-4 upgrade: real EDR consoles surface every operational
        signal an analyst needs to triage a degraded engine without
        leaving the row. We add three new columns (Last error,
        latency p95, success rate) and two inline action buttons (Test,
        Update) wired to the Wave-1 / Sprint-4 backend endpoints."""
        app = self.app
        app.antivirus_overview_providers = QTableWidget(0, 8)
        app.antivirus_overview_providers.setHorizontalHeaderLabels(
            ["Engine", "State", "Defs", "Last upd.", "p95", "Success", "Last error", "Actions"]
        )
        app._style_table(app.antivirus_overview_providers)
        header = app.antivirus_overview_providers.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        app.antivirus_overview_providers.verticalHeader().setVisible(False)
        app.antivirus_overview_providers.setMinimumHeight(180)
        # Inline buttons need a slightly taller row so two stacked QPushButtons fit.
        app.antivirus_overview_providers.verticalHeader().setDefaultSectionSize(36)
        # Legacy alias for downstream code that expected the engine status html block.
        app.antivirus_status_summary = app.antivirus_overview_providers
        return app._panel_card(
            "Provider Matrix",
            app.antivirus_overview_providers,
            lambda: app._open_panel_window("Antivirus Provider Readiness", app._clone_table(app.antivirus_overview_providers)),
        )

    def _build_mitre_heatmap_card(self) -> QWidget:
        """Tactic-grouped technique tiles — right half of mid row."""
        app = self.app
        app.antivirus_mitre_view = QTextBrowser()
        app.antivirus_mitre_view.setOpenExternalLinks(False)
        app.antivirus_mitre_view.setMinimumHeight(220)
        app.antivirus_mitre_view.setStyleSheet(
            "QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}"
        )
        # Legacy aliases for the snapshot/queue widgets the old code wrote to.
        app.antivirus_overview_snapshot = app.antivirus_mitre_view
        return app._panel_card(
            "MITRE ATT&CK Coverage",
            app.antivirus_mitre_view,
            lambda: app._open_panel_window("MITRE ATT&CK Coverage", app._clone_text_view(app.antivirus_mitre_view)),
        )

    def _build_verdict_table_card(self) -> QWidget:
        """Bottom recent-verdicts pane — filter bar + bulk-action bar +
        clickable + right-clickable verdict table.

        Sprint-3 upgrade: real product consoles don't show a flat list
        and let analysts scroll. They give the analyst a one-click way
        to slice the list (verdict / severity / time window), to act on
        many rows at once (bulk-quarantine, bulk-export), and to pivot
        each row into the standard hunt tools (VT, MalwareBazaar, copy
        SHA-256, run vault verify) via right-click."""
        from PySide6.QtWidgets import QAbstractItemView
        app = self.app

        # SHA-256 is a real, often-needed sortable/copyable column —
        # add it before the legacy 7-col layout.
        app.antivirus_results_table = QTableWidget(0, 8)
        app.antivirus_results_table.setHorizontalHeaderLabels(
            ["", "Time", "Target", "Verdict", "Severity", "MITRE", "Engines", "SHA-256"]
        )
        app._style_table(app.antivirus_results_table)
        header = app.antivirus_results_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Fixed)              # dot
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)   # time
        header.setSectionResizeMode(2, QHeaderView.Stretch)            # target
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)   # verdict
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)   # severity
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)   # mitre
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)   # engines
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)   # sha256
        app.antivirus_results_table.setColumnWidth(0, 28)
        app.antivirus_results_table.verticalHeader().setVisible(False)
        # Multi-row selection enables bulk actions (Ctrl-click / Shift-click).
        app.antivirus_results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        app.antivirus_results_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        app.antivirus_results_table.itemSelectionChanged.connect(self._on_verdict_selected)
        app.antivirus_results_table.cellDoubleClicked.connect(lambda *_: self.open_detail_drawer())
        # Right-click context menu wired via custom slot.
        app.antivirus_results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        app.antivirus_results_table.customContextMenuRequested.connect(self._show_verdict_context_menu)
        # Legacy alias kept for the recent-response queue references in old code.
        app.antivirus_overview_queue = app.antivirus_results_table

        # Filter state lives on the controller so background pollers can read it.
        self._verdict_filters: dict[str, str] = {
            "verdict": "all", "severity": "all", "time_window": "24h",
        }

        # Filter bar.
        filter_bar = self._build_verdict_filter_bar()
        # Bulk-action bar — visible always, but hint label updates with selection count.
        bulk_bar = self._build_verdict_bulk_bar()

        # Wrap everything in a single card so the existing layout call site
        # in build_tab still gets one widget.
        wrap = QFrame(); wrap.setProperty("card", True)
        wrap_layout = QVBoxLayout(wrap)
        wrap_layout.setContentsMargins(10, 8, 10, 10); wrap_layout.setSpacing(6)
        # Card header (mimics _panel_card).
        head = QHBoxLayout(); head.setSpacing(8)
        title = QLabel("Recent Verdicts")
        title.setStyleSheet("font-size:13px;font-weight:700;color:#f4f7fb;letter-spacing:0.2px;")
        head.addWidget(title); head.addStretch(1)
        live_pill = QLabel("● Live"); live_pill.setStyleSheet(
            "color:#7bd389;background:#121b27;border:1px solid #2c4260;border-radius:7px;"
            "padding:3px 8px;font-size:10px;font-weight:700;"
        )
        live_pill.setToolTip("Recent-verdict stream auto-refreshes every 2 s while the tab is active.")
        head.addWidget(live_pill)
        self._verdict_live_pill = live_pill
        open_btn = QPushButton("Open Panel"); open_btn.setMaximumWidth(104)
        open_btn.clicked.connect(lambda: app._open_panel_window("Recent Antivirus Verdicts", app._clone_table(app.antivirus_results_table)))
        head.addWidget(open_btn)
        wrap_layout.addLayout(head)
        wrap_layout.addWidget(filter_bar)
        wrap_layout.addWidget(app.antivirus_results_table, 1)
        wrap_layout.addWidget(bulk_bar)
        return wrap

    def _build_verdict_filter_bar(self) -> QWidget:
        """Verdict / severity / time-window chips above the verdict table."""
        bar = QWidget()
        layout = QHBoxLayout(bar); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(6)
        layout.addWidget(QLabel("Verdict:"))
        self._filter_chips_verdict = self._add_filter_chips(
            layout, "verdict",
            options=[("all", "All"), ("infected", "Infected"), ("suspicious", "Suspicious"),
                     ("clean", "Clean"), ("error", "Errors")],
        )
        layout.addSpacing(12)
        layout.addWidget(QLabel("Severity:"))
        self._filter_chips_severity = self._add_filter_chips(
            layout, "severity",
            options=[("all", "All"), ("critical", "Critical"), ("high", "High"),
                     ("medium", "Medium"), ("low", "Low")],
        )
        layout.addSpacing(12)
        layout.addWidget(QLabel("Time:"))
        self._filter_chips_time = self._add_filter_chips(
            layout, "time_window",
            options=[("1h", "1h"), ("24h", "24h"), ("7d", "7d"), ("all", "All")],
        )
        layout.addStretch(1)
        match_label = QLabel("0 / 0 shown")
        match_label.setStyleSheet("color:#96a5b8;font-size:11px;")
        layout.addWidget(match_label)
        self._verdict_match_label = match_label
        return bar

    def _add_filter_chips(self, parent_layout, key: str, *, options: list[tuple[str, str]]) -> dict[str, QPushButton]:
        chips: dict[str, QPushButton] = {}
        for value, label in options:
            chip = QPushButton(label)
            chip.setCheckable(True)
            chip.setMaximumHeight(24)
            self._style_filter_chip(chip, active=(value == self._verdict_filters[key]))
            chip.clicked.connect(lambda _checked=False, k=key, v=value: self._set_verdict_filter(k, v))
            parent_layout.addWidget(chip)
            chips[value] = chip
        return chips

    @staticmethod
    def _style_filter_chip(chip: QPushButton, *, active: bool) -> None:
        if active:
            chip.setStyleSheet(
                "QPushButton{background:#1d3a5f;color:#9fd0ff;border:1px solid #355179;border-radius:11px;"
                "padding:2px 10px;font-size:11px;font-weight:700;}"
            )
        else:
            chip.setStyleSheet(
                "QPushButton{background:#121b27;color:#96a5b8;border:1px solid #2c4260;border-radius:11px;"
                "padding:2px 10px;font-size:11px;}"
                "QPushButton:hover{color:#c8d8ea;border-color:#355179;}"
            )
        chip.setChecked(active)

    def _set_verdict_filter(self, key: str, value: str) -> None:
        self._verdict_filters[key] = value
        # Repaint the chip group so only the active chip pops.
        chips_attr = {
            "verdict": "_filter_chips_verdict",
            "severity": "_filter_chips_severity",
            "time_window": "_filter_chips_time",
        }.get(key)
        if chips_attr and hasattr(self, chips_attr):
            for chip_value, chip in getattr(self, chips_attr).items():
                self._style_filter_chip(chip, active=(chip_value == value))
        self._render_verdict_table()

    def _build_verdict_bulk_bar(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(6)
        self._bulk_count_label = QLabel("0 selected")
        self._bulk_count_label.setStyleSheet("color:#96a5b8;font-size:11px;")
        layout.addWidget(self._bulk_count_label)
        layout.addStretch(1)
        for label, slot, accent in [
            ("Quarantine selected", self.bulk_quarantine_selected, "#5c1f2d"),
            ("Export reports",      self.bulk_export_selected,     "#1d3a5f"),
            ("Clear selection",     self.bulk_clear_selection,     "#243446"),
        ]:
            btn = QPushButton(label)
            btn.setMaximumHeight(26)
            btn.setStyleSheet(
                f"QPushButton{{background:{accent};color:#eef4fb;border:1px solid #355179;"
                f"border-radius:6px;padding:3px 10px;font-size:11px;font-weight:600;}}"
                "QPushButton:disabled{color:#5b6d80;background:#16202c;border-color:#243446;}"
            )
            btn.setEnabled(False)
            layout.addWidget(btn)
            self._bulk_buttons = getattr(self, "_bulk_buttons", {})
            self._bulk_buttons[label] = btn
            btn.clicked.connect(slot)
        return bar

    # ------------------------------------------------------------------
    # Drawer-only widgets — created up front so existing methods that
    # reference them by attribute keep working, but only displayed when
    # the matching drawer button is pressed.
    # ------------------------------------------------------------------

    def _build_drawer_widgets(self) -> None:
        app = self.app

        # Verdict / scan-detail panes.
        app.antivirus_result_detail = QTextEdit()
        app.antivirus_result_detail.setReadOnly(True)
        app.antivirus_provider_hits = QTextBrowser()
        app.antivirus_scan_guidance = QTextBrowser()
        app.antivirus_scan_access_hint = QLabel("")
        app.antivirus_scan_access_hint.setStyleSheet("color:#96a5b8;font-size:11px;")
        app.antivirus_scan_actions = QWidget()  # placeholder so apply_role_access doesn't crash
        self.scan_buttons = getattr(self, "scan_buttons", {})

        # Quarantine drawer widgets.
        app.antivirus_quarantine_table = QTableWidget(0, 6)
        app.antivirus_quarantine_table.setHorizontalHeaderLabels(
            ["ID", "Process", "Original Path", "Quarantine Path", "Status", "Created"]
        )
        app._style_table(app.antivirus_quarantine_table)
        app.antivirus_quarantine_table.itemSelectionChanged.connect(app.show_selected_antivirus_quarantine)
        app.antivirus_quarantine_detail = QTextEdit()
        app.antivirus_quarantine_detail.setReadOnly(True)
        app.antivirus_response_notes = QTextBrowser()
        app.antivirus_response_notes.setHtml(
            "<h3>Containment Notes</h3><ul>"
            "<li><b>Quarantine</b> preserves a controlled copy for investigation.</li>"
            "<li><b>Restore</b> only after analyst validation or false-positive review.</li>"
            "<li><b>Delete</b> for final disposal after case documentation.</li>"
            "<li><b>Webhook</b> keeps downstream channels aligned with response.</li>"
            "</ul>"
        )
        app.antivirus_quarantine_access_hint = QLabel("")
        app.antivirus_quarantine_access_hint.setStyleSheet("color:#96a5b8;font-size:11px;")
        app.antivirus_quarantine_actions = QWidget()
        self.quarantine_buttons = {}

        # History drawer widgets.
        app.antivirus_history_table = QTableWidget(0, 6)
        app.antivirus_history_table.setHorizontalHeaderLabels(
            ["Time", "Category", "Target", "Severity", "Operator Action", "Status"]
        )
        app._style_table(app.antivirus_history_table)
        app.antivirus_history_table.itemSelectionChanged.connect(self.show_selected_history)
        app.antivirus_history_detail = QTextEdit()
        app.antivirus_history_detail.setReadOnly(True)
        app.antivirus_history_banner = QLabel(
            "History keeps scan, containment, and notification actions in one audit stream."
        )
        app.antivirus_history_banner.setStyleSheet(
            "color:#ffd166;background:#1b2331;border:1px solid #34507a;border-radius:8px;padding:8px 10px;font-weight:600;"
        )

        # Policy controls — created here, displayed inside the settings drawer.
        app.antivirus_policy_enabled = QCheckBox("AV enabled")
        app.antivirus_policy_provider_aegis = QCheckBox("Aegis Core")
        app.antivirus_policy_provider_sentinel = QCheckBox("Sentinel CLI")
        app.antivirus_policy_provider_cloud = QCheckBox("Cloud Intel")
        app.antivirus_policy_provider_yara = QCheckBox("YARA-X")
        app.antivirus_policy_provider_behavioural = QCheckBox("Behavioural")
        app.antivirus_policy_provider_sandbox = QCheckBox("Cloud Sandbox")
        for cb in [
            app.antivirus_policy_provider_aegis, app.antivirus_policy_provider_sentinel,
            app.antivirus_policy_provider_cloud, app.antivirus_policy_provider_yara,
            app.antivirus_policy_provider_behavioural, app.antivirus_policy_provider_sandbox,
        ]:
            cb.setChecked(True)
        app.antivirus_policy_profile = QComboBox()
        app.antivirus_policy_profile.addItems(["conservative", "balanced", "aggressive"])
        app.antivirus_policy_threshold = QComboBox()
        app.antivirus_policy_threshold.addItems(["disabled", "critical", "high"])
        app.antivirus_policy_schedule = QSpinBox()
        app.antivirus_policy_schedule.setRange(15, 10080)
        app.antivirus_policy_schedule.setValue(240)
        app.antivirus_policy_grace = QSpinBox()
        app.antivirus_policy_grace.setRange(6, 720)
        app.antivirus_policy_grace.setValue(48)
        app.antivirus_policy_yara_pack = QComboBox()
        app.antivirus_policy_yara_pack.addItems(YARA_PACKS)
        app.antivirus_policy_mitre_enabled = QCheckBox("MITRE mapping enabled")
        app.antivirus_policy_mitre_enabled.setChecked(True)
        self.policy_buttons = {}

    # ------------------------------------------------------------------
    # Drawer launchers (popups) and detail rendering
    # ------------------------------------------------------------------

    def _open_drawer(self, key: str, title: str, body: QWidget, *, width: int = 1100, height: int = 720) -> None:
        existing = self._open_drawers.get(key)
        if existing is not None:
            try:
                existing.raise_(); existing.activateWindow(); return
            except Exception:
                self._open_drawers.pop(key, None)
        dlg = QDialog(self.app)
        dlg.setWindowTitle(title)
        dlg.setModal(False)
        dlg.setWindowModality(Qt.NonModal)
        dlg.setAttribute(Qt.WA_DeleteOnClose, True)
        dlg.resize(width, height)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.addWidget(body)
        dlg.destroyed.connect(lambda *_args, k=key: self._open_drawers.pop(k, None))
        dlg.show(); dlg.raise_(); dlg.activateWindow()
        self._open_drawers[key] = dlg

    def open_settings_drawer(self) -> None:
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setSpacing(10)
        layout.setContentsMargins(0, 0, 0, 0)

        # Engine toggle row.
        engines_card = QFrame(); engines_card.setProperty("card", True)
        engines_layout = QVBoxLayout(engines_card)
        engines_layout.setContentsMargins(12, 10, 12, 10)
        engines_layout.setSpacing(6)
        engines_layout.addWidget(QLabel("<b>Active engines</b>"))
        engines_grid = QGridLayout()
        engines_grid.setHorizontalSpacing(12)
        engines_grid.setVerticalSpacing(4)
        for col, cb in enumerate([
            app.antivirus_policy_enabled,
            app.antivirus_policy_provider_aegis, app.antivirus_policy_provider_sentinel,
            app.antivirus_policy_provider_cloud, app.antivirus_policy_provider_yara,
            app.antivirus_policy_provider_behavioural, app.antivirus_policy_provider_sandbox,
        ]):
            engines_grid.addWidget(cb, col // 4, col % 4)
        engines_layout.addLayout(engines_grid)

        # Policy parameter grid.
        params_card = QFrame(); params_card.setProperty("card", True)
        params_layout = QGridLayout(params_card)
        params_layout.setContentsMargins(12, 10, 12, 10)
        params_layout.setHorizontalSpacing(10)
        params_layout.setVerticalSpacing(6)
        params = [
            ("Scan profile",         app.antivirus_policy_profile),
            ("Auto-quarantine",      app.antivirus_policy_threshold),
            ("Validation (min)",     app.antivirus_policy_schedule),
            ("Signature grace (h)", app.antivirus_policy_grace),
            ("YARA pack",            app.antivirus_policy_yara_pack),
        ]
        for idx, (label, widget) in enumerate(params):
            params_layout.addWidget(QLabel(label), idx // 3 * 2, idx % 3)
            params_layout.addWidget(widget,        idx // 3 * 2 + 1, idx % 3)
        params_layout.addWidget(app.antivirus_policy_mitre_enabled, 4, 0, 1, 3)

        # Webhook + actions row.
        webhook_row = QFrame(); webhook_row.setProperty("card", True)
        webhook_layout = QVBoxLayout(webhook_row)
        webhook_layout.setContentsMargins(12, 10, 12, 10)
        webhook_layout.setSpacing(6)
        webhook_layout.addWidget(QLabel("<b>Alert webhook</b>"))
        webhook_field = QLineEdit(app.webhook_url.text().strip())
        webhook_field.setPlaceholderText("https://example.com/webhook")
        webhook_field.textChanged.connect(app.webhook_url.setText)
        webhook_layout.addWidget(webhook_field)
        webhook_btns = QHBoxLayout()
        for label, slot, key in [
            ("Test webhook", app.test_alert_webhook, "test_webhook"),
            ("Save webhook", app.save_alert_webhook, "save_webhook"),
        ]:
            btn = QPushButton(label); btn.clicked.connect(slot)
            self.quarantine_buttons[key] = btn  # apply_role_access expects these
            webhook_btns.addWidget(btn)
        webhook_btns.addStretch(1)
        webhook_layout.addLayout(webhook_btns)

        # Footer — Save / Reload policy buttons.
        footer = QHBoxLayout()
        for key, label, slot in [
            ("refresh", "Reload Policy", self.refresh_status),
            ("save",    "Save Policy",   self.save_policy),
        ]:
            btn = QPushButton(label); btn.clicked.connect(slot)
            self.policy_buttons[key] = btn
            footer.addWidget(btn)
        footer.addStretch(1)

        layout.addWidget(engines_card)
        layout.addWidget(params_card)
        layout.addWidget(webhook_row)
        layout.addLayout(footer)
        layout.addStretch(1)

        self.apply_role_access()
        self._open_drawer("settings", "Antivirus Policy", body, width=720, height=520)

    def open_quarantine_drawer(self) -> None:
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setSpacing(8); layout.setContentsMargins(0, 0, 0, 0)

        actions = QFrame(); actions.setProperty("card", True)
        actions_layout = QHBoxLayout(actions); actions_layout.setContentsMargins(10, 8, 10, 8); actions_layout.setSpacing(6)
        for action_key, label, slot in [
            ("refresh",       "Refresh",         app.refresh_quarantine if hasattr(app, "refresh_quarantine") else self.refresh_quarantine_inventory),
            ("export_report", "Export Report",   self.export_selected_quarantine_report),
            ("restore",       "Restore",         app.restore_selected_quarantine if hasattr(app, "restore_selected_quarantine") else self.restore_selected_quarantine),
            ("delete",        "Delete",          app.delete_selected_quarantine if hasattr(app, "delete_selected_quarantine") else self.delete_selected_quarantine),
            ("open_copy",     "Open Copy",       app.open_selected_antivirus_quarantine),
        ]:
            btn = QPushButton(label); btn.clicked.connect(slot)
            self.quarantine_buttons[action_key] = btn
            actions_layout.addWidget(btn)
        actions_layout.addStretch(1)
        actions_layout.addWidget(app.antivirus_quarantine_access_hint)
        layout.addWidget(actions)

        body_split = QHBoxLayout(); body_split.setSpacing(8)
        body_split.addWidget(app._panel_card("Inventory", app.antivirus_quarantine_table,
            lambda: app._open_panel_window("Quarantine Inventory", app._clone_table(app.antivirus_quarantine_table))), 2)
        body_split.addWidget(app._panel_card("Detail", app.antivirus_quarantine_detail,
            lambda: app._open_panel_window("Quarantine Detail", app._clone_text_view(app.antivirus_quarantine_detail))), 1)
        body_split.addWidget(app._panel_card("Notes", app.antivirus_response_notes,
            lambda: app._open_panel_window("Containment Notes", app._clone_text_view(app.antivirus_response_notes))), 1)
        layout.addLayout(body_split, 1)

        self.refresh_quarantine_inventory()
        self.apply_role_access()
        self._open_drawer("quarantine", "Antivirus Quarantine", body, width=1180, height=620)

    def open_history_drawer(self) -> None:
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setSpacing(8); layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(app.antivirus_history_banner)
        layout.addWidget(app._panel_card("History", app.antivirus_history_table,
            lambda: app._open_panel_window("Antivirus History", app._clone_table(app.antivirus_history_table))), 2)
        layout.addWidget(app._panel_card("Detail", app.antivirus_history_detail,
            lambda: app._open_panel_window("History Detail", app._clone_text_view(app.antivirus_history_detail))), 1)
        self._open_drawer("history", "Antivirus History", body, width=1180, height=620)

    def open_detail_drawer(self) -> None:
        app = self.app
        row = app.antivirus_results_table.currentRow()
        if row < 0:
            app.statusBar().showMessage("Select a verdict row first")
            return
        items = getattr(app, "antivirus_scan_results", [])
        if row >= len(items):
            return
        # Reuse the existing rich render — it already updates result_detail,
        # provider_hits, scan_guidance widgets.
        self.show_selected_result()

        body = QWidget()
        layout = QVBoxLayout(body); layout.setSpacing(8); layout.setContentsMargins(0, 0, 0, 0)
        verdict_card = app._panel_card("Fused Verdict", app.antivirus_result_detail,
            lambda: app._open_panel_window("Verdict Detail", app._clone_text_view(app.antivirus_result_detail)))
        hits_card = app._panel_card("Provider Cards", app.antivirus_provider_hits,
            lambda: app._open_panel_window("Provider Cards", app._clone_text_view(app.antivirus_provider_hits)))
        guidance_card = app._panel_card("Operator Guidance", app.antivirus_scan_guidance,
            lambda: app._open_panel_window("Operator Guidance", app._clone_text_view(app.antivirus_scan_guidance)))
        top_row = QHBoxLayout(); top_row.setSpacing(8)
        top_row.addWidget(verdict_card, 1)
        top_row.addWidget(hits_card, 1)
        layout.addLayout(top_row, 1)
        layout.addWidget(guidance_card, 1)

        # Action row — quarantine, export, create case.
        actions_row = QHBoxLayout(); actions_row.setSpacing(6)
        for action_key, label, slot in [
            ("create_case",   "Create Case",     self.create_case_from_selected_result),
            ("export_report", "Export Report",   self.export_selected_result_report),
            ("quarantine",    "Quarantine",      app.quarantine_selected_antivirus_result),
        ]:
            btn = QPushButton(label); btn.clicked.connect(slot)
            self.scan_buttons[action_key] = btn
            actions_row.addWidget(btn)
        actions_row.addStretch(1)
        layout.addLayout(actions_row)

        self.apply_role_access()
        self._open_drawer("detail", "Verdict Detail", body, width=1240, height=720)

    def _on_verdict_selected(self) -> None:
        # Light update — populate detail widgets even if drawer is closed
        # so opening the drawer is instant.
        try:
            self.show_selected_result()
        except Exception:
            pass
        self._refresh_bulk_state()

    # ------------------------------------------------------------------
    # UX helpers — drag-drop, shortcut cheat sheet, toast notifications
    # ------------------------------------------------------------------

    def _handle_drag_enter(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def _handle_file_drop(self, event) -> None:
        urls = event.mimeData().urls() if event.mimeData() else []
        if not urls:
            event.ignore(); return
        path = urls[0].toLocalFile()
        if not path:
            event.ignore(); return
        # Drop-to-scan UX: fill the search field (so the analyst sees
        # what was picked up) and immediately fire a fused scan.
        if hasattr(self.app, "antivirus_target_path"):
            self.app.antivirus_target_path.setText(path)
        self.toast(f"📥 Dropped {Path(path).name} — scanning…", level="info")
        self.handle_scan_kind("full")
        event.acceptProposedAction()

    def _show_shortcut_help(self) -> None:
        from PySide6.QtWidgets import QMessageBox
        box = QMessageBox(self.app)
        box.setWindowTitle("Antivirus shortcuts")
        box.setTextFormat(Qt.RichText)
        box.setText(
            "<table cellpadding='4' style='font-family:Consolas,monospace;'>"
            "<tr><td><b>Ctrl+S</b></td><td>Run full scan against the search target</td></tr>"
            "<tr><td><b>/</b></td><td>Focus the search field</td></tr>"
            "<tr><td><b>Ctrl+Q</b></td><td>Open Quarantine drawer</td></tr>"
            "<tr><td><b>Ctrl+J</b></td><td>Open Jobs drawer (async scans)</td></tr>"
            "<tr><td><b>Ctrl+R</b></td><td>Refresh provider matrix + verdict feed</td></tr>"
            "<tr><td><b>Ctrl+L</b></td><td>Open Lists drawer (exclusion / block / allow)</td></tr>"
            "<tr><td><b>Ctrl+E</b></td><td>Open EICAR validation drawer</td></tr>"
            "<tr><td><b>?</b></td><td>This help</td></tr>"
            "<tr><td><b>Drag-drop</b></td><td>Drop any file on the tab → auto-scan</td></tr>"
            "<tr><td><b>Right-click</b></td><td>Context menu on any verdict row</td></tr>"
            "</table>"
        )
        box.exec()

    def toast(self, message: str, *, level: str = "info", duration_ms: int = 4500) -> None:
        """Lightweight toast — borderless QLabel that fades in/out at
        the bottom-right of the antivirus tab. Falls back to the
        status bar if the toast widget can't be parented."""
        from PySide6.QtCore import QTimer, QPropertyAnimation, Qt as _Qt, QPoint
        from PySide6.QtWidgets import QLabel
        app = self.app
        try:
            tab = app.tabs.currentWidget() if hasattr(app, "tabs") else None
        except Exception:
            tab = None
        if tab is None:
            try:
                app.statusBar().showMessage(message, max(2500, duration_ms))
            except Exception:
                pass
            return
        accent = {
            "error":   ("#5c1f2d", "#ff8b8b", "#8c2d44"),
            "warn":    ("#1b2331", "#f4c26b", "#34507a"),
            "success": ("#15331f", "#7bd389", "#2f9c6c"),
        }.get(level, ("#121b27", "#9fd0ff", "#2c4260"))
        bg, fg, border = accent
        toast = QLabel(message, tab)
        toast.setStyleSheet(
            f"QLabel{{background:{bg};color:{fg};border:1px solid {border};border-radius:8px;"
            f"padding:8px 14px;font-size:12px;font-weight:600;}}"
        )
        toast.adjustSize()
        # Bottom-right anchor with 24 px margin, stack upward if multiple.
        existing = getattr(self, "_active_toasts", [])
        existing = [t for t in existing if t.parent() is not None]
        offset_y = 24 + sum(t.height() + 6 for t in existing)
        x = max(8, tab.width() - toast.width() - 24)
        y = max(8, tab.height() - toast.height() - offset_y)
        toast.move(x, y)
        toast.show()
        toast.raise_()
        existing.append(toast)
        self._active_toasts = existing

        def _dismiss() -> None:
            try:
                self._active_toasts = [t for t in getattr(self, "_active_toasts", []) if t is not toast]
                toast.deleteLater()
            except Exception:
                pass
        QTimer.singleShot(max(1500, int(duration_ms)), _dismiss)

    # ------------------------------------------------------------------
    # Verdict-table bulk actions + right-click context menu
    # ------------------------------------------------------------------

    def _selected_verdict_rows(self) -> list[dict]:
        """Return the list of payload dicts the analyst has multi-selected."""
        table = self.app.antivirus_results_table
        rows = sorted({idx.row() for idx in table.selectionModel().selectedRows()})
        filtered = getattr(self, "_filtered_verdict_rows", []) or []
        return [filtered[r] for r in rows if 0 <= r < len(filtered)]

    def _refresh_bulk_state(self) -> None:
        """Update the bulk-bar count + button enabled state based on selection."""
        if not hasattr(self, "_bulk_count_label"):
            return
        selected = self._selected_verdict_rows()
        n = len(selected)
        self._bulk_count_label.setText(f"{n} selected")
        actionable = n > 0
        for label, btn in getattr(self, "_bulk_buttons", {}).items():
            btn.setEnabled(actionable)
            if actionable and label.startswith("Quarantine"):
                btn.setText(f"Quarantine selected ({n})")
            elif actionable and label.startswith("Export"):
                btn.setText(f"Export reports ({n})")
            elif label.startswith("Quarantine"):
                btn.setText("Quarantine selected")
            elif label.startswith("Export"):
                btn.setText("Export reports")

    def bulk_quarantine_selected(self) -> None:
        """Quarantine every selected row in sequence — one POST per row.

        Runs the per-row loop on a background thread so a 50-row bulk
        doesn't freeze the desktop for 30+ minutes (each call has a 45s
        backend timeout). Captures one structured reason that applies
        to the whole bulk for the audit row.
        """
        from PySide6.QtWidgets import QMessageBox
        selected = self._selected_verdict_rows()
        if not selected:
            self.app.statusBar().showMessage("Select one or more verdict rows first")
            return
        if not self._check_response_gate("quarantine"):
            return
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Bulk quarantine")
        confirm.setText(f"Quarantine {len(selected)} selected sample(s)?")
        confirm.setInformativeText(
            "Each row's underlying file path will be sealed into the cryptographic vault. "
            "Admin role + dangerous-actions gate are enforced server-side. "
            "A structured reason will be required next."
        )
        confirm.setIcon(QMessageBox.Warning)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason(f"bulk-quarantine ({len(selected)} target(s))")
        if reason is None:
            return

        targets: list[dict] = []
        skipped_no_path = 0
        actor = self.app.actor_name.text().strip() or "desktop"
        for item in selected:
            payload = item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}
            process_meta = payload.get("process", {}) if isinstance(payload.get("process"), dict) else {}
            file_path = str(payload.get("path", "") or process_meta.get("exe", "") or "")
            if not file_path:
                skipped_no_path += 1
                continue
            targets.append({
                "file_path": file_path,
                "pid": int(process_meta.get("pid", -1) or -1),
                "process_name": str(process_meta.get("name", "") or Path(file_path).name),
                "actor": actor,
            })

        if not targets:
            self.app.statusBar().showMessage(f"Bulk quarantine: nothing actionable ({skipped_no_path} rows missing file path).")
            return

        # Watchdog budget: per-call 45s, scale with the bulk size but
        # keep within `bulk_scan_timeout` (caps at 10 minutes).
        budget = bulk_scan_timeout(per_call_seconds=50, count=len(targets))
        self.app.statusBar().showMessage(
            f"Bulk quarantine: {len(targets)} target(s) running (watchdog {budget}s)..."
        )

        def _work() -> dict:
            ok = 0
            errors: list[dict] = []
            for body in targets:
                try:
                    self.app._post("/antivirus/respond/quarantine", json=body, timeout=45)
                    ok += 1
                except Exception as exc:
                    errors.append({"target": body.get("file_path", ""), "error": str(exc)})
            return {"ok": ok, "failed": len(errors), "skipped_no_path": skipped_no_path, "errors": errors[:25]}

        def _on_ok(summary: dict) -> None:
            self.app.statusBar().showMessage(
                f"Bulk quarantine: {summary['ok']} ok · {summary['failed']} failed · {summary['skipped_no_path']} skipped"
            )
            self._record_history(
                category="response",
                action="bulk-quarantine",
                target=f"{summary['ok']}/{len(targets)} target(s)",
                severity="high",
                status="ok" if summary["failed"] == 0 else "partial",
                payload=summary,
                reason=reason,
            )
            self.refresh_quarantine_inventory()

        def _on_err(message: str) -> None:
            self.app.statusBar().showMessage(f"Bulk quarantine failed: {message}")
            self._record_history(
                category="response",
                action="bulk-quarantine",
                target=f"{len(targets)} target(s)",
                severity="high",
                status="failed",
                payload={"error": message},
                reason=reason,
            )

        self._submit_async(
            f"Bulk quarantine ({len(targets)} target(s))",
            _work,
            _on_ok,
            _on_err,
            timeout_seconds=budget,
        )

    def bulk_export_selected(self) -> None:
        """Export a detection report for every selected row.

        Loops on a background thread; per-row backend timeout is 40s,
        so a 30-row bulk could otherwise freeze the UI for 20 minutes.
        """
        selected = self._selected_verdict_rows()
        if not selected:
            self.app.statusBar().showMessage("Select one or more verdict rows first")
            return

        payloads = [
            item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}
            for item in selected
        ]
        budget = bulk_scan_timeout(per_call_seconds=45, count=len(payloads))
        self.app.statusBar().showMessage(
            f"Bulk export: {len(payloads)} target(s) running (watchdog {budget}s)..."
        )

        def _work() -> dict:
            ok = 0
            errors: list[str] = []
            for source in payloads:
                try:
                    self.app._post(
                        "/antivirus/report/detection/export",
                        json={"source_scan": source},
                        timeout=40,
                    )
                    ok += 1
                except Exception as exc:
                    errors.append(str(exc))
            return {"ok": ok, "failed": len(errors), "errors": errors[:25]}

        def _on_ok(summary: dict) -> None:
            self.app.statusBar().showMessage(
                f"Bulk export: {summary['ok']} ok · {summary['failed']} failed"
            )
            if hasattr(self.app, "refresh_artifacts"):
                self.app.refresh_artifacts()

        def _on_err(message: str) -> None:
            self.app.statusBar().showMessage(f"Bulk export failed: {message}")

        self._submit_async(
            f"Bulk export ({len(payloads)} target(s))",
            _work,
            _on_ok,
            _on_err,
            timeout_seconds=budget,
        )

    def bulk_clear_selection(self) -> None:
        self.app.antivirus_results_table.clearSelection()
        self._refresh_bulk_state()

    def _show_verdict_context_menu(self, point) -> None:
        """Right-click hunt menu on the verdict table.

        Real EDR consoles never make the analyst leave the verdict view
        to copy a hash or pivot to VT — they put every common pivot in
        a single right-click menu. Same here."""
        from PySide6.QtWidgets import QMenu, QApplication
        table = self.app.antivirus_results_table
        row = table.indexAt(point).row()
        if row < 0:
            return
        filtered = getattr(self, "_filtered_verdict_rows", []) or []
        if row >= len(filtered):
            return
        item = filtered[row]
        sha = str(item.get("sha256", "") or "")
        target = str(item.get("target", "") or "")
        payload = item.get("payload", {}) if isinstance(item.get("payload"), dict) else {}

        menu = QMenu(table)
        menu.setStyleSheet(
            "QMenu{background:#16202c;color:#eef4fb;border:1px solid #2c4260;}"
            "QMenu::item{padding:5px 18px;}"
            "QMenu::item:selected{background:#1d3a5f;color:#9fd0ff;}"
            "QMenu::separator{height:1px;background:#243446;margin:3px 8px;}"
        )

        menu.addAction("Open detail",   lambda: (table.selectRow(row), self.open_detail_drawer()))
        menu.addAction("Copy SHA-256",  lambda: QApplication.clipboard().setText(sha) if sha else self.app.statusBar().showMessage("No SHA-256 on this scan"))
        menu.addAction("Copy target path", lambda: QApplication.clipboard().setText(target) if target else self.app.statusBar().showMessage("No target path on this scan"))
        menu.addSeparator()

        # External pivots — open the analyst's browser. Honour link-safety
        # rule: only follow well-known intel hostnames.
        if sha:
            menu.addAction("Lookup → VirusTotal",       lambda: QDesktopServices.openUrl(QUrl(f"https://www.virustotal.com/gui/file/{sha}")))
            menu.addAction("Lookup → MalwareBazaar",    lambda: QDesktopServices.openUrl(QUrl(f"https://bazaar.abuse.ch/sample/{sha}/")))
            menu.addAction("Lookup → Hybrid-Analysis",  lambda: QDesktopServices.openUrl(QUrl(f"https://www.hybrid-analysis.com/search?query={sha}")))
            menu.addSeparator()

        menu.addAction("Vault verify",
            lambda: self._vault_verify_for_target(target, payload))
        menu.addAction("Re-scan (async)",
            lambda: self._async_rescan_target(target))
        menu.addSeparator()
        menu.addAction("Quarantine",
            lambda: (table.selectRow(row), self.app.quarantine_selected_antivirus_result()))
        menu.addAction("Export report",
            lambda: (table.selectRow(row), self.export_selected_result_report()))
        menu.exec(table.viewport().mapToGlobal(point))

    def _vault_verify_for_target(self, target: str, payload: dict) -> None:
        """Convenience — find the vault entry whose original_path matches
        the verdict row's target and run verify against it."""
        if not target:
            self.app.statusBar().showMessage("No target path on this scan")
            return
        try:
            resp = self.app._get("/antivirus/vault", timeout=15).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"Vault list failed: {exc}")
            return
        rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
        match = next((r for r in rows if str(r.get("original_path", "")) == target), None)
        if match is None:
            self.app.statusBar().showMessage("No vault entry exists for this target — quarantine first.")
            return
        fid = str(match.get("file_id", ""))
        try:
            verify = self.app._post(f"/antivirus/vault/{fid}/verify", json={}, timeout=20).json()
            ok = bool((verify.get("result", verify) or {}).get("ok"))
            self.app.statusBar().showMessage(f"Vault verify {fid[:12]}: {'OK' if ok else 'FAIL'}")
        except Exception as exc:
            self.app.statusBar().showMessage(f"Vault verify failed: {exc}")

    def _async_rescan_target(self, target: str) -> None:
        if not target:
            self.app.statusBar().showMessage("No target path on this scan")
            return
        try:
            resp = self.app._post("/antivirus/scan/file/async", json={"file_path": target}, timeout=15).json()
            jid = (resp.get("job", {}) or {}).get("job_id", "")
            self.app.statusBar().showMessage(f"Re-scan queued — job {jid[:12]}")
        except Exception as exc:
            self.app.statusBar().showMessage(f"Re-scan submit failed: {exc}")

    # ------------------------------------------------------------------
    # Wave-1 ops drawers — vault crypto, signature updates, EICAR
    # validation, cache + worker pool stats
    # ------------------------------------------------------------------

    def open_vault_drawer(self) -> None:
        """Cryptographic vault drawer.

        The vault stores quarantined samples encrypted with AES-256-GCM
        and signed with HMAC-SHA256. This drawer surfaces the three
        crypto-grade operations the legacy `Quarantine` drawer doesn't
        offer:
          * **Verify** — re-compute the HMAC + AEAD tag and confirm the
            ciphertext on disk matches what the catalogue expects. An
            analyst should run this before unsealing a sample weeks
            after detection.
          * **Unseal** — decrypt to a destination path inside an
            approved scan root. Admin-only + dangerous-actions gate +
            enterprise approval at the API layer.
          * **Delete** — purge the ciphertext and catalogue row. Admin-
            only. Use after evidence chain documentation closes the
            case."""
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QMessageBox
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Vault entries table.
        vault_table = QTableWidget(0, 8)
        vault_table.setHorizontalHeaderLabels(
            ["File ID", "Created", "Original Path", "SHA-256", "Size (KB)", "Severity", "Status", "Actor"]
        )
        app._style_table(vault_table)
        header = vault_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeToContents)
        vault_table.verticalHeader().setVisible(False)
        layout.addWidget(app._panel_card("Sealed Samples", vault_table,
            lambda: app._open_panel_window("Vault Inventory", app._clone_table(vault_table))), 1)

        # Action row — verify / unseal / delete + status pill.
        actions = QHBoxLayout(); actions.setSpacing(6)
        verify_btn = QPushButton("Verify HMAC")
        unseal_btn = QPushButton("Unseal…")
        unseal_btn.setStyleSheet(
            "QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;"
            "padding:5px 14px;font-weight:700;}"
        )
        delete_btn = QPushButton("Delete (purge)")
        delete_btn.setStyleSheet(
            "QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;"
            "padding:5px 14px;font-weight:700;}"
        )
        actions.addWidget(verify_btn)
        actions.addWidget(unseal_btn)
        actions.addWidget(delete_btn)
        actions.addStretch(1)
        vault_status_label = QLabel("loading…"); vault_status_label.setStyleSheet("color:#96a5b8;font-size:11px;")
        actions.addWidget(vault_status_label)
        layout.addLayout(actions)

        # Result panel.
        result_view = QTextBrowser(); result_view.setMinimumHeight(150); result_view.setMaximumHeight(220)
        result_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}")
        result_view.setHtml("<p style='color:#96a5b8;font-size:12px;'>Select a sealed sample, then verify, unseal, or purge.</p>")
        layout.addWidget(app._panel_card("Operation Result", result_view, None))

        state = {"entries": [], "selected_file_id": ""}

        def _refresh_vault() -> None:
            try:
                resp = app._get("/antivirus/vault", timeout=15).json()
            except Exception as exc:
                vault_status_label.setText(f"load failed: {exc}")
                return
            rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            vault_meta = resp.get("vault", {}) if isinstance(resp.get("vault"), dict) else {}
            state["entries"] = rows
            vault_table.setRowCount(len(rows))
            for row, entry in enumerate(rows):
                created = float(entry.get("created_at", 0) or 0)
                created_str = datetime.fromtimestamp(created).strftime("%Y-%m-%d %H:%M") if created else "-"
                size_kb = max(0, int(entry.get("size_bytes", 0) or 0) // 1024)
                cells = [
                    str(entry.get("file_id", ""))[:12],
                    created_str,
                    str(entry.get("original_path", "")),
                    str(entry.get("sha256", ""))[:16] + "…" if entry.get("sha256") else "-",
                    str(size_kb),
                    str(entry.get("severity", "") or "-"),
                    str(entry.get("status", "")),
                    str(entry.get("actor", "") or "-"),
                ]
                for col, value in enumerate(cells):
                    vault_table.setItem(row, col, QTableWidgetItem(str(value)))
                # Severity colour coding.
                tint = "high" if str(entry.get("severity", "")).lower() in {"critical", "high"} else "medium" if str(entry.get("severity", "")).lower() == "medium" else "low"
                app._paint_row(vault_table, row, app._severity_color(tint))
            vault_status_label.setText(
                f"sealed: {vault_meta.get('sealed_count', len(rows))} · purged: {vault_meta.get('purged_count', 0)}"
            )

        def _on_select() -> None:
            row = vault_table.currentRow()
            if 0 <= row < len(state["entries"]):
                state["selected_file_id"] = str(state["entries"][row].get("file_id", ""))
        vault_table.itemSelectionChanged.connect(_on_select)

        def _show_result(html_payload: str) -> None:
            result_view.setHtml(html_payload)

        def _verify() -> None:
            fid = state.get("selected_file_id", "")
            if not fid:
                app.statusBar().showMessage("Select a sealed sample first")
                return
            try:
                resp = app._post(f"/antivirus/vault/{fid}/verify", json={}, timeout=20).json()
            except Exception as exc:
                _show_result(f"<p style='color:#ff8b8b;'><b>Verify failed:</b> {html.escape(str(exc))}</p>")
                return
            res = resp.get("result", resp) if isinstance(resp, dict) else {}
            ok = bool(res.get("ok"))
            colour = "#7bd389" if ok else "#ff8b8b"
            _show_result(
                f"<h3 style='color:{colour};margin:6px 0;'>Verify {'✓ PASS' if ok else '✗ FAIL'}</h3>"
                f"<p><b>file_id:</b> {html.escape(fid[:24])}</p>"
                f"<p><b>sha256:</b> {html.escape(str(res.get('sha256', '-')))}</p>"
                f"<p><b>checks:</b> hmac={res.get('hmac_ok', '-')} · aead={res.get('aead_ok', '-')}"
                f" · catalogue={res.get('catalogue_ok', '-')}</p>"
                + (f"<p style='color:#ff8b8b;'><b>reason:</b> {html.escape(str(res.get('reason', '')))}</p>" if not ok else "")
            )

        def _unseal() -> None:
            fid = state.get("selected_file_id", "")
            if not fid:
                app.statusBar().showMessage("Select a sealed sample first")
                return
            confirm = QMessageBox(app)
            confirm.setWindowTitle("Confirm unseal")
            confirm.setText("Unseal this sample to disk?")
            confirm.setInformativeText(
                "The decrypted file will be written to a destination path inside an approved scan root.\n\n"
                "Make sure host AV exclusions are in place — Defender will likely quarantine an unsealed malicious sample on contact."
            )
            confirm.setIcon(QMessageBox.Warning)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            if confirm.exec() != QMessageBox.Ok:
                return
            destination, _ = QFileDialog.getSaveFileName(app, "Unseal destination", str(self.app.base_dir if hasattr(self.app, "base_dir") else "."))
            if not destination:
                return
            try:
                resp = app._post(f"/antivirus/vault/{fid}/unseal", json={"destination_path": destination}, timeout=30).json()
            except Exception as exc:
                _show_result(f"<p style='color:#ff8b8b;'><b>Unseal failed:</b> {html.escape(str(exc))}</p>")
                return
            res = resp.get("result", resp) if isinstance(resp, dict) else {}
            ok = bool(res.get("ok"))
            colour = "#7bd389" if ok else "#ff8b8b"
            _show_result(
                f"<h3 style='color:{colour};margin:6px 0;'>Unseal {'✓ OK' if ok else '✗ FAIL'}</h3>"
                f"<p><b>file_id:</b> {html.escape(fid[:24])}</p>"
                f"<p><b>destination:</b> {html.escape(str(res.get('destination_path', destination)))}</p>"
                f"<p><b>bytes:</b> {res.get('bytes_written', '-')}</p>"
                + (f"<p style='color:#ff8b8b;'><b>reason:</b> {html.escape(str(res.get('reason', '')))}</p>" if not ok else "")
            )
            _refresh_vault()

        def _delete() -> None:
            fid = state.get("selected_file_id", "")
            if not fid:
                app.statusBar().showMessage("Select a sealed sample first")
                return
            confirm = QMessageBox(app)
            confirm.setWindowTitle("Confirm delete")
            confirm.setText("Permanently purge this sealed sample?")
            confirm.setInformativeText("Ciphertext and catalogue row will be removed. This cannot be undone.")
            confirm.setIcon(QMessageBox.Critical)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Yes)
            if confirm.exec() != QMessageBox.Yes:
                return
            try:
                resp = app._delete(f"/antivirus/vault/{fid}", timeout=20).json()
            except Exception as exc:
                _show_result(f"<p style='color:#ff8b8b;'><b>Delete failed:</b> {html.escape(str(exc))}</p>")
                return
            res = resp.get("result", resp) if isinstance(resp, dict) else {}
            ok = bool(res.get("ok"))
            colour = "#7bd389" if ok else "#ff8b8b"
            _show_result(
                f"<h3 style='color:{colour};margin:6px 0;'>Delete {'✓ OK' if ok else '✗ FAIL'}</h3>"
                f"<p><b>file_id:</b> {html.escape(fid[:24])}</p>"
                + (f"<p style='color:#ff8b8b;'><b>reason:</b> {html.escape(str(res.get('reason', '')))}</p>" if not ok else "")
            )
            _refresh_vault()

        verify_btn.clicked.connect(_verify)
        unseal_btn.clicked.connect(_unseal)
        delete_btn.clicked.connect(_delete)

        timer = QTimer(body); timer.setInterval(5000); timer.timeout.connect(_refresh_vault); timer.start()
        _refresh_vault()
        self._open_drawer("vault", "Cryptographic Vault", body, width=1180, height=620)

    def open_signatures_drawer(self) -> None:
        """Signature update drawer.

        Triggers `freshclam` (or another provider's update routine) and
        shows the rolling history of update attempts. Real EDR consoles
        give analysts the same view: when did each engine last refresh,
        how many files changed, did the run succeed or time out."""
        from PySide6.QtCore import QTimer
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Action card — provider picker + Update Now.
        action_card = QFrame(); action_card.setProperty("card", True)
        action_layout = QHBoxLayout(action_card)
        action_layout.setContentsMargins(10, 8, 10, 8); action_layout.setSpacing(8)
        action_layout.addWidget(QLabel("Provider:"))
        provider_combo = QComboBox()
        provider_combo.addItems(["sentinel_cli", "aegis_core", "yara_x"])
        action_layout.addWidget(provider_combo)
        update_btn = QPushButton("▸ Update now")
        update_btn.setStyleSheet(
            "QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;"
            "padding:5px 14px;font-weight:700;}"
        )
        action_layout.addWidget(update_btn)
        action_layout.addStretch(1)
        action_state = QLabel("idle"); action_state.setStyleSheet("color:#96a5b8;font-size:11px;")
        action_layout.addWidget(action_state)
        layout.addWidget(action_card)

        # History table.
        hist_table = QTableWidget(0, 6)
        hist_table.setHorizontalHeaderLabels(["Started", "Provider", "Status", "Files Changed", "Trigger", "Message"])
        app._style_table(hist_table)
        header = hist_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.Stretch)
        hist_table.verticalHeader().setVisible(False)
        layout.addWidget(app._panel_card("Update History (last 25)", hist_table,
            lambda: app._open_panel_window("Signature Update History", app._clone_table(hist_table))), 1)

        def _refresh_history() -> None:
            try:
                resp = app._get("/antivirus/signatures/history", params={"limit": 25}, timeout=15).json()
            except Exception as exc:
                action_state.setText(f"history load failed: {exc}")
                return
            rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            hist_table.setRowCount(len(rows))
            for row, item in enumerate(rows):
                started = float(item.get("started_at", 0) or 0)
                started_str = datetime.fromtimestamp(started).strftime("%Y-%m-%d %H:%M:%S") if started else "-"
                cells = [
                    started_str,
                    str(item.get("provider_key", "")),
                    str(item.get("status", "")),
                    str(item.get("files_changed", 0)),
                    str(item.get("trigger", "")),
                    str(item.get("message", ""))[:120],
                ]
                for col, value in enumerate(cells):
                    hist_table.setItem(row, col, QTableWidgetItem(str(value)))
                status_low = str(item.get("status", "")).lower()
                tint = "high" if status_low == "error" else "low" if status_low in {"ok", "complete", "success"} else "medium"
                app._paint_row(hist_table, row, app._severity_color(tint))

        def _trigger_update() -> None:
            provider_key = provider_combo.currentText()
            update_btn.setEnabled(False)
            action_state.setText(f"running freshclam against {provider_key}…")
            try:
                resp = app._post("/antivirus/signatures/update", json={"provider_key": provider_key}, timeout=120).json()
                result = resp.get("result", resp) if isinstance(resp, dict) else {}
                action_state.setText(
                    f"{provider_key}: {result.get('status', '?')} · files_changed={result.get('files_changed', 0)} · {str(result.get('message', ''))[:80]}"
                )
            except Exception as exc:
                action_state.setText(f"update failed: {exc}")
            finally:
                update_btn.setEnabled(True)
            _refresh_history()
        update_btn.clicked.connect(_trigger_update)

        timer = QTimer(body); timer.setInterval(5000); timer.timeout.connect(_refresh_history); timer.start()
        _refresh_history()
        self._open_drawer("signatures", "Signature Updates", body, width=1080, height=560)

    def open_eicar_drawer(self) -> None:
        """EICAR validation drawer — engine-by-engine catch matrix.

        EICAR is the standard non-malicious file every commercial AV
        engine signed for. Running it through the fused pipeline answers
        the SLO question: "Right now, which engines are *actually*
        catching things, vs. silently degraded?" A real EDR console
        surfaces this so an operator can spot a quiet failure (Sentinel
        CLI ready=true but EICAR slips through → freshclam stale)."""
        from PySide6.QtCore import QTimer
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Run row.
        run_card = QFrame(); run_card.setProperty("card", True)
        run_layout = QHBoxLayout(run_card)
        run_layout.setContentsMargins(10, 8, 10, 8); run_layout.setSpacing(8)
        run_btn = QPushButton("▸ Run EICAR validation")
        run_btn.setStyleSheet(
            "QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;"
            "padding:5px 14px;font-weight:700;}"
        )
        run_layout.addWidget(run_btn)
        run_layout.addStretch(1)
        last_run_label = QLabel("never run"); last_run_label.setStyleSheet("color:#96a5b8;font-size:11px;")
        run_layout.addWidget(last_run_label)
        layout.addWidget(run_card)

        # Catch matrix table — one row per engine, columns track outcome.
        catch_table = QTableWidget(0, 5)
        catch_table.setHorizontalHeaderLabels(["Engine", "Status", "Detection", "Score", "Notes"])
        app._style_table(catch_table)
        header = catch_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        catch_table.verticalHeader().setVisible(False)
        layout.addWidget(app._panel_card("Engine Catch Matrix", catch_table,
            lambda: app._open_panel_window("EICAR Catch Matrix", app._clone_table(catch_table))), 1)

        # Summary banner.
        summary_view = QTextBrowser(); summary_view.setMinimumHeight(120); summary_view.setMaximumHeight(180)
        summary_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}")
        summary_view.setHtml("<p style='color:#96a5b8;font-size:12px;'>Press <b>Run</b> to drop the canonical EICAR string into the scan pipeline and see which engines caught it.</p>")
        layout.addWidget(app._panel_card("Validation Summary", summary_view, None))

        def _render_catch_matrix(report: dict) -> None:
            providers = report.get("providers", {}) if isinstance(report.get("providers"), dict) else {}
            caught_by = set(report.get("caught_by", []) or [])
            sha = str(report.get("sha256", "") or "")
            hash_match = bool(report.get("hash_match"))
            status = str(report.get("status", "") or "?")
            duration_ms = int(report.get("duration_ms", 0) or 0)

            engine_rows = []
            for key, _display, _accent in ALL_PROVIDERS:
                provider_payload = providers.get(key, {}) if isinstance(providers.get(key, {}), dict) else {}
                provider_status = str(provider_payload.get("status", "")).lower()
                detection = str(provider_payload.get("malware_name", "") or "-")
                score = int(provider_payload.get("score", 0) or 0)
                notes_bits = []
                if provider_payload.get("error"):
                    notes_bits.append(f"error: {str(provider_payload['error'])[:60]}")
                if provider_payload.get("scan_time_ms"):
                    notes_bits.append(f"{provider_payload['scan_time_ms']} ms")
                notes = " · ".join(notes_bits) or "-"
                engine_rows.append((PROVIDER_KEY_TO_DISPLAY[key], provider_status or "skipped", detection, score, notes, key in caught_by))
            catch_table.setRowCount(len(engine_rows))
            for row, (display, st, det, sc, notes, caught) in enumerate(engine_rows):
                cells = [display, st, det, str(sc), notes]
                for col, value in enumerate(cells):
                    catch_table.setItem(row, col, QTableWidgetItem(str(value)))
                tint = "low" if caught else "medium" if st in {"clean", "skipped"} else "high"
                app._paint_row(catch_table, row, app._severity_color(tint))

            caught_count = len(caught_by)
            total_engines = sum(1 for k, *_ in ALL_PROVIDERS)
            colour = "#7bd389" if caught_count >= 1 else "#ff8b8b"
            summary_view.setHtml(
                f"<h3 style='color:{colour};margin:6px 0;'>EICAR run — {status}</h3>"
                f"<p><b>Caught by {caught_count}/{total_engines} engines:</b> {html.escape(', '.join(sorted(caught_by)) or '— none —')}</p>"
                f"<p><b>SHA-256:</b> {html.escape(sha)} | <b>hash_match:</b> {hash_match}</p>"
                f"<p><b>Duration:</b> {duration_ms} ms</p>"
                + ("" if caught_count >= 1 else "<p style='color:#ff8b8b;'>⚠ No engine caught EICAR. At least one local engine should — investigate degraded providers.</p>")
            )
            last_run_label.setText(datetime.now().strftime("Last run: %Y-%m-%d %H:%M:%S"))

        def _run_eicar() -> None:
            run_btn.setEnabled(False)
            last_run_label.setText("running…")
            try:
                resp = app._post("/antivirus/validation/eicar", json={}, timeout=60).json()
                report = resp.get("validation", resp) if isinstance(resp, dict) else {}
                _render_catch_matrix(report)
            except Exception as exc:
                summary_view.setHtml(f"<p style='color:#ff8b8b;'><b>EICAR run failed:</b> {html.escape(str(exc))}</p>")
                last_run_label.setText(f"failed: {exc}")
            finally:
                run_btn.setEnabled(True)
        run_btn.clicked.connect(_run_eicar)

        self._open_drawer("eicar", "EICAR Validation", body, width=1080, height=620)

    def open_stats_drawer(self) -> None:
        """Operations stats drawer — verdict cache + worker pool + vault + signature updater snapshot."""
        from PySide6.QtCore import QTimer
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # 4 KPI tiles for the most operationally useful counters.
        kpi_row = QHBoxLayout(); kpi_row.setSpacing(8)
        def _tile(title: str, accent: str) -> tuple[QWidget, QLabel, QLabel]:
            tile = QFrame(); tile.setProperty("card", True)
            tile.setStyleSheet("QFrame{background:#121b27;border:1px solid #2c4260;border-radius:9px;}")
            tile.setMinimumHeight(72); tile.setMaximumHeight(86)
            tl = QVBoxLayout(tile); tl.setContentsMargins(12, 6, 12, 6); tl.setSpacing(2)
            heading = QLabel(title); heading.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:700;letter-spacing:0.5px;")
            value = QLabel("--"); value.setStyleSheet(f"color:{accent};font-size:20px;font-weight:800;")
            sub = QLabel(""); sub.setStyleSheet("color:#7e91a8;font-size:10px;"); sub.setMinimumHeight(12)
            tl.addWidget(heading); tl.addWidget(value); tl.addWidget(sub)
            return tile, value, sub
        cache_tile, cache_value, cache_sub = _tile("CACHE", "#9fd0ff")
        pool_tile, pool_value, pool_sub = _tile("WORKER POOL", "#bda4ff")
        vault_tile, vault_value, vault_sub = _tile("VAULT", "#ff9f6b")
        sig_tile, sig_value, sig_sub = _tile("SIGNATURES", "#7bd389")
        for t in [cache_tile, pool_tile, vault_tile, sig_tile]:
            kpi_row.addWidget(t, 1)
        layout.addLayout(kpi_row)

        # Detail panel — full JSON snapshot.
        detail_view = QTextBrowser(); detail_view.setMinimumHeight(280)
        detail_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}")
        layout.addWidget(app._panel_card("Full Snapshot", detail_view,
            lambda: app._open_panel_window("Antivirus Stats Snapshot", app._clone_text_view(detail_view))), 1)

        def _refresh_stats() -> None:
            try:
                resp = app._get("/antivirus/stats", timeout=10).json()
            except Exception as exc:
                detail_view.setHtml(f"<p style='color:#ff8b8b;'>Stats load failed: {html.escape(str(exc))}</p>")
                return
            stats = resp.get("stats", {}) if isinstance(resp.get("stats"), dict) else {}
            cache = stats.get("cache", {}) if isinstance(stats.get("cache"), dict) else {}
            pool = stats.get("worker_pool", {}) if isinstance(stats.get("worker_pool"), dict) else {}
            vault = stats.get("vault", {}) if isinstance(stats.get("vault"), dict) else {}
            sig = stats.get("signature_updater", {}) if isinstance(stats.get("signature_updater"), dict) else {}

            # Cache KPI.
            db_live = int(cache.get("db_live", 0) or 0)
            mem_live = int(cache.get("memory_live", 0) or 0)
            ttl = int(cache.get("ttl_seconds", 0) or 0)
            cache_value.setText(f"{db_live + mem_live}")
            cache_sub.setText(f"db={db_live} · mem={mem_live} · ttl={ttl}s")

            # Worker pool KPI.
            running = int(pool.get("running", 0) or 0)
            pending = int(pool.get("pending", 0) or 0)
            max_workers = int(pool.get("max_workers", 0) or 0)
            pool_value.setText(f"{running}/{max_workers}")
            pool_sub.setText(f"pending: {pending}")

            # Vault KPI.
            vault_value.setText(str(vault.get("sealed_count", 0) or 0))
            purged = int(vault.get("purged_count", 0) or 0)
            vault_sub.setText(f"purged: {purged}")

            # Signature KPI — last update wallclock.
            last_update = float(sig.get("latest_update_at", 0) or 0)
            if last_update > 0:
                age_min = max(0, int((datetime.now().timestamp() - last_update) // 60))
                if age_min < 60:
                    sig_value.setText(f"{age_min}m")
                elif age_min < 60 * 24:
                    sig_value.setText(f"{age_min//60}h")
                else:
                    sig_value.setText(f"{age_min//(60*24)}d")
            else:
                sig_value.setText("—")
            sig_sub.setText(f"updates: {int(sig.get('total_runs', 0) or 0)}")

            # JSON pretty print.
            detail_view.setHtml(
                "<h3 style='color:#bda4ff;margin:6px 0;'>Antivirus Stats Snapshot</h3>"
                "<pre style='color:#c8d8ea;font-family:Consolas,monospace;font-size:11px;'>"
                + html.escape(json.dumps(stats, indent=2, ensure_ascii=False))
                + "</pre>"
            )

        timer = QTimer(body); timer.setInterval(2000); timer.timeout.connect(_refresh_stats); timer.start()
        _refresh_stats()
        self._open_drawer("stats", "Antivirus Operations Stats", body, width=1100, height=640)

    # ------------------------------------------------------------------
    # Wave-3 ops drawers — async jobs, folder watcher, webhooks
    # ------------------------------------------------------------------

    def open_jobs_drawer(self) -> None:
        """Async scan job queue drawer.

        Lists every submission with state / progress / age, lets the
        analyst cancel queued or running jobs, and refreshes itself off
        a 1-second QTimer (no WebSocket needed for in-process desktop —
        polling /antivirus/jobs is simpler and just as snappy)."""
        from PySide6.QtCore import QTimer
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Submit row — analyst can fire an async scan from here too.
        submit_card = QFrame(); submit_card.setProperty("card", True)
        submit_layout = QHBoxLayout(submit_card)
        submit_layout.setContentsMargins(10, 8, 10, 8); submit_layout.setSpacing(6)
        submit_layout.addWidget(QLabel("Submit async scan:"))
        target_input = QLineEdit(app.antivirus_target_path.text())
        target_input.setPlaceholderText("Absolute file path…")
        submit_layout.addWidget(target_input, 3)
        submit_btn = QPushButton("Submit"); submit_btn.setStyleSheet(
            "QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}"
        )
        submit_layout.addWidget(submit_btn)
        layout.addWidget(submit_card)

        # Jobs table.
        jobs_table = QTableWidget(0, 7)
        jobs_table.setHorizontalHeaderLabels(["Job ID", "Submitted", "Target", "Actor", "State", "Progress", "Duration"])
        app._style_table(jobs_table)
        header = jobs_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        jobs_table.verticalHeader().setVisible(False)
        layout.addWidget(app._panel_card("Async Scan Jobs", jobs_table,
            lambda: app._open_panel_window("Async Scan Jobs", app._clone_table(jobs_table))), 1)

        # Action row — cancel selected.
        actions = QHBoxLayout(); actions.setSpacing(6)
        cancel_btn = QPushButton("Cancel selected")
        actions.addWidget(cancel_btn)
        stats_label = QLabel(""); stats_label.setStyleSheet("color:#96a5b8;font-size:11px;")
        actions.addStretch(1)
        actions.addWidget(stats_label)
        layout.addLayout(actions)

        # State holders (avoid late-binding issues with closures).
        state = {"jobs": [], "selected_job_id": ""}

        def _refresh_jobs() -> None:
            try:
                resp = app._get("/antivirus/jobs", params={"limit": 100}, timeout=10).json()
            except Exception:
                return
            rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            stats = resp.get("stats", {}) if isinstance(resp.get("stats"), dict) else {}
            state["jobs"] = rows
            jobs_table.setRowCount(len(rows))
            for row, job in enumerate(rows):
                duration_ms = int(job.get("duration_ms", 0) or 0)
                duration = f"{duration_ms} ms" if duration_ms else "-"
                cells = [
                    str(job.get("job_id", ""))[:12],
                    datetime.fromtimestamp(float(job.get("submitted_at", 0) or 0)).strftime("%H:%M:%S") if job.get("submitted_at") else "-",
                    Path(str(job.get("target_path", ""))).name or "-",
                    str(job.get("actor", "")) or "-",
                    str(job.get("state", "")),
                    f"{int(job.get('progress', 0) or 0)}%",
                    duration,
                ]
                for col, value in enumerate(cells):
                    jobs_table.setItem(row, col, QTableWidgetItem(str(value)))
                # Severity-style row tint by state.
                state_low = str(job.get("state", "")).lower()
                tint = "high" if state_low == "error" else "medium" if state_low in {"running", "cancelling"} else "low"
                app._paint_row(jobs_table, row, app._severity_color(tint))
            by_state = stats.get("by_state", {}) if isinstance(stats.get("by_state"), dict) else {}
            stats_label.setText(" · ".join(f"{k}: {v}" for k, v in sorted(by_state.items())) or "no jobs")

        def _on_select() -> None:
            row = jobs_table.currentRow()
            if 0 <= row < len(state["jobs"]):
                state["selected_job_id"] = str(state["jobs"][row].get("job_id", ""))
        jobs_table.itemSelectionChanged.connect(_on_select)

        def _cancel_selected() -> None:
            jid = state.get("selected_job_id", "")
            if not jid:
                app.statusBar().showMessage("Select a job row first")
                return
            try:
                app._post(f"/antivirus/jobs/{jid}/cancel", json={}, timeout=10)
                app.statusBar().showMessage(f"Cancel requested for {jid[:12]}")
            except Exception as exc:
                app.statusBar().showMessage(f"Cancel failed: {exc}")
            _refresh_jobs()
        cancel_btn.clicked.connect(_cancel_selected)

        def _submit_async() -> None:
            target = target_input.text().strip()
            if not target:
                app.statusBar().showMessage("Provide a file path first")
                return
            try:
                resp = app._post("/antivirus/scan/file/async", json={"file_path": target}, timeout=15).json()
                jid = resp.get("job", {}).get("job_id", "")
                app.statusBar().showMessage(f"Queued async scan {jid[:12]}")
            except Exception as exc:
                app.statusBar().showMessage(f"Submit failed: {exc}")
            _refresh_jobs()
        submit_btn.clicked.connect(_submit_async)

        # 1 Hz auto-refresh while drawer is open. Owned by the drawer
        # widget so it dies when the drawer closes.
        timer = QTimer(body)
        timer.setInterval(1000)
        timer.timeout.connect(_refresh_jobs)
        timer.start()
        _refresh_jobs()

        self._open_drawer("jobs", "Async Scan Jobs", body, width=1080, height=560)

    def open_folder_watcher_drawer(self) -> None:
        """On-access folder watcher drawer — paths config + start/stop + stats."""
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Config card — paths textarea + max size + workspace.
        config_card = QFrame(); config_card.setProperty("card", True)
        config_layout = QGridLayout(config_card)
        config_layout.setContentsMargins(10, 8, 10, 8)
        config_layout.setHorizontalSpacing(8); config_layout.setVerticalSpacing(6)
        config_layout.addWidget(QLabel("Watched paths (one per line):"), 0, 0, 1, 4)
        paths_edit = QTextEdit(); paths_edit.setMaximumHeight(110)
        paths_edit.setPlaceholderText("C:\\Users\\Public\\Downloads\nC:\\Temp")
        config_layout.addWidget(paths_edit, 1, 0, 1, 4)
        config_layout.addWidget(QLabel("Max file size (MB):"), 2, 0)
        size_input = QSpinBox(); size_input.setRange(1, 2048); size_input.setValue(128)
        config_layout.addWidget(size_input, 2, 1)
        config_layout.addWidget(QLabel("Workspace:"), 2, 2)
        ws_input = QLineEdit(app.workspace_id.text() or "default")
        config_layout.addWidget(ws_input, 2, 3)
        layout.addWidget(config_card)

        # Action row — Configure / Start / Stop + status pill.
        actions = QHBoxLayout(); actions.setSpacing(6)
        configure_btn = QPushButton("Save Config")
        start_btn = QPushButton("▸ Start")
        start_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}")
        stop_btn = QPushButton("◼ Stop")
        stop_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:5px 14px;font-weight:700;}")
        actions.addWidget(configure_btn)
        actions.addWidget(start_btn)
        actions.addWidget(stop_btn)
        actions.addStretch(1)
        running_pill = QLabel("loading…"); running_pill.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:700;")
        actions.addWidget(running_pill)
        layout.addLayout(actions)

        # Stats panel.
        stats_view = QTextBrowser()
        stats_view.setMinimumHeight(220)
        stats_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;}")
        layout.addWidget(app._panel_card("Watcher Status", stats_view,
            lambda: app._open_panel_window("Folder Watcher Status", app._clone_text_view(stats_view))), 1)

        def _render_status(payload: dict) -> None:
            watcher = payload.get("watcher", {}) if isinstance(payload, dict) else {}
            running = bool(watcher.get("running"))
            running_pill.setText(("● Running" if running else "○ Stopped"))
            running_pill.setStyleSheet(
                f"color:{'#7bd389' if running else '#96a5b8'};font-size:11px;font-weight:700;padding:4px 10px;"
                "background:#121b27;border:1px solid #2c4260;border-radius:7px;"
            )
            roots = watcher.get("roots", []) or []
            if not paths_edit.toPlainText().strip() and roots:
                paths_edit.setPlainText("\n".join(roots))
            try:
                if int(watcher.get("max_file_size_mb", 0) or 0) > 0:
                    size_input.setValue(int(watcher["max_file_size_mb"]))
            except Exception:
                pass
            stats = watcher.get("stats", {}) or {}
            last_tick = float(stats.get("last_tick_at", 0) or 0)
            last_tick_str = datetime.fromtimestamp(last_tick).strftime("%Y-%m-%d %H:%M:%S") if last_tick else "never"
            stats_view.setHtml(
                "<h3 style='color:#bda4ff;margin:6px 0;'>Folder Watcher</h3>"
                f"<p><b>Workspace:</b> {html.escape(str(watcher.get('workspace_id', '-')))}"
                f" | <b>Tracked paths:</b> {watcher.get('tracked_paths', 0)}"
                f" | <b>Poll interval:</b> {watcher.get('poll_interval_seconds', '-')} s"
                f" | <b>Quiet period:</b> {watcher.get('quiet_period_seconds', '-')} s</p>"
                f"<p><b>Last tick:</b> {html.escape(last_tick_str)}"
                f" | <b>Ticks:</b> {stats.get('ticks', 0)}"
                f" | <b>Files seen:</b> {stats.get('files_seen', 0)}"
                f" | <b>Submitted:</b> {stats.get('files_submitted', 0)}"
                f" | <b>Skipped (size):</b> {stats.get('files_skipped_size', 0)}"
                f" | <b>Skipped (quiet):</b> {stats.get('files_skipped_quiet', 0)}</p>"
                + (f"<p style='color:#ff9ab0;'><b>Last error:</b> {html.escape(str(stats.get('last_error', '')))}</p>" if stats.get("last_error") else "")
            )

        def _refresh_status() -> None:
            try:
                resp = app._get("/antivirus/folder-watcher/status", timeout=10).json()
                _render_status(resp)
            except Exception as exc:
                stats_view.setHtml(f"<p style='color:#ff9ab0;'>Status load failed: {html.escape(str(exc))}</p>")

        def _save_config() -> None:
            paths = [line.strip() for line in paths_edit.toPlainText().splitlines() if line.strip()]
            payload = {
                "paths": paths,
                "workspace_id": ws_input.text().strip() or "default",
                "max_file_size_mb": int(size_input.value()),
            }
            try:
                resp = app._post("/antivirus/folder-watcher/configure", json=payload, timeout=10).json()
                _render_status(resp)
                app.statusBar().showMessage("Folder watcher configuration saved.")
            except Exception as exc:
                app.statusBar().showMessage(f"Configure failed: {exc}")

        def _start_watcher() -> None:
            try:
                resp = app._post("/antivirus/folder-watcher/start", json={}, timeout=10).json()
                _render_status(resp)
                app.statusBar().showMessage("Folder watcher started.")
            except Exception as exc:
                app.statusBar().showMessage(f"Start failed: {exc}")

        def _stop_watcher() -> None:
            try:
                resp = app._post("/antivirus/folder-watcher/stop", json={}, timeout=10).json()
                _render_status(resp)
                app.statusBar().showMessage("Folder watcher stopped.")
            except Exception as exc:
                app.statusBar().showMessage(f"Stop failed: {exc}")

        configure_btn.clicked.connect(_save_config)
        start_btn.clicked.connect(_start_watcher)
        stop_btn.clicked.connect(_stop_watcher)

        from PySide6.QtCore import QTimer
        timer = QTimer(body); timer.setInterval(2000); timer.timeout.connect(_refresh_status); timer.start()
        _refresh_status()
        self._open_drawer("watcher", "On-Access Folder Watcher", body, width=900, height=620)

    def open_webhooks_drawer(self) -> None:
        """Webhook deliveries + DLQ + secret rotation drawer."""
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # Secret card — show fingerprint, rotate button.
        secret_card = QFrame(); secret_card.setProperty("card", True)
        secret_layout = QHBoxLayout(secret_card)
        secret_layout.setContentsMargins(10, 8, 10, 8); secret_layout.setSpacing(8)
        secret_layout.addWidget(QLabel("<b>Active HMAC secret:</b>"))
        secret_label = QLabel("loading…"); secret_label.setStyleSheet("color:#bda4ff;font-family:monospace;")
        secret_layout.addWidget(secret_label, 1)
        rotate_btn = QPushButton("Rotate")
        rotate_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:5px 14px;font-weight:700;}")
        secret_layout.addWidget(rotate_btn)
        layout.addWidget(secret_card)

        # Test-send card.
        test_card = QFrame(); test_card.setProperty("card", True)
        test_layout = QHBoxLayout(test_card)
        test_layout.setContentsMargins(10, 8, 10, 8); test_layout.setSpacing(6)
        test_layout.addWidget(QLabel("Target URL:"))
        url_input = QLineEdit(app.webhook_url.text().strip())
        url_input.setPlaceholderText("https://example.test/hook")
        test_layout.addWidget(url_input, 3)
        send_btn = QPushButton("Test send")
        send_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}")
        test_layout.addWidget(send_btn)
        layout.addWidget(test_card)

        # Tabs — Deliveries / DLQ.
        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        # Deliveries tab.
        del_widget = QWidget(); del_layout = QVBoxLayout(del_widget); del_layout.setContentsMargins(4, 4, 4, 4)
        del_table = QTableWidget(0, 7)
        del_table.setHorizontalHeaderLabels(["Delivery ID", "Created", "Event", "Target", "Status", "State", "Attempts"])
        app._style_table(del_table)
        del_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        del_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        del_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        del_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        del_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        del_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        del_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeToContents)
        del_table.verticalHeader().setVisible(False)
        del_layout.addWidget(del_table, 1)
        tabs.addTab(del_widget, "Deliveries")

        # DLQ tab.
        dlq_widget = QWidget(); dlq_layout = QVBoxLayout(dlq_widget); dlq_layout.setContentsMargins(4, 4, 4, 4)
        dlq_table = QTableWidget(0, 7)
        dlq_table.setHorizontalHeaderLabels(["Delivery ID", "Created", "Event", "Target", "Status", "Attempts", "Last error"])
        app._style_table(dlq_table)
        dlq_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        dlq_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        dlq_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        dlq_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        dlq_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        dlq_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeToContents)
        dlq_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        dlq_table.verticalHeader().setVisible(False)
        dlq_layout.addWidget(dlq_table, 1)
        dlq_actions = QHBoxLayout(); dlq_actions.setSpacing(6)
        replay_btn = QPushButton("Replay selected")
        dlq_actions.addWidget(replay_btn); dlq_actions.addStretch(1)
        dlq_layout.addLayout(dlq_actions)
        tabs.addTab(dlq_widget, "Dead-Letter Queue")

        layout.addWidget(tabs, 1)

        # State holders.
        state = {"selected_dlq_id": ""}

        def _refresh_secret() -> None:
            try:
                resp = app._get("/webhooks/secret", timeout=10).json()
                if resp.get("configured"):
                    secret_label.setText(f"id={resp.get('secret_id', '?')[:8]} · fp=…{resp.get('secret_fingerprint', '????')}")
                else:
                    secret_label.setText("not configured (auto-provisions on first send)")
            except Exception as exc:
                secret_label.setText(f"load failed: {exc}")

        def _rotate_secret() -> None:
            try:
                resp = app._post("/webhooks/secret/rotate", json={"workspace_id": app.workspace_id.text().strip() or "default"}, timeout=10).json()
                # Show the raw secret ONCE in a popup-style status — the
                # API never echoes it again, so the operator must save it now.
                from PySide6.QtWidgets import QMessageBox
                box = QMessageBox(app)
                box.setWindowTitle("Webhook secret rotated")
                box.setText("Save this secret now — it is only shown once.")
                box.setInformativeText(f"secret_id: {resp.get('secret_id', '')}\n\nsecret: {resp.get('secret', '')}")
                box.setIcon(QMessageBox.Information)
                box.exec()
                _refresh_secret()
            except Exception as exc:
                app.statusBar().showMessage(f"Rotate failed: {exc}")

        def _test_send() -> None:
            target = url_input.text().strip()
            if not target:
                app.statusBar().showMessage("Provide a target URL first")
                return
            try:
                resp = app._post("/webhooks/test", json={
                    "target_url": target,
                    "event_type": "test.from_desktop",
                    "payload": {"shadowlab": "manual_test", "ts": datetime.now().isoformat()},
                }, timeout=15).json()
                state_text = resp.get("state", "?")
                code = resp.get("status_code", 0)
                app.statusBar().showMessage(f"Test webhook → {state_text} (HTTP {code})")
                _refresh_deliveries()
            except Exception as exc:
                app.statusBar().showMessage(f"Test failed: {exc}")

        def _refresh_deliveries() -> None:
            try:
                resp = app._get("/webhooks/deliveries", params={"limit": 100}, timeout=10).json()
                rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            except Exception:
                return
            del_table.setRowCount(len(rows))
            for row, item in enumerate(rows):
                created = float(item.get("created_at", 0) or 0)
                created_str = datetime.fromtimestamp(created).strftime("%H:%M:%S") if created else "-"
                cells = [
                    str(item.get("delivery_id", ""))[:12],
                    created_str,
                    str(item.get("event_type", "")),
                    str(item.get("target_url", ""))[:60],
                    str(item.get("last_status", "")),
                    str(item.get("state", "")),
                    str(item.get("attempts", 0)),
                ]
                for col, value in enumerate(cells):
                    del_table.setItem(row, col, QTableWidgetItem(str(value)))
                state_low = str(item.get("state", "")).lower()
                tint = "low" if state_low == "delivered" else "medium" if state_low == "retrying" else "high" if state_low == "dlq" else "low"
                app._paint_row(del_table, row, app._severity_color(tint))

        def _refresh_dlq() -> None:
            try:
                resp = app._get("/webhooks/dlq", params={"limit": 100}, timeout=10).json()
                rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            except Exception:
                return
            dlq_table.setRowCount(len(rows))
            for row, item in enumerate(rows):
                created = float(item.get("created_at", 0) or 0)
                created_str = datetime.fromtimestamp(created).strftime("%H:%M:%S") if created else "-"
                cells = [
                    str(item.get("delivery_id", ""))[:12],
                    created_str,
                    str(item.get("event_type", "")),
                    str(item.get("target_url", ""))[:60],
                    str(item.get("last_status", "")),
                    str(item.get("attempts", 0)),
                    str(item.get("last_response_excerpt", ""))[:80],
                ]
                for col, value in enumerate(cells):
                    dlq_table.setItem(row, col, QTableWidgetItem(str(value)))
                app._paint_row(dlq_table, row, app._severity_color("high"))

        def _on_dlq_select() -> None:
            row = dlq_table.currentRow()
            if row < 0:
                return
            item = dlq_table.item(row, 0)
            if item is not None:
                # Need full delivery_id, not the truncated prefix.
                try:
                    resp = app._get("/webhooks/dlq", params={"limit": 100}, timeout=10).json()
                    rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
                    if row < len(rows):
                        state["selected_dlq_id"] = str(rows[row].get("delivery_id", ""))
                except Exception:
                    pass
        dlq_table.itemSelectionChanged.connect(_on_dlq_select)

        def _replay() -> None:
            jid = state.get("selected_dlq_id", "")
            if not jid:
                app.statusBar().showMessage("Select a DLQ row first")
                return
            try:
                resp = app._post(f"/webhooks/dlq/{jid}/replay", json={}, timeout=10).json()
                replayed_id = resp.get("result", {}).get("replayed_as", "")
                app.statusBar().showMessage(f"Replayed → new delivery {replayed_id[:12]}")
                _refresh_dlq(); _refresh_deliveries()
            except Exception as exc:
                app.statusBar().showMessage(f"Replay failed: {exc}")
        replay_btn.clicked.connect(_replay)
        rotate_btn.clicked.connect(_rotate_secret)
        send_btn.clicked.connect(_test_send)

        from PySide6.QtCore import QTimer
        timer = QTimer(body); timer.setInterval(3000)
        def _all_refresh() -> None:
            _refresh_deliveries(); _refresh_dlq()
        timer.timeout.connect(_all_refresh); timer.start()
        _refresh_secret(); _all_refresh()
        self._open_drawer("webhooks", "Webhook Deliveries & DLQ", body, width=1180, height=680)

    # ------------------------------------------------------------------
    # Sprint-5 EDR drawers — Live Response / Custom YARA / Lists
    # ------------------------------------------------------------------

    def open_response_drawer(self) -> None:
        """Live Response drawer.

        4 capability blocks, each operator-grade with a status panel:
          * Kill process by PID (admin + dangerous gate)
          * Network isolation toggle (admin + dangerous + approval)
          * Artifact collection on a PID
          * VSS shadow-copy listing + per-file restore
        Every action surfaces its result in a dedicated text browser
        underneath, so the analyst sees exactly what happened — no
        silent fire-and-forget."""
        from PySide6.QtWidgets import QMessageBox, QFormLayout
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        # --- Kill process block
        kill_card = QFrame(); kill_card.setProperty("card", True)
        kill_layout = QHBoxLayout(kill_card); kill_layout.setContentsMargins(10, 8, 10, 8); kill_layout.setSpacing(6)
        kill_layout.addWidget(QLabel("PID:"))
        pid_input = QSpinBox(); pid_input.setRange(1, 999_999); pid_input.setValue(0)
        kill_layout.addWidget(pid_input)
        force_chk = QCheckBox("Force (skip protected-process check)")
        force_chk.setStyleSheet("color:#ff9ab0;font-size:11px;")
        kill_layout.addWidget(force_chk)
        kill_btn = QPushButton("Kill PID")
        kill_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:5px 14px;font-weight:700;}")
        kill_layout.addWidget(kill_btn)
        kill_layout.addStretch(1)
        layout.addWidget(app._panel_card("Kill Process", kill_card, None))

        # --- Network isolation block
        net_card = QFrame(); net_card.setProperty("card", True)
        net_layout = QHBoxLayout(net_card); net_layout.setContentsMargins(10, 8, 10, 8); net_layout.setSpacing(6)
        net_layout.addWidget(QLabel("Allow management IP:"))
        mgmt_input = QLineEdit("127.0.0.1"); mgmt_input.setMaximumWidth(160)
        net_layout.addWidget(mgmt_input)
        isolate_btn = QPushButton("◼ Isolate")
        isolate_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:5px 14px;font-weight:700;}")
        release_btn = QPushButton("▸ Release")
        release_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}")
        net_layout.addWidget(isolate_btn)
        net_layout.addWidget(release_btn)
        net_layout.addStretch(1)
        layout.addWidget(app._panel_card("Network Containment", net_card, None))

        # --- Artifact collection block
        art_card = QFrame(); art_card.setProperty("card", True)
        art_layout = QHBoxLayout(art_card); art_layout.setContentsMargins(10, 8, 10, 8); art_layout.setSpacing(6)
        art_layout.addWidget(QLabel("PID:"))
        art_pid = QSpinBox(); art_pid.setRange(1, 999_999); art_pid.setValue(0)
        art_layout.addWidget(art_pid)
        collect_btn = QPushButton("Collect Artifacts")
        art_layout.addWidget(collect_btn)
        art_layout.addStretch(1)
        layout.addWidget(app._panel_card("Artifact Collection", art_card, None))

        # --- VSS rollback block
        vss_card = QFrame(); vss_card.setProperty("card", True)
        vss_layout = QGridLayout(vss_card); vss_layout.setContentsMargins(10, 8, 10, 8)
        vss_layout.setHorizontalSpacing(6); vss_layout.setVerticalSpacing(4)
        list_btn = QPushButton("List shadow copies")
        vss_layout.addWidget(list_btn, 0, 0, 1, 2)
        vss_layout.addWidget(QLabel("Shadow volume:"), 1, 0); shadow_input = QLineEdit(); vss_layout.addWidget(shadow_input, 1, 1)
        vss_layout.addWidget(QLabel("Relative path:"),   2, 0); rel_input    = QLineEdit(); vss_layout.addWidget(rel_input, 2, 1)
        vss_layout.addWidget(QLabel("Destination:"),     3, 0); dest_input   = QLineEdit(); vss_layout.addWidget(dest_input, 3, 1)
        restore_btn = QPushButton("Restore from snapshot")
        restore_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}")
        vss_layout.addWidget(restore_btn, 4, 0, 1, 2)
        layout.addWidget(app._panel_card("VSS Rollback (Windows)", vss_card, None))

        # --- Result panel (shared across all action buttons)
        result_view = QTextBrowser()
        result_view.setMinimumHeight(180)
        result_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;font-family:Consolas,monospace;font-size:11px;}")
        result_view.setHtml("<p style='color:#96a5b8;'>Action results will appear here.</p>")
        layout.addWidget(app._panel_card("Result", result_view, None), 1)

        def _show(html_payload: str) -> None:
            result_view.setHtml(html_payload)

        def _kill() -> None:
            pid = int(pid_input.value())
            if pid <= 0:
                _show("<p style='color:#f4c26b;'>⚠ Provide a non-zero PID before requesting termination.</p>")
                return
            if not self._check_response_gate("kill"):
                return
            forcing = bool(force_chk.isChecked())
            confirm = QMessageBox(app)
            confirm.setWindowTitle("Confirm kill")
            confirm.setText(f"Terminate PID {pid}?")
            confirm.setInformativeText(
                "This sends SIGTERM (psutil) or os.kill. Critical OS processes are blocked unless 'Force' is checked.\n"
                + ("⚠ FORCE mode is on — protected-process check is bypassed." if forcing else "")
            )
            confirm.setIcon(QMessageBox.Warning if not forcing else QMessageBox.Critical)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
            if confirm.exec() != QMessageBox.Ok:
                return
            reason = self._capture_reason("kill" if not forcing else "kill --force")
            if reason is None:
                return

            def _on_ok(resp) -> None:
                ok = bool(resp.get("status") == "ok")
                _show(
                    f"<h3 style='color:{'#7bd389' if ok else '#ff8b8b'};'>Kill {'OK' if ok else 'FAIL'}</h3>"
                    f"<p style='color:#96a5b8;'>Reason: {html.escape(reason['reason_summary'])}</p>"
                    f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>"
                )
                self._record_history(
                    category="response",
                    action="kill" + (" --force" if forcing else ""),
                    target=f"PID {pid}",
                    severity="critical" if forcing else "high",
                    status="ok" if ok else "failed",
                    payload=resp,
                    reason=reason,
                )

            def _on_err(message: str) -> None:
                _show(f"<p style='color:#ff8b8b;'><b>Kill failed:</b> {html.escape(message)}</p>")
                self._record_history(
                    category="response",
                    action="kill" + (" --force" if forcing else ""),
                    target=f"PID {pid}",
                    severity="critical" if forcing else "high",
                    status="failed",
                    payload={"error": message},
                    reason=reason,
                )

            self._submit_async(
                f"Kill PID {pid}",
                lambda: app._post("/antivirus/response/kill", json={"pid": pid, "force": forcing}, timeout=15).json(),
                _on_ok,
                _on_err,
                timeout_seconds=20,
            )
        kill_btn.clicked.connect(_kill)

        def _isolate() -> None:
            if not self._check_response_gate("isolate"):
                return
            mgmt_ip = mgmt_input.text().strip() or "127.0.0.1"
            # Client-side IP validation — backend rejects malformed
            # addresses too but a clear UI error beats a 422 stack trace.
            try:
                ipaddress.ip_address(mgmt_ip)
            except ValueError:
                _show(f"<p style='color:#f4c26b;'>⚠ '{html.escape(mgmt_ip)}' is not a valid IP address.</p>")
                return
            confirm = QMessageBox(app)
            confirm.setWindowTitle("Confirm isolate")
            confirm.setText("Sever this host's network plane?")
            confirm.setInformativeText(
                f"All outbound traffic will be blocked except to {mgmt_ip}.\n"
                "Use 'Release' to undo. This action requires a structured response reason."
            )
            confirm.setIcon(QMessageBox.Critical)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Yes)
            if confirm.exec() != QMessageBox.Yes:
                return
            reason = self._capture_reason("isolate")
            if reason is None:
                return

            def _on_ok(resp) -> None:
                ok = bool(resp.get("status") == "ok")
                _show(
                    f"<h3 style='color:{'#7bd389' if ok else '#ff8b8b'};'>Isolate {'OK' if ok else 'FAIL'}</h3>"
                    f"<p style='color:#96a5b8;'>Reason: {html.escape(reason['reason_summary'])}</p>"
                    f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>"
                )
                self._record_history(
                    category="response",
                    action="network-isolate",
                    target=f"mgmt={mgmt_ip}",
                    severity="critical",
                    status="ok" if ok else "failed",
                    payload=resp,
                    reason=reason,
                )

            def _on_err(message: str) -> None:
                _show(f"<p style='color:#ff8b8b;'><b>Isolate failed:</b> {html.escape(message)}</p>")
                self._record_history(
                    category="response",
                    action="network-isolate",
                    target=f"mgmt={mgmt_ip}",
                    severity="critical",
                    status="failed",
                    payload={"error": message},
                    reason=reason,
                )

            self._submit_async(
                "Network isolate",
                lambda: app._post("/antivirus/response/network/isolate", json={"allow_management_ip": mgmt_ip}, timeout=20).json(),
                _on_ok,
                _on_err,
                timeout_seconds=25,
            )
        isolate_btn.clicked.connect(_isolate)

        def _release() -> None:
            if not self._check_response_gate("release"):
                return
            reason = self._capture_reason("release (network)")
            if reason is None:
                return

            def _on_ok(resp) -> None:
                ok = bool(resp.get("status") == "ok")
                _show(
                    f"<h3 style='color:{'#7bd389' if ok else '#ff8b8b'};'>Release {'OK' if ok else 'FAIL'}</h3>"
                    f"<p style='color:#96a5b8;'>Reason: {html.escape(reason['reason_summary'])}</p>"
                    f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>"
                )
                self._record_history(
                    category="response",
                    action="network-release",
                    target="host",
                    severity="high",
                    status="ok" if ok else "failed",
                    payload=resp,
                    reason=reason,
                )

            def _on_err(message: str) -> None:
                _show(f"<p style='color:#ff8b8b;'><b>Release failed:</b> {html.escape(message)}</p>")

            self._submit_async(
                "Network release",
                lambda: app._post("/antivirus/response/network/release", json={}, timeout=15).json(),
                _on_ok,
                _on_err,
                timeout_seconds=20,
            )
        release_btn.clicked.connect(_release)

        def _collect() -> None:
            pid = int(art_pid.value())
            try:
                resp = app._get(f"/antivirus/response/artifacts/{pid}", timeout=20).json()
            except Exception as exc:
                _show(f"<p style='color:#ff8b8b;'><b>Collect failed:</b> {html.escape(str(exc))}</p>"); return
            _show(f"<h3 style='color:#bda4ff;'>Artifacts for PID {pid}</h3>"
                  f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>")
        collect_btn.clicked.connect(_collect)

        def _list_vss() -> None:
            try:
                resp = app._get("/antivirus/response/vss/snapshots", timeout=20).json()
            except Exception as exc:
                _show(f"<p style='color:#ff8b8b;'><b>VSS list failed:</b> {html.escape(str(exc))}</p>"); return
            snapshots = resp.get("result", {}).get("snapshots", [])
            if snapshots:
                shadow_input.setText(str(snapshots[0].get("shadow_volume", "")))
            _show(f"<h3 style='color:#bda4ff;'>{len(snapshots)} shadow copies</h3>"
                  f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>")
        list_btn.clicked.connect(_list_vss)

        def _restore() -> None:
            payload = {
                "shadow_volume": shadow_input.text().strip(),
                "relative_path": rel_input.text().strip(),
                "destination_path": dest_input.text().strip(),
            }
            if not all(payload.values()):
                _show("<p style='color:#f4c26b;'>⚠ Fill in shadow volume, relative path, and destination first.</p>")
                return
            # Sanity-check destination — VSS restore writes to disk and
            # we don't want a typo aiming the restore at C:\\Windows.
            dest_lower = payload["destination_path"].lower().replace("/", "\\")
            risky_dests = ("\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\system\\")
            if any(part in dest_lower for part in risky_dests):
                _show(
                    "<p style='color:#ff8b8b;'>"
                    "⛔ Destination points at a Windows system folder. "
                    "Refusing to restore — pick a non-system path."
                    "</p>"
                )
                return
            if not self._check_response_gate("vss-restore"):
                return
            reason = self._capture_reason("vss-restore")
            if reason is None:
                return

            def _on_ok(resp) -> None:
                ok = bool(resp.get("status") == "ok")
                _show(
                    f"<h3 style='color:{'#7bd389' if ok else '#ff8b8b'};'>Restore {'OK' if ok else 'FAIL'}</h3>"
                    f"<p style='color:#96a5b8;'>Reason: {html.escape(reason['reason_summary'])}</p>"
                    f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>"
                )
                self._record_history(
                    category="response",
                    action="vss-restore",
                    target=str(payload.get("destination_path") or ""),
                    severity="high",
                    status="ok" if ok else "failed",
                    payload=resp,
                    reason=reason,
                )

            def _on_err(message: str) -> None:
                _show(f"<p style='color:#ff8b8b;'><b>Restore failed:</b> {html.escape(message)}</p>")

            self._submit_async(
                "VSS restore",
                lambda: app._post("/antivirus/response/vss/restore", json=payload, timeout=60).json(),
                _on_ok,
                _on_err,
                timeout_seconds=70,
            )
        restore_btn.clicked.connect(_restore)

        self._open_drawer("response", "Live Response", body, width=1080, height=720)

    def open_rules_drawer(self) -> None:
        """Custom YARA rule editor drawer.

        Two-pane layout: left rule list (with valid/error pill), right
        QPlainTextEdit source editor. `Save` validates via yara.compile
        before writing to disk; `Test rule` dry-runs the rule against a
        sample path the analyst types in the bottom row."""
        from PySide6.QtWidgets import QPlainTextEdit, QListWidget, QSplitter
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(6)

        splitter = QSplitter(Qt.Horizontal)

        # Left: list + new/delete
        left = QWidget(); left_layout = QVBoxLayout(left); left_layout.setContentsMargins(4, 4, 4, 4); left_layout.setSpacing(4)
        left_layout.addWidget(QLabel("<b>Custom rules</b>"))
        rules_list = QListWidget()
        rules_list.setMinimumWidth(220)
        left_layout.addWidget(rules_list, 1)
        list_btns = QHBoxLayout(); list_btns.setSpacing(4)
        new_btn = QPushButton("New"); del_btn = QPushButton("Delete")
        del_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:4px 10px;font-weight:600;}")
        list_btns.addWidget(new_btn); list_btns.addWidget(del_btn); list_btns.addStretch(1)
        left_layout.addLayout(list_btns)
        splitter.addWidget(left)

        # Right: editor + actions
        right = QWidget(); right_layout = QVBoxLayout(right); right_layout.setContentsMargins(4, 4, 4, 4); right_layout.setSpacing(4)
        name_row = QHBoxLayout(); name_row.setSpacing(6)
        name_row.addWidget(QLabel("Name:"))
        name_input = QLineEdit(); name_input.setPlaceholderText("alphanum, _, - (max 64 chars)")
        name_row.addWidget(name_input)
        right_layout.addLayout(name_row)
        editor = QPlainTextEdit()
        editor.setPlaceholderText('rule example_indicator { strings: $a = "magic_marker" condition: $a }')
        editor.setStyleSheet("QPlainTextEdit{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;font-family:Consolas,monospace;font-size:12px;}")
        right_layout.addWidget(editor, 1)
        action_row = QHBoxLayout(); action_row.setSpacing(6)
        save_btn = QPushButton("Save")
        save_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:5px 14px;font-weight:700;}")
        action_row.addWidget(save_btn)
        action_row.addWidget(QLabel("Sample:"))
        sample_input = QLineEdit(); sample_input.setPlaceholderText("Absolute file path to test against…")
        action_row.addWidget(sample_input, 1)
        test_btn = QPushButton("Test rule")
        action_row.addWidget(test_btn)
        right_layout.addLayout(action_row)
        result_view = QTextBrowser()
        result_view.setMaximumHeight(160)
        result_view.setStyleSheet("QTextBrowser{background:#0e1720;border:1px solid #243446;border-radius:9px;color:#eef4fb;font-family:Consolas,monospace;font-size:11px;}")
        right_layout.addWidget(result_view)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter, 1)

        rules_state: dict[str, list] = {"rows": []}

        def _refresh_list() -> None:
            try:
                resp = app._get("/antivirus/yara/custom", timeout=10).json()
            except Exception as exc:
                result_view.setHtml(f"<p style='color:#ff8b8b;'>List failed: {html.escape(str(exc))}</p>"); return
            rows = resp.get("rows", []) if isinstance(resp.get("rows"), list) else []
            rules_state["rows"] = rows
            rules_list.clear()
            for row in rows:
                glyph = "✓" if row.get("valid") else "✗"
                rules_list.addItem(f"{glyph} {row.get('name', '?')}  ({row.get('rule_count', 0)} rules)")

        def _on_select() -> None:
            row = rules_list.currentRow()
            if 0 <= row < len(rules_state["rows"]):
                name = rules_state["rows"][row].get("name", "")
                try:
                    resp = app._get(f"/antivirus/yara/custom/{name}", timeout=10).json()
                except Exception:
                    return
                rule = resp.get("rule", {})
                name_input.setText(rule.get("name", ""))
                editor.setPlainText(rule.get("source", ""))
                if not rule.get("valid"):
                    result_view.setHtml(f"<p style='color:#ff8b8b;'><b>Compile error:</b> {html.escape(str(rule.get('error', '')))}</p>")
                else:
                    result_view.setHtml(f"<p style='color:#7bd389;'>✓ Rule compiles cleanly. {rule.get('size_bytes', 0)} bytes.</p>")
        rules_list.currentRowChanged.connect(lambda _row: _on_select())

        def _new_rule() -> None:
            name_input.setText(""); editor.setPlainText("rule new_rule {\n    meta:\n        author = \"shadowlab\"\n    strings:\n        $a = \"replace_me\"\n    condition:\n        $a\n}\n")
            result_view.setHtml("<p style='color:#96a5b8;'>New rule template loaded. Edit and Save.</p>")
        new_btn.clicked.connect(_new_rule)

        def _save() -> None:
            name = name_input.text().strip()
            if not name:
                result_view.setHtml("<p style='color:#f4c26b;'>⚠ Name is required.</p>"); return
            try:
                resp = app._put(f"/antivirus/yara/custom/{name}", json={"source": editor.toPlainText()}, timeout=15).json()
            except Exception as exc:
                result_view.setHtml(f"<p style='color:#ff8b8b;'><b>Save failed:</b> {html.escape(str(exc))}</p>"); return
            ok = bool(resp.get("status") == "ok")
            colour = "#7bd389" if ok else "#ff8b8b"
            result_view.setHtml(f"<h3 style='color:{colour};'>Save {'OK' if ok else 'FAIL'}</h3>"
                                f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>")
            if ok:
                _refresh_list()
        save_btn.clicked.connect(_save)

        def _delete() -> None:
            name = name_input.text().strip()
            if not name:
                return
            from PySide6.QtWidgets import QMessageBox
            confirm = QMessageBox(app); confirm.setWindowTitle("Delete rule")
            confirm.setText(f"Delete custom rule '{name}'?")
            confirm.setIcon(QMessageBox.Warning)
            confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Yes)
            if confirm.exec() != QMessageBox.Yes:
                return
            try:
                resp = app._delete(f"/antivirus/yara/custom/{name}", timeout=10).json()
            except Exception as exc:
                result_view.setHtml(f"<p style='color:#ff8b8b;'><b>Delete failed:</b> {html.escape(str(exc))}</p>"); return
            result_view.setHtml(f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>")
            _refresh_list()
        del_btn.clicked.connect(_delete)

        def _test() -> None:
            name = name_input.text().strip()
            sample = sample_input.text().strip()
            if not name or not sample:
                result_view.setHtml("<p style='color:#f4c26b;'>⚠ Both rule name and sample path are required.</p>"); return
            try:
                resp = app._post(f"/antivirus/yara/custom/{name}/dry-run", json={"sample_path": sample}, timeout=45).json()
            except Exception as exc:
                result_view.setHtml(f"<p style='color:#ff8b8b;'><b>Dry-run failed:</b> {html.escape(str(exc))}</p>"); return
            res = resp.get("result", {})
            colour = "#ff8b8b" if res.get("match_count", 0) > 0 else "#7bd389"
            result_view.setHtml(f"<h3 style='color:{colour};'>{res.get('match_count', 0)} match(es) · {res.get('elapsed_ms', 0)} ms</h3>"
                                f"<pre>{html.escape(json.dumps(resp, indent=2, ensure_ascii=False))}</pre>")
        test_btn.clicked.connect(_test)

        _refresh_list()
        self._open_drawer("rules", "Custom YARA Rules", body, width=1240, height=720)

    def open_lists_drawer(self) -> None:
        """Exclusion / blocklist / allowlist drawer.

        QTabWidget with one tab per list kind. Each tab has a table of
        current entries + an add row + a remove button. Hashes are
        auto-classified (MD5/SHA1/SHA256 regex), everything else is
        treated as a path. Path entries match prefix (so `C:\\Tools`
        excludes everything under that directory)."""
        app = self.app
        body = QWidget()
        layout = QVBoxLayout(body); layout.setContentsMargins(0, 0, 0, 0); layout.setSpacing(8)

        intro = QLabel(
            "<b>Exclusions</b> skip the fused scan entirely · "
            "<b>Blocklist</b> auto-quarantines on hit · "
            "<b>Allowlist</b> bypasses cloud feeds. "
            "Hashes (MD5/SHA1/SHA256) are auto-detected; everything else is treated as a path prefix."
        )
        intro.setWordWrap(True); intro.setStyleSheet("color:#96a5b8;font-size:11px;")
        layout.addWidget(intro)

        tabs = QTabWidget(); tabs.setDocumentMode(True)

        def _make_tab(kind: str) -> QWidget:
            widget = QWidget(); inner = QVBoxLayout(widget); inner.setContentsMargins(4, 4, 4, 4); inner.setSpacing(6)
            table = QTableWidget(0, 5)
            table.setHorizontalHeaderLabels(["Value", "Kind", "Note", "Actor", "Added"])
            app._style_table(table)
            table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
            table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
            table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
            table.verticalHeader().setVisible(False)
            inner.addWidget(table, 1)
            row = QHBoxLayout(); row.setSpacing(6)
            row.addWidget(QLabel("Value:"))
            value_input = QLineEdit(); value_input.setPlaceholderText("hash or absolute path")
            row.addWidget(value_input, 2)
            row.addWidget(QLabel("Note:"))
            note_input = QLineEdit(); note_input.setPlaceholderText("optional analyst note")
            row.addWidget(note_input, 1)
            add_btn = QPushButton("Add")
            add_btn.setStyleSheet("QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:6px;padding:4px 12px;font-weight:600;}")
            row.addWidget(add_btn)
            remove_btn = QPushButton("Remove selected")
            remove_btn.setStyleSheet("QPushButton{background:#5c1f2d;color:#ff9ab0;border:1px solid #8c2d44;border-radius:6px;padding:4px 12px;font-weight:600;}")
            row.addWidget(remove_btn)
            inner.addLayout(row)

            def _refresh() -> None:
                try:
                    resp = app._get(f"/antivirus/lists/{kind}", timeout=10).json()
                except Exception:
                    return
                items = resp.get("items", []) if isinstance(resp.get("items"), list) else []
                table.setRowCount(len(items))
                for r, item in enumerate(items):
                    cells = [
                        str(item.get("value", "")),
                        str(item.get("kind", "")),
                        str(item.get("note", "")),
                        str(item.get("actor", "")),
                        datetime.fromtimestamp(float(item.get("added_at", 0) or 0)).strftime("%Y-%m-%d %H:%M") if item.get("added_at") else "—",
                    ]
                    for c, v in enumerate(cells):
                        table.setItem(r, c, QTableWidgetItem(v))

            def _add() -> None:
                value = value_input.text().strip()
                if not value:
                    app.statusBar().showMessage("⚠ Value required", 4000); return
                try:
                    app._post(f"/antivirus/lists/{kind}/add", json={"value": value, "note": note_input.text().strip()}, timeout=10)
                    value_input.clear(); note_input.clear()
                    app.statusBar().showMessage(f"✓ Added to {kind}", 4000)
                except Exception as exc:
                    app.statusBar().showMessage(f"✗ Add failed: {exc}", 6000)
                _refresh()
            add_btn.clicked.connect(_add)

            def _remove() -> None:
                row_idx = table.currentRow()
                if row_idx < 0:
                    return
                value_item = table.item(row_idx, 0)
                if value_item is None:
                    return
                try:
                    app._post(f"/antivirus/lists/{kind}/remove", json={"value": value_item.text()}, timeout=10)
                    app.statusBar().showMessage(f"✓ Removed from {kind}", 4000)
                except Exception as exc:
                    app.statusBar().showMessage(f"✗ Remove failed: {exc}", 6000)
                _refresh()
            remove_btn.clicked.connect(_remove)

            _refresh()
            return widget

        tabs.addTab(_make_tab("exclusions"), "Exclusions")
        tabs.addTab(_make_tab("blocklist"),  "Blocklist")
        tabs.addTab(_make_tab("allowlist"),  "Allowlist")
        layout.addWidget(tabs, 1)

        self._open_drawer("lists", "Exclusion / Block / Allow Lists", body, width=1080, height=620)

    # ------------------------------------------------------------------
    # KPI + matrix + MITRE rendering
    # ------------------------------------------------------------------

    def _refresh_kpis(self) -> None:
        app = self.app
        providers = app.antivirus_status_payload.get("providers", {}) if isinstance(app.antivirus_status_payload, dict) else {}
        ready = sum(1 for key, *_ in ALL_PROVIDERS if isinstance(providers.get(key, {}), dict) and providers.get(key, {}).get("available"))
        app._set_metric_label(app.antivirus_kpi_engines, f"{ready}/6")
        ready_names = [PROVIDER_KEY_TO_DISPLAY[key] for key, *_ in ALL_PROVIDERS
                       if isinstance(providers.get(key, {}), dict) and providers.get(key, {}).get("available")]
        app.antivirus_kpi_engines_sub.setText(", ".join(ready_names[:4]) if ready_names else "no engines ready")

        scans = getattr(app, "antivirus_scan_results", [])
        suspicious_count = sum(1 for item in scans if str(item.get("status", "")).lower() == "suspicious")
        infected_count = sum(1 for item in scans if str(item.get("status", "")).lower() == "infected")
        app._set_metric_label(app.antivirus_kpi_suspicious, str(suspicious_count))
        app.antivirus_kpi_suspicious_sub.setText(f"{infected_count} infected · {len(scans)} scans")

        quarantine_count = len(getattr(app, "quarantine_records", []))
        app._set_metric_label(app.antivirus_kpi_quarantine, str(quarantine_count))
        app.antivirus_kpi_quarantine_sub.setText("vault entries")

        coverage = getattr(app, "antivirus_mitre_coverage", {}) or {}
        total_tech = int(coverage.get("total_techniques", 0) or 0)
        tactics = coverage.get("tactics_covered", []) or []
        app._set_metric_label(app.antivirus_kpi_mitre, f"{total_tech}t / {len(tactics)}tact")
        top_tactics = ", ".join(str(t) for t in tactics[:3]) or "no techniques observed"
        app.antivirus_kpi_mitre_sub.setText(top_tactics)

        # 24-hour sparkline refresh — the heavy fetch is throttled to once
        # every ~30 s so the rapid auto-refresh ticks don't hammer the
        # endpoint. Series fed: total scans / suspicious / infected, plus
        # an engines-ready running line for the first tile.
        self._maybe_refresh_kpi_sparklines()

    def _maybe_refresh_kpi_sparklines(self) -> None:
        app = self.app
        last = getattr(self, "_last_kpi_spark_fetch", 0.0)
        now = time.time()
        if now - last < 30.0:
            return
        try:
            resp = app._get(
                "/antivirus/scans/timeseries",
                params={"window": 24 * 3600, "buckets": 24},
                timeout=4,
            ).json()
        except Exception:
            return
        points = resp.get("points", []) if isinstance(resp.get("points"), list) else []
        totals = [int(p.get("total", 0) or 0) for p in points]
        suspicious = [int(p.get("suspicious", 0) or 0) for p in points]
        infected = [int(p.get("infected", 0) or 0) for p in points]
        # Apply to the relevant tiles. The Engines tile reuses totals as
        # an activity proxy (24h scan volume); a real 'engines ready
        # over time' would need a status time-series we don't yet store.
        if hasattr(app, "antivirus_kpi_engines_spark"):
            app.antivirus_kpi_engines_spark.set_data(totals)
        if hasattr(app, "antivirus_kpi_suspicious_spark"):
            app.antivirus_kpi_suspicious_spark.set_data(suspicious)
        if hasattr(app, "antivirus_kpi_quarantine_spark"):
            # Quarantine tile shows infected ratio as a proxy — real
            # vault history would need a /vault/timeseries endpoint.
            app.antivirus_kpi_quarantine_spark.set_data(infected)
        if hasattr(app, "antivirus_kpi_mitre_spark"):
            # MITRE tile shows the same suspicious series — most MITRE
            # techniques surface from suspicious / infected verdicts.
            app.antivirus_kpi_mitre_spark.set_data([s + i for s, i in zip(suspicious, infected)])
        self._last_kpi_spark_fetch = now

    def _render_provider_matrix(self, providers: dict) -> None:
        """Repaint the 8-column Provider Matrix.

        Per-provider health (latency p95, success rate, last error) is
        sourced from the in-memory ring buffer behind
        `/antivirus/providers/health`. The fetch is best-effort: if the
        endpoint is unreachable (auth missing, server bouncing) the
        matrix still renders with the provider_status snapshot and
        shows '-' in the health columns rather than crashing."""
        from PySide6.QtWidgets import QPushButton, QWidget
        table = self.app.antivirus_overview_providers
        table.setRowCount(len(ALL_PROVIDERS))
        # Best-effort health pull. Always 0.5 s timeout so a slow API
        # doesn't stall every status refresh.
        health: dict[str, dict] = {}
        try:
            resp = self.app._get("/antivirus/providers/health", timeout=4).json()
            health = resp.get("providers", {}) if isinstance(resp.get("providers"), dict) else {}
        except Exception:
            health = {}
        for row, (key, display, accent) in enumerate(ALL_PROVIDERS):
            provider = providers.get(key, {}) if isinstance(providers.get(key, {}), dict) else {}
            available = bool(provider.get("available"))
            definitions = "loaded" if provider.get("definitions_loaded") else "pending"
            updated = float(provider.get("latest_signature_update", 0) or 0)
            if updated > 0:
                age_h = max(0, int((datetime.now().timestamp() - updated) // 3600))
                age = f"{age_h//24}d" if age_h >= 24 else f"{age_h}h"
            else:
                age = "live" if available else "—"
            health_row = health.get(key, {}) if isinstance(health.get(key), dict) else {}
            calls = int(health_row.get("calls", 0) or 0)
            p95 = int(health_row.get("p95_ms", 0) or 0)
            success_rate = health_row.get("success_rate")
            success_text = "—"
            if calls > 0 and success_rate is not None:
                success_text = f"{int(round(success_rate * 100))}% ({calls})"
            p95_text = f"{p95} ms" if p95 > 0 else "—"
            # "Last error" — prefer rolling-health error, fall back to provider status error.
            last_error = (str(health_row.get("last_error", "") or "")
                          or str(provider.get("error", "") or ""))
            if not last_error and not available:
                last_error = "engine not loaded"
            last_error_short = (last_error[:80] + "…") if len(last_error) > 80 else (last_error or "—")
            state_text = "ready" if available else "offline"
            cells = [display, state_text, definitions, age, p95_text, success_text, last_error_short]
            for col, value in enumerate(cells):
                item = QTableWidgetItem(str(value))
                if col == 6 and last_error:
                    item.setToolTip(last_error)
                table.setItem(row, col, item)
            # Inline action cell — Test + Update buttons stacked.
            action_cell = QWidget()
            from PySide6.QtWidgets import QHBoxLayout as _HBox
            action_layout = _HBox(action_cell)
            action_layout.setContentsMargins(2, 2, 2, 2); action_layout.setSpacing(4)
            test_btn = QPushButton("Test")
            test_btn.setMaximumHeight(24); test_btn.setMinimumWidth(50)
            test_btn.setStyleSheet(
                "QPushButton{background:#1d3a5f;color:#9fd0ff;border:1px solid #355179;border-radius:5px;padding:2px 8px;font-size:10px;font-weight:600;}"
                "QPushButton:hover{background:#244a78;}"
            )
            test_btn.clicked.connect(lambda _checked=False, k=key: self._provider_test_connection(k))
            update_btn = QPushButton("Update")
            update_btn.setMaximumHeight(24); update_btn.setMinimumWidth(60)
            update_btn.setStyleSheet(
                "QPushButton{background:#1f6f4a;color:#eaffe5;border:1px solid #2f9c6c;border-radius:5px;padding:2px 8px;font-size:10px;font-weight:600;}"
                "QPushButton:hover{background:#258759;}"
                "QPushButton:disabled{color:#5b6d80;background:#16202c;border-color:#243446;}"
            )
            # "Update" only meaningful for engines that have a refresh
            # endpoint (sentinel_cli freshclam, aegis_core vendored, yara_x packs).
            update_btn.setEnabled(key in {"sentinel_cli", "aegis_core", "yara_x"})
            update_btn.clicked.connect(lambda _checked=False, k=key: self._provider_force_update(k))
            action_layout.addWidget(test_btn)
            action_layout.addWidget(update_btn)
            action_layout.addStretch(1)
            table.setCellWidget(row, 7, action_cell)
            self.app._paint_row(table, row, self.app._severity_color("low" if available else "high"))

    def _provider_test_connection(self, provider_key: str) -> None:
        """Inline 'Test' button — fires a synthetic per-engine probe and
        surfaces timing + outcome into the status bar."""
        self.app.statusBar().showMessage(f"Testing {provider_key}…")
        try:
            resp = self.app._post(f"/antivirus/providers/{provider_key}/test", json={}, timeout=30).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"{provider_key} test failed: {exc}")
            return
        if str(resp.get("status", "")).lower() == "error":
            self.app.statusBar().showMessage(f"{provider_key} test → error: {str(resp.get('error', ''))[:80]}")
            return
        elapsed = int(resp.get("elapsed_ms", 0) or 0)
        outcome = str(resp.get("verdict_status", "?"))
        caught = "caught" if resp.get("caught") else "missed"
        self.app.statusBar().showMessage(
            f"{provider_key} test → {outcome} · {caught} EICAR · {elapsed} ms"
        )
        # Refresh matrix so the new health datapoint shows up immediately.
        self.refresh_status()

    def _provider_force_update(self, provider_key: str) -> None:
        """Inline 'Update' button — triggers freshclam (or the provider's
        update routine) without leaving the matrix."""
        self.app.statusBar().showMessage(f"Forcing {provider_key} signature update…")
        try:
            resp = self.app._post("/antivirus/signatures/update", json={"provider_key": provider_key}, timeout=120).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"{provider_key} update failed: {exc}")
            return
        result = resp.get("result", resp) if isinstance(resp, dict) else {}
        self.app.statusBar().showMessage(
            f"{provider_key} update: {result.get('status', '?')} · files_changed={result.get('files_changed', 0)}"
        )
        self.refresh_status()

    def _render_mitre_heatmap(self) -> None:
        app = self.app
        coverage = getattr(app, "antivirus_mitre_coverage", {}) or {}
        techniques = getattr(app, "antivirus_mitre_techniques", []) or []
        if not techniques:
            app.antivirus_mitre_view.setHtml(
                "<h3 style='color:#bda4ff;margin:6px 0;'>MITRE ATT&CK Coverage</h3>"
                "<p style='color:#96a5b8;font-size:12px;'>No techniques mapped yet. Run a scan with the behavioural, "
                "YARA-X, or cloud sandbox engine enabled to populate ATT&CK coverage.</p>"
            )
            return
        by_tactic = coverage.get("by_tactic", {}) if isinstance(coverage.get("by_tactic"), dict) else {}
        rows: list[str] = []
        for tactic in sorted(by_tactic.keys()):
            tac_techs = by_tactic.get(tactic, []) or []
            tac_techs_sorted = sorted(tac_techs, key=lambda t: str(t.get("id", "")))
            tile_html = "".join(
                f"<span style='display:inline-block;background:#1d2a3b;border:1px solid #2c4260;"
                f"border-radius:5px;padding:2px 7px;margin:2px;font-size:11px;color:#eef4fb;' "
                f"title='{html.escape(str(t.get('name', '')))} · sources: {html.escape(', '.join(t.get('sources', [])))}'>"
                f"<b style='color:#bda4ff;'>{html.escape(str(t.get('id', '')))}</b> "
                f"<span style='color:#c8d8ea;'>{html.escape(str(t.get('name', ''))[:32])}</span></span>"
                for t in tac_techs_sorted
            )
            rows.append(
                f"<div style='margin:4px 0;'>"
                f"<div style='color:#9fd0ff;font-weight:700;font-size:12px;margin-bottom:2px;'>"
                f"{html.escape(str(tactic))} <span style='color:#7e91a8;font-weight:500;'>· {len(tac_techs)} technique(s)</span></div>"
                f"<div>{tile_html}</div></div>"
            )
        app.antivirus_mitre_view.setHtml(
            "<h3 style='color:#bda4ff;margin:6px 0;'>MITRE ATT&CK Coverage</h3>"
            f"<p style='color:#96a5b8;font-size:11px;'>Total: <b>{coverage.get('total_techniques', 0)}</b> techniques across "
            f"<b>{len(by_tactic)}</b> tactic(s) — aggregated from current verdict + recent cached scans.</p>"
            + "".join(rows)
        )

    def _refresh_recent_mitre(self) -> None:
        """Pull /antivirus/mitre/coverage in recent_scans mode."""
        app = self.app
        try:
            payload = app._post("/antivirus/mitre/coverage", json={"limit": 100}, timeout=15).json()
        except Exception:
            return
        app.antivirus_recent_mitre_payload = payload
        coverage = payload.get("coverage", {}) if isinstance(payload.get("coverage"), dict) else {}
        techniques = payload.get("techniques", []) if isinstance(payload.get("techniques"), list) else []
        # If the current scan didn't have its own techniques, surface the
        # recent-scans aggregation so the heat-map isn't empty between runs.
        if not getattr(app, "antivirus_mitre_techniques", []):
            app.antivirus_mitre_techniques = techniques
            app.antivirus_mitre_coverage = coverage
        self._render_mitre_heatmap()
        self._refresh_kpis()

    # ------------------------------------------------------------------
    # Scan dispatch — routes the split-button menu to the right endpoint
    # ------------------------------------------------------------------

    def handle_scan_kind(self, kind: str) -> None:
        """Dispatch the Scan split-button menu to the right scan path
        with explicit user feedback at every stage.

        Previously a click that hit a slow endpoint or a path-validation
        error fell silently — the analyst had no way to know whether
        the click had even registered. Now every dispatch:
          * Disables the Scan button + flips its label to '⏳ Scanning…'
            so a second click can't double-fire
          * Shows the action in the status bar at start ('Scanning <path>
            via <kind>…')
          * Reports the verdict + duration on success ('clean · 4 engines
            · 234 ms')
          * Shows the failure reason on error ('Scan failed: 400 — File
            not found')

        Always re-enables the button at the end via try/finally."""
        from PySide6.QtCore import QTimer
        kind = (kind or "full").lower()

        # EICAR + selected-process don't use the search field; route them
        # to their dedicated paths and exit early.
        if kind == "validation":
            self._with_scan_busy("EICAR validation", self.scan_validation_sample); return
        if kind == "process":
            self._with_scan_busy("Process scan", self.scan_selected_process); return

        target = (self.app.antivirus_target_path.text() or "").strip()
        if not target:
            self.app.statusBar().showMessage("⚠ Provide a hash or absolute path first.", 5000)
            return

        if kind == "full":
            self._with_scan_busy(f"Full scan {Path(target).name}", self.scan_target_file)
            return

        endpoint_map = {
            "yara":        ("/antivirus/scan/yara",        "yara_x"),
            "behavioural": ("/antivirus/scan/behavioural", "behavioural"),
            "sandbox":     ("/antivirus/scan/sandbox",     "cloud_sandbox"),
        }
        if kind not in endpoint_map:
            return
        endpoint, scope = endpoint_map[kind]
        body = {"file_path": target, "yara_pack": self.app.antivirus_policy_yara_pack.currentText()}

        def _run():
            try:
                response = self.app._post(endpoint, json=body, timeout=120).json()
            except Exception as exc:
                self.app.statusBar().showMessage(f"✗ {kind} scan failed: {exc}", 8000)
                self.app._show_error(self.app.antivirus_result_detail, f"{kind.title()} scan failed", exc)
                return
            result = response.get("result", response) if isinstance(response, dict) else response
            provider_payload = result if isinstance(result, dict) else {}
            wrapped = {
                "status": str(provider_payload.get("status", "unknown") or "unknown"),
                "path": target,
                "sha256": str(provider_payload.get("sha256", "") or ""),
                "providers": {scope: provider_payload},
                "summary": {
                    "fused_verdict": str(provider_payload.get("status", "unknown") or "unknown"),
                    "severity": str(provider_payload.get("severity", "low") or "low"),
                    "score": int(provider_payload.get("score", 0) or 0),
                    "confidence": str(provider_payload.get("confidence", "low") or "low"),
                    "detections": [provider_payload.get("malware_name")] if provider_payload.get("malware_name") else [],
                    "provider_hits": [scope] if str(provider_payload.get("status", "")).lower() == "infected" else [],
                    "provider_suspicious": [scope] if str(provider_payload.get("status", "")).lower() == "suspicious" else [],
                    "reasons": provider_payload.get("reasons", []) or [],
                    "recommended_actions": [],
                    "provider_cards": [{
                        "provider": scope, "engine": PROVIDER_KEY_TO_DISPLAY.get(scope, scope),
                        "status": str(provider_payload.get("status", "")), "malware_name": str(provider_payload.get("malware_name", "")),
                        "scan_time_ms": int(provider_payload.get("scan_time_ms", 0) or 0),
                        "score": int(provider_payload.get("score", 0) or 0),
                        "error": str(provider_payload.get("error", "")),
                    }],
                    "mitre_techniques": [],
                    "mitre_coverage": {"total_techniques": 0, "tactics_covered": [], "by_tactic": {}},
                },
                "policy": self.app.antivirus_status_payload.get("policy", {}) if isinstance(self.app.antivirus_status_payload, dict) else {},
            }
            self._record_scan_result(wrapped, scope=f"{kind}-direct")
            verdict = str(provider_payload.get("status", "unknown"))
            elapsed = int(provider_payload.get("scan_time_ms", 0) or 0)
            self.app.statusBar().showMessage(
                f"✓ {kind} scan complete · verdict={verdict} · {elapsed} ms", 6000
            )

        self._with_scan_busy(f"{kind.title()} scan {Path(target).name}", _run)

    def _with_scan_busy(self, label: str, runner) -> None:
        """Run `runner` synchronously while disabling the Scan button and
        flipping its label to a busy indicator. Keeps the click obviously
        acknowledged so the analyst doesn't double-fire while the API
        is mid-flight (the synchronous /antivirus/scan/file path can take
        30+ seconds when the cloud sandbox is in the provider set)."""
        from PySide6.QtCore import QCoreApplication
        scan_btn = (self.scan_buttons or {}).get("full")
        original_text = ""
        if scan_btn is not None:
            try:
                original_text = scan_btn.text()
                scan_btn.setEnabled(False)
                scan_btn.setText("⏳ Scanning…")
                # Force the disabled+text repaint to actually hit the screen
                # before the synchronous network call blocks the event loop.
                QCoreApplication.processEvents()
            except Exception:
                pass
        self.app.statusBar().showMessage(f"⏳ {label}…")
        try:
            runner()
        finally:
            if scan_btn is not None:
                try:
                    scan_btn.setEnabled(True)
                    scan_btn.setText(original_text or "▸ Scan")
                except Exception:
                    pass

    def _build_overview_controls_card_unused(self) -> QWidget:
        app = self.app
        controls_card = QFrame()
        controls_card.setProperty("card", True)
        controls_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        controls_layout = QVBoxLayout(controls_card)
        controls_layout.setContentsMargins(10, 6, 10, 6)
        controls_layout.setSpacing(4)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.setSpacing(8)
        app.antivirus_policy_badge = QLabel("Policy: loading")
        app.antivirus_policy_badge.setStyleSheet(
            "color:#9fd0ff;background:#121b27;border:1px solid #2c4260;border-radius:7px;padding:5px 8px;font-size:11px;font-weight:600;"
        )
        app.antivirus_policy_badge.setMaximumHeight(30)
        app.antivirus_live_status = QLabel("Engines idle")
        app.antivirus_live_status.setStyleSheet("color:#96a5b8;font-size:10px;")
        app.antivirus_auto_refresh = QCheckBox("Auto refresh")
        app.antivirus_auto_refresh.setChecked(True)
        app.antivirus_auto_refresh.setStyleSheet("font-size:10px;padding:0;margin:0;")
        app.antivirus_auto_refresh.setMaximumHeight(26)
        app.antivirus_role_badge = QLabel("Antivirus role: viewer")
        app.antivirus_role_badge.setStyleSheet(
            "color:#f4c26b;background:#121b27;border:1px solid #2c4260;border-radius:7px;padding:5px 8px;font-size:11px;font-weight:600;"
        )
        app.antivirus_role_badge.setMaximumHeight(30)
        # Compact top-row metric cards next to policy/loading strip.
        def _mini_metric(title: str, accent: str) -> tuple[QWidget, QLabel]:
            card = QFrame()
            card.setProperty("card", True)
            card.setMinimumHeight(30)
            card.setMaximumHeight(30)
            card.setMinimumWidth(150)
            card.setMaximumWidth(180)
            card.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            row = QHBoxLayout(card)
            row.setContentsMargins(8, 3, 8, 3)
            row.setSpacing(6)
            name = QLabel(title)
            name.setStyleSheet("color:#96a5b8;font-size:9px;font-weight:600;")
            value = QLabel("--")
            value.setStyleSheet(f"color:{accent};font-size:10px;font-weight:700;")
            row.addWidget(name)
            row.addStretch(1)
            row.addWidget(value)
            return card, value

        aegis_metric_card, app.antivirus_aegis_value = _mini_metric("Aegis", "#8ec5ff")
        sentinel_metric_card, app.antivirus_sentinel_value = _mini_metric("Sentinel", "#7bd389")
        severity_metric_card, app.antivirus_last_scan_value = _mini_metric("Severity", "#ffd166")
        quarantine_metric_card, app.antivirus_quarantine_value = _mini_metric("Quarantine", "#ff9f6b")

        status_row.addWidget(app.antivirus_policy_badge, 1)
        status_row.addWidget(app.antivirus_live_status)
        status_row.addWidget(app.antivirus_role_badge)
        status_row.addWidget(aegis_metric_card)
        status_row.addWidget(sentinel_metric_card)
        status_row.addWidget(severity_metric_card)
        status_row.addWidget(quarantine_metric_card)
        status_row.addWidget(app.antivirus_auto_refresh)
        status_row.addStretch(1)
        controls_layout.addLayout(status_row)

        policy_row = QWidget()
        policy_row_layout = QHBoxLayout(policy_row)
        policy_row_layout.setContentsMargins(0, 0, 0, 0)
        policy_row_layout.setSpacing(8)
        app.antivirus_policy_enabled = QCheckBox("AV enabled")
        app.antivirus_policy_provider_aegis = QCheckBox("Aegis Core")
        app.antivirus_policy_provider_sentinel = QCheckBox("Sentinel CLI")
        app.antivirus_policy_provider_aegis.setChecked(True)
        app.antivirus_policy_provider_sentinel.setChecked(True)
        app.antivirus_policy_profile = QComboBox()
        app.antivirus_policy_profile.addItems(["conservative", "balanced", "aggressive"])
        app.antivirus_policy_threshold = QComboBox()
        app.antivirus_policy_threshold.addItems(["disabled", "critical", "high"])
        app.antivirus_policy_schedule = QSpinBox()
        app.antivirus_policy_schedule.setRange(15, 10080)
        app.antivirus_policy_schedule.setValue(240)
        app.antivirus_policy_grace = QSpinBox()
        app.antivirus_policy_grace.setRange(6, 720)
        app.antivirus_policy_grace.setValue(48)
        for label, widget in [
            ("Profile", app.antivirus_policy_profile),
            ("Auto-Quarantine", app.antivirus_policy_threshold),
            ("Validation (min)", app.antivirus_policy_schedule),
            ("Signature Grace (h)", app.antivirus_policy_grace),
        ]:
            policy_row_layout.addWidget(QLabel(label))
            policy_row_layout.addWidget(widget)
        policy_row_layout.addWidget(app.antivirus_policy_enabled)
        policy_row_layout.addWidget(app.antivirus_policy_provider_aegis)
        policy_row_layout.addWidget(app.antivirus_policy_provider_sentinel)
        self.policy_buttons = {}
        for key, label, callback in [
            ("refresh", "Load Policy", self.refresh_status),
            ("save", "Save Policy", self.save_policy),
        ]:
            button = QPushButton(label)
            button.clicked.connect(callback)
            self.policy_buttons[key] = button
            policy_row_layout.addWidget(button)
        policy_row_layout.addStretch(1)
        controls_layout.addWidget(self.app._panel_card("Policy Controls", policy_row, None))

        return controls_card

    def _build_scan_controls_card(self) -> QWidget:
        app = self.app
        card = QFrame()
        card.setProperty("card", True)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(4)

        path_row = QHBoxLayout()
        path_row.setContentsMargins(0, 0, 0, 0)
        path_row.setSpacing(6)
        app.antivirus_target_path = QLineEdit(str(self.validation_sample_path()))
        app.antivirus_target_path.setPlaceholderText("File path to scan")
        app.antivirus_target_path.setMinimumWidth(320)
        app.antivirus_webhook_url = QLineEdit(app.webhook_url.text().strip())
        app.antivirus_webhook_url.setPlaceholderText("Webhook URL")
        app.antivirus_webhook_url.textChanged.connect(app.webhook_url.setText)
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.pick_scan_target_file)
        path_row.addWidget(QLabel("Scan Target"))
        path_row.addWidget(app.antivirus_target_path, 5)
        path_row.addWidget(browse_btn)
        path_row.addWidget(QLabel("Webhook"))
        path_row.addWidget(app.antivirus_webhook_url, 4)
        layout.addLayout(path_row)

        actions = QWidget()
        app.antivirus_scan_actions = actions
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(6)
        self.scan_buttons = {}
        for action_key, label, callback in [
            ("refresh", "Refresh Engines", app.refresh_antivirus_workspace),
            ("validation", "Scan Validation", app.scan_antivirus_validation_sample),
            ("file", "Scan File", app.scan_antivirus_target),
            ("process", "Scan Process", app.scan_antivirus_selected_process),
            ("create_case", "Create Case", self.create_case_from_selected_result),
            ("export_report", "Export Report", self.export_selected_result_report),
            ("quarantine", "Quarantine Detection", app.quarantine_selected_antivirus_result),
            ("clear", "Clear Results", self.clear_scan_results),
        ]:
            button = QPushButton(label)
            button.clicked.connect(callback)
            self.scan_buttons[action_key] = button
            actions_layout.addWidget(button)
        actions_layout.addStretch(1)
        layout.addWidget(app._panel_card("Scan & Response Controls", actions, None))
        app.antivirus_scan_access_hint = QLabel("Viewer mode is read-only. Apply an analyst or admin key to run scans.")
        app.antivirus_scan_access_hint.setStyleSheet("color:#96a5b8;font-size:11px;")
        layout.addWidget(app.antivirus_scan_access_hint)
        return card

    def _build_quarantine_controls_card(self) -> QWidget:
        app = self.app
        card = QFrame()
        card.setProperty("card", True)
        layout = QVBoxLayout(card)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(6)

        actions = QWidget()
        app.antivirus_quarantine_actions = actions
        actions_layout = QHBoxLayout(actions)
        actions_layout.setContentsMargins(0, 0, 0, 0)
        actions_layout.setSpacing(6)
        self.quarantine_buttons = {}
        for action_key, label, callback in [
            ("refresh", "Refresh Quarantine", app.refresh_quarantine),
            ("export_report", "Export Quarantine", self.export_selected_quarantine_report),
            ("restore", "Restore Selected", app.restore_selected_quarantine),
            ("delete", "Delete Selected", app.delete_selected_quarantine),
            ("open_copy", "Open Quarantine Copy", app.open_selected_antivirus_quarantine),
            ("test_webhook", "Test Webhook", app.test_alert_webhook),
            ("save_webhook", "Save Webhook", app.save_alert_webhook),
        ]:
            button = QPushButton(label)
            button.clicked.connect(callback)
            self.quarantine_buttons[action_key] = button
            actions_layout.addWidget(button)
        actions_layout.addStretch(1)
        layout.addWidget(app._panel_card("Containment Actions", actions, None))
        app.antivirus_quarantine_access_hint = QLabel("Viewer can inspect history only. Analysts can review inventory. Admins can contain and restore.")
        app.antivirus_quarantine_access_hint.setStyleSheet("color:#96a5b8;font-size:11px;")
        layout.addWidget(app.antivirus_quarantine_access_hint)
        return card

    def _build_overview_page(self) -> QWidget:
        app = self.app
        page = QWidget()
        layout = QGridLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(8)
        layout.setVerticalSpacing(4)

        controls = self._build_overview_controls_card()

        app.antivirus_status_summary = QTextBrowser()
        app.antivirus_status_summary.setProperty("role", "brief")
        app.antivirus_status_summary.setMinimumHeight(180)
        app.antivirus_status_summary.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        app.antivirus_status_summary.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        app.antivirus_overview_snapshot = QTextBrowser()
        app.antivirus_overview_snapshot.setProperty("role", "brief")
        app.antivirus_overview_snapshot.setMinimumHeight(180)
        app.antivirus_overview_snapshot.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        app.antivirus_overview_snapshot.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        app.antivirus_overview_providers = QTableWidget(0, 4)
        app.antivirus_overview_providers.setHorizontalHeaderLabels(["Engine", "State", "Version", "Coverage"])
        app._style_table(app.antivirus_overview_providers)
        app.antivirus_overview_providers.setMinimumHeight(180)
        app.antivirus_overview_providers.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        app.antivirus_overview_queue = QTableWidget(0, 4)
        app.antivirus_overview_queue.setHorizontalHeaderLabels(["Time", "Action", "Target", "Status"])
        app._style_table(app.antivirus_overview_queue)
        app.antivirus_overview_queue.setMinimumHeight(180)
        app.antivirus_overview_queue.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(controls, 0, 0, 1, 4, Qt.AlignTop)

        status_card = app._panel_card(
            "Engine Posture",
            app.antivirus_status_summary,
            lambda: app._open_panel_window("Antivirus Engine Posture", app._clone_text_view(app.antivirus_status_summary)),
        )
        status_card.setMinimumHeight(260)
        status_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        snapshot_card = app._panel_card(
            "Operational Snapshot",
            app.antivirus_overview_snapshot,
            lambda: app._open_panel_window("Antivirus Operational Snapshot", app._clone_text_view(app.antivirus_overview_snapshot)),
        )
        snapshot_card.setMinimumHeight(260)
        snapshot_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        providers_card = app._panel_card(
            "Provider Readiness",
            app.antivirus_overview_providers,
            lambda: app._open_panel_window("Antivirus Provider Readiness", app._clone_table(app.antivirus_overview_providers)),
        )
        providers_card.setMinimumWidth(320)
        providers_card.setMinimumHeight(260)
        providers_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        queue_card = app._panel_card(
            "Recent Response Queue",
            app.antivirus_overview_queue,
            lambda: app._open_panel_window("Antivirus Recent Response Queue", app._clone_table(app.antivirus_overview_queue)),
        )
        queue_card.setMinimumWidth(320)
        queue_card.setMinimumHeight(260)
        queue_card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        layout.addWidget(status_card, 1, 0)
        layout.addWidget(snapshot_card, 1, 1)
        layout.addWidget(providers_card, 1, 2)
        layout.addWidget(queue_card, 1, 3)

        layout.setColumnStretch(0, 1)
        layout.setColumnStretch(1, 1)
        layout.setColumnStretch(2, 1)
        layout.setColumnStretch(3, 1)
        layout.setRowStretch(0, 0)
        layout.setRowStretch(1, 1)
        return page

    def current_role(self) -> str:
        context = getattr(self.app, "auth_context", {}) if hasattr(self.app, "auth_context") else {}
        role = str(context.get("role", "viewer") or "viewer").lower()
        if role not in {"viewer", "analyst", "admin", "locked"}:
            return "viewer"
        return role

    def apply_role_access(self) -> None:
        app = self.app
        role = self.current_role()
        is_locked = role == "locked"
        can_scan = role in {"analyst", "admin"}
        can_contain = role == "admin"
        can_view_inventory = role in {"analyst", "admin"}
        can_manage_policy = role == "admin"
        role_label = "locked" if is_locked else role
        accent = "#ff8b8b" if is_locked else "#f4c26b" if role == "viewer" else "#9fd0ff" if role == "analyst" else "#7fe39d"
        if hasattr(app, "antivirus_role_badge"):
            access_text = (
                "locked"
                if is_locked
                else "read-only"
                if role == "viewer"
                else "hunt"
                if role == "analyst"
                else "contain"
            )
            # Compact form for the row-1 chip (the verbose
            # "Antivirus role: admin | Admin containment workflow"
            # blew past the chip's max width on 1280×720). Tooltip
            # carries the long form for analysts who want it.
            app.antivirus_role_badge.setText(f"{role_label} · {access_text}")
            app.antivirus_role_badge.setToolTip(
                f"Antivirus role: {role_label}\n"
                f"{('Backend locked' if is_locked else 'Read-only review' if role == 'viewer' else 'Analyst hunt workflow' if role == 'analyst' else 'Admin containment workflow')}"
            )
            app.antivirus_role_badge.setStyleSheet(
                f"color:{accent};background:#121b27;border:1px solid #2c4260;border-radius:7px;padding:3px 10px;font-size:11px;font-weight:600;"
            )
        for action_key, button in self.scan_buttons.items():
            if action_key in {"refresh", "clear"}:
                allowed = True
            elif action_key == "quarantine":
                allowed = can_contain
            elif action_key in {"create_case", "export_report"}:
                allowed = can_scan
            else:
                allowed = can_scan
            button.setEnabled(allowed)
        for action_key, button in self.quarantine_buttons.items():
            allowed = can_contain if action_key in {"restore", "delete", "test_webhook", "save_webhook"} else can_view_inventory
            button.setVisible(allowed)
            button.setEnabled(allowed)
        for action_key, button in self.policy_buttons.items():
            allowed = can_manage_policy or action_key == "refresh"
            button.setVisible(allowed)
            button.setEnabled(allowed)
        if hasattr(app, "antivirus_scan_access_hint"):
            if is_locked:
                app.antivirus_scan_access_hint.setText("Authentication is required. Apply a valid viewer, analyst, or admin key to unlock Antivirus.")
            elif role == "viewer":
                app.antivirus_scan_access_hint.setText("Viewer mode is read-only. Apply an analyst or admin key to run scans.")
            elif role == "analyst":
                app.antivirus_scan_access_hint.setText("Analyst mode can run scans and review verdicts. Admin is required for quarantine response.")
            else:
                app.antivirus_scan_access_hint.setText("Admin mode can run scans and trigger containment.")
        if hasattr(app, "antivirus_quarantine_access_hint"):
            if is_locked:
                app.antivirus_quarantine_access_hint.setText("Authentication is required before quarantine inventory and response actions are available.")
            elif role == "viewer":
                app.antivirus_quarantine_access_hint.setText("Viewer mode keeps containment actions hidden. Use analyst or admin access for inventory workflows.")
            elif role == "analyst":
                app.antivirus_quarantine_access_hint.setText("Analyst mode can inspect quarantine inventory and open copies. Admin is required to restore, delete, or configure webhooks.")
            else:
                app.antivirus_quarantine_access_hint.setText("Admin mode exposes full containment, restore, delete, and webhook workflows.")
        if hasattr(app, "antivirus_target_path"):
            app.antivirus_target_path.setEnabled(can_scan)
        for widget_name in [
            "antivirus_policy_enabled",
            "antivirus_policy_provider_aegis",
            "antivirus_policy_provider_sentinel",
            "antivirus_policy_provider_cloud",
            "antivirus_policy_provider_yara",
            "antivirus_policy_provider_behavioural",
            "antivirus_policy_provider_sandbox",
            "antivirus_policy_profile",
            "antivirus_policy_threshold",
            "antivirus_policy_schedule",
            "antivirus_policy_grace",
            "antivirus_policy_yara_pack",
            "antivirus_policy_mitre_enabled",
        ]:
            if hasattr(app, widget_name):
                getattr(app, widget_name).setEnabled(can_manage_policy)
        if hasattr(app, "antivirus_results_table"):
            app.antivirus_results_table.setEnabled(True)
        if hasattr(app, "antivirus_quarantine_table"):
            app.antivirus_quarantine_table.setEnabled(can_view_inventory)
        if hasattr(app, "antivirus_quarantine_detail"):
            if is_locked:
                app.antivirus_quarantine_detail.setPlainText("Authentication required to access quarantine inventory.")
            elif role == "viewer":
                app.antivirus_quarantine_detail.setPlainText("Viewer mode does not expose quarantine inventory operations.")

    def _build_scan_page(self) -> QWidget:
        app = self.app
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        layout.addWidget(self._build_scan_controls_card())

        app.antivirus_results_table = QTableWidget(0, 6)
        app.antivirus_results_table.setHorizontalHeaderLabels(["Scope", "Target", "Severity", "Detections", "Providers", "Status"])
        app._style_table(app.antivirus_results_table)
        app.antivirus_results_table.setProperty("panel_compact", True)
        app.antivirus_results_table.horizontalHeader().setStretchLastSection(False)
        app.antivirus_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        app.antivirus_results_table.itemSelectionChanged.connect(app.show_selected_antivirus_result)

        app.antivirus_result_detail = QTextEdit()
        app.antivirus_result_detail.setReadOnly(True)
        app.antivirus_result_detail.setProperty("panel_compact", True)
        app.antivirus_result_detail.setMinimumHeight(280)
        app.antivirus_result_detail.setMaximumHeight(280)

        app.antivirus_scan_guidance = QTextBrowser()
        app.antivirus_scan_guidance.setProperty("role", "brief")
        app.antivirus_scan_guidance.setProperty("panel_compact", True)
        app.antivirus_scan_guidance.setMinimumHeight(280)
        app.antivirus_scan_guidance.setMaximumHeight(280)
        app.antivirus_scan_guidance.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        app.antivirus_scan_guidance.setHtml("<h3>Operator Guidance</h3><p>No scan selected.</p>")
        app.antivirus_provider_hits = QTextBrowser()
        app.antivirus_provider_hits.setProperty("role", "brief")
        app.antivirus_provider_hits.setProperty("panel_compact", True)
        app.antivirus_provider_hits.setMinimumHeight(280)
        app.antivirus_provider_hits.setMaximumHeight(280)
        app.antivirus_provider_hits.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        app.antivirus_provider_hits.setHtml("<h3>Provider Hits</h3><p>No scan selected.</p>")

        app.antivirus_results_table.setMinimumHeight(280)
        app.antivirus_results_table.setMaximumHeight(280)
        scan_panels = QWidget()
        scan_panels_layout = QHBoxLayout(scan_panels)
        scan_panels_layout.setContentsMargins(0, 0, 0, 0)
        scan_panels_layout.setSpacing(8)
        results_card = app._panel_card(
            "Scan Results",
            app.antivirus_results_table,
            lambda: app._open_panel_window("Antivirus Scan Results", app._clone_table(app.antivirus_results_table)),
        )
        verdict_card = app._panel_card(
            "Fused Verdict",
            app.antivirus_result_detail,
            lambda: app._open_panel_window("Antivirus Verdict Detail", app._clone_text_view(app.antivirus_result_detail)),
        )
        hits_card = app._panel_card(
            "Provider Hits",
            app.antivirus_provider_hits,
            lambda: app._open_panel_window("Antivirus Provider Hits", app._clone_text_view(app.antivirus_provider_hits)),
        )
        guidance_card = app._panel_card(
            "Operator Guidance",
            app.antivirus_scan_guidance,
            lambda: app._open_panel_window("Antivirus Scan Guidance", app._clone_text_view(app.antivirus_scan_guidance)),
        )
        for card in [results_card, verdict_card, hits_card, guidance_card]:
            card.setMinimumWidth(320)
            card.setMinimumHeight(338)
            card.setMaximumHeight(338)
            card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            scan_panels_layout.addWidget(card, 1)
        layout.addWidget(scan_panels, 1)
        return page

    def pick_scan_target_file(self) -> None:
        current = self.app.antivirus_target_path.text().strip()
        start_dir = str(Path(current).parent) if current else str(Path(__file__).resolve().parent.parent)
        file_path, _ = QFileDialog.getOpenFileName(self.app, "Select File To Scan", start_dir, "All Files (*.*)")
        if file_path:
            self.app.antivirus_target_path.setText(file_path)

    def clear_scan_results(self) -> None:
        self.app.antivirus_scan_results = []
        self.app.antivirus_results_table.setRowCount(0)
        self.app.antivirus_results_table.clearSelection()
        self.app._set_metric_label(self.app.antivirus_last_scan_value, "none")
        self._set_scan_empty_state("No scan selected yet. Run a validation, file, or process scan to review a fused verdict.")
        self._render_overview_snapshot()

    def _build_quarantine_page(self) -> QWidget:
        app = self.app
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        layout.addWidget(self._build_quarantine_controls_card())

        app.antivirus_quarantine_table = QTableWidget(0, 6)
        app.antivirus_quarantine_table.setHorizontalHeaderLabels(["ID", "Process", "Original Path", "Quarantine Path", "Status", "Created"])
        app._style_table(app.antivirus_quarantine_table)
        app.antivirus_quarantine_table.itemSelectionChanged.connect(app.show_selected_antivirus_quarantine)

        app.antivirus_quarantine_detail = QTextEdit()
        app.antivirus_quarantine_detail.setReadOnly(True)
        app.antivirus_quarantine_detail.setMinimumHeight(150)

        app.antivirus_response_notes = QTextBrowser()
        app.antivirus_response_notes.setProperty("role", "brief")
        app.antivirus_response_notes.setMinimumHeight(150)
        app.antivirus_response_notes.setHtml(
            "<h3>Containment Notes</h3>"
            "<ul>"
            "<li><b>Quarantine:</b> preserves a controlled copy for investigation.</li>"
            "<li><b>Restore:</b> use only after analyst validation or false-positive review.</li>"
            "<li><b>Delete:</b> use for final disposal after case documentation.</li>"
            "<li><b>Webhook:</b> keep downstream response channels aligned with containment actions.</li>"
            "</ul>"
        )

        app.antivirus_quarantine_table.setMinimumHeight(170)
        quarantine_panels = QWidget()
        quarantine_panels_layout = QHBoxLayout(quarantine_panels)
        quarantine_panels_layout.setContentsMargins(0, 0, 0, 0)
        quarantine_panels_layout.setSpacing(8)
        quarantine_panels_layout.addWidget(
            app._panel_card(
                "Quarantine Inventory",
                app.antivirus_quarantine_table,
                lambda: app._open_panel_window("Antivirus Quarantine Inventory", app._clone_table(app.antivirus_quarantine_table)),
            ),
            2,
        )
        quarantine_panels_layout.addWidget(
            app._panel_card(
                "Quarantine Detail",
                app.antivirus_quarantine_detail,
                lambda: app._open_panel_window("Antivirus Quarantine Detail", app._clone_text_view(app.antivirus_quarantine_detail)),
            ),
            1,
        )
        quarantine_panels_layout.addWidget(
            app._panel_card(
                "Response Notes",
                app.antivirus_response_notes,
                lambda: app._open_panel_window("Antivirus Response Notes", app._clone_text_view(app.antivirus_response_notes)),
            ),
            1,
        )
        layout.addWidget(quarantine_panels, 1)
        return page

    def _build_history_page(self) -> QWidget:
        app = self.app
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        app.antivirus_history_table = QTableWidget(0, 6)
        app.antivirus_history_table.setHorizontalHeaderLabels(["Time", "Category", "Target", "Severity", "Operator Action", "Status"])
        app._style_table(app.antivirus_history_table)
        app.antivirus_history_table.itemSelectionChanged.connect(self.show_selected_history)

        app.antivirus_history_detail = QTextEdit()
        app.antivirus_history_detail.setReadOnly(True)
        app.antivirus_history_detail.setMinimumHeight(150)

        summary_card = QFrame()
        summary_card.setProperty("card", True)
        summary_layout = QHBoxLayout(summary_card)
        summary_layout.setContentsMargins(12, 10, 12, 10)
        summary_layout.setSpacing(8)
        app.antivirus_history_banner = QLabel("History keeps scan, containment, and notification actions in one audit stream.")
        app.antivirus_history_banner.setStyleSheet(
            "color:#ffd166;background:#1b2331;border:1px solid #34507a;border-radius:8px;padding:8px 10px;font-weight:600;"
        )
        summary_layout.addWidget(app.antivirus_history_banner, 1)
        layout.addWidget(summary_card)

        app.antivirus_history_table.setMinimumHeight(170)
        layout.addWidget(
            app._panel_card(
                "Antivirus History",
                app.antivirus_history_table,
                lambda: app._open_panel_window("Antivirus History", app._clone_table(app.antivirus_history_table)),
            ),
            1,
        )
        layout.addWidget(
            app._panel_card(
                "History Detail",
                app.antivirus_history_detail,
                lambda: app._open_panel_window("Antivirus History Detail", app._clone_text_view(app.antivirus_history_detail)),
            ),
            1,
        )
        return page

    def validation_sample_path(self) -> Path:
        return Path(__file__).resolve().parent.parent / "shadowlab_out" / "antivirus" / "validation" / "shadowlab_validation_sample.txt"

    def refresh_workspace(self) -> None:
        # Re-sync role-derived button enabled-state on every workspace
        # refresh — analyst-to-admin rotations during a session shouldn't
        # require a tab-switch to reflect in the Scan / Quarantine /
        # Vault buttons.
        self.apply_role_access()
        role = self.current_role()
        if role == "locked":
            self._set_scan_empty_state("Authentication is required before antivirus engines, verdicts, and quarantine workflows can be loaded.")
            self._set_quarantine_empty_state("Authentication is required to access quarantine inventory.")
            self._set_history_empty_state("Authentication is required to load antivirus audit history.")
            self.app.antivirus_overview_providers.setRowCount(0)
            self.app.antivirus_overview_queue.setRowCount(0)
            self.app.antivirus_status_summary.setHtml(
                "<h3>Antivirus Engine Posture</h3><p>Authentication required. Apply a valid key to load provider status, policy posture, and readiness.</p>"
            )
            self._render_overview_snapshot()
            return
        self.refresh_status()
        if role in {"analyst", "admin"}:
            self.refresh_quarantine_inventory()
        else:
            self.app.quarantine_records = []
            self.app.antivirus_quarantine_table.setRowCount(0)
            self._set_quarantine_empty_state("Viewer mode does not expose quarantine inventory. Apply analyst or admin access to review containment records.")
            self.app._set_metric_label(self.app.antivirus_quarantine_value, "0")
            self._render_overview_snapshot()

    def refresh_status(self) -> None:
        app = self.app
        try:
            payload = app._get("/antivirus/status", timeout=20).json()
        except Exception as exc:
            app.antivirus_status_payload = {}
            app.antivirus_overview_providers.setRowCount(0)
            app.antivirus_status_summary.setHtml(
                "<h3>Antivirus Engine Posture</h3><p>Provider status is unavailable right now. Refresh again after backend readiness is restored.</p>"
            )
            app.antivirus_live_status.setText("Engines unavailable")
            app._show_error(app.antivirus_result_detail, "Antivirus status load failed", exc)
            return
        app.antivirus_status_payload = payload
        providers = payload.get("providers", {}) if isinstance(payload.get("providers", {}), dict) else {}
        policy = payload.get("policy", {}) if isinstance(payload.get("policy", {}), dict) else {}
        signature_health = payload.get("signature_health", {}) if isinstance(payload.get("signature_health", {}), dict) else {}
        self._render_provider_matrix(providers)
        self._refresh_recent_mitre()
        app.antivirus_policy_badge.setText(
            "Policy: "
            + ("enabled" if policy.get("enabled") else "disabled")
            + " | "
            + str(policy.get("scan_profile", "balanced"))
            + " | Providers: "
            + ", ".join(str(item) for item in policy.get("providers", []))
        )
        app.antivirus_live_status.setText(f"Engines refreshed | Signature health: {signature_health.get('overall', 'unknown')}")
        self._apply_policy_to_controls(policy)
        self._refresh_kpis()

    def _update_engine_metrics(self, providers: dict) -> None:
        # Replaced by _refresh_kpis() in the product-grade layout, but kept
        # for backwards compatibility with auto-refresh callers.
        self._refresh_kpis()

    def _render_status_summary(self, providers: dict, policy: dict, signature_health: dict) -> str:
        rows: list[str] = []
        for key in ["aegis_core", "sentinel_cli"]:
            provider = providers.get(key, {}) if isinstance(providers.get(key, {}), dict) else {}
            details: list[str] = []
            if provider.get("version"):
                details.append(f"version {html.escape(str(provider.get('version')))}")
            if provider.get("definitions_loaded") is not None:
                details.append("definitions loaded" if provider.get("definitions_loaded") else "definitions pending")
            if provider.get("database_files"):
                details.append(f"db files {len(provider.get('database_files', []))}")
            if provider.get("system_rule_files") or provider.get("user_rule_files"):
                details.append(
                    f"rules sys={html.escape(str(provider.get('system_rule_files', 0)))} user={html.escape(str(provider.get('user_rule_files', 0)))}"
                )
            rows.append(
                f"<li><b>{html.escape(str(provider.get('display_name', key)))}</b>: "
                f"{'ready' if provider.get('available') else 'offline'}"
                + (f" | {' | '.join(details)}" if details else "")
                + "</li>"
            )
        return (
            "<h3>Antivirus Engine Posture</h3>"
            f"<p><b>Profile:</b> {html.escape(str(policy.get('scan_profile', 'balanced')))}"
            f" | <b>Auto-quarantine:</b> {html.escape(str(policy.get('auto_quarantine_threshold', 'disabled')))}</p>"
            f"<p><b>Signature health:</b> {html.escape(str(signature_health.get('overall', 'unknown')))}"
            f" | <b>Grace:</b> {html.escape(str(signature_health.get('grace_hours', policy.get('signature_grace_hours', 48))))}h"
            f" | <b>Validation:</b> {html.escape(str(policy.get('scheduled_validation_minutes', 240)))} min</p>"
            f"<ul>{''.join(rows)}</ul>"
        )

    def _apply_policy_to_controls(self, policy: dict) -> None:
        app = self.app
        if not hasattr(app, "antivirus_policy_enabled"):
            return
        providers = [str(item) for item in policy.get("providers", [])]
        app.antivirus_policy_enabled.setChecked(bool(policy.get("enabled", True)))
        toggle_for_key = {
            "aegis_core":     app.antivirus_policy_provider_aegis,
            "sentinel_cli":   app.antivirus_policy_provider_sentinel,
            "cloud_intel":    app.antivirus_policy_provider_cloud,
            "yara_x":         app.antivirus_policy_provider_yara,
            "behavioural":    app.antivirus_policy_provider_behavioural,
            "cloud_sandbox":  app.antivirus_policy_provider_sandbox,
        }
        for key, toggle in toggle_for_key.items():
            toggle.setChecked(key in providers)
        app.antivirus_policy_profile.setCurrentText(str(policy.get("scan_profile", "balanced")))
        app.antivirus_policy_threshold.setCurrentText(str(policy.get("auto_quarantine_threshold", "disabled")))
        app.antivirus_policy_schedule.setValue(int(policy.get("scheduled_validation_minutes", 240) or 240))
        app.antivirus_policy_grace.setValue(int(policy.get("signature_grace_hours", 48) or 48))
        yara_pack = str(policy.get("yara_pack", "enterprise") or "enterprise").lower()
        if yara_pack in YARA_PACKS:
            app.antivirus_policy_yara_pack.setCurrentText(yara_pack)
        app.antivirus_policy_mitre_enabled.setChecked(bool(policy.get("mitre_mapping_enabled", True)))

    def save_policy(self) -> None:
        app = self.app
        providers: list[str] = []
        toggle_for_key = [
            ("aegis_core",    app.antivirus_policy_provider_aegis),
            ("sentinel_cli",  app.antivirus_policy_provider_sentinel),
            ("cloud_intel",   app.antivirus_policy_provider_cloud),
            ("yara_x",        app.antivirus_policy_provider_yara),
            ("behavioural",   app.antivirus_policy_provider_behavioural),
            ("cloud_sandbox", app.antivirus_policy_provider_sandbox),
        ]
        for key, toggle in toggle_for_key:
            if toggle.isChecked():
                providers.append(key)
        payload = {
            "enabled": app.antivirus_policy_enabled.isChecked(),
            "providers": providers,
            "max_file_size_mb": 128,
            "scan_profile": app.antivirus_policy_profile.currentText(),
            "quarantine_on_infected": app.antivirus_policy_threshold.currentText() != "disabled",
            "auto_quarantine_threshold": app.antivirus_policy_threshold.currentText(),
            "require_admin_for_quarantine": True,
            "scan_timeout_seconds": 120,
            "scheduled_validation_minutes": int(app.antivirus_policy_schedule.value()),
            "signature_grace_hours": int(app.antivirus_policy_grace.value()),
            "yara_pack": app.antivirus_policy_yara_pack.currentText(),
            "mitre_mapping_enabled": app.antivirus_policy_mitre_enabled.isChecked(),
        }
        try:
            result = app._put("/antivirus/policy", json=payload, timeout=20).json()
        except Exception as exc:
            app._show_error(app.antivirus_result_detail, "Antivirus policy save failed", exc)
            return
        self._record_history(
            category="policy",
            action="save policy",
            target="antivirus policy",
            severity="low",
            status=str(result.get("status", "updated") or "updated"),
            payload=result,
        )
        app.statusBar().showMessage("Antivirus policy updated.")
        self.refresh_status()

    def _refresh_provider_table(self, providers: dict) -> None:
        table = self.app.antivirus_overview_providers
        keys = ["aegis_core", "sentinel_cli"]
        table.setRowCount(len(keys))
        for row, key in enumerate(keys):
            provider = providers.get(key, {}) if isinstance(providers.get(key, {}), dict) else {}
            coverage = []
            if provider.get("definitions_loaded") is not None:
                coverage.append("definitions" if provider.get("definitions_loaded") else "pending defs")
            if provider.get("database_files"):
                coverage.append(f"{len(provider.get('database_files', []))} db files")
            if provider.get("system_rule_files"):
                coverage.append(f"{provider.get('system_rule_files')} rule files")
            values = [
                provider.get("display_name", key),
                "ready" if provider.get("available") else "offline",
                provider.get("version", "n/a"),
                ", ".join(str(item) for item in coverage) or "runtime only",
            ]
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(str(value)))
            self.app._paint_row(table, row, self.app._severity_color("low" if provider.get("available") else "high"))

    def _render_overview_snapshot(self) -> None:
        # In the product-grade layout the snapshot is replaced by KPI tiles
        # plus the MITRE heat-map. Keep this method as a delegating
        # compatibility shim so legacy callers stay safe.
        self._refresh_kpis()
        self._render_mitre_heatmap()

    def _refresh_overview_queue(self) -> None:
        # The recent-response queue is now the verdict table itself; this
        # shim avoids breaking older callers that expected a separate
        # widget refresh.
        return None

    def scan_validation_sample(self) -> None:
        self.app.antivirus_target_path.setText(str(self.validation_sample_path()))
        self.scan_target_file()

    def scan_target_file(self) -> None:
        target = self.app.antivirus_target_path.text().strip()
        if not target:
            self.app.statusBar().showMessage("⚠ Provide a file path to scan", 5000)
            return
        # Pre-flight: check the path actually exists locally so the
        # analyst gets a fast, specific error instead of a 400 from the
        # server-side path-validation gate.
        path_obj = Path(target).expanduser()
        if not path_obj.exists():
            self.app.statusBar().showMessage(f"✗ Target path not found on disk: {path_obj}", 8000)
            return
        try:
            result = self.app._post("/antivirus/scan/file", json={"file_path": target}, timeout=120).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"✗ Scan failed: {exc}", 10000)
            self.app._show_error(self.app.antivirus_result_detail, "Antivirus file scan failed", exc)
            return
        self._record_scan_result(result, scope="file")
        # Visible verdict feedback in the status bar.
        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        verdict = str(summary.get("fused_verdict", result.get("status", "unknown")))
        severity = str(summary.get("severity", "low"))
        engine_count = len(result.get("providers", {}) if isinstance(result.get("providers"), dict) else {})
        duration_ms = int(result.get("duration_ms", 0) or 0)
        glyph = "●" if verdict in {"infected", "malicious"} else "◐" if verdict == "suspicious" else "○"
        self.app.statusBar().showMessage(
            f"{glyph} Scan complete · {verdict} · {severity} · {engine_count} engines · {duration_ms} ms", 8000
        )
        # Toast — visible without staring at the status bar.
        toast_level = "error" if verdict in {"infected", "malicious"} else "warn" if verdict == "suspicious" else "success"
        try:
            self.toast(
                f"{glyph} {verdict.upper()} · {Path(target or 'target').name} · {duration_ms} ms",
                level=toast_level,
                duration_ms=6000,
            )
        except Exception:
            pass

    def scan_selected_process(self) -> None:
        pid = self._selected_process_pid()
        if pid is None:
            self.app.statusBar().showMessage("⚠ Select a process first in the Processes tab", 5000)
            return
        try:
            result = self.app._post(f"/antivirus/scan/processes/{pid}", timeout=120).json()
        except Exception as exc:
            self.app.statusBar().showMessage(f"✗ Process scan failed: {exc}", 10000)
            self.app._show_error(self.app.antivirus_result_detail, "Antivirus process scan failed", exc)
            return
        self._record_scan_result(result, scope="process")
        summary = result.get("summary", {}) if isinstance(result.get("summary"), dict) else {}
        verdict = str(summary.get("fused_verdict", result.get("status", "unknown")))
        self.app.statusBar().showMessage(f"✓ Process scan complete · pid={pid} · verdict={verdict}", 6000)

    def _selected_process_pid(self) -> int | None:
        selected = getattr(self.app, "selected_process", None)
        if isinstance(selected, dict):
            try:
                return int(selected.get("pid", 0) or 0)
            except Exception:
                return None
        table = getattr(self.app, "proc_table", None)
        row = table.currentRow() if table is not None else -1
        if row < 0:
            return None
        item = table.item(row, 1)
        if item is None:
            return None
        try:
            return int(item.text())
        except Exception:
            return None

    def _record_scan_result(self, result: dict, *, scope: str) -> None:
        app = self.app
        summary = result.get("summary", {}) if isinstance(result.get("summary", {}), dict) else {}
        providers = result.get("providers", {}) if isinstance(result.get("providers", {}), dict) else {}
        process_meta = result.get("process", {}) if isinstance(result.get("process", {}), dict) else {}
        target = process_meta.get("exe") if scope == "process" else result.get("path")
        verdict = str(summary.get("fused_verdict", result.get("status", "unknown")) or "unknown").lower()
        techniques = summary.get("mitre_techniques", []) if isinstance(summary.get("mitre_techniques"), list) else []
        first_tech_id = str(techniques[0].get("id", "")) if techniques else ""
        mitre_text = (
            f"{first_tech_id} +{len(techniques)-1}" if len(techniques) > 1
            else first_tech_id or "—"
        )
        provider_keys = [k for k, v in providers.items() if isinstance(v, dict)]
        engines_text = ", ".join(PROVIDER_KEY_TO_DISPLAY.get(k, k) for k in provider_keys[:3])
        if len(provider_keys) > 3:
            engines_text += f" +{len(provider_keys)-3}"
        row_payload = {
            "scope": scope,
            "target": str(target or ""),
            "severity": str(summary.get("severity", "low") or "low"),
            "verdict": verdict,
            "status": str(result.get("status", verdict) or verdict),
            "mitre_text": mitre_text,
            "engines_text": engines_text or "—",
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "created_at": time.time(),
            "sha256": str(result.get("sha256", "") or ""),
            "payload": result,
        }
        app.antivirus_scan_results.insert(0, row_payload)
        # Cap list to last 200 to keep memory bounded — bigger than the
        # old 100 because filter-narrowed views feel empty otherwise.
        app.antivirus_scan_results = app.antivirus_scan_results[:200]
        # Keep the latest scan's MITRE coverage front-and-centre on the heat-map.
        app.antivirus_mitre_techniques = techniques
        app.antivirus_mitre_coverage = summary.get("mitre_coverage", {}) if isinstance(summary.get("mitre_coverage"), dict) else {}
        self._render_mitre_heatmap()
        self._render_verdict_table(select_first=True)
        self._record_history(
            category="scan",
            action=f"{scope} scan",
            target=row_payload["target"],
            severity=row_payload["severity"],
            status=row_payload["status"],
            payload=result,
        )
        self.show_selected_result()
        self._refresh_kpis()

    def _render_verdict_table(self, *, select_first: bool = False) -> None:
        """Apply current filter chips and repaint the verdict table.

        Filter rules — a row passes when:
          * verdict chip == 'all' OR row.verdict matches (with the
            'infected' chip also matching 'malicious');
          * severity chip == 'all' OR row.severity matches;
          * time_window chip == 'all' OR row.created_at >= now-window.
        """
        app = self.app
        table = app.antivirus_results_table
        all_rows = list(getattr(app, "antivirus_scan_results", []))
        filt = getattr(self, "_verdict_filters", {"verdict": "all", "severity": "all", "time_window": "24h"})
        verdict_f = filt.get("verdict", "all")
        severity_f = filt.get("severity", "all")
        window_f = filt.get("time_window", "24h")
        cutoff = 0.0
        if window_f != "all":
            seconds = {"1h": 3600, "24h": 24 * 3600, "7d": 7 * 24 * 3600}.get(window_f, 24 * 3600)
            cutoff = time.time() - seconds

        def _passes(item: dict) -> bool:
            verdict_low = str(item.get("verdict", "")).lower()
            if verdict_f == "infected" and verdict_low not in {"infected", "malicious"}:
                return False
            if verdict_f == "error" and verdict_low not in {"error", "degraded"}:
                return False
            if verdict_f not in {"all", "infected", "error"} and verdict_low != verdict_f:
                return False
            if severity_f != "all" and str(item.get("severity", "")).lower() != severity_f:
                return False
            if cutoff > 0 and float(item.get("created_at", 0) or 0) < cutoff:
                return False
            return True

        filtered = [item for item in all_rows if _passes(item)]
        # Cache the filtered slice for bulk-action handlers.
        self._filtered_verdict_rows = filtered
        table.setRowCount(len(filtered))
        for row, item in enumerate(filtered):
            verdict_low = str(item["verdict"]).lower()
            dot = "●" if verdict_low in {"infected", "malicious"} else "◐" if verdict_low == "suspicious" else "○"
            sha = str(item.get("sha256", "") or "")
            sha_display = (sha[:12] + "…") if sha else "—"
            cells = [
                dot,
                item.get("timestamp", ""),
                Path(item["target"]).name if item.get("target") else "—",
                verdict_low,
                item.get("severity", ""),
                item.get("mitre_text", "—"),
                item.get("engines_text", "—"),
                sha_display,
            ]
            for col, value in enumerate(cells):
                cell = QTableWidgetItem(str(value))
                if col == 0:
                    cell.setTextAlignment(Qt.AlignCenter)
                    cell.setForeground(self._verdict_brush(verdict_low))
                if col == 7 and sha:
                    cell.setToolTip(f"{sha} (right-click → Copy SHA-256)")
                table.setItem(row, col, cell)
            app._paint_row(table, row, app._severity_color(item.get("severity", "low")))
        # Match-counter label.
        if hasattr(self, "_verdict_match_label"):
            self._verdict_match_label.setText(f"{len(filtered)} / {len(all_rows)} shown")
        if select_first and filtered:
            table.selectRow(0)
        self._refresh_bulk_state()

    def _verdict_brush(self, verdict: str):
        from PySide6.QtGui import QBrush, QColor
        return QBrush(QColor(VERDICT_COLOUR.get(str(verdict).lower(), "#c8d8ea")))

    def show_selected_result(self) -> None:
        row = self.app.antivirus_results_table.currentRow()
        if row < 0:
            self._set_scan_empty_state()
            return
        items = getattr(self.app, "antivirus_scan_results", [])
        if row >= len(items):
            self._set_scan_empty_state()
            return
        payload = items[row]["payload"]
        summary = payload.get("summary", {}) if isinstance(payload.get("summary", {}), dict) else {}
        process_meta = payload.get("process", {}) if isinstance(payload.get("process", {}), dict) else {}
        target = process_meta.get("exe") or payload.get("path") or "unknown target"
        reasons = "".join(f"<li>{html.escape(str(item))}</li>" for item in summary.get("reasons", [])[:6])
        actions = "".join(f"<li>{html.escape(str(item))}</li>" for item in summary.get("recommended_actions", [])[:5])
        self.app.antivirus_result_detail.setHtml(
            "<h3>Fused Verdict</h3>"
            f"<p><b>Target:</b> {html.escape(str(target))}</p>"
            f"<p><b>Verdict:</b> {html.escape(str(summary.get('fused_verdict', payload.get('status', 'unknown'))))}"
            f" | <b>Severity:</b> {html.escape(str(summary.get('severity', 'low')))}"
            f" | <b>Confidence:</b> {html.escape(str(summary.get('confidence', 'low')))}"
            f" | <b>Score:</b> {html.escape(str(summary.get('score', 0)))}</p>"
            f"<p><b>Auto-quarantine ready:</b> {html.escape(str(summary.get('auto_quarantine_ready', False)))}"
            f" | <b>SHA-256:</b> {html.escape(str(payload.get('sha256', '') or 'unavailable'))}</p>"
            f"<h4>Why It Triggered</h4><ul>{reasons or '<li>No reasons recorded.</li>'}</ul>"
            f"<h4>Recommended Actions</h4><ul>{actions or '<li>No actions recorded.</li>'}</ul>"
        )
        provider_cards = summary.get("provider_cards", []) if isinstance(summary.get("provider_cards", []), list) else []
        provider_html: list[str] = []
        for card in provider_cards:
            provider_html.append(
                "<li>"
                f"<b>{html.escape(str(card.get('engine', card.get('provider', 'provider'))))}</b>: "
                f"{html.escape(str(card.get('status', 'unknown')))}"
                + (
                    f" | detection {html.escape(str(card.get('malware_name', '')))}"
                    if str(card.get("malware_name", "")).strip()
                    else ""
                )
                + (
                    f" | error {html.escape(str(card.get('error', '')))}"
                    if str(card.get("error", "")).strip()
                    else ""
                )
                + f" | {html.escape(str(card.get('scan_time_ms', 0)))} ms"
                + "</li>"
            )
        self.app.antivirus_provider_hits.setHtml(
            "<h3>Provider-by-Provider Hits</h3>"
            + (f"<ul>{''.join(provider_html)}</ul>" if provider_html else "<p>No provider details recorded.</p>")
        )
        self.app.antivirus_scan_guidance.setHtml(
            "<h3>Operator Guidance</h3>"
            f"<p><b>Current threshold:</b> {html.escape(str(payload.get('policy', {}).get('auto_quarantine_threshold', 'disabled')))}</p>"
            f"<p><b>Profile:</b> {html.escape(str(payload.get('policy', {}).get('scan_profile', 'balanced')))}</p>"
            "<p>Use analyst mode for scan triage and admin mode for containment. High-confidence dual-engine hits should pivot into quarantine and enterprise case escalation.</p>"
        )

    def quarantine_selected_result(self) -> None:
        row = self.app.antivirus_results_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a detection result first")
            return
        items = getattr(self.app, "antivirus_scan_results", [])
        if row >= len(items):
            return
        if not self._check_response_gate("quarantine"):
            return
        payload = items[row]["payload"]
        process_meta = payload.get("process", {}) if isinstance(payload.get("process", {}), dict) else {}
        target_path = str(payload.get("path", "") or "")
        if not target_path:
            self.app._show_error(
                self.app.antivirus_quarantine_detail,
                "Antivirus quarantine blocked",
                Exception("Selected detection has no file path; refusing to send an empty quarantine request."),
            )
            return
        body = {
            "file_path": target_path,
            "pid": int(process_meta.get("pid", -1) or -1),
            "process_name": str(process_meta.get("name", "") or Path(target_path).name),
            "actor": self.app.actor_name.text().strip() or "desktop",
        }
        if hasattr(self.app, "_selected_enterprise_case_id"):
            try:
                case_id = self.app._selected_enterprise_case_id()
            except Exception:
                case_id = None
            if case_id is not None:
                body["case_id"] = int(case_id)
        reason = self._capture_reason("quarantine")
        if reason is None:
            return

        def _on_ok(result: dict) -> None:
            self.app._show_json(self.app.antivirus_quarantine_detail, result)
            self._record_history(
                category="response",
                action="quarantine",
                target=str(body.get("file_path") or process_meta.get("exe") or process_meta.get("name") or ""),
                severity="high",
                status=str(result.get("status", "submitted") or "submitted"),
                payload=result,
                reason=reason,
            )
            self.refresh_quarantine_inventory()

        def _on_err(message: str) -> None:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Antivirus quarantine failed", Exception(message))
            self._record_history(
                category="response",
                action="quarantine",
                target=target_path,
                severity="high",
                status="failed",
                payload={"error": message},
                reason=reason,
            )

        self._submit_async(
            f"Quarantine {Path(target_path).name}",
            lambda: self.app._post("/antivirus/respond/quarantine", json=body, timeout=45).json(),
            _on_ok,
            _on_err,
            timeout_seconds=55,
        )

    def create_case_from_selected_result(self) -> None:
        row = self.app.antivirus_results_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a scan result first")
            return
        items = getattr(self.app, "antivirus_scan_results", [])
        if row >= len(items):
            return
        payload = items[row]["payload"]
        summary = payload.get("summary", {}) if isinstance(payload.get("summary", {}), dict) else {}
        target = str(payload.get("process", {}).get("exe") or payload.get("path") or "antivirus detection")
        owner = self.app.enterprise_case_owner.text().strip() or self.app.actor_name.text().strip() or "desktop"
        priority = "critical" if str(summary.get("severity", "high")).lower() == "critical" else "high"
        case_payload = {
            "title": f"AV detection: {Path(target).name}",
            "owner": owner,
            "priority": priority,
            "source_scan": payload,
            "create_story": True,
        }
        try:
            result = self.app._post("/antivirus/enterprise/cases", json=case_payload, timeout=40).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_result_detail, "Create enterprise case failed", exc)
            return
        case_record = result.get("case", {}) if isinstance(result.get("case", {}), dict) else {}
        case_id = int(case_record.get("id", 0) or 0)
        self._record_history(
            category="enterprise",
            action="create case",
            target=target,
            severity=str(summary.get("severity", "high") or "high"),
            status=str(result.get("status", "created") or "created"),
            payload=result,
        )
        self.app.enterprise_case_title.setText(str(case_record.get("title", self.app.enterprise_case_title.text())))
        self.app.enterprise_case_owner.setText(str(case_record.get("owner", owner)))
        priority_value = str(case_record.get("priority", priority))
        idx = self.app.enterprise_case_priority.findText(priority_value)
        if idx >= 0:
            self.app.enterprise_case_priority.setCurrentIndex(idx)
        self.app.statusBar().showMessage(f"Enterprise case {case_id} created from antivirus detection.")
        self.show_selected_result()
        if hasattr(self.app, "refresh_enterprise_workspace"):
            self.app.refresh_enterprise_workspace()

    def export_selected_result_report(self) -> None:
        row = self.app.antivirus_results_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a scan result first")
            return
        items = getattr(self.app, "antivirus_scan_results", [])
        if row >= len(items):
            return
        try:
            result = self.app._post(
                "/antivirus/report/detection/export",
                json={"source_scan": items[row]["payload"]},
                timeout=40,
            ).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_result_detail, "Detection report export failed", exc)
            return
        self._record_history(
            category="artifact",
            action="export detection report",
            target=str(items[row].get("target", "")),
            severity=str(items[row].get("severity", "low")),
            status=str(result.get("status", "exported")),
            payload=result,
        )
        self.app.statusBar().showMessage("Antivirus detection report exported.")
        if hasattr(self.app, "refresh_artifacts"):
            self.app.refresh_artifacts()

    def export_selected_quarantine_report(self) -> None:
        row = self.app.antivirus_quarantine_table.currentRow()
        if row < 0:
            self.app.statusBar().showMessage("Select a quarantine item first")
            return
        items = getattr(self.app, "quarantine_records", [])
        if row >= len(items):
            return
        try:
            result = self.app._post(
                "/antivirus/report/quarantine/export",
                json={"quarantine_record": items[row]},
                timeout=40,
            ).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Quarantine report export failed", exc)
            return
        self._record_history(
            category="artifact",
            action="export quarantine report",
            target=str(items[row].get("quarantine_path", items[row].get("original_path", ""))),
            severity="medium",
            status=str(result.get("status", "exported")),
            payload=result,
        )
        self.app.statusBar().showMessage("Antivirus quarantine report exported.")
        if hasattr(self.app, "refresh_artifacts"):
            self.app.refresh_artifacts()

    def refresh_quarantine_inventory(self) -> None:
        try:
            items = self.app._get("/quarantine", timeout=20).json()
        except Exception as exc:
            self.app.quarantine_records = []
            self.app.antivirus_quarantine_table.setRowCount(0)
            self.app._set_metric_label(self.app.antivirus_quarantine_value, "0")
            self.app._show_error(self.app.antivirus_quarantine_detail, "Quarantine load failed", exc)
            return
        self.app.quarantine_records = items
        self.app.antivirus_quarantine_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                item.get("id", ""),
                item.get("process_name", ""),
                item.get("original_path", ""),
                item.get("quarantine_path", ""),
                item.get("status", ""),
                item.get("created_at", ""),
            ]
            for column, value in enumerate(values):
                self.app.antivirus_quarantine_table.setItem(row, column, QTableWidgetItem(str(value)))
            severity = "medium" if str(item.get("status", "")).lower() == "active" else "low"
            self.app._paint_row(self.app.antivirus_quarantine_table, row, self.app._severity_color(severity))
        if items:
            self._set_quarantine_empty_state("Select a quarantine item to inspect its record, original path, and containment status.")
        else:
            self._set_quarantine_empty_state("No quarantine items recorded.\n\nTrigger containment from the Scan tab or refresh later if another operator already quarantined a target.")
        self.app._set_metric_label(self.app.antivirus_quarantine_value, str(len(items)))
        self._render_overview_snapshot()

    def show_selected_quarantine(self) -> None:
        row = self.app.antivirus_quarantine_table.currentRow()
        if row < 0:
            self._set_quarantine_empty_state()
            return
        items = getattr(self.app, "quarantine_records", [])
        if row >= len(items):
            self._set_quarantine_empty_state()
            return
        self.app._show_json(self.app.antivirus_quarantine_detail, items[row])

    def restore_selected_quarantine(self) -> None:
        row = self.app.antivirus_quarantine_table.currentRow()
        if row < 0:
            self._set_quarantine_empty_state("Select a quarantine item before restoring it.")
            return
        if not self._check_response_gate("quarantine"):
            return
        quarantine_id = self.app.antivirus_quarantine_table.item(row, 0).text()
        reason = self._capture_reason(f"quarantine-restore (id={quarantine_id})")
        if reason is None:
            return
        try:
            result = self.app._post(f"/quarantine/{quarantine_id}/restore", timeout=30).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Quarantine restore failed", exc)
            self._record_history(
                category="response",
                action="restore",
                target=quarantine_id,
                severity="medium",
                status="failed",
                payload={"error": str(exc)},
                reason=reason,
            )
            return
        self.app._show_json(self.app.antivirus_quarantine_detail, result)
        self._record_history(
            category="response",
            action="restore",
            target=quarantine_id,
            severity="medium",
            status=str(result.get("status", "restored") or "restored"),
            payload=result,
            reason=reason,
        )
        self.refresh_quarantine_inventory()

    def delete_selected_quarantine(self) -> None:
        from PySide6.QtWidgets import QMessageBox
        row = self.app.antivirus_quarantine_table.currentRow()
        if row < 0:
            self._set_quarantine_empty_state("Select a quarantine item before deleting it.")
            return
        if not self._check_response_gate("quarantine"):
            return
        quarantine_id = self.app.antivirus_quarantine_table.item(row, 0).text()
        # Confirm — the server delete is irreversible (vault entry is
        # purged) and we don't want a stray click to destroy evidence
        # mid-investigation.
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Confirm quarantine delete")
        confirm.setText(f"Permanently delete quarantine entry {quarantine_id}?")
        confirm.setInformativeText(
            "The sealed copy will be unrecoverable. Provide a structured reason next."
        )
        confirm.setIcon(QMessageBox.Critical)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason(f"quarantine-delete (id={quarantine_id})")
        if reason is None:
            return
        try:
            result = self.app._delete(f"/quarantine/{quarantine_id}", timeout=30).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Quarantine delete failed", exc)
            self._record_history(
                category="response",
                action="delete",
                target=quarantine_id,
                severity="high",
                status="failed",
                payload={"error": str(exc)},
                reason=reason,
            )
            return
        self.app._show_json(self.app.antivirus_quarantine_detail, result)
        self._record_history(
            category="response",
            action="delete",
            target=quarantine_id,
            severity="high",
            status=str(result.get("status", "deleted") or "deleted"),
            payload=result,
            reason=reason,
        )
        self.refresh_quarantine_inventory()

    def open_selected_quarantine(self) -> None:
        row = self.app.antivirus_quarantine_table.currentRow()
        if row < 0:
            self._set_quarantine_empty_state("Select a quarantine item before opening its preserved copy.")
            return
        items = getattr(self.app, "quarantine_records", [])
        if row >= len(items):
            return
        target = str(items[row].get("quarantine_path", "") or "")
        if not target:
            self.app.statusBar().showMessage("No quarantine copy path available")
            return
        self._record_history(
            category="response",
            action="open quarantine copy",
            target=target,
            severity="low",
            status="opened",
            payload=items[row],
        )
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(target).resolve())))

    def test_alert_webhook(self) -> None:
        if not self.app.webhook_url.text().strip():
            self.app.statusBar().showMessage("Enter a webhook URL first")
            return
        try:
            result = self.app._post(
                "/alerts/test",
                json={"webhook_url": self.app.webhook_url.text().strip(), "message": "ShadowLab test alert"},
                timeout=20,
            ).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Webhook test failed", exc)
            return
        self.app._show_json(self.app.antivirus_quarantine_detail, result)
        self._record_history(
            category="notification",
            action="test webhook",
            target=self.app.webhook_url.text().strip(),
            severity="low",
            status=str(result.get("status", "sent") or "sent"),
            payload=result,
        )

    def save_alert_webhook(self) -> None:
        if not self.app.webhook_url.text().strip():
            self.app.statusBar().showMessage("Enter a webhook URL first")
            return
        try:
            result = self.app._post(
                "/alerts/configure",
                json={"webhook_url": self.app.webhook_url.text().strip(), "message": "ShadowLab configured"},
                timeout=20,
            ).json()
        except Exception as exc:
            self.app._show_error(self.app.antivirus_quarantine_detail, "Webhook save failed", exc)
            return
        self.app._show_json(self.app.antivirus_quarantine_detail, result)
        self._record_history(
            category="notification",
            action="save webhook",
            target=self.app.webhook_url.text().strip(),
            severity="low",
            status=str(result.get("status", "configured") or "configured"),
            payload=result,
        )

    def _record_history(self, *, category: str, action: str, target: str, severity: str, status: str, payload: dict, reason: dict | None = None) -> None:
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
        # Mirror into the UI list so the in-app table render path
        # doesn't need to reload from disk on every action.
        if not hasattr(self.app, "antivirus_history_entries") or not isinstance(self.app.antivirus_history_entries, list):
            self.app.antivirus_history_entries = []
        self.app.antivirus_history_entries.insert(0, entry)
        del self.app.antivirus_history_entries[ANTIVIRUS_AUDIT_LOG_RETENTION:]
        self._refresh_history_table()
        self._render_overview_snapshot()

    def _refresh_history_table(self) -> None:
        table = self.app.antivirus_history_table
        items = getattr(self.app, "antivirus_history_entries", [])
        table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                item.get("timestamp", ""),
                item.get("category", ""),
                item.get("target", ""),
                item.get("severity", ""),
                item.get("action", ""),
                item.get("status", ""),
            ]
            for column, value in enumerate(values):
                table.setItem(row, column, QTableWidgetItem(str(value)))
            self.app._paint_row(table, row, self.app._severity_color(str(item.get("severity", "low"))))
        if not items:
            self._set_history_empty_state()

    def show_selected_history(self) -> None:
        row = self.app.antivirus_history_table.currentRow()
        if row < 0:
            self._set_history_empty_state()
            return
        items = getattr(self.app, "antivirus_history_entries", [])
        if row >= len(items):
            self._set_history_empty_state()
            return
        self.app._show_json(self.app.antivirus_history_detail, items[row]["payload"])
