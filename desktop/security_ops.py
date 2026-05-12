from __future__ import annotations

import datetime as _dt
import html
import json
import time
from pathlib import Path

from PySide6.QtGui import QBrush, QColor, QDesktopServices, QFont, QKeySequence, QShortcut
from PySide6.QtCore import Qt, QUrl
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


# ----- Secret-redaction layer for the Detail pane.
#
# Even though the server already encrypts secrets at rest, mutating
# responses (rotate, save policy, etc.) routinely echo back fields like
# `secret_id`, raw `secret`, webhook URLs with tokens, or fresh API
# credentials. Dumping them verbatim into the on-screen "Detail" pane
# turns every shoulder-surf / screen-share into a credential leak. We
# redact client-side before display.
_SECRET_FIELDS: frozenset[str] = frozenset({
    "secret", "secret_id", "secret_value", "new_secret", "raw_secret",
    "token", "access_token", "refresh_token", "bearer", "api_key",
    "client_secret", "shared_key", "authorization", "password",
    "signing_key", "signing_secret", "private_key", "credential",
})
_URL_TOKEN_RE = (
    # Discord / Slack / Telegram webhooks all embed their auth token in
    # the path; mask everything after the third "/" past the host.
    r"(https?://[^/\s]+/[^/\s]+/[^/\s]+/)([^\s\"']+)"
)


def _redact_payload(obj):
    """Recursive deep-copy that masks secret-bearing keys and webhook tokens."""
    if isinstance(obj, dict):
        out: dict = {}
        for key, value in obj.items():
            if str(key).lower() in _SECRET_FIELDS and value not in (None, "", 0):
                out[key] = "***redacted***"
            else:
                out[key] = _redact_payload(value)
        return out
    if isinstance(obj, list):
        return [_redact_payload(item) for item in obj]
    if isinstance(obj, str):
        import re as _re
        return _re.sub(_URL_TOKEN_RE, r"\1***redacted***", obj)
    return obj


def _redact_url_for_display(url: str) -> str:
    """Show scheme://host + a hint of the path, mask the token."""
    if not url:
        return "<no webhook configured>"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path[:24]
        return f"{parsed.scheme}://{host}/***redacted***"
    except Exception:
        return url[:24] + "..."


# ----- KPI / status colour palette (matches the dark theme used elsewhere)
_KPI_OK = "#1b4332"        # deep green
_KPI_WARN = "#5c4400"      # amber
_KPI_CRIT = "#5f1d1d"      # deep red
_KPI_NEUTRAL = "#1f2933"   # slate
_KPI_TEXT_OK = "#9ae6b4"
_KPI_TEXT_WARN = "#f6e05e"
_KPI_TEXT_CRIT = "#feb2b2"
_KPI_TEXT_NEUTRAL = "#cbd5e0"

_KPI_TONE_PALETTE = {
    "ok": (_KPI_OK, _KPI_TEXT_OK),
    "warn": (_KPI_WARN, _KPI_TEXT_WARN),
    "crit": (_KPI_CRIT, _KPI_TEXT_CRIT),
    "neutral": (_KPI_NEUTRAL, _KPI_TEXT_NEUTRAL),
}


class _SparklineWidget(QWidget):
    """Tiny inline trend strip rendered with QPainter (no QtCharts dep).

    Holds the most recent ~30 numeric samples and draws a connected
    polyline scaled to the chip width. We keep it small so it fits
    inside the existing 86-px KPI chip without changing the layout.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(18)
        self.setMinimumWidth(60)
        self._samples: list[float] = []
        self._tone_colour: str = "#9aa5b1"

    def push(self, value: float, tone: str = "neutral") -> None:
        self._samples.append(float(value or 0))
        if len(self._samples) > 30:
            self._samples = self._samples[-30:]
        self._tone_colour = {
            "ok": "#9ae6b4", "warn": "#f6e05e", "crit": "#feb2b2", "neutral": "#9aa5b1",
        }.get(tone, "#9aa5b1")
        self.update()

    def paintEvent(self, event):  # type: ignore[override]
        from PySide6.QtGui import QPainter, QPen, QColor
        if len(self._samples) < 2:
            return
        painter = QPainter(self)
        try:
            painter.setRenderHint(QPainter.Antialiasing, True)
            pen = QPen(QColor(self._tone_colour))
            pen.setWidth(2)
            painter.setPen(pen)
            w = max(1, self.width() - 4)
            h = max(1, self.height() - 4)
            lo = min(self._samples)
            hi = max(self._samples)
            span = max(1.0, hi - lo)
            step = w / (len(self._samples) - 1)
            prev = None
            for idx, sample in enumerate(self._samples):
                x = 2 + idx * step
                y = 2 + (h - (sample - lo) / span * h)
                if prev is not None:
                    painter.drawLine(int(prev[0]), int(prev[1]), int(x), int(y))
                prev = (x, y)
        finally:
            painter.end()


class _KpiChip(QFrame):
    """Compact KPI chip - three stacked labels inside a rounded frame.

    Rendering with Qt widgets (instead of inline HTML inside a
    QTextBrowser) avoids the layout collapse seen on tall content + the
    inability to size chips uniformly across the strip.

    Clickable when an `on_click` handler is wired in - the cursor turns
    into a pointing-hand so the affordance is obvious. Drill-down lets
    an operator jump from "Drift: 5" to the integrity panel without
    hunting for the right card.

    A small `_SparklineWidget` lives below the hint line; `update()`
    pushes the latest numeric value into it so the operator gets a
    trend without leaving the KPI strip.
    """

    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("kpiChip")
        self.setFrameShape(QFrame.NoFrame)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        # No per-chip card border — the strip reads as one visual unit
        # instead of five separate mini-cards. Removes the screenshot-
        # reported "every chip looks like its own panel" complaint.
        self.setMinimumHeight(64)
        self.setMaximumHeight(74)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 6, 10, 6)
        outer.setSpacing(0)
        self._label = QLabel(label.upper())
        self._label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;")
        self._value = QLabel("- -")
        self._value.setStyleSheet("color:#5a6675;font-size:18px;font-weight:800;")
        self._hint = QLabel("awaiting refresh")
        self._hint.setStyleSheet("color:#7a8694;font-size:10px;")
        self._hint.setWordWrap(False)
        self._spark = _SparklineWidget(self)
        # Collapse the sparkline's layout slot entirely until we have a
        # numeric sample - otherwise the (hidden) widget still reserved
        # ~20px of vertical space that read as a grey horizontal band
        # inside the empty chip.
        self._spark.setVisible(False)
        self._spark.setMaximumHeight(0)
        outer.addWidget(self._label)
        outer.addWidget(self._value)
        outer.addWidget(self._hint)
        outer.addWidget(self._spark)
        self._outer_layout = outer
        self._on_click = None
        self._has_data = False
        self.set_tone("neutral")

    def set_click_handler(self, handler) -> None:
        self._on_click = handler
        from PySide6.QtCore import Qt as _Qt
        self.setCursor(_Qt.PointingHandCursor)
        self.setToolTip("Click to drill into the related panel")

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._on_click is not None:
            try:
                self._on_click()
            except Exception:
                pass
        super().mouseReleaseEvent(event)

    def set_tone(self, tone: str) -> None:
        # Defer background + border to the global `card='true'` QSS so
        # every chip across all consoles shares one chrome palette. The
        # tone only colours the big value label (matches SOC Overview).
        _, fg = _KPI_TONE_PALETTE.get(tone, _KPI_TONE_PALETTE["neutral"])
        value_colour = fg if self._has_data else "#5a6675"
        self._value.setStyleSheet(f"color:{value_colour};font-size:18px;font-weight:800;")

    def update(self, value: str, tone: str = "neutral", hint: str = "") -> None:
        # First real update flips the chip out of its sparse empty state
        # - restores the bright value colour, drops the italic hint
        # treatment, and reveals the sparkline strip.
        self._has_data = True
        self._value.setText(str(value))
        self._hint.setText(hint or "")
        # Data state hint: same readable contrast SOC Overview tiles
        # use, instead of the italic 'awaiting refresh' empty treatment.
        self._hint.setStyleSheet("color:#c8d8ea;font-size:10px;")
        self.set_tone(tone)
        try:
            numeric = float(str(value).replace(",", "").split()[0])
            self._spark.push(numeric, tone)
            self._spark.setMaximumHeight(14)
            self._spark.setVisible(True)
            self.setMinimumHeight(64)
            self.setMaximumHeight(92)
        except (TypeError, ValueError, IndexError):
            pass

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
    from _response_dialog import prompt_response_reason as _prompt_response_reason
except ImportError:  # pragma: no cover
    from desktop._response_dialog import prompt_response_reason as _prompt_response_reason


# Server-side accepted Security Ops actions. Mirrored client-side so
# typo/new-button additions can't reach an undocumented endpoint.
SECURITY_OPS_ACTION_ALLOWLIST: frozenset[str] = frozenset({
    "rotate-secrets", "clear-webhook", "save-yara-policy",
    "load-yara-policy", "refresh-integrity", "export-report",
    "refresh-workspace", "refresh-yara",
})

# Actions that require a structured reason (ticket + category +
# narrative). These touch secrets, detection policy, or on-host
# evidence - the audit chain must explain *why* each one ran.
SECURITY_OPS_REASON_REQUIRED: frozenset[str] = frozenset({
    "rotate-secrets", "clear-webhook", "save-yara-policy", "export-report",
})

SECURITY_OPS_DEBOUNCE_SECONDS = 1.5

SECURITY_OPS_AUDIT_RETENTION = 500


class SecurityOpsWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        self._audit_store = AuditLogStore(
            self.audit_log_path,
            retention=SECURITY_OPS_AUDIT_RETENTION,
        )
        _install_audit_mirror(self._audit_store, app, source_slug="security-ops")
        self._gate = ActionGate(
            allowlist=SECURITY_OPS_ACTION_ALLOWLIST,
            debounce_seconds=SECURITY_OPS_DEBOUNCE_SECONDS,
            status_bar=lambda msg: app.statusBar().showMessage(msg),
        )
        self._reason = ReasonCapture(
            reason_required=SECURITY_OPS_REASON_REQUIRED,
            parent=app,
            on_cancel=lambda action: app.statusBar().showMessage(
                f"`{action}` cancelled - structured reason required."
            ),
        )
        self._last_action_click: dict[str, float] = {}
        # Track every mutating-action button so a single refresh helper
        # can disable the lot during long-running calls and the action
        # handlers can restore them afterwards. Populated in build_tab().
        self._action_buttons: list = []
        self._busy_message: str = ""
        # Sudo-mode countdown - refreshed every time a sensitive action
        # is performed. Used to gate Rotate / Clear Webhook so re-MFA is
        # demanded on stale sessions.
        self._sudo_expires_at: float = 0.0
        self._sudo_label = None

    # ------------------------------------------------------------------ #
    # Audit + reason helpers (paylaşılan model with Antivirus / Enterprise
    # / Intel / Network / History).
    # ------------------------------------------------------------------ #

    def audit_log_path(self) -> Path:
        return Path.cwd() / "shadowlab_out" / "security-ops-audit-log.json"

    def load_audit_log(self) -> list[dict]:
        return self._audit_store.load()

    def _check_action_gate(self, action: str) -> bool:
        # Delegate to the shared `ActionGate`. Legacy mirror dict is
        # updated for tests that read it directly.
        ok = self._gate.check(action)
        if ok:
            self._last_action_click[action] = time.time()
        return ok

    def _capture_reason(self, action: str) -> dict | None:
        # Delegate to the shared `ReasonCapture`. Returns `{}` for
        # non-reason-required actions so the audit pipeline can still
        # attach metadata uniformly.
        return self._reason.capture(action)

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
            category="security-ops",
            action=action,
            target=target,
            severity=severity,
            status=status,
            payload=payload,
            actor=actor,
            workspace=workspace,
            reason=reason if reason else None,
        )

    # ------------------------------------------------------------------ #
    # Tab layout - product-grade dashboard:
    #   1. Header + "Last refreshed" timestamp + Refresh All affordance.
    #   2. KPI strip - five chips give one-glance posture (integrity,
    #      drift, webhook, YARA, last rotation). Tone-coded.
    #   3. Two control cards in a row (Security Ops + YARA), each with
    #      a destructive-action chip badge.
    #   4. Two-column main grid:
    #        Left  - Posture (rich HTML) + Integrity Drift table.
    #        Right - Platform Readiness (status badges) + YARA Sources.
    #   5. Bottom row - Local YARA Policy editor + Security Ops Detail
    #      (response/audit log).
    # ------------------------------------------------------------------ #

    def build_tab(self) -> QWidget:
        app = self.app
        w = QWidget(); l = QVBoxLayout(w); l.setContentsMargins(8, 8, 8, 8); l.setSpacing(8)
        app._tab_header(
            l,
            "Security Ops & Platform Readiness",
            "Signed integrity, observability, migrations, database readiness and secret lifecycle operations without disturbing existing workspaces.",
        )

        # --- (1) Header strip: last-refreshed, workspace badge, time-window,
        #     auto-refresh, sudo countdown, refresh-all.
        from PySide6.QtWidgets import QCheckBox, QComboBox
        header_row = QWidget()
        header_layout = QHBoxLayout(header_row)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(12)
        self._last_refresh_label = QLabel("Last refreshed: never")
        self._last_refresh_label.setStyleSheet("color:#9aa5b1; font-size:12px;")
        app.security_ops_last_refresh = self._last_refresh_label
        header_layout.addWidget(self._last_refresh_label)

        # Workspace badge - shows which workspace these metrics belong
        # to so a multi-tenant admin doesn't accidentally read tenant-A
        # drift while logged into tenant-B.
        self._workspace_badge = QLabel("workspace: -")
        self._workspace_badge.setStyleSheet(
            "color:#cbd5e0; background:#1f2933; padding:4px 10px; border-radius:8px;"
            " font-size:11px; font-weight:600;"
        )
        self._workspace_badge.setToolTip("Active workspace for the metrics on this page.")
        header_layout.addWidget(self._workspace_badge)

        header_layout.addStretch(1)

        # Time-window selector - affects which slice of history feeds
        # into the abuse / DLQ / drift queries. Stored on the controller
        # so subsequent refreshes pick up the change.
        self._time_window_combo = QComboBox()
        self._time_window_combo.addItems(["1h", "24h", "7d", "All"])
        self._time_window_combo.setCurrentText("24h")
        self._time_window_combo.setToolTip(
            "Restrict abuse anomalies, dead letters and drift counts to this rolling window."
        )
        self._time_window_combo.currentTextChanged.connect(lambda _: self._on_time_window_changed())
        window_label = QLabel("Window:")
        window_label.setStyleSheet("color:#9aa5b1;font-size:11px;")
        header_layout.addWidget(window_label)
        header_layout.addWidget(self._time_window_combo)

        # Auto-refresh toggle - opt-in 30s polling. Off by default so
        # workspaces with slow integrity scans don't pile up requests.
        self._auto_refresh_check = QCheckBox("Auto-refresh 30s")
        self._auto_refresh_check.setStyleSheet("color:#cbd5e0;font-size:11px;")
        self._auto_refresh_check.toggled.connect(self._toggle_auto_refresh)
        header_layout.addWidget(self._auto_refresh_check)

        # Sudo-mode chip - shows MFA grace window. Hidden while >0,
        # turns warning-coloured when re-verify is needed.
        self._sudo_label = QLabel("🔒 Sudo: re-verify required")
        self._sudo_label.setStyleSheet(
            "color:#feb2b2; background:#5f1d1d; padding:4px 10px; border-radius:8px; font-size:12px;"
        )
        self._sudo_label.setToolTip(
            "Destructive actions (Rotate Secrets / Clear Webhook) require a fresh MFA "
            "verification within the last 5 minutes. POST /auth/mfa/verify to refresh."
        )
        header_layout.addWidget(self._sudo_label)

        refresh_all_btn = QPushButton("Refresh All (Ctrl+R)")
        refresh_all_btn.setShortcut(QKeySequence("Ctrl+R"))
        refresh_all_btn.clicked.connect(app.refresh_security_ops_workspace)
        app._bind_capability(refresh_all_btn, "can_manage_integrations")
        header_layout.addWidget(refresh_all_btn)
        self._refresh_all_btn = refresh_all_btn
        self._action_buttons.append(refresh_all_btn)
        l.addWidget(header_row)

        # (compliance strip is now embedded inside the Posture Overview
        # card built in section (2) below - kept inline with the KPIs
        # so the dashboard reads as one cohesive header)

        # Tick the sudo countdown every second so "5m 00s → 4m 59s …"
        # animates in real time. The timer parents to the tab widget,
        # so it stops automatically when the tab is destroyed.
        from PySide6.QtCore import QTimer
        self._sudo_tick = QTimer(w)
        self._sudo_tick.setInterval(1000)
        self._sudo_tick.timeout.connect(self._update_sudo_chip)
        self._sudo_tick.start()
        self._update_sudo_chip()

        # --- (2) Posture Overview card - one self-contained widget that
        #         packages the compliance strip + KPI chips into a single
        #         framed surface. The earlier layout left the compliance
        #         line orphaned above the chips with no visual grouping;
        #         this rolls them together and gives the empty state a
        #         dedicated subtitle so the dashboard reads coherently
        #         before the first refresh.
        # Compliance strip lives inline above the KPI chips. Keeping it
        # as a plain QLabel - no wrapping framed card - reclaims the
        # ~80 px of chrome the old "PLATFORM POSTURE" header surface ate.
        self._compliance_label = QLabel("")
        self._compliance_label.setStyleSheet("color:#9aa5b1; font-size:11px; padding:0 2px;")
        l.addWidget(self._compliance_label)

        # KPI strip - 5 equal-width chips (widget-based so they actually
        # size uniformly; the earlier HTML-in-TextBrowser approach
        # collapsed on first refresh).
        kpi_strip = QWidget()
        kpi_layout = QHBoxLayout(kpi_strip)
        kpi_layout.setContentsMargins(0, 0, 0, 0)
        kpi_layout.setSpacing(8)
        self._kpi_chips: dict[str, _KpiChip] = {}
        # Each chip drills into the most relevant panel - clicking
        # "Drift" focuses the Integrity Drift card, "YARA Errors"
        # surfaces the local YARA error list, etc.
        chip_drill_targets = {
            "integrity": ("integrity_drift", None),
            "drift": ("integrity_drift", None),
            "dead_letters": ("ops_detail", lambda: self._focus_dead_letters()),
            "yara_errors": ("yara_sources", lambda: self.app.load_local_yara_errors()),
            "last_rotation": ("ops_detail", lambda: self._focus_rotation_history()),
        }
        for key, label in (
            ("integrity", "Integrity"),
            ("drift", "Drift"),
            ("dead_letters", "Dead Letters"),
            ("yara_errors", "YARA Errors"),
            ("last_rotation", "Last Rotation"),
        ):
            chip = _KpiChip(label)
            target_key, custom = chip_drill_targets.get(key, (None, None))
            if custom or target_key:
                chip.set_click_handler(
                    custom or (lambda tk=target_key: self._focus_panel(tk))
                )
            self._kpi_chips[key] = chip
            kpi_layout.addWidget(chip, 1)
        app.security_ops_kpi_strip = kpi_strip
        self._render_compliance_strip(initial=True)
        l.addWidget(kpi_strip)

        # --- (3) Control cards - Security Ops + YARA.
        controls = QWidget()
        row = QHBoxLayout(controls); row.setContentsMargins(0, 0, 0, 0); row.setSpacing(8)
        refresh_btn = QPushButton("Refresh Security Ops"); refresh_btn.clicked.connect(app.refresh_security_ops_workspace)
        export_btn = QPushButton("Export Ops Report"); export_btn.clicked.connect(app.export_security_ops_report)
        refresh_integrity_btn = QPushButton("Refresh Integrity"); refresh_integrity_btn.clicked.connect(app.refresh_integrity_manifest)
        # Destructive button shortcuts use Ctrl+Shift+<X> so an accidental
        # Ctrl+<X> can never trigger them. Hint is rendered inline so the
        # operator doesn't need a cheat-sheet.
        rotate_btn = QPushButton("⚠ Rotate Secrets (Ctrl+Shift+R)")
        rotate_btn.setShortcut(QKeySequence("Ctrl+Shift+R"))
        rotate_btn.setToolTip("Destructive - requires confirmation and structured reason. Shortcut: Ctrl+Shift+R")
        rotate_btn.setStyleSheet("QPushButton { color: #feb2b2; } QPushButton:hover { background:#5f1d1d; }")
        rotate_btn.clicked.connect(app.rotate_security_secrets)
        clear_webhook_btn = QPushButton("⚠ Clear Webhook (Ctrl+Shift+W)")
        clear_webhook_btn.setShortcut(QKeySequence("Ctrl+Shift+W"))
        clear_webhook_btn.setToolTip("Destructive - silences outbound alerts until re-configured. Shortcut: Ctrl+Shift+W")
        clear_webhook_btn.setStyleSheet("QPushButton { color: #feb2b2; } QPushButton:hover { background:#5f1d1d; }")
        clear_webhook_btn.clicked.connect(app.clear_alert_webhook_secret)
        # Non-destructive "ping" of the configured webhook so the
        # analyst can verify the destination is alive *before* clearing
        # or rotating. Same delivery semantics the dispatcher uses,
        # routed through /integrations/alerts/webhook/test.
        test_webhook_btn = QPushButton("Test Webhook")
        test_webhook_btn.setToolTip(
            "Send a signed probe payload to the currently configured alert webhook "
            "and surface the HTTP status. Non-destructive - use before Clear Webhook "
            "if you suspect the destination is unreachable."
        )
        test_webhook_btn.clicked.connect(self.test_alert_webhook)

        for btn in (refresh_btn, export_btn, refresh_integrity_btn, test_webhook_btn, rotate_btn, clear_webhook_btn):
            app._bind_capability(btn, "can_manage_integrations")
            row.addWidget(btn)
            self._action_buttons.append(btn)
        self._rotate_btn = rotate_btn
        self._clear_webhook_btn = clear_webhook_btn
        self._test_webhook_btn = test_webhook_btn
        row.addStretch(1)
        controls_cards_row = QWidget()
        controls_cards_layout = QHBoxLayout(controls_cards_row)
        controls_cards_layout.setContentsMargins(0, 0, 0, 0)
        controls_cards_layout.setSpacing(8)
        controls_cards_layout.addWidget(app._panel_card("Security Ops Controls", controls, None), 1)

        yara_controls = QWidget(); yara_row = QHBoxLayout(yara_controls); yara_row.setContentsMargins(0, 0, 0, 0); yara_row.setSpacing(8)
        refresh_yara_btn = QPushButton("Refresh YARA Ops"); refresh_yara_btn.clicked.connect(app.refresh_yara_ops_workspace)
        load_yara_policy_btn = QPushButton("Load YARA Policy"); load_yara_policy_btn.clicked.connect(app.load_local_yara_policy)
        save_yara_policy_btn = QPushButton("Save YARA Policy"); save_yara_policy_btn.clicked.connect(app.save_local_yara_policy)
        self._yara_errors_btn = QPushButton("YARA Errors"); self._yara_errors_btn.clicked.connect(app.load_local_yara_errors)
        app.security_ops_yara_errors_btn = self._yara_errors_btn
        for btn in (refresh_yara_btn, load_yara_policy_btn, save_yara_policy_btn, self._yara_errors_btn):
            app._bind_capability(btn, "can_manage_integrations")
            yara_row.addWidget(btn)
            self._action_buttons.append(btn)
        yara_row.addStretch(1)
        controls_cards_layout.addWidget(app._panel_card("Local YARA Controls", yara_controls, None), 1)
        l.addWidget(controls_cards_row)

        # --- (4) Main 2-column grid.
        app.security_ops_summary = QTextBrowser()
        app.security_ops_summary.setProperty("role", "brief")
        app.security_ops_summary.setMinimumHeight(220)
        app.security_ops_summary.setHtml(self._empty_state_html(
            "Security Ops Posture",
            "Press <b>Refresh All</b> (or Ctrl+R) to load integrity status, drift counts, "
            "abuse signals, dead-letter queue depth, and YARA compile health. Nothing has "
            "been collected yet - refresh runs on a worker thread and won't block the UI.",
        ))

        app.security_integrity_table = QTableWidget(0, 2)
        app.security_integrity_table.setHorizontalHeaderLabels(["Bucket", "Count"])
        app._style_table(app.security_integrity_table)
        app.security_integrity_table.setMinimumHeight(180)
        self._install_empty_table_placeholder(
            app.security_integrity_table,
            "No integrity drift recorded. Press Refresh Integrity after a scan.",
        )

        app.security_platform_table = QTableWidget(0, 2)
        app.security_platform_table.setHorizontalHeaderLabels(["Domain", "Status"])
        app._style_table(app.security_platform_table)
        app.security_platform_table.setMinimumHeight(180)
        self._install_empty_table_placeholder(
            app.security_platform_table,
            "Platform readiness not loaded yet.",
        )

        # YARA Source Analytics container - table + inline filter so a
        # 20+ row pack of analytics stays browsable.
        from PySide6.QtWidgets import QLineEdit
        yara_container = QWidget()
        yara_container_layout = QVBoxLayout(yara_container)
        yara_container_layout.setContentsMargins(0, 0, 0, 0)
        yara_container_layout.setSpacing(4)
        yara_filter_row = QWidget()
        yara_filter_layout = QHBoxLayout(yara_filter_row)
        yara_filter_layout.setContentsMargins(0, 0, 0, 0)
        yara_filter_layout.setSpacing(6)
        yara_filter_label = QLabel("🔍")
        yara_filter_label.setStyleSheet("color:#9aa5b1;font-size:12px;")
        self._yara_filter = QLineEdit()
        self._yara_filter.setPlaceholderText("filter by source name…")
        self._yara_filter.setClearButtonEnabled(True)
        self._yara_filter.textChanged.connect(self._apply_yara_filter)
        yara_filter_layout.addWidget(yara_filter_label)
        yara_filter_layout.addWidget(self._yara_filter)

        app.security_yara_table = QTableWidget(0, 4)
        app.security_yara_table.setHorizontalHeaderLabels(["Source", "Hits", "Suppressed", "Avg Score"])
        app._style_table(app.security_yara_table)
        app.security_yara_table.setMinimumHeight(160)
        app.security_yara_table.setSortingEnabled(True)
        yara_container_layout.addWidget(yara_filter_row)
        yara_container_layout.addWidget(app.security_yara_table, 1)
        # Surface the composite container through `panel_card`, but keep
        # the table reference on `app` for the renderer to populate.
        self._yara_container = yara_container
        self._install_empty_table_placeholder(
            app.security_yara_table,
            "No YARA hits aggregated yet. Run scans then Refresh YARA Ops.",
        )

        app.security_yara_policy = QTextEdit()
        app.security_yara_policy.setPlaceholderText(
            'Load policy from the server, or paste JSON here:\n'
            '{\n  "allowlist_rule_patterns": ["Hacktool_*"],\n'
            '  "boost_rule_patterns": {"APT_*": 1.5},\n'
            '  "suppression_rule_patterns": []\n}'
        )
        app.security_yara_policy.setMinimumHeight(220)
        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        app.security_yara_policy.setFont(font)

        app.security_ops_detail = QTextEdit()
        app.security_ops_detail.setReadOnly(True)
        app.security_ops_detail.setMinimumHeight(220)
        app.security_ops_detail.setPlainText(
            "Response payloads, errors, and exported report paths appear here. "
            "Mutating actions (rotate, clear webhook, save policy, export) also "
            "leave an audit row in shadowlab_out/security-ops-audit-log.json."
        )

        # --- (4) Main grid: 3 + 3 panels, equal width, equal height.
        #
        # Row 1 (status overview): Posture | Platform Readiness | Integrity Drift
        # Row 2 (drill-down/edit):  YARA Sources | YARA Policy | Detail
        #
        # Both rows use HBoxLayouts with stretch=1 per cell so column
        # widths are identical regardless of internal widget content.

        top_row = QWidget()
        top_row_layout = QHBoxLayout(top_row)
        top_row_layout.setContentsMargins(0, 0, 0, 0)
        top_row_layout.setSpacing(8)
        top_row_layout.addWidget(
            app._panel_card("Security Ops Posture", app.security_ops_summary,
                            lambda: app._open_panel_window("Security Ops Posture", app._clone_text_view(app.security_ops_summary))),
            1,
        )
        top_row_layout.addWidget(
            app._panel_card("Platform Readiness", app.security_platform_table,
                            lambda: app._open_panel_window("Platform Readiness", app._clone_table(app.security_platform_table))),
            1,
        )
        top_row_layout.addWidget(
            app._panel_card("Integrity Drift", app.security_integrity_table,
                            lambda: app._open_panel_window("Integrity Drift", app._clone_table(app.security_integrity_table))),
            1,
        )
        l.addWidget(top_row, 1)

        bottom_row = QWidget()
        bottom_row_layout = QHBoxLayout(bottom_row)
        bottom_row_layout.setContentsMargins(0, 0, 0, 0)
        bottom_row_layout.setSpacing(8)
        bottom_row_layout.addWidget(
            app._panel_card("YARA Source Analytics", self._yara_container,
                            lambda: app._open_panel_window("YARA Source Analytics", app._clone_table(app.security_yara_table))),
            1,
        )
        bottom_row_layout.addWidget(
            app._panel_card("Local YARA Policy", app.security_yara_policy,
                            lambda: app._open_panel_window("Local YARA Policy", app._clone_text_view(app.security_yara_policy))),
            1,
        )
        bottom_row_layout.addWidget(
            app._panel_card("Security Ops Detail", app.security_ops_detail,
                            lambda: app._open_panel_window("Security Ops Detail", app._clone_text_view(app.security_ops_detail))),
            1,
        )
        l.addWidget(bottom_row, 1)
        return w

    # ------------------------------------------------------------------ #
    # Empty-state / KPI helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _empty_state_html(title: str, body: str) -> str:
        return (
            f"<div style='padding:8px'>"
            f"<h3 style='margin:0 0 8px 0;color:#cbd5e0'>{html.escape(title)}</h3>"
            f"<p style='color:#9aa5b1;line-height:1.45;margin:0'>{body}</p>"
            f"</div>"
        )

    def _update_kpi_chips(
        self,
        *,
        integrity_status: str,
        signature_valid: bool,
        modified: int,
        missing: int,
        dead_letters: int,
        yara_errors: int,
        last_rotation_label: str,
    ) -> None:
        """Push fresh values into the five widget-based KPI chips."""
        drift_count = int(modified or 0) + int(missing or 0)
        self._kpi_chips["integrity"].update(
            integrity_status.upper() or "UNKNOWN",
            "ok" if integrity_status == "ok" and signature_valid else ("warn" if integrity_status == "drift_detected" else "crit"),
            "signature valid" if signature_valid else "signature MISSING",
        )
        self._kpi_chips["drift"].update(
            str(drift_count),
            "ok" if drift_count == 0 else ("warn" if drift_count < 5 else "crit"),
            f"{int(modified or 0)} modified / {int(missing or 0)} missing",
        )
        self._kpi_chips["dead_letters"].update(
            str(int(dead_letters or 0)),
            "ok" if not dead_letters else ("warn" if dead_letters < 10 else "crit"),
            "webhook DLQ depth",
        )
        self._kpi_chips["yara_errors"].update(
            str(int(yara_errors or 0)),
            "ok" if not yara_errors else "crit",
            "compile failures",
        )
        self._kpi_chips["last_rotation"].update(
            last_rotation_label or "n/a",
            "ok" if last_rotation_label and last_rotation_label != "n/a" else "warn",
            "secret rotation",
        )

    # ------------------------------------------------------------------ #
    # Busy / Sudo / Compliance helpers
    # ------------------------------------------------------------------ #

    def _set_busy(self, busy: bool, message: str = "") -> None:
        """Disable every mutating action button while a long call runs.

        Without this, multiple Refresh / Rotate clicks fire parallel HTTP
        requests and the user has no signal that the first one is still
        in flight. We also flip the cursor to a busy spinner and push a
        status-bar message so the operator knows something is happening.
        """
        from PySide6.QtCore import Qt as _Qt
        for btn in self._action_buttons:
            try:
                btn.setEnabled(not busy)
            except Exception:
                continue
        if busy:
            self.app.setCursor(_Qt.WaitCursor)
            self._busy_message = message or "Working…"
            self.app.statusBar().showMessage(self._busy_message)
        else:
            self.app.unsetCursor()
            if self._busy_message:
                self.app.statusBar().clearMessage()
            self._busy_message = ""

    SUDO_WINDOW_SECONDS = 5 * 60  # mirrors api/security MFA session TTL

    def _mark_sudo_verified(self) -> None:
        """Called after a successful destructive action - extends the sudo window."""
        self._sudo_expires_at = time.time() + self.SUDO_WINDOW_SECONDS
        self._update_sudo_chip()

    def _sudo_remaining_seconds(self) -> int:
        return max(0, int(self._sudo_expires_at - time.time()))

    def _sudo_required(self) -> bool:
        """Return True iff the sudo window has elapsed.

        Even when the server-side MFA gate is off (`SHADOWLAB_REQUIRE_MFA_
        FOR_ROLES` empty), this gives the desktop a self-imposed re-verify
        prompt before destructive actions. Operators can suppress it via
        the `Refresh All` flow which also marks sudo as fresh.
        """
        return self._sudo_remaining_seconds() == 0

    def _update_sudo_chip(self) -> None:
        if self._sudo_label is None:
            return
        remaining = self._sudo_remaining_seconds()
        if remaining <= 0:
            self._sudo_label.setText("🔒 Sudo: re-verify required")
            self._sudo_label.setStyleSheet(
                "color:#feb2b2; background:#5f1d1d; padding:4px 10px; border-radius:8px; font-size:12px;"
            )
        else:
            mins, secs = divmod(remaining, 60)
            self._sudo_label.setText(f"🔓 Sudo active · {mins}m {secs:02d}s")
            self._sudo_label.setStyleSheet(
                "color:#9ae6b4; background:#1b4332; padding:4px 10px; border-radius:8px; font-size:12px;"
            )

    def _ensure_sudo_or_warn(self, action_label: str) -> bool:
        """Confirm with the operator before letting a sensitive action run
        on a stale session. Returns True iff the operator either has a
        fresh sudo window OR explicitly confirms continuing."""
        if not self._sudo_required():
            return True
        warn = QMessageBox(self.app)
        warn.setWindowTitle("Re-verify recommended")
        warn.setText(f"Sudo window expired - proceed with {action_label}?")
        warn.setInformativeText(
            "It has been more than 5 minutes since the last verified destructive "
            "action on this session. Stepping away and coming back creates a window "
            "for an unattended workstation. Run POST /auth/mfa/verify before "
            "continuing for maximum assurance, or click OK to proceed at your own risk."
        )
        warn.setIcon(QMessageBox.Warning)
        warn.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        return warn.exec() == QMessageBox.Ok

    def _render_compliance_strip(self, initial: bool = False) -> None:
        """Render the small ✓/✗ row showing the platform's hardened posture.

        Reads the live auth-context payload the main app caches after
        successful login. `initial=True` paints placeholders before the
        first refresh - uses tone-coded "pending" dots instead of a
        single grey sentence so the eye still has chip-shaped anchors
        when the rest of the strip is empty.
        """

        def pending(label: str) -> str:
            return f"<span style='color:#7a8694'>○ {label}</span>"

        if initial or not getattr(self.app, "current_auth_context", None):
            items = [
                pending("Auth"),
                pending("OIDC"),
                pending("Sudo"),
                pending("Profile"),
                pending("Hardened"),
            ]
            self._compliance_label.setText("  ·  ".join(items))
            return
        ctx = getattr(self.app, "current_auth_context", {}) or {}
        features = ctx.get("features", {}) if isinstance(ctx, dict) else {}

        def chip(ok: bool, label: str) -> str:
            colour = "#9ae6b4" if ok else "#feb2b2"
            mark = "✓" if ok else "✗"
            return f"<span style='color:{colour}'>{mark} {label}</span>"

        items = [
            chip(bool(ctx.get("auth_required")), "Auth enforced"),
            chip(bool(features.get("oidc_enabled")) or ctx.get("auth_source") == "oidc", "OIDC available"),
            chip(self._sudo_remaining_seconds() > 0, "Sudo window"),
            chip(features.get("policy_profile") in {"corp", "prod"}, f"Profile: {features.get('policy_profile', 'lab')}"),
            chip(not features.get("dangerous_actions_enabled", False) or features.get("policy_profile") == "lab", "Hardened"),
        ]
        self._compliance_label.setText("  ·  ".join(items))

    def _apply_yara_filter(self, query: str) -> None:
        """Hide rows whose first column doesn't contain the query substring."""
        table = self.app.security_yara_table
        needle = (query or "").strip().lower()
        for r in range(table.rowCount()):
            item = table.item(r, 0)
            haystack = item.text().lower() if item else ""
            table.setRowHidden(r, bool(needle) and needle not in haystack)

    def _render_skeleton_rows(self) -> None:
        """Replace empty-state placeholders with shimmer rows during refresh.

        Lightweight stand-in for proper skeleton screens - sets every
        cell to a grey ellipsis so the operator sees "we're working"
        instead of stale empty-state copy. Real data replaces them on
        successful render.
        """
        for table, cols in (
            (self.app.security_integrity_table, 2),
            (self.app.security_platform_table, 2),
            (self.app.security_yara_table, 4),
        ):
            table.clearSpans()
            table.setRowCount(3)
            for r in range(3):
                for c in range(cols):
                    item = QTableWidgetItem("· · ·")
                    item.setForeground(QBrush(QColor("#3a4452")))
                    item.setTextAlignment(int(Qt.AlignCenter))
                    item.setFlags(item.flags() & ~Qt.ItemIsEditable & ~Qt.ItemIsSelectable)
                    table.setItem(r, c, item)

    def _on_time_window_changed(self) -> None:
        """Re-fetch the dashboard so the new window affects metrics.

        The selected window is also passed forward as a query-string
        hint to endpoints that honour it; backends that don't read the
        parameter just ignore it.
        """
        self.app.statusBar().showMessage(
            f"Time window changed to {self._time_window_combo.currentText()} - refreshing…"
        )
        self.refresh_security_ops_workspace()

    def _current_time_window(self) -> str:
        try:
            return self._time_window_combo.currentText()
        except AttributeError:
            return "24h"

    def _toggle_auto_refresh(self, checked: bool) -> None:
        """Start / stop a 30s polling timer for the Security Ops dashboard.

        Lightweight - refresh runs on a worker thread already so the
        UI never blocks. We pause polling whenever the tab is not the
        active one to avoid wasted bandwidth.
        """
        from PySide6.QtCore import QTimer as _QT
        if not hasattr(self, "_auto_refresh_timer"):
            self._auto_refresh_timer = _QT(self.app)
            self._auto_refresh_timer.setInterval(30000)
            self._auto_refresh_timer.timeout.connect(self.refresh_security_ops_workspace)
        if checked:
            self._auto_refresh_timer.start()
            self.app.statusBar().showMessage("Auto-refresh enabled (30s)", 4000)
        else:
            self._auto_refresh_timer.stop()
            self.app.statusBar().showMessage("Auto-refresh disabled", 4000)

    def _update_workspace_badge(self) -> None:
        """Reflect the live workspace value in the header chip."""
        try:
            workspace_id = ""
            if hasattr(self.app, "workspace_id") and hasattr(self.app.workspace_id, "text"):
                workspace_id = self.app.workspace_id.text().strip()
            workspace_id = workspace_id or (
                getattr(self.app, "current_auth_context", {}) or {}
            ).get("workspace_id", "default")
            self._workspace_badge.setText(f"workspace: {workspace_id}")
        except Exception:
            self._workspace_badge.setText("workspace: default")

    def _show_toast(self, message: str, *, tone: str = "neutral", duration_ms: int = 4000) -> None:
        """Surface a transient notification banner at the bottom of the tab.

        Lightweight alternative to QSystemTrayIcon - keeps the message
        in the same window the operator is already looking at. Tone-
        coded ({ok, warn, crit}) so cleared/raised events read at a glance.
        """
        palette = {
            "ok": ("#1b4332", "#9ae6b4"),
            "warn": ("#5c4400", "#f6e05e"),
            "crit": ("#5f1d1d", "#feb2b2"),
            "neutral": ("#1f2933", "#cbd5e0"),
        }
        bg, fg = palette.get(tone, palette["neutral"])
        toast = QLabel(message, self.app)
        toast.setStyleSheet(
            f"QLabel {{ background:{bg}; color:{fg}; padding:8px 14px; border-radius:10px;"
            f" font-weight:600; }}"
        )
        toast.setWindowFlags(Qt.SubWindow | Qt.FramelessWindowHint | Qt.WindowDoesNotAcceptFocus)
        toast.adjustSize()
        # Position centered along the bottom edge of the parent window.
        parent_geom = self.app.geometry()
        x = parent_geom.x() + (parent_geom.width() - toast.width()) // 2
        y = parent_geom.y() + parent_geom.height() - toast.height() - 60
        toast.move(x, y)
        toast.show()
        from PySide6.QtCore import QTimer as _QT
        _QT.singleShot(int(duration_ms), toast.deleteLater)

    def _confirm_yara_policy_diff(self, current: dict, new: dict) -> bool:
        """Show a unified diff of YARA policy before saving.

        Returns True iff the operator confirms. The diff is rendered
        inside a QMessageBox detailedText pane (monospace + scrollable)
        so even large rule-pattern blocks are reviewable.
        """
        import difflib
        try:
            current_text = json.dumps(current or {}, indent=2, sort_keys=True, ensure_ascii=False)
            new_text = json.dumps(new or {}, indent=2, sort_keys=True, ensure_ascii=False)
        except Exception:
            return True  # if serialisation fails, defer to existing reason flow
        if current_text == new_text:
            QMessageBox.information(
                self.app,
                "No changes",
                "The submitted YARA policy is identical to the server's current copy. Nothing to save.",
            )
            return False
        diff = "\n".join(
            difflib.unified_diff(
                current_text.splitlines(),
                new_text.splitlines(),
                fromfile="current",
                tofile="proposed",
                lineterm="",
            )
        )
        # Tally rule-level changes so the headline summary is concrete.
        added = sum(1 for ln in diff.splitlines() if ln.startswith("+ ") or (ln.startswith("+") and not ln.startswith("+++")))
        removed = sum(1 for ln in diff.splitlines() if ln.startswith("- ") or (ln.startswith("-") and not ln.startswith("---")))
        confirm = QMessageBox(self.app)
        confirm.setWindowTitle("Review YARA policy diff")
        confirm.setIcon(QMessageBox.Question)
        confirm.setText("Apply the following YARA policy changes?")
        confirm.setInformativeText(
            f"<b>{added}</b> line(s) added · <b>{removed}</b> line(s) removed.<br>"
            "Click <b>Show Details</b> to inspect the full unified diff before saving."
        )
        confirm.setDetailedText(diff)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        return confirm.exec() == QMessageBox.Ok

    def _focus_panel(self, target_key: str) -> None:
        """Bring the relevant card to the foreground when a KPI is clicked.

        For Qt we scroll the parent widget to the panel and briefly
        highlight its border so the operator sees what was selected.
        """
        widget = {
            "integrity_drift": getattr(self.app, "security_integrity_table", None),
            "yara_sources": getattr(self.app, "security_yara_table", None),
            "ops_detail": getattr(self.app, "security_ops_detail", None),
            "platform": getattr(self.app, "security_platform_table", None),
        }.get(target_key)
        if widget is None:
            return
        try:
            parent = widget.parentWidget()
            if parent:
                parent.setFocus()
            widget.setFocus()
            # Briefly flash the border to draw the eye.
            original = widget.styleSheet()
            widget.setStyleSheet(original + " QTableWidget, QTextEdit { border: 2px solid #f6e05e; }")
            from PySide6.QtCore import QTimer
            QTimer.singleShot(900, lambda: widget.setStyleSheet(original))
        except Exception:
            return

    def _focus_dead_letters(self) -> None:
        """Pull the live DLQ list into the Detail pane and focus it."""
        try:
            data = self.app._get("/integrations/webhook/dlq", timeout=15).json()
        except Exception as exc:
            self.app._show_error(self.app.security_ops_detail, "Dead-letter fetch failed", exc)
            self._focus_panel("ops_detail")
            return
        self.app._show_json(self.app.security_ops_detail, _redact_payload(data))
        self._focus_panel("ops_detail")

    def _focus_rotation_history(self) -> None:
        """Surface the rotation worker history feed.

        Renders a compact list of the most-recent 5 rotation events in
        the Detail pane so the operator can see "who rotated what,
        when" without scrolling raw JSON. The full payload is still
        appended below the summary for forensics.
        """
        app = self.app
        try:
            data = app._get("/auth/rotation/status", timeout=10).json()
        except Exception as exc:
            app._show_error(app.security_ops_detail, "Rotation status fetch failed", exc)
            self._focus_panel("ops_detail")
            return
        recent = (data or {}).get("recent_rotations", []) if isinstance(data, dict) else []
        # Build a small human-readable summary first; reverse so newest
        # is on top, cap at 5 rows.
        lines: list[str] = [
            "═══ Rotation History (newest first) ═══",
            f"Worker enabled: {bool(data.get('enabled'))}    "
            f"Interval: {int(data.get('interval_seconds', 0))}s    "
            f"Max age: {int(data.get('max_age_seconds', 0))}s",
            f"Last pass: {self._format_relative_time(data.get('last_run_at'))}",
            "",
        ]
        if not recent:
            lines.append("• No rotations executed in this window yet.")
        else:
            for entry in list(reversed(recent))[:5]:
                target = str(entry.get("target", "?"))
                workspace = str(entry.get("workspace_id", "")) or "-"
                ok = bool(entry.get("ok", True))
                when = self._format_relative_time(entry.get("at"))
                detail_bits: list[str] = [f"target={target}", f"workspace={workspace}", f"when={when}"]
                if entry.get("secret_id"):
                    detail_bits.append(f"secret_id={entry['secret_id']}")
                if entry.get("reason"):
                    detail_bits.append(f"reason={entry['reason']}")
                badge = "✓" if ok else "✗"
                lines.append(f"{badge} " + "  ·  ".join(detail_bits))
        lines.append("")
        lines.append("─── full payload ───")
        app.security_ops_detail.setPlainText(
            "\n".join(lines) + "\n" + json.dumps(_redact_payload(data), indent=2, ensure_ascii=False, default=str)
        )
        self._focus_panel("ops_detail")

    def _fetch_current_webhook_url(self) -> str:
        """Best-effort lookup of the configured alert webhook URL."""
        try:
            payload = self.app._get("/integrations/alerts/webhook", timeout=8).json()
            url = ""
            if isinstance(payload, dict):
                url = str(
                    payload.get("webhook_url")
                    or payload.get("url")
                    or payload.get("destination")
                    or ""
                )
            return url
        except Exception:
            return ""

    @staticmethod
    def _install_empty_table_placeholder(table: QTableWidget, message: str) -> None:
        """Render a single italic-grey row when the table has no data.

        Real refresh logic always sets `rowCount` before populating, so
        the placeholder is overwritten the moment data lands.
        """
        table.setRowCount(1)
        item = QTableWidgetItem(message)
        item.setForeground(QBrush(QColor("#9aa5b1")))
        font = QFont(); font.setItalic(True); item.setFont(font)
        item.setFlags(item.flags() & ~Qt.ItemIsEditable & ~Qt.ItemIsSelectable)
        table.setItem(0, 0, item)
        if table.columnCount() > 1:
            table.setSpan(0, 0, 1, table.columnCount())

    def refresh_security_ops_workspace(self) -> None:
        app = self.app
        # Async: 4 sequential GETs (45 + 30 + 30 + 30 = up to 135s
        # cumulative timeout) used to lock the UI thread for the whole
        # window. Move them onto a worker - partial failures stay
        # individually reportable instead of taking the whole refresh
        # down.
        self._set_busy(True, "Refreshing Security Ops…")
        # Drop shimmer rows into tables so the dashboard reads "we're
        # working" instead of holding stale empty-state copy.
        self._render_skeleton_rows()
        app.security_ops_detail.setPlainText(
            "Security Ops refresh running on worker thread - UI stays responsive..."
        )

        def _gather() -> dict:
            partials: dict = {"errors": []}
            for key, fn in (
                ("report", lambda: app._get("/enterprise/report/security-ops", timeout=45).json()),
                ("observability", lambda: app._get("/observability/summary", timeout=30).json()),
                ("yara_health", lambda: app._get("/yara/local/health", timeout=30).json()),
                ("yara_analytics", lambda: app._get("/yara/local/analytics", timeout=30).json()),
            ):
                try:
                    partials[key] = fn()
                except Exception as exc:
                    partials[key] = None
                    partials["errors"].append({"endpoint": key, "error": str(exc)})
            return partials

        def _on_done(partials: dict) -> None:
            try:
                report = partials.get("report") or {}
                observability = partials.get("observability") or {}
                yara_health = partials.get("yara_health") or {}
                yara_analytics = partials.get("yara_analytics") or {}
                errors = partials.get("errors") or []
                if errors and not isinstance(report, dict):
                    msg = "; ".join(f"{e['endpoint']}: {e['error']}" for e in errors[:3])
                    app._show_error(app.security_ops_detail, "Security Ops refresh failed", Exception(msg))
                    return
                self._render_security_ops_dashboard(report, observability, yara_health, yara_analytics, errors)
                # A successful refresh implies a live, attended session -
                # extend the sudo window so destructive follow-ups don't
                # immediately demand a re-verify.
                self._mark_sudo_verified()
                self._render_compliance_strip()
                self._update_workspace_badge()
            finally:
                self._set_busy(False)

        def _on_err(message: str) -> None:
            try:
                app._show_error(app.security_ops_detail, "Security Ops refresh failed", Exception(message))
            finally:
                self._set_busy(False)

        submit_async_call(
            parent=app,
            label="security-ops refresh",
            work=_gather,
            on_success=_on_done,
            on_failure=_on_err,
            timeout_seconds=150,
        )

    def _render_security_ops_dashboard(
        self,
        report: dict,
        observability: dict,
        yara_health: dict,
        yara_analytics: dict,
        errors: list,
    ) -> None:
        app = self.app
        integrity = report.get("integrity", {}) if isinstance(report, dict) else {}
        abuse = report.get("abuse", {}) if isinstance(report, dict) else {}
        database = report.get("database", {}) if isinstance(report, dict) else {}
        sources = yara_analytics.get("sources", []) if isinstance(yara_analytics, dict) else []
        counts = integrity.get("counts", {}) if isinstance(integrity.get("counts"), dict) else {}

        # ---------------- KPI strip ----------------
        integrity_status = str(integrity.get("status", "unknown") or "unknown")
        sig_valid = bool(integrity.get("signature_valid", False))
        modified = int(counts.get("modified", 0) or 0)
        missing = int(counts.get("missing", 0) or 0)
        dead_letters = int(abuse.get("dead_letters", 0) or 0)
        yara_errors = int(yara_health.get("compile_error_count", 0) or 0)
        last_rotation = report.get("last_secret_rotation", "") if isinstance(report, dict) else ""
        self._update_kpi_chips(
            integrity_status=integrity_status,
            signature_valid=sig_valid,
            modified=modified,
            missing=missing,
            dead_letters=dead_letters,
            yara_errors=yara_errors,
            last_rotation_label=self._format_relative_time(last_rotation) if last_rotation else "n/a",
        )

        # ---------------- Last-refresh stamp + YARA errors badge ----
        self._last_refresh_label.setText(
            f"Last refreshed: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        # Surface compile-error count directly on the button so the
        # analyst doesn't have to click in to discover there are errors.
        previous_error_count = getattr(self, "_last_yara_error_count", -1)
        if yara_errors > 0:
            self._yara_errors_btn.setText(f"YARA Errors ({yara_errors})")
            self._yara_errors_btn.setStyleSheet(
                "QPushButton { color: #feb2b2; font-weight: 600; } "
                "QPushButton:hover { background:#5f1d1d; }"
            )
            # Toast - fire only when the count crosses 0 → N, so an
            # always-broken environment doesn't nag the operator on
            # every refresh.
            if previous_error_count == 0 or previous_error_count == -1 and yara_errors > 0:
                self._show_toast(
                    f"YARA compile errors detected: {yara_errors}",
                    tone="crit",
                    duration_ms=6000,
                )
        else:
            self._yara_errors_btn.setText("YARA Errors")
            self._yara_errors_btn.setStyleSheet("")
            if previous_error_count and previous_error_count > 0:
                self._show_toast("YARA compile errors cleared", tone="ok", duration_ms=4000)
        self._last_yara_error_count = yara_errors

        # ---------------- Posture summary (rich HTML) ----------------
        app.security_ops_summary.setHtml(
            f"<h3 style='margin:0 0 6px 0'>Security Ops Posture</h3>"
            f"<table style='font-size:13px;color:#cbd5e0' cellpadding='3'>"
            f"<tr><td><b>Integrity status</b></td><td>{html.escape(integrity_status)}</td></tr>"
            f"<tr><td><b>Signature valid</b></td><td>{'✅' if sig_valid else '❌'} {html.escape(str(sig_valid))}</td></tr>"
            f"<tr><td><b>Dead letters</b></td><td>{html.escape(str(dead_letters))}</td></tr>"
            f"<tr><td><b>Observability events</b></td><td>{html.escape(str(observability.get('event_count', 0)))}</td></tr>"
            f"<tr><td><b>YARA compile errors</b></td><td>{html.escape(str(yara_errors))}</td></tr>"
            f"<tr><td><b>YARA scans tracked</b></td><td>{html.escape(str(len(yara_analytics.get('recent_scans', []))))}</td></tr>"
            f"</table>"
            + (f"<p style='color:#feb2b2;margin-top:8px'><b>Partial refresh:</b> {len(errors)} endpoint(s) failed - see Detail pane.</p>" if errors else "")
        )

        # ---------------- Integrity Drift table (tone-coded counts) ----
        integrity_rows = [
            ("verified", counts.get("verified", 0), "ok"),
            ("modified", counts.get("modified", 0), "warn" if int(counts.get("modified", 0) or 0) else "ok"),
            ("missing", counts.get("missing", 0), "crit" if int(counts.get("missing", 0) or 0) else "ok"),
            ("untracked", counts.get("untracked", 0), "warn" if int(counts.get("untracked", 0) or 0) else "ok"),
        ]
        app.security_integrity_table.clearSpans()
        app.security_integrity_table.setRowCount(len(integrity_rows))
        for r, (bucket, value, tone) in enumerate(integrity_rows):
            bucket_item = QTableWidgetItem(str(bucket))
            count_item = QTableWidgetItem(str(value))
            count_item.setTextAlignment(int(Qt.AlignCenter))
            if tone == "ok":
                count_item.setForeground(QBrush(QColor(_KPI_TEXT_OK)))
            elif tone == "warn":
                count_item.setForeground(QBrush(QColor(_KPI_TEXT_WARN)))
            elif tone == "crit":
                count_item.setForeground(QBrush(QColor(_KPI_TEXT_CRIT)))
            bold = QFont(); bold.setBold(True); count_item.setFont(bold)
            app.security_integrity_table.setItem(r, 0, bucket_item)
            app.security_integrity_table.setItem(r, 1, count_item)

        # ---------------- Platform Readiness (badge cells) ------------
        db_info = (database.get("database") or {}) if isinstance(database, dict) else {}
        db_backend = str(db_info.get("backend", "unknown") or "unknown")
        db_mode = str(db_info.get("mode", "unknown") or "unknown")
        migrations_applied = len(((database.get("migrations") or {}).get("applied", []))) if isinstance(database, dict) else 0
        anomaly_count = len(abuse.get("anomalies", [])) if isinstance(abuse, dict) else 0

        platform_rows = [
            ("database backend", db_backend, "ok" if db_backend != "unknown" else "warn"),
            ("database mode", db_mode, "ok" if db_mode in {"embedded", "shared-runtime"} else "warn"),
            ("migrations applied", str(migrations_applied), "ok" if migrations_applied else "warn"),
            ("abuse anomalies", str(anomaly_count), "ok" if anomaly_count == 0 else ("warn" if anomaly_count < 3 else "crit")),
        ]
        app.security_platform_table.clearSpans()
        app.security_platform_table.setRowCount(len(platform_rows))
        for r, (domain, status_value, tone) in enumerate(platform_rows):
            d_item = QTableWidgetItem(str(domain))
            s_item = QTableWidgetItem(str(status_value))
            colour = {"ok": _KPI_TEXT_OK, "warn": _KPI_TEXT_WARN, "crit": _KPI_TEXT_CRIT}.get(tone, _KPI_TEXT_NEUTRAL)
            s_item.setForeground(QBrush(QColor(colour)))
            bold = QFont(); bold.setBold(True); s_item.setFont(bold)
            app.security_platform_table.setItem(r, 0, d_item)
            app.security_platform_table.setItem(r, 1, s_item)

        # ---------------- YARA Source Analytics -----------------------
        app.security_yara_table.clearSpans()
        rows = list(sources[:12])
        if rows:
            app.security_yara_table.setRowCount(len(rows))
            for r, item in enumerate(rows):
                app.security_yara_table.setItem(r, 0, QTableWidgetItem(str(item.get("source", "unknown"))))
                app.security_yara_table.setItem(r, 1, QTableWidgetItem(str(item.get("total_hits", 0))))
                app.security_yara_table.setItem(r, 2, QTableWidgetItem(str(item.get("suppressed_hits", 0))))
                app.security_yara_table.setItem(r, 3, QTableWidgetItem(f"{float(item.get('avg_score', 0) or 0):.1f}"))
        else:
            self._install_empty_table_placeholder(
                app.security_yara_table,
                "No YARA hits yet - run scans then Refresh YARA Ops.",
            )

        app._show_json(app.security_ops_detail, _redact_payload({
            "report": report,
            "observability": observability,
            "yara_health": yara_health,
            "yara_analytics": yara_analytics,
            "_partial_errors": errors,
        }))

    @staticmethod
    def _format_relative_time(value) -> str:
        """Best-effort 'Nm ago' / 'Nh ago' label for a timestamp.

        Accepts UNIX-epoch floats/ints and ISO-8601 strings. Returns
        the raw value on parse failure so the dashboard still surfaces
        something rather than blanking out.
        """
        try:
            if isinstance(value, (int, float)) and float(value) > 0:
                seconds = max(0, int(time.time() - float(value)))
            else:
                parsed = _dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=_dt.timezone.utc)
                seconds = max(0, int(_dt.datetime.now(_dt.timezone.utc).timestamp() - parsed.timestamp()))
        except Exception:
            return str(value)[:24]
        if seconds < 60:
            return f"{seconds}s ago"
        if seconds < 3600:
            return f"{seconds // 60}m ago"
        if seconds < 86400:
            return f"{seconds // 3600}h ago"
        return f"{seconds // 86400}d ago"

    def refresh_yara_ops_workspace(self) -> None:
        app = self.app
        try:
            health = app._get("/yara/local/health", timeout=30).json()
            analytics = app._get("/yara/local/analytics", timeout=30).json()
        except Exception as exc:
            app._show_error(app.security_ops_detail, "YARA ops refresh failed", exc)
            return
        app.security_ops_summary.setHtml(
            "<h3>Local YARA Operations</h3>"
            f"<p><b>Policy loaded:</b> {html.escape(str(health.get('policy_loaded', False)))}"
            f"<br><b>Compile errors:</b> {html.escape(str(health.get('compile_error_count', 0)))}"
            f"<br><b>Enterprise rules loaded:</b> {html.escape(str(health.get('enterprise_rules_loaded', 0)))}</p>"
        )
        sources = analytics.get("sources", []) if isinstance(analytics, dict) else []
        app.security_yara_table.setRowCount(len(sources[:12]))
        for r, item in enumerate(sources[:12]):
            app.security_yara_table.setItem(r, 0, QTableWidgetItem(str(item.get("source", "unknown"))))
            app.security_yara_table.setItem(r, 1, QTableWidgetItem(str(item.get("total_hits", 0))))
            app.security_yara_table.setItem(r, 2, QTableWidgetItem(str(item.get("suppressed_hits", 0))))
            app.security_yara_table.setItem(r, 3, QTableWidgetItem(f"{float(item.get('avg_score', 0) or 0):.1f}"))
        if not sources:
            app.security_ops_detail.setPlainText("No local YARA analytics are available yet. Refresh after running detection workflows or loading policy.")
        app._show_json(app.security_ops_detail, _redact_payload({"yara_health": health, "yara_analytics": analytics}))

    def load_local_yara_policy(self) -> None:
        app = self.app
        try:
            result = app._get("/yara/local/policy", timeout=30).json()
        except Exception as exc:
            app._show_error(app.security_ops_detail, "Local YARA policy load failed", exc)
            return
        app.security_yara_policy.setPlainText(json.dumps(result.get("policy", {}), indent=2, ensure_ascii=False))
        app._show_json(app.security_ops_detail, _redact_payload(result))

    def save_local_yara_policy(self) -> None:
        app = self.app
        if not self._check_action_gate("save-yara-policy"):
            return
        try:
            payload = json.loads(app.security_yara_policy.toPlainText() or "{}")
        except ValueError as exc:
            app._show_error(app.security_ops_detail, "Local YARA policy save failed", exc)
            return
        # Block save-with-no-changes early so audit history stays clean.
        try:
            current = app._get("/yara/local/policy", timeout=15).json()
            current_policy = current.get("policy", {}) if isinstance(current, dict) else {}
        except Exception:
            current_policy = {}
        # Defensive heuristic: refuse to save a runaway allow-list pattern
        # that would silence the entire detection surface.
        allow_patterns = payload.get("allowlist_rule_patterns", []) if isinstance(payload, dict) else []
        if any(p in {"*", ".*", "**"} for p in (allow_patterns or [])):
            warn = QMessageBox(app)
            warn.setWindowTitle("Refusing to save catch-all allow-list")
            warn.setIcon(QMessageBox.Critical)
            warn.setText("Allow-list pattern would suppress every YARA hit.")
            warn.setInformativeText(
                "Patterns like '*', '.*', or '**' match every rule and effectively "
                "disable the local YARA pipeline. Narrow the pattern (e.g. "
                "'Hacktool_*' or 'PUA_*') and try again."
            )
            warn.exec()
            return
        # Side-by-side diff preview so the analyst sees exactly what
        # they're committing. Cancel → bail, OK → proceed to reason.
        if not self._confirm_yara_policy_diff(current_policy, payload):
            return
        # YARA policy override determines which detection rules are
        # boosted, suppressed, or allow-listed. Forensic-critical -
        # capture the ticket so SOC managers can audit *why* a rule
        # was suppressed.
        reason = self._capture_reason("save-yara-policy")
        if reason is None:
            return
        try:
            result = app._put("/yara/local/policy", json={"policy": payload}, timeout=30).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        # Capture a snapshot of WHAT changed (allowlist / boost / suppression
        # counts) so the audit row is searchable without diffing JSON
        # blobs.
        allowlist_count = len(payload.get("allowlist_rule_patterns", [])) if isinstance(payload, dict) else 0
        boost_count = len(payload.get("boost_rule_patterns", {})) if isinstance(payload, dict) else 0
        suppression_count = len(payload.get("suppression_rule_patterns", [])) if isinstance(payload, dict) else 0
        self._record_audit(
            action="save-yara-policy",
            target=f"allowlist={allowlist_count} boost={boost_count} suppress={suppression_count}",
            severity="medium",
            status="ok" if ok else "failed",
            payload={"summary": {"allowlist_count": allowlist_count, "boost_count": boost_count, "suppression_count": suppression_count}, "response": result},
            reason=reason,
        )
        if not ok:
            app._show_error(app.security_ops_detail, "Local YARA policy save failed", Exception(error))
            return
        app.security_yara_policy.setPlainText(json.dumps(result.get("policy", {}), indent=2, ensure_ascii=False))
        app._show_json(app.security_ops_detail, _redact_payload(result))
        self.refresh_yara_ops_workspace()

    def load_local_yara_errors(self) -> None:
        app = self.app
        try:
            result = app._get("/yara/local/errors", timeout=30).json()
        except Exception as exc:
            app._show_error(app.security_ops_detail, "Local YARA errors failed", exc)
            return
        app._show_json(app.security_ops_detail, _redact_payload(result))

    def refresh_integrity_manifest(self) -> None:
        app = self.app
        if not self._check_action_gate("refresh-integrity"):
            return
        try:
            result = app._post("/integrity/refresh", timeout=30).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        # Manifest refresh isn't destructive - it recomputes hashes -
        # but the audit row makes drift events traceable to the
        # operator who triggered the recompute.
        counts = result.get("counts", {}) if isinstance(result, dict) else {}
        self._record_audit(
            action="refresh-integrity",
            target=f"verified={counts.get('verified', 0)} modified={counts.get('modified', 0)} missing={counts.get('missing', 0)}",
            severity="low",
            status="ok" if ok else "failed",
            payload=result,
        )
        if not ok:
            app._show_error(app.security_ops_detail, "Integrity refresh failed", Exception(error))
            return
        app._show_json(app.security_ops_detail, _redact_payload(result))
        self.refresh_security_ops_workspace()

    def rotate_security_secrets(self) -> None:
        app = self.app
        if not self._check_action_gate("rotate-secrets"):
            return
        if not self._ensure_sudo_or_warn("Rotate Secrets"):
            return
        # Confirmation dialog because secret rotation invalidates active
        # webhook subscriptions and connector creds - operator must
        # actively confirm. We also show the live webhook destination so
        # they know what's about to be invalidated.
        current_url = self._fetch_current_webhook_url()
        masked = _redact_url_for_display(current_url) if current_url else "<no webhook configured>"
        confirm = QMessageBox(app)
        confirm.setWindowTitle("Confirm secret rotation")
        confirm.setText("Rotate ALL ShadowLab security secrets?")
        confirm.setInformativeText(
            "<b>This will invalidate:</b><br>"
            "• Integrity signing key (manifest re-signed)<br>"
            "• Alert webhook secret (subscriptions must be re-established)<br>"
            "• Every connector secret (re-paste required at each integration)<br><br>"
            f"<b>Current webhook:</b> <code>{html.escape(masked)}</code><br><br>"
            "A structured reason will be required next."
        )
        confirm.setIcon(QMessageBox.Critical)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason("rotate-secrets")
        if reason is None:
            return
        body = {
            "rotate_integrity_signing_key": True,
            "reencrypt_webhook_secret": True,
            "reencrypt_connector_secrets": True,
            "clear_alert_webhook": False,
        }
        try:
            result = app._post("/enterprise/secrets/rotate", json=body, timeout=45).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        self._record_audit(
            action="rotate-secrets",
            target="integrity_key + webhook_secret + connector_secrets",
            severity="critical",
            status="ok" if ok else "failed",
            payload={"request": body, "response": result},
            reason=reason,
        )
        if not ok:
            app._show_error(app.security_ops_detail, "Secret rotation failed", Exception(error))
            return
        app._show_json(app.security_ops_detail, _redact_payload(result))
        self.refresh_security_ops_workspace()

    def test_alert_webhook(self) -> None:
        """Send a probe payload to the live alert webhook and surface the result."""
        app = self.app
        if not self._check_action_gate("refresh-workspace"):
            return
        self._set_busy(True, "Pinging configured webhook…")
        try:
            try:
                result = app._post(
                    "/integrations/alerts/webhook/test",
                    json={"title": "ShadowLab webhook probe",
                          "summary": "Manual desktop test - no incident attached"},
                    timeout=15,
                ).json()
                ok = True
            except Exception as exc:
                result = {"error": str(exc)}
                ok = False
            self._record_audit(
                action="refresh-workspace",
                target="webhook-test",
                severity="low",
                status="ok" if ok else "failed",
                payload=result,
            )
            if ok:
                status_code = result.get("status_code") if isinstance(result, dict) else None
                state = result.get("state", "delivered") if isinstance(result, dict) else "delivered"
                app.statusBar().showMessage(
                    f"Webhook probe {state} (HTTP {status_code or '?'}) - see Detail panel."
                )
            else:
                app.statusBar().showMessage("Webhook probe failed - see Detail panel.")
            app._show_json(app.security_ops_detail, _redact_payload(result))
        finally:
            self._set_busy(False)

    def clear_alert_webhook_secret(self) -> None:
        app = self.app
        if not self._check_action_gate("clear-webhook"):
            return
        if not self._ensure_sudo_or_warn("Clear Webhook"):
            return
        # Look up the live destination so the analyst knows exactly what
        # they're about to silence - token redacted to keep this safe in
        # screen-share scenarios.
        current_url = self._fetch_current_webhook_url()
        masked = _redact_url_for_display(current_url) if current_url else "<no webhook configured>"
        # Clearing the webhook secret silences alert delivery - easy to
        # do by accident, hard to recover from. Demand confirmation +
        # structured reason.
        confirm = QMessageBox(app)
        confirm.setWindowTitle("Confirm webhook clear")
        confirm.setText("Clear the alert webhook secret?")
        confirm.setInformativeText(
            f"<b>Currently configured destination:</b><br><code>{html.escape(masked)}</code><br><br>"
            "Outbound alert webhooks will silently fail until a new secret is configured. "
            "Use only if the current webhook destination is compromised. A structured "
            "reason will be required next."
        )
        confirm.setIcon(QMessageBox.Critical)
        confirm.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        if confirm.exec() != QMessageBox.Ok:
            return
        reason = self._capture_reason("clear-webhook")
        if reason is None:
            return
        body = {
            "rotate_integrity_signing_key": False,
            "reencrypt_webhook_secret": False,
            "reencrypt_connector_secrets": False,
            "clear_alert_webhook": True,
        }
        try:
            result = app._post("/enterprise/secrets/rotate", json=body, timeout=30).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        self._record_audit(
            action="clear-webhook",
            target="alert_webhook_secret",
            severity="high",
            status="ok" if ok else "failed",
            payload={"response": result},
            reason=reason,
        )
        if not ok:
            app._show_error(app.security_ops_detail, "Webhook clearing failed", Exception(error))
            return
        if hasattr(app, "webhook_url"):
            app.webhook_url.clear()
        app._show_json(app.security_ops_detail, _redact_payload(result))
        self.refresh_security_ops_workspace()

    def export_security_ops_report(self) -> None:
        app = self.app
        if not self._check_action_gate("export-report"):
            return
        # Off-host evidence - a security ops report leaves the appliance
        # with sensitive integrity drift / secret rotation history.
        # Capture a structured reason so the chain-of-custody is
        # auditable.
        reason = self._capture_reason("export-report")
        if reason is None:
            return
        try:
            result = app._post("/enterprise/report/security-ops/export", timeout=45).json()
            ok = True
            error = ""
        except Exception as exc:
            result = {"error": str(exc)}
            ok = False
            error = str(exc)
        html_path = str(result.get("html_path", "") or "") if isinstance(result, dict) else ""
        self._record_audit(
            action="export-report",
            target=f"html={html_path or 'pending'}",
            severity="medium",
            status="ok" if ok else "failed",
            payload=result,
            reason=reason,
        )
        if not ok:
            app._show_error(app.security_ops_detail, "Security Ops export failed", Exception(error))
            return
        app._show_json(app.security_ops_detail, _redact_payload(result))
        if html_path:
            QDesktopServices.openUrl(QUrl.fromLocalFile(html_path))
