from __future__ import annotations

import calendar
import html
import time
from typing import Any

from PySide6.QtCore import QMargins, QPointF, Qt, QTimer
from PySide6.QtGui import QColor, QPen
from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtCore import QUrl
from PySide6.QtGui import QIcon, QKeySequence
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QSystemTrayIcon,
    QTableWidget,
    QTextBrowser,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)


# --------------------------------------------------------------------------- #
# Visual tokens
# --------------------------------------------------------------------------- #

_SEVERITY_COLOR = {
    "critical": "#ff4d6d",
    "high":     "#ff6b8a",
    "medium":   "#f4c26b",
    "warning":  "#f4c26b",
    "low":      "#7fd7ff",
    "info":     "#7fd7ff",
    "unknown":  "#96a5b8",
    "":         "#96a5b8",
}

_STATUS_COLOR = {
    "healthy":   ("#0f3d2d", "#7fe39d"),
    "ok":        ("#0f3d2d", "#7fe39d"),
    "available": ("#0f3d2d", "#7fe39d"),
    "active":    ("#0f3d2d", "#7fe39d"),
    "degraded":  ("#3d2f0f", "#f4c26b"),
    "warning":   ("#3d2f0f", "#f4c26b"),
    "stale":     ("#3d2f0f", "#f4c26b"),
    "error":     ("#3d1722", "#ff6b8a"),
    "critical":  ("#3d1722", "#ff4d6d"),
    "down":      ("#3d1722", "#ff6b8a"),
    "locked":    ("#1f2a38", "#96a5b8"),
    "unknown":   ("#1f2a38", "#96a5b8"),
}

_PANEL_HEIGHT_COMPACT = 96
_PANEL_HEIGHT_WIDE = 120


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _severity_color(severity: Any) -> str:
    return _SEVERITY_COLOR.get(str(severity or "unknown").strip().lower(), "#96a5b8")


def _status_pair(status: Any) -> tuple[str, str]:
    return _STATUS_COLOR.get(str(status or "unknown").strip().lower(), _STATUS_COLOR["unknown"])


def _badge(label: str, status: str = "unknown") -> str:
    bg, fg = _status_pair(status)
    return (
        f"<span style=\"display:inline-block;padding:1px 7px;border-radius:9px;"
        f"background:{bg};color:{fg};font-size:10px;font-weight:700;"
        f"letter-spacing:0.4px;text-transform:uppercase;\">{_esc(label)}</span>"
    )


def _sev_pill(severity: Any) -> str:
    color = _severity_color(severity)
    label = str(severity or "unknown").upper() or "UNKNOWN"
    return (
        f"<span style=\"display:inline-block;padding:1px 7px;border-radius:9px;"
        f"background:rgba(255,255,255,0.04);color:{color};font-size:10px;"
        f"font-weight:800;letter-spacing:0.4px;\">{_esc(label)}</span>"
    )


def _progress_bar(percent: float, color: str = "#28a0ff") -> str:
    pct = max(0.0, min(100.0, float(percent)))
    return (
        "<div style=\"background:#0e1622;border:1px solid #243446;border-radius:6px;"
        "height:6px;overflow:hidden;\">"
        f"<div style=\"width:{pct:.1f}%;height:6px;background:{color};\"></div>"
        "</div>"
    )


def _stack_bar(segments: list[tuple[float, str]]) -> str:
    """Render a horizontal stacked bar from (weight, color) tuples."""
    total = sum(max(0.0, float(seg[0])) for seg in segments) or 1.0
    cells = []
    for weight, color in segments:
        pct = max(0.0, float(weight)) / total * 100.0
        if pct <= 0:
            continue
        cells.append(
            f"<div style=\"display:inline-block;width:{pct:.2f}%;height:6px;"
            f"background:{color};\"></div>"
        )
    return (
        "<div style=\"background:#0e1622;border:1px solid #243446;border-radius:6px;"
        "height:6px;overflow:hidden;line-height:0;font-size:0;white-space:nowrap;\">"
        + "".join(cells) + "</div>"
    )


_SPARK_BLOCKS = "▁▂▃▄▅▆▇█"


def _sparkline(values: list[float], width: int = 12) -> str:
    """Render a tiny Unicode-block sparkline. Returns "" for empty
    series so the suffix can collapse cleanly. The character set is
    monospace-friendly and renders correctly in QLabel rich-text."""
    cleaned = [float(v) for v in values if v is not None]
    if not cleaned:
        return ""
    if len(cleaned) > width:
        # Fold to `width` buckets by averaging non-overlapping windows.
        bucket = max(1, len(cleaned) // width)
        folded: list[float] = []
        for i in range(0, len(cleaned), bucket):
            chunk = cleaned[i:i + bucket]
            if chunk:
                folded.append(sum(chunk) / len(chunk))
        cleaned = folded[-width:]
    lo, hi = min(cleaned), max(cleaned)
    rng = max(1e-9, hi - lo)
    out_chars: list[str] = []
    for v in cleaned:
        idx = int(round((v - lo) / rng * (len(_SPARK_BLOCKS) - 1)))
        out_chars.append(_SPARK_BLOCKS[max(0, min(idx, len(_SPARK_BLOCKS) - 1))])
    return "".join(out_chars)


def _filter_chip_row(panel_key: str, axis: str, current: str,
                     options: list[tuple[str, str]]) -> str:
    """Render an inline row of filter chips backed by anchor links.

    Each chip is a `<a href="action://filter:<panel>:<axis>:<value>">`.
    `_on_panel_anchor_clicked` interprets the click and updates the
    controller's `_panel_filters` map then re-renders the relevant
    panel via `refresh_dashboard_panels` (which now uses cached data —
    no extra HTTP needed for filter changes).
    """
    chips: list[str] = []
    cur = (current or "all").strip().lower()
    for value, label in options:
        active = (value == cur)
        # Active chip = filled background + brighter text; inactive = subtle.
        if active:
            style = ("background:#1d3a5c;color:#cfeaff;border:1px solid #28507a;"
                     "border-radius:9px;padding:1px 8px;font-size:10px;font-weight:700;"
                     "text-decoration:none;letter-spacing:0.3px;")
        else:
            style = ("background:#0e1622;color:#7a8a9c;border:1px solid #243446;"
                     "border-radius:9px;padding:1px 8px;font-size:10px;font-weight:600;"
                     "text-decoration:none;letter-spacing:0.3px;")
        chips.append(
            f"<a href='action://filter:{_esc(panel_key)}:{_esc(axis)}:{_esc(value)}' "
            f"style=\"{style}\">{_esc(label)}</a>"
        )
    label = axis.replace("_", " ").title()
    chips_html = "&nbsp;".join(chips)
    return (
        "<span style='color:#7a8a9c;font-size:10px;font-weight:600;margin-right:4px;'>"
        f"{_esc(label)}:</span>{chips_html}"
    )


def _pagination_footer(showing: int, total: int, panel_key: str) -> str:
    """Render a small `Showing N of M · See all (M) →` footer that
    routes to the corresponding Open Panel via the anchor click handler.
    Returns empty string when nothing is hidden so the panel stays
    clean for short lists.
    """
    if total <= showing or total <= 0:
        return ""
    return (
        "<p style='color:#7a8a9c;margin:6px 0 0;font-size:11px;'>"
        f"Showing {showing} of {total} &middot; "
        f"<a href='action://open:{_esc(panel_key)}' "
        "style='color:#7fd7ff;text-decoration:none;font-weight:600;'>See all &rarr;</a>"
        "</p>"
    )


def _hourly_buckets(events: list[dict], *, now: float, hours: int = 24,
                    timestamp_key: str = "created_at") -> list[int]:
    """Bucket events into per-hour counts over the last `hours` hours.
    Index 0 is the oldest hour, index -1 is the most recent.
    """
    buckets = [0] * hours
    cutoff = now - hours * 3600
    for event in events:
        if not isinstance(event, dict):
            continue
        ts = _coerce_epoch(event.get(timestamp_key))
        if ts <= 0 or ts < cutoff:
            continue
        bucket_idx = int((ts - cutoff) // 3600)
        if 0 <= bucket_idx < hours:
            buckets[bucket_idx] += 1
    return buckets


def _format_age(epoch_seconds: float | None, *, now: float | None = None) -> str:
    if not epoch_seconds:
        return "--"
    try:
        seconds = max(0.0, (now or time.time()) - float(epoch_seconds))
    except (TypeError, ValueError):
        return "--"
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds / 60)}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def _coerce_epoch(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    text = str(value).strip()
    # A trailing "Z" means the timestamp is UTC: it must be converted with
    # calendar.timegm (UTC), not time.mktime (local), or every age/dwell/
    # heatmap value is skewed by the operator's UTC offset.
    for fmt, is_utc in (
        ("%Y-%m-%d %H:%M:%S", False),
        ("%Y-%m-%dT%H:%M:%S", False),
        ("%Y-%m-%dT%H:%M:%SZ", True),
    ):
        try:
            parsed = time.strptime(text, fmt)
        except (TypeError, ValueError):
            continue
        return calendar.timegm(parsed) if is_utc else time.mktime(parsed)
    return 0.0


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------- #
# Controller
# --------------------------------------------------------------------------- #


class DashboardWorkspaceController:
    """Owns the SOC Dashboards tab and the SOC Overview tab.

    The Dashboards tab is meant to behave like a real product-grade SOC
    command center: it fuses incident queue, antivirus engine posture,
    MITRE coverage, threat-intel pulse, recent alerts, and access/policy
    context onto a single scan-friendly surface, with graceful
    degradation when the API session is locked or an endpoint is
    unavailable.
    """

    def __init__(self, app) -> None:
        self.app = app
        self._auto_refresh_timer: QTimer | None = None
        self._auto_refresh_btn: QPushButton | None = None
        self._refresh_in_progress = False
        self._last_dashboard_refresh: float = 0.0
        # Chunked-refresh queue + payload buffer.  Every refresh tick
        # pulls one item from the queue and reschedules via
        # QTimer.singleShot(0, ...) so tab-switching, repaints, button
        # clicks all stay responsive while the 12 endpoints drain.
        self._refresh_queue: list = []
        self._refresh_step_data: dict = {}
        # Freshness ticker (P3-22) — updates the staleness badge every
        # 5 s without re-fetching.  Colour escalates green → amber → red
        # the longer it's been since the last successful refresh.
        self._freshness_timer: QTimer | None = None
        self._freshness_label: "QLabel | None" = None
        # Time-range picker — drives client-side cutoff for alerts /
        # incidents and the "OPEN ALERTS" KPI subtitle. Default 24h.
        self._dashboard_window_seconds: int = 86_400
        self._dashboard_window_label: str = "24h"
        self._range_combo: "QComboBox | None" = None
        # Per-endpoint last-error map; rendered into panels with a retry
        # link when an API call fails so the panel doesn't silently
        # display stale or empty data.
        self._last_errors: dict[str, str] = {}
        # Critical-incident toast state — we diff active critical/high
        # incident IDs against the previous refresh and surface a system
        # tray notification for any newcomer.
        self._known_critical_ids: set[str] = set()
        self._tray_icon: "QSystemTrayIcon | None" = None
        self._tray_initialised: bool = False
        # Cache for incident lookup (drill-down + triage)
        self._latest_incidents: list[dict] = []
        # Workspace switcher (P2-19) state
        self._workspace_combo: "QComboBox | None" = None
        self._workspace_known: set[str] = {"default"}
        # Cache for export menu (last refresh's incidents + alerts)
        self._latest_alerts: list[dict] = []
        # Inline filter chip state (#1) — per-panel, per-key.  Anchor
        # clicks on `action://filter:<panel>:<key>:<value>` mutate this
        # dict and re-render. "all" means no filter.
        self._panel_filters: dict[str, dict[str, str]] = {
            "incidents": {"severity": "all", "status": "all"},
            "alerts":    {"severity": "all", "status": "all"},
            "audit":     {"kind": "all",     "result": "all"},
        }
        # Cache of last refresh's payload — lets filter chip clicks
        # re-render without re-fetching from the API.
        self._cached_refresh_data: dict | None = None
        # Notification panel (P1-13) — bell icon drop-down keeps the
        # last 30 events (new incidents + dispatched high-severity
        # alerts) so the analyst can review what's happened since they
        # last looked at the dashboard.
        self._notifications: list[dict] = []
        self._notifications_unread: int = 0
        self._notification_button: "QPushButton | None" = None
        self._known_alert_ids: set[str] = set()
        # View presets (P2-18) — three layout profiles surfaced as a
        # combo in the header. Hidden panels are tracked here so a
        # dynamic refresh doesn't override the operator's choice.
        self._view_combo: "QComboBox | None" = None
        self._panel_card_refs: dict[str, QWidget] = {}
        self._dash_grid = None

    # ------------------------------------------------------------------ #
    # Dashboard tab build
    # ------------------------------------------------------------------ #

    def build_dashboard_tab(self) -> QWidget:
        app = self.app
        w = QWidget()
        w.setProperty("no_vertical_scroll", True)
        root = QVBoxLayout(w)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(6)

        root.addWidget(self._build_header())

        # Compact pill-style KPI strip (same look as Processes / Telemetry
        # Rows / Last Incident / Artifacts pills in the global app
        # header). Underlying QLabel widgets for the original card KPI
        # strip are still constructed for legacy compatibility.
        self._build_kpi_widgets()
        root.addWidget(self._build_kpi_pill_row())

        # Panel grid -----------------------------------------------------
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setHorizontalSpacing(10)
        grid.setVerticalSpacing(10)

        app.dash_metrics  = self._build_panel_browser("Incident Queue",
            "Run monitor or refresh history to populate the active incident queue.")
        app.dash_engines  = self._build_panel_browser("Engine Posture",
            "Antivirus and detection engine availability will appear here once /antivirus/status responds.")
        app.dash_mitre    = self._build_panel_browser("MITRE Coverage",
            "Detection lifecycle and MITRE technique coverage will populate after the first monitor session.")
        app.dash_threat   = self._build_panel_browser("Threat Intel Pulse",
            "No hash, IP, sandbox, or enrichment queries recorded yet.")
        app.dash_auth     = self._build_panel_browser("Access & Policy",
            "Apply an API key to load role, workspace, and policy context.")
        app.dash_timeline = self._build_panel_browser("Timeline Story",
            "Refresh history or run monitor to build an activity narrative.")

        app.dash_alerts = self._build_panel_browser("Recent Alerts",
            "Recent dispatched alerts (Slack / email / webhook / queue) will surface here.",
            min_height=_PANEL_HEIGHT_WIDE)

        # Detection Rule Health — pulls /enterprise/detections/lifecycle
        # to expose disabled / silent / experimental rule counts. Without
        # this surface a stalled rule sits invisibly until an incident
        # quietly slips through.
        app.dash_rules = self._build_panel_browser("Detection Rules",
            "Detection rule lifecycle (enabled / disabled / silent / experimental) will populate after the next refresh.")

        # Fleet / Hosts — situational awareness: how many endpoints
        # are reporting, agent-stale, offline. Real-product SOC dashboards
        # always show a fleet pill before going operator-deep.
        app.dash_fleet = self._build_panel_browser("Fleet & Hosts",
            "Agent-reporting endpoints will appear here once /hosts responds.")

        # Telemetry Gaps — surface signal sources that are missing or
        # silent so the analyst doesn't act on partial data.
        app.dash_gaps = self._build_panel_browser("Telemetry Gaps",
            "Signal-source gap analysis will appear here from /enterprise/telemetry/gaps.")

        # Connector / integration health (P1-9) — Slack / Email /
        # Webhook / SIEM forwarder etc. Visible to admins only; the
        # error-state path renders a clean "locked" message for
        # analysts and viewers.
        app.dash_connectors = self._build_panel_browser("Integrations",
            "Connector health (Slack / Email / Webhook / SIEM forwarder) will appear from /enterprise/connectors.")

        # Severity heatmap (P2-14) — 7-day × 24-hour grid of alert
        # volume coloured by max severity in each cell. Replaces the
        # Access & Policy slot — that data is already surfaced via the
        # freshness badge, workspace switcher and policy pills.
        app.dash_heatmap = self._build_panel_browser("Severity Heatmap",
            "Alert volume by hour-of-day / day-of-week will populate after the first refresh.")

        # Compliance / SLA snapshot (P2-17)
        app.dash_sla = self._build_panel_browser("Compliance & SLA",
            "MTTR, SLA breach count, and policy compliance will appear from /antivirus/sla.")

        # Audit trail (P3-23) — last N entries from /history/auth and
        # /history/actions merged.  Admin-only (the endpoints require
        # admin), surfaced in the Detailed view preset.
        app.dash_audit = self._build_panel_browser("Audit Trail",
            "Recent auth + action events (admin-only) will appear from /history/auth and /history/actions.")

        # Wire drill-down anchors: clicking an incident or alert row
        # routes via `_on_panel_anchor_clicked` to the Enterprise tab,
        # while `action://...` URLs trigger a refresh / retry.
        for browser in (app.dash_metrics, app.dash_alerts, app.dash_engines,
                        app.dash_mitre, app.dash_threat, app.dash_auth,
                        app.dash_timeline, app.dash_rules, app.dash_fleet,
                        app.dash_gaps, app.dash_connectors, app.dash_heatmap,
                        app.dash_sla, app.dash_audit):
            browser.setOpenLinks(False)
            browser.anchorClicked.connect(self._on_panel_anchor_clicked)

        # 3x2 main grid
        # Cards stored in `_panel_card_refs` so view-presets can show /
        # hide them without rebuilding the layout.
        cards = self._panel_card_refs
        cards["incidents"]   = app._panel_card("Incident Queue",    app.dash_metrics,  app._open_dashboard_metrics_panel)
        cards["engines"]     = app._panel_card("Engine Posture",    app.dash_engines,  self.open_dashboard_engines_panel)
        cards["mitre"]       = app._panel_card("MITRE Coverage",    app.dash_mitre,    self.open_dashboard_mitre_panel)
        cards["rules"]       = app._panel_card("Detection Rules",   app.dash_rules,    self.open_dashboard_rules_panel)
        cards["fleet"]       = app._panel_card("Fleet & Hosts",     app.dash_fleet,    self.open_dashboard_fleet_panel)
        cards["heatmap"]     = app._panel_card("Severity Heatmap",  app.dash_heatmap,  self.open_dashboard_heatmap_panel)
        cards["alerts"]      = app._panel_card("Recent Alerts",     app.dash_alerts,   self.open_dashboard_alerts_panel)
        cards["gaps"]        = app._panel_card("Telemetry Gaps",    app.dash_gaps,     self.open_dashboard_gaps_panel)
        cards["connectors"]  = app._panel_card("Integrations",      app.dash_connectors, self.open_dashboard_connectors_panel)
        cards["sla"]         = app._panel_card("Compliance & SLA",  app.dash_sla,      self.open_dashboard_sla_panel)
        # Access & Policy now lives only inside the legacy widget; data
        # is mostly surfaced via the freshness badge / workspace combo,
        # so we hide the card by default and let the operator surface
        # it via the Detailed view preset.
        cards["auth"]        = app._panel_card("Access & Policy",   app.dash_auth,     app._open_dashboard_auth_panel)
        cards["audit"]       = app._panel_card("Audit Trail",        app.dash_audit,    self.open_dashboard_audit_panel)

        # Cards are positioned dynamically by `_relayout_dashboard` so
        # each view preset packs ONLY its visible panels, with no
        # QSplitter nesting. The previous static 3-col grid + a 4-way
        # `wide_split` + a 2-way `detail_split` produced the uneven
        # "3 / 3 / 4 / 2" rows the operator flagged. Now every view is a
        # uniform N-column grid (Detailed = 4 equal columns, 12 panels →
        # 4×3) with all cells the same size.
        self._dash_grid = grid
        root.addLayout(grid, 1)
        # Apply whichever view preset is currently selected — must run
        # after the grid is built and the cards exist.
        QTimer.singleShot(0, self._apply_current_view)
        return w

    def _build_header(self) -> QWidget:
        app = self.app
        header = QWidget()
        row = QHBoxLayout(header)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        title_block = QWidget()
        title_layout = QVBoxLayout(title_block)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)
        # Shortened from "Security Operations Command Center" because
        # the stale badge + refresh bell on the right squeezed the full
        # phrase to "Security Operations Comm…" at typical viewport
        # widths. "Security Operations" stays semantically clear and
        # leaves room for the chrome on the right.
        title = QLabel("Security Operations")
        title.setStyleSheet("font-size:16px;font-weight:800;color:#f4f7fb;")
        subtitle = QLabel(
            "Live incident queue, engine posture, MITRE coverage, threat-intel pulse, and operator readiness."
        )
        subtitle.setStyleSheet("color:#96a5b8;font-size:11px;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        row.addWidget(title_block, 1)

        # Freshness staleness (P3-22) — auto-updating badge that shows
        # how old the dashboard data is. Independent of API calls so a
        # stalled backend visibly drifts to red.
        freshness = QLabel("● stale")
        freshness.setStyleSheet(
            "color:#96a5b8;font-size:11px;font-weight:700;padding:4px 10px;"
            "border-radius:10px;background:#1f2a38;border:1px solid #243446;"
        )
        freshness.setToolTip("Time since the last successful Dashboards refresh. "
                              "Green=fresh, amber=>1m, red=>5m.")
        self._freshness_label = freshness
        row.addWidget(freshness)

        # Bell notification button (P1-13)
        bell_btn = QPushButton("🔔")
        bell_btn.setMinimumWidth(48)
        bell_btn.setToolTip("Recent SOC events (new incidents + high-severity alerts).")
        bell_btn.setAccessibleName("Notification bell — recent SOC events")
        bell_btn.setShortcut(QKeySequence("Ctrl+Shift+N"))
        bell_btn.clicked.connect(lambda _checked=False, b=bell_btn: self._open_notification_panel(b))
        self._notification_button = bell_btn
        row.addWidget(bell_btn)

        # Status strip --------------------------------------------------
        app.dashboard_status_label = QLabel("waiting for data")
        app.dashboard_status_label.setStyleSheet(
            "color:#96a5b8;font-size:11px;padding:0 6px;font-weight:600;"
        )
        row.addWidget(app.dashboard_status_label)

        # Start the freshness ticker. Independent of auto-refresh — just
        # updates the badge cosmetically.
        if self._freshness_timer is None:
            self._freshness_timer = QTimer(app)
            self._freshness_timer.setInterval(5_000)
            self._freshness_timer.timeout.connect(self._update_freshness_badge)
            self._freshness_timer.start()
            self._update_freshness_badge()

        # Workspace switcher (P2-19) — sticky combo bound to the global
        # `app.workspace_id` field so all subsequent API calls (which
        # read X-ShadowLab-Workspace from that text) flow through the
        # selected workspace. Populated lazily from /hosts on first
        # refresh.
        ws_label = QLabel("Workspace:")
        ws_label.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:600;padding:0 4px;")
        row.addWidget(ws_label)
        ws_combo = QComboBox()
        ws_combo.setMinimumWidth(120)
        ws_combo.setEditable(True)
        ws_combo.lineEdit().setPlaceholderText("default")
        ws_combo.lineEdit().setText(
            (app.workspace_id.text().strip() if hasattr(app, "workspace_id") else "") or "default"
        )
        ws_combo.lineEdit().editingFinished.connect(self._on_workspace_edited)
        ws_combo.currentIndexChanged.connect(self._on_workspace_picked)
        ws_combo.setAccessibleName("Workspace selector")
        self._workspace_combo = ws_combo
        self._workspace_known: set[str] = {ws_combo.lineEdit().text().strip().lower() or "default"}
        row.addWidget(ws_combo)

        # Time-range picker — feeds client-side cutoff for alerts /
        # incidents and the "OPEN ALERTS" KPI subtitle.
        range_label = QLabel("Range:")
        range_label.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:600;padding:0 4px;")
        row.addWidget(range_label)
        range_combo = QComboBox()
        range_combo.setMinimumWidth(110)
        for label, seconds in (
            ("Last 1h",   3_600),
            ("Last 24h",  86_400),
            ("Last 7d",   604_800),
            ("Last 30d",  2_592_000),
        ):
            range_combo.addItem(label, seconds)
        range_combo.setCurrentIndex(1)  # default 24h
        range_combo.currentIndexChanged.connect(self._on_range_changed)
        range_combo.setAccessibleName("Time range selector")
        self._range_combo = range_combo
        row.addWidget(range_combo)

        # View preset (P2-18) — toggles which panels are visible.
        view_label = QLabel("View:")
        view_label.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:600;padding:0 4px;")
        row.addWidget(view_label)
        view_combo = QComboBox()
        view_combo.setMinimumWidth(110)
        for label in ("Default", "Compact", "Detailed"):
            view_combo.addItem(label)
        # Restore last-used view from QSettings.
        try:
            last_view = self.app.settings.value("dashboard_view", "Default", type=str) or "Default"
            idx = view_combo.findText(last_view)
            if idx >= 0:
                view_combo.setCurrentIndex(idx)
        except Exception:
            pass
        view_combo.currentIndexChanged.connect(self._on_view_changed)
        view_combo.setAccessibleName("Dashboard view preset selector")
        self._view_combo = view_combo
        row.addWidget(view_combo)

        # NOTE on capability binding: read-only Dashboard buttons used to
        # be bound to "can_view_history", which is NOT a real backend
        # capability (api/security.build_capabilities never sets it), so
        # `bind_capability` was disabling them for every authenticated
        # role.  We drop those bindings — these actions are read-only
        # (or open a UI sub-panel) and the underlying API endpoints
        # already enforce role checks.

        # Auto-Refresh — user-driven toggle. Tab-switch auto-refresh
        # was removed (no longer fires on tab change), so the only
        # background timer is this one and it ONLY runs while the
        # button is checked. Click to start, click again to stop.
        auto_btn = QPushButton("Auto-Refresh: OFF")
        auto_btn.setCheckable(True)
        auto_btn.setMinimumWidth(140)
        auto_btn.setAccessibleName("Toggle auto-refresh — starts on first click, stops on next click")
        auto_btn.toggled.connect(self._on_auto_refresh_toggled)
        self._auto_refresh_btn = auto_btn
        row.addWidget(auto_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setAccessibleName("Refresh Dashboards now")
        refresh_btn.clicked.connect(self.refresh_dashboard_panels)
        row.addWidget(refresh_btn)

        triage_btn = QPushButton("Enterprise Triage")
        triage_btn.setAccessibleName("Open Enterprise Triage workspace")
        triage_btn.clicked.connect(self._open_enterprise_triage)
        # `can_manage_incidents` is real — bind it so viewers see it disabled.
        app._bind_capability(triage_btn, "can_manage_incidents")
        row.addWidget(triage_btn)

        incident_btn = QPushButton("Open Incident Queue")
        incident_btn.setAccessibleName("Open Incident Queue with inline triage")
        incident_btn.clicked.connect(self._open_incident_queue_panel)
        row.addWidget(incident_btn)

        # Export menu — surfaces incident / alert CSV and a PNG snapshot.
        export_btn = QPushButton("Export ▾")
        export_btn.setMinimumWidth(90)
        export_btn.setAccessibleName("Export menu — CSV / PNG")
        export_btn.clicked.connect(lambda _checked=False, b=export_btn: self._open_export_menu(b))
        row.addWidget(export_btn)

        return header

    # ------------------------------------------------------------------ #
    # Header button handlers — wired here (not via app aliases) so they
    # call the local methods directly and survive any controller swap.
    # ------------------------------------------------------------------ #

    def _open_enterprise_triage(self) -> None:
        app = self.app
        try:
            # Switch to Enterprise tab first so the workspace is visible.
            switcher = getattr(app, "_switch_to_tab", None)
            if callable(switcher):
                switcher("Enterprise")
            # Then trigger the enterprise workspace refresh — guarded
            # because the controller might not be wired yet.
            refresher = getattr(app, "refresh_enterprise_workspace", None)
            if callable(refresher):
                refresher()
        except Exception:
            return

    def _open_incident_queue_panel(self) -> None:
        # Direct call — avoids the `app.` alias indirection that the
        # earlier wiring relied on.  Guards against race when the panel
        # widgets aren't yet built.
        if hasattr(self.app, "dash_metrics"):
            try:
                self.open_dashboard_metrics_panel()
            except Exception:
                return

    def _on_workspace_edited(self) -> None:
        if self._workspace_combo is None:
            return
        value = self._workspace_combo.lineEdit().text().strip().lower() or "default"
        self._apply_workspace(value)

    def _on_workspace_picked(self, index: int) -> None:
        if self._workspace_combo is None:
            return
        value = (self._workspace_combo.itemText(index) or "").strip().lower() or "default"
        self._apply_workspace(value)

    def _apply_workspace(self, workspace: str) -> None:
        app = self.app
        workspace = workspace or "default"
        if hasattr(app, "workspace_id"):
            current = app.workspace_id.text().strip().lower() or "default"
            if current != workspace:
                app.workspace_id.setText(workspace)
        # Refresh dashboard with new workspace context.
        try:
            self.refresh_dashboard_panels()
        except Exception:
            pass

    def _refresh_workspace_choices(self, hosts_raw: Any, incidents: list[dict]) -> None:
        """Populate the workspace combo with distinct workspace_ids
        observed in /hosts and /incidents responses, preserving the
        currently-selected value.
        """
        if self._workspace_combo is None:
            return
        observed: set[str] = set(self._workspace_known)
        for record in (hosts_raw or []):
            if isinstance(record, dict):
                ws = str(record.get("workspace_id") or "").strip().lower()
                if ws:
                    observed.add(ws)
        for inc in (incidents or []):
            if isinstance(inc, dict):
                ws = str(inc.get("workspace_id") or "").strip().lower()
                if ws:
                    observed.add(ws)
        observed.add("default")
        if observed == self._workspace_known:
            return
        self._workspace_known = observed
        # Repopulate without firing change signals.
        self._workspace_combo.blockSignals(True)
        current_text = self._workspace_combo.lineEdit().text().strip().lower() or "default"
        self._workspace_combo.clear()
        for ws in sorted(observed):
            self._workspace_combo.addItem(ws)
        # Restore current
        idx = self._workspace_combo.findText(current_text)
        if idx >= 0:
            self._workspace_combo.setCurrentIndex(idx)
        else:
            self._workspace_combo.lineEdit().setText(current_text)
        self._workspace_combo.blockSignals(False)

    def _open_export_menu(self, anchor_button: QPushButton) -> None:
        from PySide6.QtWidgets import QMenu  # local import — avoids top-of-file churn
        menu = QMenu(anchor_button)
        menu.addAction("Incidents - CSV",   self._export_incidents_csv)
        menu.addAction("Recent Alerts - CSV", self._export_alerts_csv)
        menu.addSeparator()
        menu.addAction("Dashboard - PNG snapshot", self._export_dashboard_png)
        menu.exec(anchor_button.mapToGlobal(anchor_button.rect().bottomLeft()))

    # ------------------------------------------------------------------ #
    # Export (P2-20)
    # ------------------------------------------------------------------ #

    def _export_csv_dialog(self, suggested_name: str) -> str | None:
        from PySide6.QtWidgets import QFileDialog
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        default = str((self._default_export_dir() / f"{suggested_name}-{stamp}.csv"))
        path, _ = QFileDialog.getSaveFileName(
            self.app, f"Export {suggested_name}", default, "CSV files (*.csv)"
        )
        return path or None

    def _default_export_dir(self):
        from pathlib import Path
        candidate = Path.cwd() / "shadowlab_out"
        try:
            candidate.mkdir(parents=True, exist_ok=True)
        except Exception:
            from tempfile import gettempdir
            return Path(gettempdir())
        return candidate

    def _write_csv(self, path: str, rows: list[dict], columns: list[str]) -> bool:
        import csv
        try:
            with open(path, "w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
                writer.writeheader()
                for row in rows:
                    writer.writerow({col: ("" if row.get(col) is None else row.get(col)) for col in columns})
            return True
        except Exception:
            return False

    def _export_incidents_csv(self) -> None:
        rows = self._latest_incidents
        if not rows:
            self._toast_status("No incidents to export.", error=True)
            return
        path = self._export_csv_dialog("incidents")
        if not path:
            return
        columns = [
            "incident_id", "severity", "status", "title", "owner",
            "created_at", "workspace_id", "summary",
        ]
        if self._write_csv(path, rows, columns):
            self._toast_status(f"Exported {len(rows)} incident(s) -> {path}")
        else:
            self._toast_status(f"Failed to write {path}", error=True)

    def _export_alerts_csv(self) -> None:
        rows = self._latest_alerts
        if not rows:
            self._toast_status("No alerts to export (current window).", error=True)
            return
        path = self._export_csv_dialog("alerts")
        if not path:
            return
        columns = [
            "created_at", "severity", "status", "title",
            "destination_type", "destination", "detail", "workspace_id",
        ]
        if self._write_csv(path, rows, columns):
            self._toast_status(f"Exported {len(rows)} alert(s) -> {path}")
        else:
            self._toast_status(f"Failed to write {path}", error=True)

    def _export_dashboard_png(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        from pathlib import Path
        # Find the Dashboards tab widget — this controller doesn't hold a
        # direct reference, so we ask the QTabWidget on `app.tabs`.
        tabs = getattr(self.app, "tabs", None)
        if tabs is None:
            self._toast_status("Dashboard tab not available.", error=True)
            return
        target_widget = None
        for index in range(tabs.count()):
            if tabs.tabText(index).strip().lower() == "dashboards":
                target_widget = tabs.widget(index)
                break
        if target_widget is None:
            self._toast_status("Dashboards tab not found.", error=True)
            return
        stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime())
        default = str(Path(self._default_export_dir()) / f"dashboard-{stamp}.png")
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Export Dashboard PNG", default, "PNG image (*.png)"
        )
        if not path:
            return
        try:
            pixmap = target_widget.grab()
            if not pixmap.save(path, "PNG"):
                self._toast_status(f"Failed to save PNG to {path}", error=True)
                return
            self._toast_status(f"Saved PNG -> {path}")
        except Exception as exc:
            self._toast_status(f"PNG export failed: {self._summarise_error(exc)}", error=True)

    def _toast_status(self, message: str, *, error: bool = False) -> None:
        # Surface in the dashboard status pill + the main app status bar
        # for redundancy. The status pill clears on next refresh.
        if hasattr(self.app, "dashboard_status_label"):
            color = "#ff8aa3" if error else "#7fe39d"
            self.app.dashboard_status_label.setStyleSheet(
                f"color:{color};font-size:11px;padding:0 6px;font-weight:600;"
            )
            self.app.dashboard_status_label.setText(message[:120])
        try:
            self.app.statusBar().showMessage(message, 5000)
        except Exception:
            return

    def _update_freshness_badge(self) -> None:
        """Repaint the freshness badge based on time since the last
        successful refresh.  Called by a 5-second QTimer.
        """
        if self._freshness_label is None:
            return
        # Locked session — not an error, just informational.
        if not getattr(self.app, "auth_session_ready", False):
            self._freshness_label.setText("● locked")
            self._freshness_label.setStyleSheet(
                "color:#96a5b8;font-size:11px;font-weight:700;padding:4px 10px;"
                "border-radius:10px;background:#1f2a38;border:1px solid #2c4260;"
            )
            return
        if not self._last_dashboard_refresh:
            self._freshness_label.setText("● no data")
            self._freshness_label.setStyleSheet(
                "color:#96a5b8;font-size:11px;font-weight:700;padding:4px 10px;"
                "border-radius:10px;background:#1f2a38;border:1px solid #2c4260;"
            )
            return
        age = max(0.0, time.time() - self._last_dashboard_refresh)
        if age < 60:
            text = f"● fresh {int(age)}s"
            bg, fg, border = "#0f3d2d", "#7fe39d", "#1f6648"
        elif age < 300:
            text = f"● stale {int(age // 60)}m"
            bg, fg, border = "#3d2f0f", "#f4c26b", "#5a4416"
        else:
            text = f"● STALE {int(age // 60)}m"
            bg, fg, border = "#3d1722", "#ff8aa3", "#5b1f2d"
        self._freshness_label.setText(text)
        self._freshness_label.setStyleSheet(
            f"color:{fg};font-size:11px;font-weight:700;padding:4px 10px;"
            f"border-radius:10px;background:{bg};border:1px solid {border};"
        )

    def _on_range_changed(self, index: int) -> None:
        if self._range_combo is None:
            return
        seconds = self._range_combo.itemData(index)
        text = self._range_combo.itemText(index)
        try:
            self._dashboard_window_seconds = int(seconds) if seconds else 86_400
        except (TypeError, ValueError):
            self._dashboard_window_seconds = 86_400
        # Friendly short label used in KPI subtitles ("1h"/"24h"/"7d"/"30d")
        self._dashboard_window_label = text.replace("Last ", "").strip() or "24h"
        # Light-touch refresh — falls back gracefully if API not ready yet.
        try:
            self.refresh_dashboard_panels()
        except Exception:
            pass

    def _build_kpi_widgets(self) -> None:
        app = self.app

        def _new_value(color: str) -> QLabel:
            label = QLabel("--")
            label.setStyleSheet(f"color:{color};font-size:18px;font-weight:800;")
            return label

        def _new_sub(text: str) -> QLabel:
            sub = QLabel(text)
            sub.setStyleSheet("color:#c8d8ea;font-size:10px;")
            sub.setWordWrap(True)
            return sub

        def _new_bar() -> QLabel:
            bar = QLabel()
            bar.setMinimumHeight(6)
            bar.setMaximumHeight(6)
            bar.setStyleSheet(
                "background:#0e1622;border:1px solid #243446;border-radius:4px;"
            )
            bar.setText("")
            return bar

        app.dashboard_kpi_incident      = _new_value("#ff6b8a")
        app.dashboard_kpi_incident_sub  = _new_sub("incident posture")
        app.dashboard_kpi_incident_bar  = _new_bar()

        app.dashboard_kpi_alerts        = _new_value("#7fd7ff")
        app.dashboard_kpi_alerts_sub    = _new_sub("alerts (24h)")
        app.dashboard_kpi_alerts_bar    = _new_bar()

        app.dashboard_kpi_engines       = _new_value("#7fe39d")
        app.dashboard_kpi_engines_sub   = _new_sub("engine availability")
        app.dashboard_kpi_engines_bar   = _new_bar()

        app.dashboard_kpi_mitre         = _new_value("#c98bff")
        app.dashboard_kpi_mitre_sub     = _new_sub("MITRE technique coverage")
        app.dashboard_kpi_mitre_bar     = _new_bar()

        app.dashboard_kpi_telemetry     = _new_value("#f4c26b")
        app.dashboard_kpi_telemetry_sub = _new_sub("latest monitor samples")
        app.dashboard_kpi_telemetry_bar = _new_bar()

        # DWELL = median age of currently active incidents — proxy for
        # MTTD/MTTR maturity (we lack a `resolved_at` column, so dwell is
        # the cleanest meaningful operator-facing metric we can compute).
        app.dashboard_kpi_dwell         = _new_value("#ffb168")
        app.dashboard_kpi_dwell_sub     = _new_sub("median active incident age")
        app.dashboard_kpi_dwell_bar     = _new_bar()

        # Legacy aliases used by other modules
        app.dashboard_kpi_processes      = QLabel("--")
        app.dashboard_kpi_processes_sub  = QLabel("host process inventory")
        app.dashboard_kpi_artifacts      = QLabel("--")
        app.dashboard_kpi_artifacts_sub  = QLabel("evidence files")

        # Compact pill labels — match the global app header pill look
        # (Processes / Telemetry Rows / Last Incident / Artifacts).
        # `_update_kpi_strip` writes single-line `LABEL: value` text into
        # these. Colour is applied dynamically by severity/threshold.
        app.dash_pill_risk       = QLabel("Risk: --")
        app.dash_pill_incident   = QLabel("Incidents: --")
        app.dash_pill_alerts     = QLabel("Alerts 24h: --")
        app.dash_pill_engines    = QLabel("Engines: --")
        app.dash_pill_mitre      = QLabel("MITRE: --")
        app.dash_pill_telemetry  = QLabel("Telemetry: --")
        app.dash_pill_dwell      = QLabel("Dwell: --")
        for pill, accessible in (
            (app.dash_pill_risk,      "Composite risk score"),
            (app.dash_pill_incident,  "Active incidents"),
            (app.dash_pill_alerts,    "Open alerts in window"),
            (app.dash_pill_engines,   "Engine availability"),
            (app.dash_pill_mitre,     "MITRE technique coverage"),
            (app.dash_pill_telemetry, "Telemetry pressure"),
            (app.dash_pill_dwell,     "Median active incident dwell time"),
        ):
            pill.setStyleSheet(
                "background:#121b27;color:#c8d8ea;border:1px solid #2c4260;"
                "border-radius:10px;padding:6px 10px;font-weight:600;font-size:11px;"
            )
            # P3-24 — screen-reader friendly names + keyboard focus.
            pill.setAccessibleName(accessible)
            pill.setFocusPolicy(Qt.TabFocus)
        # Risk pill is the hero indicator — always rendered first and
        # given a slightly stronger border so the operator's eye lands
        # on it before the contributing metrics.
        app.dash_pill_risk.setToolTip(
            "Composite workspace risk score 0-100. "
            "Sum of severity-weighted active incidents, open alerts, "
            "MITRE coverage gaps, engine staleness, and median dwell."
        )

    def _build_kpi_pill_row(self) -> QWidget:
        """Single-line KPI pill row that mirrors the look of the
        global app header metrics (Processes / Telemetry Rows / ...).
        Risk score (P2-15) is rendered first as the hero indicator.
        """
        app = self.app
        wrap = QWidget()
        wrap.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        row = QHBoxLayout(wrap)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        for pill in (app.dash_pill_risk, app.dash_pill_incident, app.dash_pill_alerts,
                     app.dash_pill_engines, app.dash_pill_mitre,
                     app.dash_pill_telemetry, app.dash_pill_dwell):
            row.addWidget(pill)
        row.addStretch(1)
        return wrap

    def _build_panel_browser(self, title: str, body: str, *, min_height: int = _PANEL_HEIGHT_COMPACT) -> QTextBrowser:
        browser = QTextBrowser()
        browser.setProperty("role", "brief")
        browser.setOpenExternalLinks(False)
        browser.setMinimumHeight(min_height)
        # No setMaximumHeight: SizePolicy.Expanding lets the panel grow to
        # fill the dashboard tab on larger screens. The panel_card wrapper
        # already manages its own padding and title bar.
        browser.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        browser.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        browser.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        browser.setHtml(self._dashboard_empty_html(body))
        return browser

    def _build_quick_actions(self) -> QWidget:
        app = self.app
        quick = QWidget()
        quick.setProperty("panel_compact", True)
        quick.setMaximumHeight(48)
        row = QHBoxLayout(quick)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        capabilities = {
            "Run Monitor":        "can_run_monitor",
            "Load Processes":     "can_run_hunt",
            "Refresh History":    "can_view_history",
            "Refresh Dashboard":  "can_view_history",
            "Enterprise Triage":  "can_manage_incidents",
            "Open Incident Queue": "can_view_history",
        }
        for text, fn in [
            ("Refresh Dashboard",   app.refresh_overview),
            ("Run Monitor",         app.run_monitor),
            ("Load Processes",      app.refresh_processes),
            ("Refresh History",     app.refresh_history),
            ("Enterprise Triage",   app.refresh_enterprise_workspace),
            ("Open Incident Queue", app._open_dashboard_metrics_panel),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(fn)
            cap = capabilities.get(text)
            if cap:
                app._bind_capability(btn, cap)
            row.addWidget(btn)
        row.addStretch(1)
        return quick

    # ------------------------------------------------------------------ #
    # KPI tile / empty HTML
    # ------------------------------------------------------------------ #

    def _dashboard_kpi_tile(self, title: str, value: QLabel, sub: QLabel, bar: QLabel, accent: str) -> QWidget:
        tile = QFrame()
        tile.setProperty("card", True)
        tile.setMinimumHeight(70)
        tile.setMaximumHeight(78)
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(2)
        label = QLabel(title)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;")
        value.setStyleSheet(f"color:{accent};font-size:18px;font-weight:800;")
        sub.setStyleSheet("color:#c8d8ea;font-size:10px;")
        sub.setWordWrap(True)
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addWidget(sub)
        layout.addWidget(bar)
        return tile

    def _dashboard_empty_html(self, body: str, _legacy: str | None = None) -> str:
        # Backwards-compatible: callers used to pass (title, body); the
        # panel_card wrapper renders its own title now, so we only show
        # the muted hint line in the body.
        if _legacy is not None:
            body = _legacy
        return (
            f"<p style='color:#96a5b8;margin:6px 0 0;font-size:11px;'>{_esc(body)}</p>"
        )

    # ------------------------------------------------------------------ #
    # Auto-refresh
    # ------------------------------------------------------------------ #

    def _on_auto_refresh_toggled(self, checked: bool) -> None:
        if checked:
            if self._auto_refresh_timer is None:
                self._auto_refresh_timer = QTimer(self.app)
                self._auto_refresh_timer.setInterval(30_000)  # 30 s
                self._auto_refresh_timer.timeout.connect(self._auto_refresh_tick)
            self._auto_refresh_timer.start()
            if self._auto_refresh_btn is not None:
                self._auto_refresh_btn.setText("Auto-Refresh: 30s")
        else:
            if self._auto_refresh_timer is not None:
                self._auto_refresh_timer.stop()
            if self._auto_refresh_btn is not None:
                self._auto_refresh_btn.setText("Auto-Refresh: OFF")

    def _auto_refresh_tick(self) -> None:
        if self._refresh_in_progress:
            return
        try:
            self.refresh_dashboard_panels()
        except Exception:
            # never let a transient API blip crash the timer
            return

    # ------------------------------------------------------------------ #
    # API helper
    # ------------------------------------------------------------------ #

    # Per-endpoint client-side limit (#5).  We pass `?limit=N` so the
    # backend can opt-in to pagination later without a UI change.  When
    # the backend ignores the param the response is identical to today.
    _ENDPOINT_LIMITS = {
        "/incidents":                       200,
        "/history/alerts":                  200,
        "/history/auth":                    100,
        "/history/actions":                 100,
        "/enterprise/detections/lifecycle": 200,
        "/hosts":                           500,
    }

    def _api_get(self, path: str, *, default: Any = None, timeout: float = 4.0) -> Any:
        """Fetch a JSON endpoint with last-error tracking.

        On success the path's previous error (if any) is cleared. On
        failure we record a short reason in `_last_errors[path]` so the
        renderer can surface "Couldn't load — Retry" with the cause
        instead of leaving the panel silently empty.

        A locked session (no API key applied yet) is NOT treated as an
        error — the panels fall through to their soft empty-state hint
        instead of painting eight red error cards on first launch.

        For list endpoints (#5 — backend pagination) we attach a
        `limit=N` query param so the API can opt into paged responses
        without a UI rewrite.
        """
        app = self.app
        if not getattr(app, "auth_session_ready", False):
            # Soft state: clear any stale error so the panel renders its
            # default "Run monitor / apply key" hint rather than red.
            self._last_errors.pop(path, None)
            return default
        try:
            limit = self._ENDPOINT_LIMITS.get(path)
            kwargs = {"timeout": timeout}
            if limit is not None:
                kwargs["params"] = {"limit": limit}
            response = app._get(path, **kwargs)
        except Exception as exc:
            self._last_errors[path] = self._summarise_error(exc)
            return default
        try:
            status = int(getattr(response, "status_code", 500))
        except (TypeError, ValueError):
            status = 500
        if status >= 400:
            try:
                detail = response.json().get("detail") if response.headers.get("content-type", "").startswith("application/json") else response.text
            except Exception:
                detail = ""
            self._last_errors[path] = f"HTTP {status}{(' - ' + str(detail)[:80]) if detail else ''}"
            return default
        try:
            payload = response.json()
        except Exception as exc:
            self._last_errors[path] = self._summarise_error(exc)
            return default
        # success — clear stale error
        self._last_errors.pop(path, None)
        return payload

    def _summarise_error(self, exc: Exception) -> str:
        text = str(exc) or exc.__class__.__name__
        return text[:120]

    # ------------------------------------------------------------------ #
    # Panel refresh — called from monitor_ops / refresh_overview pipelines
    # ------------------------------------------------------------------ #

    # Steps for incremental refresh — (data_key, http_path, default).
    _REFRESH_STEPS: list[tuple[str, str, Any]] = [
        ("incidents_raw",   "/incidents",                            []),
        ("alerts_raw",      "/history/alerts",                       []),
        ("av_status",       "/antivirus/status",                     {}),
        ("mitre",           "/enterprise/mitre/summary",             {}),
        ("rules_raw",       "/enterprise/detections/lifecycle",      []),
        ("hosts_raw",       "/hosts",                                []),
        ("telemetry_raw",   "/history/telemetry?limit=300",          []),
        ("gaps_raw",        "/enterprise/telemetry/gaps",            {}),
        ("connectors_raw",  "/enterprise/connectors",                []),
        ("sla_raw",         "/antivirus/sla",                        {}),
        ("auth_log_raw",    "/history/auth",                         []),
        ("action_log_raw",  "/history/actions",                      []),
    ]

    def refresh_dashboard_panels(self) -> None:
        """Public entry point — chunked refresh.

        We don't run a QThread worker (the earlier attempt crashed on
        cleanup), but we DO want tab-switching and other UI events to
        stay responsive while the 12 endpoints drain. So instead of one
        big synchronous call, the fetch is broken into a queue and
        each `QTimer.singleShot(0)` tick processes a single endpoint.
        Between ticks Qt's event loop redraws, repaints, dispatches
        clicks, and switches tabs — meaning the operator only ever
        feels at most one HTTP RTT (~50-150 ms) of latency at a time.
        """
        if self._refresh_in_progress:
            return
        self._refresh_in_progress = True
        # Snapshot so adding more steps later doesn't mutate mid-refresh.
        self._refresh_queue = list(self._REFRESH_STEPS)
        self._refresh_step_data = {"now": time.time()}
        QTimer.singleShot(0, self._process_refresh_step)

    def _rerender_panels_from_cache(self) -> None:
        """Re-run `_apply_refresh_data` against the cached payload from
        the last refresh — used when an inline filter chip is clicked.
        Falls back to a full refresh if no cache yet (first launch).
        """
        if self._cached_refresh_data is None:
            self.refresh_dashboard_panels()
            return
        try:
            # Refresh `now` so freshness / age columns reflect current time
            payload = dict(self._cached_refresh_data)
            payload["now"] = time.time()
            self._apply_refresh_data(payload)
        except Exception:
            return

    def _process_refresh_step(self) -> None:
        """Fetch one endpoint per tick, then reschedule. When the queue
        empties, apply the rendered payload to the panels.
        """
        try:
            if not self._refresh_queue:
                # Drain done — render once, all data ready. Stash a
                # copy so filter-chip clicks can re-render without
                # firing 12 more HTTP calls.
                self._cached_refresh_data = dict(self._refresh_step_data)
                try:
                    self._apply_refresh_data(self._refresh_step_data)
                finally:
                    self._refresh_in_progress = False
                    self._refresh_queue = []
                    self._refresh_step_data = {}
                return
            key, path, default = self._refresh_queue.pop(0)
            self._refresh_step_data[key] = self._api_get(path, default=default) or default
            QTimer.singleShot(0, self._process_refresh_step)
        except Exception:
            # Never let a refresh blip leave us stuck — clear the lock.
            self._refresh_in_progress = False
            self._refresh_queue = []
            self._refresh_step_data = {}

    def _apply_refresh_data(self, data: dict) -> None:
        """Render half — runs on the main thread, safe to touch widgets.

        Consumes the dict assembled incrementally by
        `_process_refresh_step` (one endpoint per QTimer tick, keys
        defined in `_REFRESH_STEPS`) so the render path has zero
        coupling to the HTTP fetch beyond the already-materialised
        payload.
        """
        app = self.app
        try:
            now = float(data.get("now") or time.time())
            window = max(60, int(self._dashboard_window_seconds or 86_400))
            cutoff = now - window

            incidents_raw = data.get("incidents_raw") or []
            alerts_raw    = data.get("alerts_raw") or []
            av_status     = data.get("av_status") or {}
            mitre         = data.get("mitre") or {}
            rules_raw     = data.get("rules_raw") or []
            hosts_raw     = data.get("hosts_raw") or []
            telemetry_raw = data.get("telemetry_raw") or []
            gaps_raw      = data.get("gaps_raw") or {}
            connectors_raw = data.get("connectors_raw") or []
            sla_raw       = data.get("sla_raw") or {}
            auth_log_raw  = data.get("auth_log_raw") or []
            action_log_raw = data.get("action_log_raw") or []

            if not isinstance(incidents_raw, list):
                incidents_raw = []
            if not isinstance(alerts_raw, list):
                alerts_raw = []
            if not isinstance(av_status, dict):
                av_status = {}
            if not isinstance(mitre, dict):
                mitre = {}

            # Apply time-range window client-side. We keep the *full*
            # incident list for the queue panel (operators want to see
            # in-flight incidents older than the window), but use the
            # filtered set for KPI counts so window-driven KPIs change.
            def _within_window(item: dict) -> bool:
                created = _coerce_epoch(item.get("created_at")) if isinstance(item, dict) else 0
                return created == 0 or created >= cutoff

            incidents = [i for i in incidents_raw if isinstance(i, dict)]
            alerts = [a for a in alerts_raw if isinstance(a, dict) and _within_window(a)]

            providers = av_status.get("providers", {}) if isinstance(av_status.get("providers"), dict) else {}
            sig_health = av_status.get("signature_health", {}) if isinstance(av_status.get("signature_health"), dict) else {}

            latest_result = getattr(app, "latest_monitor_result", {}) or {}
            telemetry_rows = latest_result.get("telemetry_rows", getattr(app, "latest_monitor_rows", []))
            telemetry_rows = telemetry_rows if isinstance(telemetry_rows, list) else []
            derived_from_history = False
            if not telemetry_rows and isinstance(telemetry_raw, list):
                # Mirror `_within_window`'s contract: a row whose `ts`
                # can't be coerced to an epoch (0.0) is kept rather than
                # silently dropped, so a single malformed timestamp can't
                # blank the entire Telemetry Trend. The endpoint already
                # caps the set at limit=300 and orders ts DESC, so the
                # [:300] + reversed() yields oldest→newest for the chart.
                def _telemetry_in_window(row: Any) -> bool:
                    if not isinstance(row, dict):
                        return False
                    epoch = _coerce_epoch(row.get("ts"))
                    return epoch == 0 or epoch >= cutoff

                telemetry_rows = list(reversed([
                    row for row in telemetry_raw if _telemetry_in_window(row)
                ][:300]))
                derived_from_history = True

            # Persist the history-derived rows so the SOC Overview's own
            # render path (`refresh_overview_widgets` → chart / Signal
            # Coverage / status pill) can consume the SAME data the KPI
            # strip just used. Without this the `telemetry_raw` refresh
            # step only fed the KPI tiles: the Overview chart reads
            # `app.latest_history_telemetry_rows`, which is otherwise set
            # ONLY when the History tab is rendered — so a dashboard
            # refresh that ran without a History-tab visit (or where the
            # /history call failed but /history/telemetry succeeded) left
            # the KPI strip showing "300 samples" while the chart stayed
            # stuck on "waiting for monitor". Guarded so we never shadow
            # a live monitor session or wipe an existing fallback with an
            # empty fetch.
            if derived_from_history and telemetry_rows and not latest_result:
                app.latest_history_telemetry_rows = telemetry_rows

            # --- Update KPI strip ------------------------------------ #
            self._update_kpi_strip(
                incidents, alerts, providers, sig_health, mitre, telemetry_rows, now, window,
            )

            # --- Render data panels (with per-panel error state) ----- #
            self._render_with_error("/incidents", app.dash_metrics,
                lambda: self._render_incident_queue(incidents, latest_result, now))
            self._render_with_error("/antivirus/status", app.dash_engines,
                lambda: self._render_engine_posture(providers, sig_health, av_status))
            self._render_with_error("/enterprise/mitre/summary", app.dash_mitre,
                lambda: self._render_mitre_panel(mitre, latest_result))
            self._render_with_error("/enterprise/detections/lifecycle", app.dash_rules,
                lambda: self._render_rules_panel(rules_raw))
            self._render_with_error("/history/alerts", app.dash_alerts,
                lambda: self._render_alerts_panel(alerts, now))
            self._render_with_error("/hosts", app.dash_fleet,
                lambda: self._render_fleet_panel(hosts_raw, now))
            self._render_with_error("/enterprise/telemetry/gaps", app.dash_gaps,
                lambda: self._render_gaps_panel(gaps_raw))
            self._render_with_error("/enterprise/connectors", app.dash_connectors,
                lambda: self._render_connectors_panel(connectors_raw))
            self._render_with_error("/antivirus/sla", app.dash_sla,
                lambda: self._render_sla_panel(sla_raw))
            self._render_with_error("/history/actions", app.dash_audit,
                lambda: self._render_audit_panel(auth_log_raw, action_log_raw, now))
            # Heatmap renders directly from already-fetched alerts +
            # incidents; no separate error path.
            try:
                app.dash_heatmap.setHtml(self._render_heatmap_panel(alerts, incidents, now))
            except Exception:
                pass

            # Pure local-state panels (no API path, no error skin)
            app.dash_threat.setHtml(self._render_threat_panel())
            app.dash_auth.setHtml(self._render_auth_panel())
            app.dash_timeline.setHtml(self._render_timeline_panel())

            # Cache full incident list for triage drill-down lookups
            self._latest_incidents = list(incidents)
            # Cache alerts for the export menu
            self._latest_alerts = list(alerts)
            # Critical-incident toast diff + high-sev alert bell diff
            self._maybe_emit_critical_toast(incidents)
            self._maybe_emit_alert_notifications(alerts)
            # Refresh the workspace switcher options based on observed
            # workspace ids in the latest payloads.
            self._refresh_workspace_choices(hosts_raw, incidents)

            # Header status pill + freshness badge
            self._last_dashboard_refresh = now
            self._update_freshness_badge()
            if hasattr(app, "dashboard_status_label"):
                stamp = time.strftime("%H:%M:%S", time.localtime(now))
                if not getattr(app, "auth_session_ready", False):
                    app.dashboard_status_label.setText(f"locked - apply API key  -  last attempt {stamp}")
                else:
                    err_count = len(self._last_errors)
                    parts = [f"refreshed {stamp}", f"window {self._dashboard_window_label}"]
                    parts.append(f"incidents:{len(incidents)} alerts:{len(alerts)} engines:{len(providers)}")
                    if err_count:
                        parts.append(f"errors:{err_count}")
                    app.dashboard_status_label.setText("  -  ".join(parts))

            # NOTE: deliberately NOT calling refresh_overview_widgets()
            # here. Wiring the QtCharts series mutation into the high-
            # frequency dashboard auto-refresh drain segfaults PySide6
            # (QtCharts series replaced while the chart is mid-paint on
            # the same event-loop turn). The original architecture keeps
            # Overview chart updates on explicit, infrequent triggers
            # (monitor_ops.refresh_overview / run_monitor) — respect
            # that. The minor one-click data-lag is an acceptable trade
            # vs. a hard crash. Bug-1 (persisting
            # latest_history_telemetry_rows below) still ensures the
            # data is present when the explicit trigger fires.
        except Exception:
            # Render-side failures should never crash the worker callback —
            # the next refresh tick will recover. Log via status pill.
            if hasattr(app, "dashboard_status_label"):
                app.dashboard_status_label.setText(
                    f"render error at {time.strftime('%H:%M:%S', time.localtime())}"
                )

    def _render_with_error(self, path: str, browser: QTextBrowser, renderer) -> None:
        """Render `renderer()` into `browser` unless `_last_errors[path]`
        carries a recent failure — in which case show an inline error
        card with a Retry link that re-runs `refresh_dashboard_panels`.
        """
        err = self._last_errors.get(path)
        if err:
            browser.setHtml(self._render_error_state(path, err))
            return
        try:
            browser.setHtml(renderer())
        except Exception as exc:
            # Renderer-side bug — show the error so we don't fail silently.
            self._last_errors[path] = self._summarise_error(exc)
            browser.setHtml(self._render_error_state(path, str(exc)))

    def _render_error_state(self, path: str, message: str) -> str:
        return (
            "<div style='padding:8px 10px;border:1px solid #5b1f2d;border-radius:8px;"
            "background:#2a1018;'>"
            f"<div style='color:#ff8aa3;font-size:12px;font-weight:700;'>"
            f"Couldn't load <span style='font-family:monospace;'>{_esc(path)}</span></div>"
            f"<div style='color:#c8d8ea;font-size:11px;margin-top:3px;'>{_esc(message)[:140]}</div>"
            "<div style='margin-top:6px;'>"
            "<a href='action://retry' style='color:#7fd7ff;font-size:11px;font-weight:700;text-decoration:none;'>Retry &rarr;</a>"
            "</div></div>"
        )

    # ------------------------------------------------------------------ #
    # KPI computation
    # ------------------------------------------------------------------ #

    def _update_kpi_strip(
        self,
        incidents: list[dict],
        alerts: list[dict],
        providers: dict[str, dict],
        sig_health: dict,
        mitre: dict,
        telemetry_rows: list[dict],
        now: float,
        window_seconds: int = 86_400,
    ) -> None:
        app = self.app

        # --- Active incidents + DWELL time ------------------------- #
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
        active = 0
        active_ages: list[float] = []
        for inc in incidents:
            if not isinstance(inc, dict):
                continue
            status = str(inc.get("status", "open") or "open").strip().lower()
            if status in {"closed", "resolved", "suppressed"}:
                continue
            active += 1
            sev = str(inc.get("severity", "unknown") or "unknown").strip().lower()
            if sev not in sev_counts:
                sev = "unknown"
            sev_counts[sev] += 1
            created = _coerce_epoch(inc.get("created_at"))
            if created > 0:
                active_ages.append(max(0.0, now - created))

        primary_sev = "info"
        for level in ("critical", "high", "medium", "low", "info", "unknown"):
            if sev_counts[level] > 0:
                primary_sev = level
                break
        app.dashboard_kpi_incident.setText(str(active))
        app.dashboard_kpi_incident.setStyleSheet(
            f"color:{_severity_color(primary_sev)};font-size:18px;font-weight:800;"
        )
        app.dashboard_kpi_incident_sub.setText(
            f"crit {sev_counts['critical']} - high {sev_counts['high']} - med {sev_counts['medium']} - low {sev_counts['low']}"
        )
        app.dashboard_kpi_incident_bar.setText("")
        sev_segments = [
            (sev_counts["critical"], "#ff4d6d"),
            (sev_counts["high"],     "#ff6b8a"),
            (sev_counts["medium"],   "#f4c26b"),
            (sev_counts["low"],      "#7fd7ff"),
            (sev_counts["info"] + sev_counts["unknown"], "#3a4b62"),
        ]
        if active > 0:
            self._set_label_html(app.dashboard_kpi_incident_bar, _stack_bar(sev_segments))
        else:
            self._set_label_html(app.dashboard_kpi_incident_bar, _stack_bar([(1, "#243446")]))

        # --- Open alerts (within selected time window) ------------- #
        # `alerts` is already filtered to the window upstream — recount
        # severities + open status here.
        alert_total = 0
        alert_open = 0
        alert_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for record in alerts:
            if not isinstance(record, dict):
                continue
            alert_total += 1
            sev = str(record.get("severity", "info") or "info").strip().lower()
            if sev in alert_sev:
                alert_sev[sev] += 1
            status = str(record.get("status", "open") or "open").strip().lower()
            if status not in {"acknowledged", "resolved", "closed", "delivered"}:
                alert_open += 1
        app.dashboard_kpi_alerts.setText(str(alert_total))
        app.dashboard_kpi_alerts_sub.setText(
            f"{alert_open} open - crit {alert_sev['critical']} high {alert_sev['high']} ({self._dashboard_window_label})"
        )
        self._set_label_html(
            app.dashboard_kpi_alerts_bar,
            _stack_bar([
                (alert_sev["critical"], "#ff4d6d"),
                (alert_sev["high"],     "#ff6b8a"),
                (alert_sev["medium"],   "#f4c26b"),
                (alert_sev["low"],      "#7fd7ff"),
                (alert_sev["info"],     "#3a4b62"),
            ]) if alert_total else _stack_bar([(1, "#243446")]),
        )

        # --- Engine availability ----------------------------------- #
        total_engines = len(providers)
        healthy = sum(1 for info in providers.values() if isinstance(info, dict) and info.get("available"))
        stale = 0
        if isinstance(sig_health, dict):
            stale = sum(
                1 for entry in sig_health.values()
                if isinstance(entry, dict) and str(entry.get("status", "")).lower() in {"stale", "warning", "missing"}
            )
        if total_engines == 0:
            engine_label = "0 / 0"
            engine_color = "#96a5b8"
            engine_pct = 0.0
        else:
            engine_label = f"{healthy} / {total_engines}"
            ratio = healthy / total_engines
            engine_color = "#7fe39d" if ratio == 1.0 else ("#f4c26b" if ratio >= 0.5 else "#ff6b8a")
            engine_pct = ratio * 100.0
        app.dashboard_kpi_engines.setText(engine_label)
        app.dashboard_kpi_engines.setStyleSheet(
            f"color:{engine_color};font-size:18px;font-weight:800;"
        )
        app.dashboard_kpi_engines_sub.setText(
            f"{healthy} healthy - {stale} stale signatures" if total_engines else "no provider snapshot yet"
        )
        self._set_label_html(app.dashboard_kpi_engines_bar, _progress_bar(engine_pct, engine_color))

        # --- MITRE coverage ---------------------------------------- #
        coverage_pct, coverage_label = self._compute_mitre_coverage(mitre)
        app.dashboard_kpi_mitre.setText(f"{coverage_pct:.0f}%" if coverage_pct > 0 else "--")
        coverage_color = "#c98bff" if coverage_pct >= 60 else ("#f4c26b" if coverage_pct >= 25 else "#ff6b8a")
        app.dashboard_kpi_mitre.setStyleSheet(
            f"color:{coverage_color};font-size:18px;font-weight:800;"
        )
        app.dashboard_kpi_mitre_sub.setText(coverage_label)
        self._set_label_html(app.dashboard_kpi_mitre_bar, _progress_bar(coverage_pct, coverage_color))

        # --- Telemetry pressure ------------------------------------ #
        # Guard `isinstance(r, dict)` to match the defensive style used
        # at the CPU-sparkline builder below (line ~1765). Without it a
        # single non-dict element in a malformed history payload raises
        # AttributeError, aborting the WHOLE KPI strip + the rest of
        # _apply_refresh_data (outer except → "render error"), i.e. one
        # bad row silently blanks the entire dashboard.
        telemetry_dicts = [r for r in telemetry_rows if isinstance(r, dict)]
        if telemetry_dicts:
            avg_cpu = sum(float(r.get("cpu", 0) or 0) for r in telemetry_dicts) / max(1, len(telemetry_dicts))
            avg_mem = sum(float(r.get("mem_percent", 0) or 0) for r in telemetry_dicts) / max(1, len(telemetry_dicts))
            pressure = max(avg_cpu, avg_mem)
            label = f"{pressure:.0f}%"
            sub = f"CPU {avg_cpu:.1f}% - MEM {avg_mem:.1f}% - n={len(telemetry_dicts)}"
            color = "#7fe39d" if pressure < 50 else ("#f4c26b" if pressure < 80 else "#ff6b8a")
        else:
            pressure, label = 0.0, "--"
            sub = "no telemetry samples yet"
            color = "#96a5b8"
        app.dashboard_kpi_telemetry.setText(label)
        app.dashboard_kpi_telemetry.setStyleSheet(
            f"color:{color};font-size:18px;font-weight:800;"
        )
        app.dashboard_kpi_telemetry_sub.setText(sub)
        self._set_label_html(app.dashboard_kpi_telemetry_bar, _progress_bar(pressure, color))

        # --- DWELL (median age of currently active incidents) ----- #
        if active_ages:
            sorted_ages = sorted(active_ages)
            mid = len(sorted_ages) // 2
            if len(sorted_ages) % 2 == 1:
                median = sorted_ages[mid]
            else:
                median = 0.5 * (sorted_ages[mid - 1] + sorted_ages[mid])
            longest = max(sorted_ages)
            dwell_text = _format_age(now - median, now=now)
            longest_text = _format_age(now - longest, now=now)
            # SOC SLA-ish thresholds: <1h green, <24h amber, otherwise red
            if median < 3600:
                dwell_color = "#7fe39d"
            elif median < 86400:
                dwell_color = "#f4c26b"
            else:
                dwell_color = "#ff6b8a"
            # Bar progress: median age vs 7-day max (cap)
            dwell_pct = min(100.0, (median / 604_800.0) * 100.0)
            dwell_sub = f"longest {longest_text} - n={len(active_ages)}"
        else:
            dwell_text = "--"
            dwell_color = "#96a5b8"
            dwell_pct = 0.0
            dwell_sub = "no active incidents"
        app.dashboard_kpi_dwell.setText(dwell_text)
        app.dashboard_kpi_dwell.setStyleSheet(
            f"color:{dwell_color};font-size:18px;font-weight:800;"
        )
        app.dashboard_kpi_dwell_sub.setText(dwell_sub)
        self._set_label_html(app.dashboard_kpi_dwell_bar, _progress_bar(dwell_pct, dwell_color))

        # --- Risk score (P2-15) ----------------------------------- #
        # Composite 0–100 across five dimensions, each capped at a
        # configured weight so no single signal dominates. The exact
        # weights are deliberately conservative — a workspace with
        # zero criticals, full MITRE coverage and healthy engines
        # should comfortably score < 20.
        risk = 0.0
        risk += min(40.0, sev_counts["critical"] * 12 + sev_counts["high"] * 5
                          + sev_counts["medium"] * 2 + sev_counts["low"] * 1)
        risk += min(20.0, alert_sev["critical"] * 4 + alert_sev["high"] * 2 + alert_sev["medium"] * 0.5)
        # MITRE coverage gap contributes the inverse — full coverage = 0
        risk += max(0.0, (100.0 - coverage_pct) * 0.10)   # up to 10
        # Engine availability gap
        if total_engines:
            engine_gap = (total_engines - healthy) / total_engines
            risk += min(15.0, engine_gap * 15.0 + stale * 2.0)
        # Dwell ageing
        if active_ages:
            longest_age = max(active_ages)
            if longest_age > 86_400:
                risk += min(15.0, (longest_age / 86_400) * 3.0)
            elif longest_age > 3_600:
                risk += min(8.0, (longest_age / 3_600) * 1.0)

        risk_score = min(100.0, max(0.0, risk))
        if risk_score >= 70:
            risk_color = "#ff4d6d"; risk_label = "CRITICAL"
        elif risk_score >= 45:
            risk_color = "#ff6b8a"; risk_label = "HIGH"
        elif risk_score >= 25:
            risk_color = "#f4c26b"; risk_label = "ELEVATED"
        elif risk_score >= 10:
            risk_color = "#7fd7ff"; risk_label = "GUARDED"
        else:
            risk_color = "#7fe39d"; risk_label = "LOW"

        if hasattr(app, "dash_pill_risk"):
            self._set_pill(app.dash_pill_risk,
                f"Risk: {int(round(risk_score))}",
                f" - {risk_label}",
                risk_color,
                spark="",  # gauge — single point in time
            )

        # --- Mirror the same metrics into the compact pill row ---- #
        # Matches the global hero pill style; colour-coded by severity /
        # threshold for at-a-glance scan, with a 24h Unicode-block
        # sparkline appended for trend context (P1-10).
        if hasattr(app, "dash_pill_incident"):
            # Bucket incident creations over the last 24h
            inc_buckets = _hourly_buckets(incidents, now=now, hours=24)
            alert_buckets = _hourly_buckets(alerts, now=now, hours=24)
            cpu_series = [float(r.get("cpu", 0) or 0) for r in telemetry_rows[-30:] if isinstance(r, dict)]
            dwell_series = [age / 3600.0 for age in active_ages]  # hours

            primary_color = _severity_color(primary_sev) if active else "#c8d8ea"
            self._set_pill(app.dash_pill_incident,
                f"Incidents: {active}",
                f" - C:{sev_counts['critical']} H:{sev_counts['high']} M:{sev_counts['medium']}" if active else "",
                primary_color,
                spark=_sparkline(inc_buckets),
            )
            alerts_color = ("#ff6b8a" if alert_sev["critical"] or alert_sev["high"] >= 3 else
                            "#f4c26b" if alert_open else "#c8d8ea")
            self._set_pill(app.dash_pill_alerts,
                f"Alerts {self._dashboard_window_label}: {alert_total}",
                f" - {alert_open} open" if alert_total else "",
                alerts_color,
                spark=_sparkline(alert_buckets),
            )
            self._set_pill(app.dash_pill_engines,
                f"Engines: {engine_label}",
                f" - {stale} stale" if total_engines and stale else "",
                engine_color,
                spark="",  # engines: availability gauge — no time series available
            )
            mitre_text = f"{coverage_pct:.0f}%" if coverage_pct > 0 else "--"
            self._set_pill(app.dash_pill_mitre,
                f"MITRE: {mitre_text}",
                "",
                coverage_color,
                spark="",
            )
            self._set_pill(app.dash_pill_telemetry,
                f"Telemetry: {label}",
                f" - n={len(telemetry_rows)}" if telemetry_rows else "",
                color,
                spark=_sparkline(cpu_series),
            )
            self._set_pill(app.dash_pill_dwell,
                f"Dwell: {dwell_text}",
                f" - n={len(active_ages)}" if active_ages else "",
                dwell_color,
                spark=_sparkline(sorted(dwell_series)) if len(dwell_series) >= 3 else "",
            )

    def _set_pill(self, label: QLabel, primary: str, suffix: str, accent: str,
                   spark: str = "") -> None:
        # Coloured value with muted suffix, all on one line. Stylesheet
        # mirrors the global hero pill but tints the foreground. A
        # 24h Unicode-block sparkline (when supplied) gets appended in
        # the accent colour with slightly larger glyphs for legibility.
        spark_html = ""
        if spark:
            spark_html = (
                f"<span style=\"color:{accent};font-family:'Cascadia Mono','Consolas',monospace;"
                f"font-size:13px;letter-spacing:0px;margin-left:6px;\">{spark}</span>"
            )
        label.setText(
            f"<span style='color:{accent};font-weight:800;'>{primary}</span>"
            f"<span style='color:#7a8a9c;'>{suffix}</span>"
            f"{spark_html}"
        )
        label.setStyleSheet(
            "background:#121b27;border:1px solid #2c4260;border-radius:10px;"
            "padding:6px 10px;font-weight:600;font-size:11px;"
        )

    def _set_label_html(self, label: QLabel, html_text: str) -> None:
        # QLabel doesn't natively render `<div>` borders well; we use a
        # tiny rich-text container with margin reset to keep the bar
        # crisp in the KPI tile.
        label.setText(
            f"<div style='margin:0;padding:0;line-height:0;font-size:0;'>{html_text}</div>"
        )
        label.setTextFormat(Qt.RichText)

    def _compute_mitre_coverage(self, mitre: dict) -> tuple[float, str]:
        if not isinstance(mitre, dict):
            return 0.0, "no MITRE bundle loaded"
        coverage = mitre.get("coverage") if isinstance(mitre.get("coverage"), dict) else {}
        if coverage:
            covered = _coerce_int(coverage.get("covered_techniques") or coverage.get("covered"))
            total = _coerce_int(coverage.get("total_techniques") or coverage.get("total"))
            if total > 0:
                pct = covered / total * 100.0
                return pct, f"{covered} / {total} techniques covered"
        techniques = mitre.get("techniques") if isinstance(mitre.get("techniques"), list) else []
        if techniques:
            seen = sum(1 for t in techniques if isinstance(t, dict) and (t.get("observed") or t.get("seen") or t.get("hits")))
            total = len(techniques)
            if total:
                return seen / total * 100.0, f"{seen} / {total} techniques observed"
        summary = mitre.get("summary") if isinstance(mitre.get("summary"), dict) else {}
        if summary:
            covered = _coerce_int(summary.get("covered"))
            total = _coerce_int(summary.get("total")) or _coerce_int(summary.get("technique_count"))
            if total > 0:
                return covered / total * 100.0, f"{covered} / {total} techniques covered"
        return 0.0, "no MITRE bundle loaded"

    # ------------------------------------------------------------------ #
    # Panel renderers
    # ------------------------------------------------------------------ #

    def _render_incident_queue(self, incidents: list[dict], latest_result: dict, now: float) -> str:
        rows: list[str] = []
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

        # Inline filter chips (#1)
        filters = self._panel_filters.get("incidents", {})
        sev_filter = filters.get("severity", "all")
        status_filter = filters.get("status", "all")
        chips_html = (
            "<div style='margin:0 0 6px;'>"
            + _filter_chip_row("incidents", "severity", sev_filter, [
                ("all",      "All"),
                ("critical", "Critical"),
                ("high",     "High"),
                ("medium",   "Medium"),
                ("low",      "Low"),
            ])
            + "<span style='margin:0 8px;color:#243446;'>|</span>"
            + _filter_chip_row("incidents", "status", status_filter, [
                ("all",         "All"),
                ("open",        "Open"),
                ("acknowledged","Ack"),
                ("closed",      "Closed"),
            ])
            + "</div>"
        )

        # Apply filters BEFORE the active-only narrowing so the operator
        # can also pull up closed incidents via the chip.
        # The rest of the panel treats {"acknowledged","ack"} and
        # {"closed","resolved","suppressed"} as equivalent; the filter
        # predicate must canonicalize the same way or the "Ack"/"Closed"
        # chips silently hide incidents whose API status is an alias.
        _status_alias = {
            "ack": "acknowledged",
            "resolved": "closed",
            "suppressed": "closed",
        }

        def _passes(inc: dict) -> bool:
            if sev_filter != "all":
                if str(inc.get("severity", "unknown")).lower() != sev_filter:
                    return False
            if status_filter != "all":
                raw = str(inc.get("status", "open")).lower()
                if _status_alias.get(raw, raw) != status_filter:
                    return False
            return True

        if status_filter == "all":
            # Default behavior: hide closed incidents
            active = [i for i in incidents if isinstance(i, dict)
                      and str(i.get("status", "open")).lower() not in {"closed", "resolved", "suppressed"}
                      and _passes(i)]
        else:
            active = [i for i in incidents if isinstance(i, dict) and _passes(i)]

        active.sort(
            key=lambda inc: (
                sev_order.get(str(inc.get("severity", "unknown")).lower(), 5),
                -_coerce_epoch(inc.get("created_at")),
            )
        )

        if not active:
            # fall back to in-memory latest incident if API didn't return one
            inc = latest_result.get("incident") if isinstance(latest_result.get("incident"), dict) else {}
            if inc:
                active = [inc]

        for inc in active[:5]:
            sev = str(inc.get("severity", "unknown") or "unknown").strip().lower()
            title = (inc.get("title") or inc.get("incident_id") or "(untitled incident)").strip() or "(untitled)"
            owner = inc.get("owner") or inc.get("assignee") or "unassigned"
            status = str(inc.get("status", "open") or "open").strip().lower()
            age = _format_age(_coerce_epoch(inc.get("created_at")), now=now)
            inc_id = str(inc.get("incident_id") or inc.get("id") or "").strip()
            # Drill-down anchor — opens slide-over detail dialog (#4)
            link_target = f"incident://{inc_id}" if inc_id else "incident://"
            title_html = (
                f"<a href='{_esc(link_target)}' "
                "style='color:#f4f7fb;text-decoration:none;' title='Click for full detail'>"
                f"{_esc(title[:48])}</a>"
            )
            # Quick actions per row (#3) — only for incidents with an id.
            quick_actions_html = ""
            if inc_id:
                action_link_style = (
                    "color:#7fd7ff;text-decoration:none;font-size:10px;"
                    "padding:1px 5px;border:1px solid #243446;border-radius:6px;"
                    "background:#0e1622;margin-left:3px;font-weight:600;"
                )
                actions_list = []
                if status not in {"acknowledged", "ack"}:
                    actions_list.append(
                        f"<a href='action://triage:{_esc(inc_id)}:ack' style=\"{action_link_style}\" title='Acknowledge'>Ack</a>"
                    )
                actions_list.append(
                    f"<a href='action://triage:{_esc(inc_id)}:assign' style=\"{action_link_style}\" title='Assign owner'>Assign</a>"
                )
                if status not in {"closed", "resolved"}:
                    actions_list.append(
                        f"<a href='action://triage:{_esc(inc_id)}:close' style=\"{action_link_style}\" title='Close'>Close</a>"
                    )
                quick_actions_html = "".join(actions_list)
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;width:14px;'>"
                f"<span style='display:inline-block;width:6px;height:18px;background:{_severity_color(sev)};border-radius:2px;'></span></td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;'>{title_html}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_sev_pill(sev)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;'>{_badge(status, status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(owner)[:14]}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(age)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;text-align:right;white-space:nowrap;'>{quick_actions_html}</td>"
                "</tr>"
            )

        if not rows:
            body = "<p style='color:#96a5b8;margin:0;font-size:11px;'>No active incidents in workspace.</p>"
        else:
            body = (
                "<table width='100%' cellspacing='0' cellpadding='0' "
                "style='border-collapse:collapse;font-size:11px;'>"
                "<thead><tr style='color:#96a5b8;text-align:left;'>"
                "<th></th><th style='padding:0 6px 4px;'>Title</th>"
                "<th style='padding:0 6px 4px;'>Sev</th><th style='padding:0 6px 4px;'>Status</th>"
                "<th style='padding:0 6px 4px;'>Owner</th>"
                "<th style='padding:0 6px 4px;text-align:right;'>Age</th>"
                "<th style='padding:0 6px 4px;text-align:right;'>Actions</th></tr></thead>"
                f"<tbody>{''.join(rows)}</tbody></table>"
            )

        total_active = len([i for i in incidents if isinstance(i, dict) and str(i.get("status", "open")).lower() not in {"closed", "resolved", "suppressed"}])
        total_all = len(incidents)
        # Filter-aware total (matches the chip row's selection)
        match_count = len(active)
        return (
            chips_html
            + f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"Showing {min(5, len(rows))} of {match_count} match(es) &middot; {total_active} active &middot; {total_all} total.</p>"
            + body
            + _pagination_footer(min(5, len(rows)), match_count, "incidents")
        )

    def _render_rules_panel(self, rules_payload: Any) -> str:
        """Render Detection Rule Health from `/enterprise/detections/lifecycle`.

        Endpoint shape varies; we accept either:
          - a list of rule dicts with at least `status`, `name`/`title`,
            `last_fired_at`, `phase`/`stage`/`mode`
          - a dict with `summary` aggregate + `rules` list
        """
        rules: list[dict] = []
        summary: dict[str, Any] = {}
        if isinstance(rules_payload, list):
            rules = [r for r in rules_payload if isinstance(r, dict)]
        elif isinstance(rules_payload, dict):
            inner = rules_payload.get("rules") or rules_payload.get("items") or []
            if isinstance(inner, list):
                rules = [r for r in inner if isinstance(r, dict)]
            if isinstance(rules_payload.get("summary"), dict):
                summary = rules_payload["summary"]

        if not rules and not summary:
            return self._dashboard_empty_html(
                "No detection rules surfaced yet. /enterprise/detections/lifecycle returned no records."
            )

        # Aggregate
        now = time.time()
        total = len(rules) if rules else _coerce_int(summary.get("total"))
        enabled = 0
        disabled = 0
        experimental = 0
        silent = 0
        recent_fires = 0
        for r in rules:
            phase = str(r.get("phase") or r.get("stage") or r.get("mode") or "production").strip().lower()
            status = str(r.get("status") or ("enabled" if r.get("enabled", True) else "disabled")).strip().lower()
            last_fired = _coerce_epoch(r.get("last_fired_at") or r.get("last_seen") or r.get("last_match_at"))
            if status == "disabled" or r.get("enabled") is False:
                disabled += 1
            else:
                enabled += 1
            if phase in {"experimental", "tuning", "beta", "candidate"}:
                experimental += 1
            if last_fired and (now - last_fired) < 86_400:
                recent_fires += 1
            elif enabled and (last_fired == 0 or (now - last_fired) > 30 * 86_400):
                # rule is enabled but hasn't fired in 30+ days
                if r.get("enabled", status != "disabled"):
                    silent += 1
        if summary:
            total = total or _coerce_int(summary.get("total"))
            enabled = enabled or _coerce_int(summary.get("enabled"))
            disabled = disabled or _coerce_int(summary.get("disabled"))
            experimental = experimental or _coerce_int(summary.get("experimental"))
            silent = silent or _coerce_int(summary.get("silent"))
            recent_fires = recent_fires or _coerce_int(summary.get("recent_fires") or summary.get("fires_24h"))

        # Color cues
        silent_color = "#7fe39d" if silent == 0 else ("#f4c26b" if silent < 3 else "#ff6b8a")
        disabled_color = "#7fe39d" if disabled == 0 else ("#f4c26b" if disabled < 5 else "#ff6b8a")

        # Top recently-firing rules (or top silent ones if none firing)
        firing = [r for r in rules if _coerce_epoch(r.get("last_fired_at") or r.get("last_seen")) > now - 86_400]
        firing.sort(key=lambda r: -_coerce_epoch(r.get("last_fired_at") or r.get("last_seen")))
        spotlight = firing[:4]
        spotlight_label = "Recently fired"
        if not spotlight:
            silents = [r for r in rules if str(r.get("status", "enabled")).lower() != "disabled"
                       and _coerce_epoch(r.get("last_fired_at") or r.get("last_seen")) == 0]
            spotlight = silents[:4]
            spotlight_label = "Silent (no recent fires)"

        rows: list[str] = []
        for r in spotlight:
            name = str(r.get("name") or r.get("title") or r.get("id") or "(rule)")[:60]
            phase = str(r.get("phase") or r.get("stage") or r.get("mode") or "production").lower()
            last_fired = _coerce_epoch(r.get("last_fired_at") or r.get("last_seen"))
            age = _format_age(last_fired, now=now) if last_fired else "never"
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;'>{_esc(name)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(phase, 'active' if phase == 'production' else 'warning')}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(age)}</td>"
                "</tr>"
            )

        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"{total} rule(s) - <span style='color:#7fe39d;'>{enabled} enabled</span> - "
            f"<span style='color:{disabled_color};'>{disabled} disabled</span> - "
            f"<span style='color:{silent_color};'>{silent} silent</span> - "
            f"<span style='color:#7fd7ff;'>{experimental} experimental</span> - "
            f"<span style='color:#ffb168;'>{recent_fires} fires 24h</span></p>"
            f"<p style='color:#96a5b8;margin:0 0 4px;font-size:11px;'><b>{_esc(spotlight_label)}</b></p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            f"<tbody>{''.join(rows) if rows else '<tr><td style=\"color:#96a5b8;font-size:11px;padding:4px 0;\">No rules to spotlight.</td></tr>'}</tbody>"
            "</table>"
        )

    def _render_fleet_panel(self, hosts_raw: Any, now: float) -> str:
        if not isinstance(hosts_raw, list) or not hosts_raw:
            return self._dashboard_empty_html(
                "No endpoints reporting yet. Agent inventory appears here from /hosts."
            )
        hosts = [h for h in hosts_raw if isinstance(h, dict)]
        total = len(hosts)
        online = 0
        stale = 0
        offline = 0
        platforms: dict[str, int] = {}
        # Convention: a host is "stale" if last_seen older than 1h, "offline" if older than 24h
        for h in hosts:
            last_seen = _coerce_epoch(h.get("last_seen"))
            api_status = str(h.get("api_status") or "").strip().lower()
            age = max(0.0, now - last_seen) if last_seen > 0 else None
            if api_status in {"down", "offline", "unreachable"} or (age is not None and age > 86_400):
                offline += 1
            elif age is None or age > 3_600:
                stale += 1
            else:
                online += 1
            plat = str(h.get("platform") or "unknown").lower()
            platforms[plat] = platforms.get(plat, 0) + 1

        spotlight = sorted(
            hosts,
            key=lambda h: (_coerce_epoch(h.get("last_seen")) or 0),
        )[:5]  # oldest seen first — operator wants to see what's slipping

        rows: list[str] = []
        for h in spotlight:
            host_label = str(h.get("host") or h.get("host_id") or "(unknown)")[:28]
            platform = str(h.get("platform") or "—")[:10]
            role = str(h.get("role") or "—")[:14]
            ip_addr = str(h.get("ip_address") or "")[:18]
            agent_v = str(h.get("agent_version") or "")[:10]
            last_seen = _coerce_epoch(h.get("last_seen"))
            seen_text = _format_age(last_seen, now=now) if last_seen else "never"
            api_status = str(h.get("api_status") or "unknown").strip().lower()
            age = max(0.0, now - last_seen) if last_seen > 0 else None
            if api_status in {"down", "offline", "unreachable"} or (age is not None and age > 86_400):
                badge_status = "down"
            elif age is None or age > 3_600:
                badge_status = "warning"
            else:
                badge_status = "healthy"
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;font-weight:600;'>{_esc(host_label)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(platform)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(role)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;'>{_esc(ip_addr)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(badge_status, badge_status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(seen_text)}</td>"
                "</tr>"
            )

        platform_summary = " &middot; ".join(
            f"{_esc(name)} <b style='color:#c8d8ea;'>{count}</b>"
            for name, count in sorted(platforms.items(), key=lambda kv: -kv[1])[:4]
        )

        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"<b style='color:#f4f7fb;'>{total}</b> endpoint(s) - "
            f"<span style='color:#7fe39d;'>{online} healthy</span> - "
            f"<span style='color:#f4c26b;'>{stale} stale (&gt;1h)</span> - "
            f"<span style='color:#ff6b8a;'>{offline} offline (&gt;24h)</span>"
            f"{(' &middot; ' + platform_summary) if platform_summary else ''}</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th style='padding:0 6px 4px;'>Host</th>"
            "<th style='padding:0 6px 4px;'>OS</th>"
            "<th style='padding:0 6px 4px;'>Role</th>"
            "<th style='padding:0 6px 4px;'>IP</th>"
            "<th style='padding:0 6px 4px;'>Status</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Last Seen</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            + _pagination_footer(len(rows), total, "fleet")
        )

    # ------------------------------------------------------------------ #
    # P2-14 — Severity heatmap by hour (7 day × 24 hour grid)
    # ------------------------------------------------------------------ #

    _DAY_LABELS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")

    def _render_heatmap_panel(self, alerts: list[dict], incidents: list[dict], now: float) -> str:
        # Bucket events into a 7×24 matrix keyed by (day_offset, hour).
        # day_offset 0 = today, 1 = yesterday, ... 6 = 6 days ago.
        matrix = [[0] * 24 for _ in range(7)]
        sev_max = [["info"] * 24 for _ in range(7)]

        sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

        # Day axis must be a *calendar*-day offset, not an elapsed-24h
        # bucket: the row label is a weekday and the hour comes from the
        # event's local clock, so both axes have to use the same local
        # calendar or cells land under the wrong weekday.
        def _local_midnight(t: float) -> float:
            lt = time.localtime(t)
            return time.mktime(
                (lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)
            )

        today_midnight = _local_midnight(now)

        def _bucket(event: dict, default_sev: str = "info") -> None:
            ts = _coerce_epoch(event.get("created_at"))
            if ts <= 0:
                return
            local_struct = time.localtime(ts)
            day = int((today_midnight - _local_midnight(ts)) // 86_400)
            if day < 0 or day >= 7:
                return
            hour = local_struct.tm_hour
            matrix[day][hour] += 1
            sev = str(event.get("severity") or default_sev or "info").strip().lower()
            if sev_rank.get(sev, 0) > sev_rank.get(sev_max[day][hour], 0):
                sev_max[day][hour] = sev

        for alert in (alerts or []):
            if isinstance(alert, dict):
                _bucket(alert)
        for incident in (incidents or []):
            if isinstance(incident, dict):
                _bucket(incident, default_sev=str(incident.get("severity") or "medium"))

        # Determine palette: each cell coloured by max severity, opacity
        # by event count. Empty cells are dim grey.
        palette = {
            "info":     "#243446",
            "low":      "#28507a",
            "medium":   "#7a5a16",
            "high":     "#7a2438",
            "critical": "#a01a35",
        }

        cells = [
            "<table cellspacing='0' cellpadding='0' "
            "style='border-collapse:collapse;font-size:9px;font-family:Cascadia Mono,Consolas,monospace;'>"
        ]
        # Header row — hour labels
        cells.append("<tr><td></td>")
        for hour in range(24):
            cells.append(
                f"<td style='padding:0 2px;color:#7a8a9c;text-align:center;font-size:8px;'>{hour:02d}</td>"
            )
        cells.append("</tr>")

        max_count = max((max(row) for row in matrix), default=0) or 1
        for day_idx in range(6, -1, -1):  # render oldest → newest
            label = self._DAY_LABELS[time.localtime(today_midnight - day_idx * 86_400).tm_wday]
            cells.append(f"<tr><td style='padding:0 4px 0 0;color:#7a8a9c;font-size:9px;text-align:right;'>{label}</td>")
            for hour in range(24):
                count = matrix[day_idx][hour]
                sev = sev_max[day_idx][hour]
                if count == 0:
                    bg = "#16202c"
                else:
                    base = palette.get(sev, palette["info"])
                    # Ratio-driven opacity by count vs row max
                    intensity = 0.35 + 0.65 * (count / max_count)
                    bg = base if intensity >= 0.7 else (base + "B3" if intensity >= 0.5 else base + "80")
                tooltip = f"{label} {hour:02d}:00 — {count} event(s), max sev: {sev}"
                cells.append(
                    f"<td title=\"{_esc(tooltip)}\" style='width:14px;height:14px;"
                    f"padding:0;background:{bg};border:1px solid #0e1622;'></td>"
                )
            cells.append("</tr>")
        cells.append("</table>")

        total_events = sum(sum(row) for row in matrix)
        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"<b style='color:#f4f7fb;'>{total_events}</b> event(s) over 7 days &middot; "
            f"colour = max severity per hour, intensity = volume.</p>"
            + "".join(cells)
        )

    # ------------------------------------------------------------------ #
    # P3-23 — Audit trail (auth + actions merged)
    # ------------------------------------------------------------------ #

    def _render_audit_panel(self, auth_log: Any, action_log: Any, now: float) -> str:
        events: list[dict] = []
        if isinstance(auth_log, list):
            for entry in auth_log:
                if not isinstance(entry, dict):
                    continue
                events.append({
                    "kind": "auth",
                    "ts": _coerce_epoch(entry.get("created_at") or entry.get("ts")),
                    "actor": str(entry.get("actor") or entry.get("user") or "—"),
                    "action": str(entry.get("event") or entry.get("action") or entry.get("type") or "auth"),
                    "result": str(entry.get("result") or entry.get("status") or "ok").lower(),
                    "detail": str(entry.get("detail") or entry.get("source") or entry.get("ip") or ""),
                })
        if isinstance(action_log, list):
            for entry in action_log:
                if not isinstance(entry, dict):
                    continue
                events.append({
                    "kind": "action",
                    "ts": _coerce_epoch(entry.get("created_at") or entry.get("ts")),
                    "actor": str(entry.get("actor") or entry.get("user") or "—"),
                    "action": str(entry.get("action") or entry.get("event") or "action"),
                    "result": str(entry.get("result") or entry.get("status") or "ok").lower(),
                    "detail": str(entry.get("detail") or entry.get("target") or entry.get("path") or ""),
                })
        # Inline filter chips (#1)
        filters = self._panel_filters.get("audit", {})
        kind_filter = filters.get("kind", "all")
        result_filter = filters.get("result", "all")
        chips_html = (
            "<div style='margin:0 0 6px;'>"
            + _filter_chip_row("audit", "kind", kind_filter, [
                ("all",    "All"),
                ("auth",   "Auth"),
                ("action", "Action"),
            ])
            + "<span style='margin:0 8px;color:#243446;'>|</span>"
            + _filter_chip_row("audit", "result", result_filter, [
                ("all",     "All"),
                ("ok",      "OK"),
                ("warning", "Warning"),
                ("failed",  "Failed"),
            ])
            + "</div>"
        )

        if not events:
            return chips_html + self._dashboard_empty_html(
                "No audit events yet. Trail populates from /history/auth and /history/actions (admin-only)."
            )

        def _event_passes(event: dict) -> bool:
            if kind_filter != "all" and event.get("kind") != kind_filter:
                return False
            if result_filter != "all":
                result = str(event.get("result") or "ok").lower()
                if result_filter == "ok" and result not in {"ok", "success", "accepted", "applied"}:
                    return False
                if result_filter == "warning" and result not in {"warning", "warn", "stale"}:
                    return False
                if result_filter == "failed" and not any(tok in result for tok in ("fail", "error", "denied")):
                    return False
            return True

        events = [e for e in events if _event_passes(e)]
        events.sort(key=lambda e: -(e.get("ts") or 0))

        rows: list[str] = []
        for entry in events[:8]:
            kind = entry["kind"]
            result = entry["result"]
            if "fail" in result or "error" in result or "denied" in result:
                badge_status = "down"
            elif result in {"ok", "success", "accepted", "applied"}:
                badge_status = "healthy"
            else:
                badge_status = "warning"
            kind_color = "#7fd7ff" if kind == "auth" else "#c98bff"
            ts = entry["ts"]
            age = _format_age(ts, now=now) if ts else "—"
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:{kind_color};font-size:11px;font-weight:700;'>{_esc(kind)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;'>{_esc(entry['action'])[:32]}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(entry['actor'])[:20]}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(result, badge_status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;'>{_esc(entry['detail'])[:48]}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(age)}</td>"
                "</tr>"
            )

        auth_count = sum(1 for e in events if e["kind"] == "auth")
        action_count = sum(1 for e in events if e["kind"] == "action")
        return (
            chips_html
            + f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"<b style='color:#f4f7fb;'>{len(events)}</b> match(es) - "
            f"<span style='color:#7fd7ff;'>{auth_count} auth</span> - "
            f"<span style='color:#c98bff;'>{action_count} action</span> - showing latest {min(8, len(events))}.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th style='padding:0 6px 4px;'>Kind</th>"
            "<th style='padding:0 6px 4px;'>Action</th>"
            "<th style='padding:0 6px 4px;'>Actor</th>"
            "<th style='padding:0 6px 4px;'>Result</th>"
            "<th style='padding:0 6px 4px;'>Detail</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Age</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            + _pagination_footer(min(8, len(events)), len(events), "audit")
        )

    # ------------------------------------------------------------------ #
    # P2-17 — Compliance & SLA snapshot
    # ------------------------------------------------------------------ #

    def _render_sla_panel(self, sla_raw: Any) -> str:
        if not isinstance(sla_raw, dict) or not sla_raw:
            return self._dashboard_empty_html(
                "No SLA snapshot returned by /antivirus/sla."
            )
        # Endpoint shape varies; pick what we can find.
        mttr_seconds = sla_raw.get("mttr_seconds") or sla_raw.get("mean_resolution_seconds")
        mtta_seconds = sla_raw.get("mtta_seconds") or sla_raw.get("mean_acknowledge_seconds")
        breaches = _coerce_int(sla_raw.get("breach_count") or sla_raw.get("breaches"))
        target_seconds = _coerce_int(sla_raw.get("target_seconds") or 3600)
        compliance_pct = sla_raw.get("compliance_pct")
        if compliance_pct is None:
            compliance_pct = sla_raw.get("compliance") or 0
        try:
            compliance_pct = float(compliance_pct)
        except (TypeError, ValueError):
            compliance_pct = 0.0

        def _fmt_age(value: Any) -> str:
            try:
                v = float(value or 0)
            except (TypeError, ValueError):
                return "--"
            if v <= 0:
                return "--"
            if v < 60:
                return f"{int(v)}s"
            if v < 3600:
                return f"{int(v / 60)}m"
            if v < 86400:
                return f"{v / 3600:.1f}h"
            return f"{v / 86400:.1f}d"

        comp_color = "#7fe39d" if compliance_pct >= 95 else ("#f4c26b" if compliance_pct >= 75 else "#ff6b8a")
        breach_color = "#7fe39d" if breaches == 0 else ("#f4c26b" if breaches < 5 else "#ff6b8a")

        rows = (
            "<tr>"
            f"<td style='padding:3px 6px;color:#96a5b8;font-size:11px;'>MTTA</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{_esc(_fmt_age(mtta_seconds))}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#96a5b8;font-size:11px;'>MTTR</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{_esc(_fmt_age(mttr_seconds))}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#96a5b8;font-size:11px;'>SLA target</td>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;text-align:right;'>{_esc(_fmt_age(target_seconds))}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#96a5b8;font-size:11px;'>Compliance</td>"
            f"<td style='padding:3px 6px;color:{comp_color};font-size:11px;text-align:right;font-weight:700;'>{compliance_pct:.0f}%</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#96a5b8;font-size:11px;'>Breach count</td>"
            f"<td style='padding:3px 6px;color:{breach_color};font-size:11px;text-align:right;font-weight:700;'>{breaches}</td>"
            "</tr>"
        )
        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>SLA posture from <code>/antivirus/sla</code>.</p>"
            f"<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;'>{rows}</table>"
            + _progress_bar(compliance_pct, comp_color)
        )

    def _render_connectors_panel(self, connectors_raw: Any) -> str:
        """Render Slack / Email / Webhook / SIEM forwarder integration
        health from `/enterprise/connectors`. The endpoint is admin-only;
        when the operator's role can't read it the error-state path
        already shows a "Locked: apply API key" hint, so this renderer
        only handles the success case.
        """
        if not isinstance(connectors_raw, list) or not connectors_raw:
            return self._dashboard_empty_html(
                "No integrations configured. Hook up Slack / Email / Webhook / SIEM forwarder via /enterprise/connectors."
            )
        connectors = [c for c in connectors_raw if isinstance(c, dict)]
        total = len(connectors)
        healthy = 0
        degraded = 0
        down = 0
        rows: list[str] = []
        # Sort: down first, then degraded, then healthy — operator wants to see breakage first
        priority = {"down": 0, "error": 0, "failed": 0, "degraded": 1, "warning": 1, "rate-limited": 1,
                    "stale": 1, "ok": 2, "healthy": 2, "active": 2, "delivered": 2}
        connectors_sorted = sorted(
            connectors,
            key=lambda c: priority.get(str(c.get("status") or c.get("state") or "unknown").strip().lower(), 3),
        )
        now = time.time()
        for conn in connectors_sorted[:6]:
            kind = str(conn.get("kind") or conn.get("type") or conn.get("connector_type") or "—")[:18]
            name = str(conn.get("name") or conn.get("label") or conn.get("id") or kind)[:28]
            status = str(conn.get("status") or conn.get("state") or "unknown").strip().lower() or "unknown"
            last_at = _coerce_epoch(conn.get("last_delivery_at") or conn.get("last_seen") or conn.get("updated_at"))
            last_text = _format_age(last_at, now=now) if last_at else "never"
            failures = _coerce_int(conn.get("failure_count") or conn.get("errors") or conn.get("dlq_count"))
            target = str(conn.get("target") or conn.get("destination") or conn.get("url") or "")[:36]
            if status in {"healthy", "ok", "active", "delivered"}:
                healthy += 1
                badge_status = "healthy"
            elif status in {"degraded", "warning", "stale", "rate-limited", "rate_limited"}:
                degraded += 1
                badge_status = "warning"
            elif status in {"down", "error", "failed", "offline"}:
                down += 1
                badge_status = "down"
            else:
                badge_status = "unknown"
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;font-weight:600;'>{_esc(name)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(kind)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(status, badge_status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;'>{_esc(target)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:{'#ff6b8a' if failures else '#7fe39d'};font-size:11px;text-align:right;'>{failures}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(last_text)}</td>"
                "</tr>"
            )
        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"<b style='color:#f4f7fb;'>{total}</b> integration(s) - "
            f"<span style='color:#7fe39d;'>{healthy} healthy</span> - "
            f"<span style='color:#f4c26b;'>{degraded} degraded</span> - "
            f"<span style='color:#ff6b8a;'>{down} down</span></p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th style='padding:0 6px 4px;'>Name</th>"
            "<th style='padding:0 6px 4px;'>Kind</th>"
            "<th style='padding:0 6px 4px;'>Status</th>"
            "<th style='padding:0 6px 4px;'>Target</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Errors</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Last</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            + _pagination_footer(len(rows), total, "connectors")
        )

    def _render_gaps_panel(self, gaps_raw: Any) -> str:
        if not isinstance(gaps_raw, dict) or not gaps_raw:
            return self._dashboard_empty_html(
                "No telemetry-gap analysis returned by /enterprise/telemetry/gaps."
            )

        # Endpoint shape varies per backend version — handle generically.
        gaps_list: list[dict] = []
        for key in ("gaps", "items", "sources", "results"):
            value = gaps_raw.get(key)
            if isinstance(value, list):
                gaps_list = [g for g in value if isinstance(g, dict)]
                break
        if not gaps_list and isinstance(gaps_raw.get("by_source"), dict):
            for src, info in gaps_raw["by_source"].items():
                if isinstance(info, dict):
                    gaps_list.append({"source": src, **info})

        summary = gaps_raw.get("summary") if isinstance(gaps_raw.get("summary"), dict) else {}
        total_gaps = _coerce_int(summary.get("total")) or len(gaps_list)
        critical_gaps = _coerce_int(summary.get("critical"))
        warning_gaps = _coerce_int(summary.get("warning"))

        if not gaps_list and not summary:
            return self._dashboard_empty_html(
                "Telemetry-gap analysis returned an empty payload — nothing to flag."
            )

        # Auto-categorize sources by name
        rows: list[str] = []
        for gap in gaps_list[:6]:
            source = str(gap.get("source") or gap.get("name") or gap.get("id") or "(source)")[:24]
            severity = str(gap.get("severity") or gap.get("level") or "warning").strip().lower()
            detail = str(gap.get("detail") or gap.get("reason") or gap.get("description") or "")[:60]
            coverage = gap.get("coverage_pct") if "coverage_pct" in gap else gap.get("coverage")
            cov_text = ""
            if coverage is not None:
                try:
                    cov_text = f"{float(coverage):.0f}%"
                except (TypeError, ValueError):
                    cov_text = "--"
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;font-weight:600;'>{_esc(source)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_sev_pill(severity)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(detail) or '&mdash;'}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(cov_text)}</td>"
                "</tr>"
            )

        if not rows:
            return (
                "<p style='color:#7fe39d;margin:0 0 6px;font-size:11px;'>"
                f"<b>{total_gaps}</b> gap(s) reported &middot; no actionable rows surfaced.</p>"
            )

        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"<b style='color:#f4f7fb;'>{total_gaps}</b> gap(s) - "
            f"<span style='color:#ff4d6d;'>{critical_gaps} critical</span> - "
            f"<span style='color:#f4c26b;'>{warning_gaps} warning</span></p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th style='padding:0 6px 4px;'>Source</th>"
            "<th style='padding:0 6px 4px;'>Sev</th>"
            "<th style='padding:0 6px 4px;'>Detail</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Cov</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            + _pagination_footer(len(rows), total_gaps, "gaps")
        )

    def _render_engine_posture(self, providers: dict[str, dict], sig_health: dict, av_status: dict) -> str:
        if not providers:
            return self._dashboard_empty_html(
                "Engine Posture",
                "No antivirus / detection providers reported. Hit Refresh after applying credentials.",
            )

        rows: list[str] = []
        for key, info in sorted(providers.items()):
            if not isinstance(info, dict):
                continue
            available = bool(info.get("available"))
            status_label = "healthy" if available else "down"
            sig_entry = sig_health.get(key) if isinstance(sig_health, dict) else None
            sig_status = "ok"
            sig_age_text = "--"
            if isinstance(sig_entry, dict):
                sig_status = str(sig_entry.get("status", "ok") or "ok").strip().lower() or "ok"
                age_seconds = sig_entry.get("age_seconds")
                if age_seconds is None:
                    sig_age_text = _format_age(_coerce_epoch(info.get("latest_signature_update")))
                else:
                    try:
                        sig_age_text = _format_age(time.time() - float(age_seconds))
                    except (TypeError, ValueError):
                        sig_age_text = "--"
            else:
                sig_age_text = _format_age(_coerce_epoch(info.get("latest_signature_update")))

            errors = _coerce_int(info.get("error_count") or info.get("errors"))
            version = str(info.get("version") or info.get("definition_version") or "--")[:14]

            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-weight:600;'>{_esc(key)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(status_label, status_label)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge('sig ' + sig_status, sig_status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(version)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(sig_age_text)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:{('#ff6b8a' if errors else '#7fe39d')};font-size:11px;text-align:right;'>{errors}</td>"
                "</tr>"
            )

        policy = av_status.get("policy") if isinstance(av_status.get("policy"), dict) else {}
        mode = str(policy.get("mode") or policy.get("profile") or "default")
        sandbox = "on" if policy.get("sandbox_enabled") else "off"

        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>Policy <b>{_esc(mode)}</b> &middot; sandbox {_esc(sandbox)}.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th style='padding:0 6px 4px;'>Engine</th><th style='padding:0 6px 4px;'>Status</th>"
            "<th style='padding:0 6px 4px;'>Sigs</th><th style='padding:0 6px 4px;'>Ver</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Age</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Err</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    # The 14 MITRE ATT&CK Enterprise tactics (canonical kill-chain order).
    _MITRE_TACTIC_ORDER = (
        ("reconnaissance",        "Recon"),
        ("resource-development",  "Resource Dev"),
        ("initial-access",        "Initial Access"),
        ("execution",             "Execution"),
        ("persistence",           "Persistence"),
        ("privilege-escalation",  "Priv Esc"),
        ("defense-evasion",       "Def Evasion"),
        ("credential-access",     "Cred Access"),
        ("discovery",             "Discovery"),
        ("lateral-movement",      "Lateral Mvt"),
        ("collection",            "Collection"),
        ("command-and-control",   "C2"),
        ("exfiltration",          "Exfiltration"),
        ("impact",                "Impact"),
    )

    def _render_mitre_panel(self, mitre: dict, latest_result: dict) -> str:
        """Render MITRE Coverage as a 14-tactic mini-heatmap.

        Each tactic gets a compact tile shaded by observed-vs-total
        density: full purple → ≥75 % covered, amber → 25–74 %, dim red
        → <25 %. Tactic with zero techniques in the bundle stays grey.
        Click-through is surfaced for tactics that have hits.
        """
        coverage_pct, coverage_label = self._compute_mitre_coverage(mitre)
        techniques = mitre.get("techniques") if isinstance(mitre.get("techniques"), list) else []

        # Group techniques by canonical tactic id
        by_tactic: dict[str, dict[str, int]] = {key: {"total": 0, "hits": 0} for key, _ in self._MITRE_TACTIC_ORDER}

        def _normalise_tactic(raw: Any) -> str:
            if not raw:
                return ""
            if isinstance(raw, list):
                raw = raw[0] if raw else ""
            return str(raw).strip().lower().replace("_", "-").replace(" ", "-")

        for tech in techniques:
            if not isinstance(tech, dict):
                continue
            tactic = _normalise_tactic(tech.get("tactic") or tech.get("phase") or tech.get("kill_chain_phase"))
            if tactic not in by_tactic:
                # Some payloads use slightly different slugs — try common aliases
                alias = {"defense_evasion": "defense-evasion", "privilege_escalation": "privilege-escalation",
                         "credential_access": "credential-access", "lateral_movement": "lateral-movement",
                         "command_control": "command-and-control", "command_and_control": "command-and-control",
                         "resource_development": "resource-development", "initial_access": "initial-access"}.get(tactic.replace("-", "_"))
                if alias and alias in by_tactic:
                    tactic = alias
                else:
                    continue
            by_tactic[tactic]["total"] += 1
            hits = _coerce_int(tech.get("hits") or tech.get("observed") or tech.get("count"))
            if hits > 0 or tech.get("seen"):
                by_tactic[tactic]["hits"] += 1

        # Build the heatmap row(s). Two rows × 7 cells fits the 152-px panel.
        cells: list[str] = []
        for slug, label in self._MITRE_TACTIC_ORDER:
            stats = by_tactic[slug]
            total = stats["total"]
            hits = stats["hits"]
            if total == 0:
                bg, fg, border = "#16202c", "#5a6a7e", "#243446"
                pct_text = "—"
            else:
                ratio = hits / total
                if ratio >= 0.75:
                    bg, fg, border = "#3a1f4b", "#e0c1ff", "#5b3a78"
                elif ratio >= 0.25:
                    bg, fg, border = "#3d2f0f", "#f4c26b", "#5a4416"
                else:
                    bg, fg, border = "#2a1018", "#ff8aa3", "#5b1f2d"
                pct_text = f"{int(ratio * 100)}%"
            cells.append(
                "<td style='padding:0;width:14.28%;'>"
                "<div style='margin:1px;padding:5px 4px;border-radius:5px;"
                f"background:{bg};border:1px solid {border};text-align:center;'>"
                f"<div style='color:{fg};font-size:9px;font-weight:700;letter-spacing:0.3px;'>{_esc(label)}</div>"
                f"<div style='color:{fg};font-size:11px;font-weight:800;line-height:1.1;'>{pct_text}</div>"
                f"<div style='color:{fg};opacity:0.7;font-size:9px;'>{hits}/{total if total else '0'}</div>"
                "</div></td>"
            )

        # Two rows of 7
        row1 = "<tr>" + "".join(cells[:7]) + "</tr>"
        row2 = "<tr>" + "".join(cells[7:]) + "</tr>"

        bar_color = "#c98bff" if coverage_pct >= 60 else ("#f4c26b" if coverage_pct >= 25 else "#ff6b8a")
        return (
            f"<p style='color:#96a5b8;margin:0 0 4px;font-size:11px;'>{_esc(coverage_label)}</p>"
            + _progress_bar(coverage_pct, bar_color)
            + "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;margin-top:4px;table-layout:fixed;'>"
            + row1 + row2
            + "</table>"
        )

    def _render_threat_panel(self) -> str:
        app = self.app
        history = list(getattr(app, "threat_history", []) or [])[:5]
        if not history:
            return self._dashboard_empty_html(
                "Threat Intel Pulse",
                "No hash, IP, sandbox, or enrichment queries recorded yet.",
            )
        items = []
        for entry in history:
            if not isinstance(entry, dict):
                continue
            kind = str(entry.get("type", "query") or "query").lower()
            value = str(entry.get("value", "") or "")
            verdict = str(entry.get("verdict") or entry.get("status") or "queried").lower()
            items.append(
                "<li style='margin:1px 0;font-size:11px;'>"
                f"<span style='color:#7fd7ff;font-weight:700;'>{_esc(kind)}</span> "
                f"<span style='color:#c8d8ea;'>{_esc(value[:54])}</span> "
                f"{_badge(verdict, verdict)}"
                "</li>"
            )
        pivots = "suspicious process hash, remote IP reputation, persistence target review"
        return (
            "<p style='color:#96a5b8;margin:0 0 4px;font-size:11px;'>Recent IOC lookups and enrichment pivots.</p>"
            f"<ul style='margin:0;padding-left:16px;'>{''.join(items)}</ul>"
            f"<p style='color:#96a5b8;margin:4px 0 0;font-size:11px;'><b>Next pivots:</b> {_esc(pivots)}</p>"
        )

    def _render_auth_panel(self) -> str:
        app = self.app
        auth = getattr(app, "auth_context", {}) or {}
        ready = bool(getattr(app, "auth_session_ready", False))
        role = str(auth.get("role", "locked" if not ready else "viewer"))
        try:
            workspace_id = str(auth.get("workspace_id") or app.workspace_id.text().strip() or "default")
        except Exception:
            workspace_id = str(auth.get("workspace_id", "default"))
        features = auth.get("features", {}) if isinstance(auth.get("features"), dict) else {}
        policy = str(features.get("policy_profile", "lab"))
        dangerous = bool(features.get("dangerous_actions_enabled", False))
        approvals = bool(features.get("require_enterprise_approval", False))

        cells = [
            ("Role", _badge(role, "active" if ready else "locked")),
            ("Workspace", _esc(workspace_id[:18])),
            ("Policy", _badge(policy, "ok")),
            ("Dangerous Actions", _badge("on" if dangerous else "off", "warning" if dangerous else "ok")),
            ("Approvals", _badge("required" if approvals else "off", "warning" if approvals else "ok")),
        ]
        rows = "".join(
            f"<tr><td style='padding:2px 6px;color:#96a5b8;font-size:11px;'>{_esc(label)}</td>"
            f"<td style='padding:2px 6px;'>{value}</td></tr>"
            for label, value in cells
        )
        hint = (
            "Apply a valid API key to unlock active workflows."
            if not ready else
            "Access context active &middot; capabilities enforced server-side."
        )
        return (
            f"<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;'>{rows}</table>"
            f"<p style='color:#96a5b8;margin:6px 0 0;font-size:11px;'>{hint}</p>"
        )

    def _render_timeline_panel(self) -> str:
        app = self.app
        timeline_plain = ""
        try:
            timeline_plain = app.timeline_summary.toPlainText().strip()
        except Exception:
            timeline_plain = ""
        lines = [line.strip() for line in timeline_plain.splitlines() if line.strip()]
        if not lines:
            return self._dashboard_empty_html(
                "Timeline Story",
                "No timeline narrative yet. Run monitor and refresh timeline.",
            )
        items = "".join(f"<li style='margin:1px 0;font-size:11px;'>{_esc(line[:120])}</li>" for line in lines[:5])
        return f"<ul style='margin:4px 0 0;padding-left:16px;'>{items}</ul>"

    def _render_alerts_panel(self, alerts: list[dict], now: float) -> str:
        # Inline filter chips (#1)
        filters = self._panel_filters.get("alerts", {})
        sev_filter = filters.get("severity", "all")
        status_filter = filters.get("status", "all")
        chips_html = (
            "<div style='margin:0 0 6px;'>"
            + _filter_chip_row("alerts", "severity", sev_filter, [
                ("all",      "All"),
                ("critical", "Critical"),
                ("high",     "High"),
                ("medium",   "Medium"),
                ("low",      "Low"),
                ("info",     "Info"),
            ])
            + "<span style='margin:0 8px;color:#243446;'>|</span>"
            + _filter_chip_row("alerts", "status", status_filter, [
                ("all",          "All"),
                ("open",         "Open"),
                ("acknowledged", "Ack"),
                ("delivered",    "Delivered"),
            ])
            + "</div>"
        )

        if not alerts:
            return chips_html + self._dashboard_empty_html(
                "Recent Alerts",
                "No alerts dispatched in this workspace yet.",
            )

        def _alert_passes(alert: dict) -> bool:
            if sev_filter != "all":
                if str(alert.get("severity", "info")).lower() != sev_filter:
                    return False
            if status_filter != "all":
                if str(alert.get("status", "open")).lower() != status_filter:
                    return False
            return True

        filtered = [a for a in alerts if isinstance(a, dict) and _alert_passes(a)]
        # Sort by created_at desc
        sorted_alerts = sorted(
            filtered,
            key=lambda a: -_coerce_epoch(a.get("created_at")),
        )

        rows: list[str] = []
        for record in sorted_alerts[:8]:
            sev = str(record.get("severity", "info") or "info").strip().lower()
            title = str(record.get("title") or record.get("detail") or "(no title)")[:80]
            destination = str(record.get("destination", "") or "")[:32]
            dest_type = str(record.get("destination_type", "") or "").lower()
            status = str(record.get("status", "queued") or "queued").lower()
            age = _format_age(_coerce_epoch(record.get("created_at")), now=now)
            rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;width:14px;'>"
                f"<span style='display:inline-block;width:6px;height:14px;background:{_severity_color(sev)};border-radius:2px;'></span></td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;'>{_esc(title)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_sev_pill(sev)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(status, status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(dest_type)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;'>{_esc(destination)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#96a5b8;font-size:11px;text-align:right;'>{_esc(age)}</td>"
                "</tr>"
            )

        return (
            chips_html
            + f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"{len(filtered)} match(es) of {len(alerts)} workspace alert(s) - showing latest {len(rows)}.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th></th><th style='padding:0 6px 4px;'>Title</th>"
            "<th style='padding:0 6px 4px;'>Sev</th><th style='padding:0 6px 4px;'>Status</th>"
            "<th style='padding:0 6px 4px;'>Channel</th><th style='padding:0 6px 4px;'>Destination</th>"
            "<th style='padding:0 6px 4px;text-align:right;'>Age</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
            + _pagination_footer(len(rows), len(filtered), "alerts")
        )

    # ------------------------------------------------------------------ #
    # Open-in-panel callbacks
    # ------------------------------------------------------------------ #

    def open_dashboard_metrics_panel(self) -> None:
        """Open Incident Queue with bulk operations (#2) + per-row inline
        triage. The pop-up renders ALL cached incidents (not just the
        top-5 inline preview) in a QTableWidget with a checkbox column;
        the action toolbar above the table acts on the selected rows.
        Per-row Quick action menu lives on the right of every row.
        """
        app = self.app

        panel = QWidget()
        wrap = QVBoxLayout(panel)
        wrap.setContentsMargins(8, 8, 8, 8)
        wrap.setSpacing(8)

        # Header label + match count
        header_label = QLabel("Incident Queue — bulk operations")
        header_label.setStyleSheet("color:#f4f7fb;font-size:14px;font-weight:800;")
        wrap.addWidget(header_label)

        # Bulk action toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)
        select_label = QLabel("0 selected")
        select_label.setStyleSheet("color:#96a5b8;font-size:11px;font-weight:600;padding:0 8px;")
        toolbar.addWidget(select_label)
        toolbar.addStretch(1)

        # Build table
        from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView
        from PySide6.QtCore import Qt as _Qt

        rows = list(self._latest_incidents) if self._latest_incidents else []
        # Sort by severity then age (newest first)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        rows.sort(key=lambda i: (
            sev_order.get(str(i.get("severity", "unknown")).lower(), 5),
            -_coerce_epoch(i.get("created_at")),
        ))

        table = QTableWidget()
        table.setColumnCount(7)
        table.setHorizontalHeaderLabels(["", "ID", "Severity", "Status", "Title", "Owner", "Age"])
        table.setRowCount(len(rows))
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)  # Title stretches
        table.setStyleSheet(
            "QTableWidget { background:#0e1622; color:#c8d8ea; border:1px solid #243446;"
            "selection-background-color:#1d3a5c; selection-color:#cfeaff; gridline-color:#1d2733; }"
            "QHeaderView::section { background:#121b27; color:#96a5b8; padding:5px 8px;"
            "border:0px;border-bottom:1px solid #243446;font-weight:700;font-size:11px; }"
            "QTableWidget::item { padding:4px 6px; }"
        )

        now = time.time()

        def _on_check_changed(_checked: bool = False):
            count = sum(
                1 for r in range(table.rowCount())
                if (item := table.item(r, 0)) is not None and item.checkState() == _Qt.Checked
            )
            select_label.setText(f"{count} selected")

        for row_idx, inc in enumerate(rows):
            inc_id = str(inc.get("incident_id") or inc.get("id") or "").strip()
            sev = str(inc.get("severity", "unknown") or "unknown").lower()
            status = str(inc.get("status", "open") or "open").lower()
            title = str(inc.get("title") or inc.get("incident_id") or "(untitled)")
            owner = str(inc.get("owner") or inc.get("assignee") or "unassigned")
            age = _format_age(_coerce_epoch(inc.get("created_at")), now=now)

            check_item = QTableWidgetItem()
            check_item.setFlags(_Qt.ItemIsUserCheckable | _Qt.ItemIsEnabled | _Qt.ItemIsSelectable)
            check_item.setCheckState(_Qt.Unchecked)
            check_item.setData(_Qt.UserRole, inc_id)
            table.setItem(row_idx, 0, check_item)

            id_item = QTableWidgetItem(inc_id)
            id_item.setForeground(QColor("#7fd7ff"))
            table.setItem(row_idx, 1, id_item)

            sev_item = QTableWidgetItem(sev.upper())
            sev_item.setForeground(QColor(_severity_color(sev)))
            table.setItem(row_idx, 2, sev_item)

            status_item = QTableWidgetItem(status)
            table.setItem(row_idx, 3, status_item)

            table.setItem(row_idx, 4, QTableWidgetItem(title))
            table.setItem(row_idx, 5, QTableWidgetItem(owner))

            age_item = QTableWidgetItem(age)
            age_item.setForeground(QColor("#96a5b8"))
            table.setItem(row_idx, 6, age_item)

        table.itemChanged.connect(_on_check_changed)

        def _selected_ids() -> list[str]:
            ids: list[str] = []
            for r in range(table.rowCount()):
                item = table.item(r, 0)
                if item is not None and item.checkState() == _Qt.Checked:
                    inc_id = str(item.data(_Qt.UserRole) or "").strip()
                    if inc_id:
                        ids.append(inc_id)
            return ids

        def _bulk_apply(verb: str) -> None:
            ids = _selected_ids()
            if not ids:
                app.statusBar().showMessage("No incidents selected.", 4000)
                return
            confirm = QMessageBox.question(
                panel, f"Bulk {verb}",
                f"Apply '{verb}' to {len(ids)} incident(s)?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return
            success = 0
            failed: list[str] = []
            for inc_id in ids:
                try:
                    self._inline_triage_action(inc_id, verb)
                    success += 1
                except Exception:
                    failed.append(inc_id)
            try:
                msg = f"Bulk {verb}: {success}/{len(ids)} OK"
                if failed:
                    msg += f" ({len(failed)} failed)"
                app.statusBar().showMessage(msg, 6000)
            except Exception:
                pass

        # Toolbar buttons
        for label, verb in (("Ack selected", "ack"),
                             ("Close selected", "close"),
                             ("Assign selected", "assign")):
            btn = QPushButton(label)
            btn.clicked.connect(lambda _checked=False, _v=verb: _bulk_apply(_v))
            app._bind_capability(btn, "can_manage_incidents")
            toolbar.addWidget(btn)

        # Select-all helper
        def _toggle_all(_checked: bool = False):
            target = _Qt.Unchecked
            # If any unchecked → check all; else uncheck all
            for r in range(table.rowCount()):
                item = table.item(r, 0)
                if item is not None and item.checkState() == _Qt.Unchecked:
                    target = _Qt.Checked
                    break
            for r in range(table.rowCount()):
                item = table.item(r, 0)
                if item is not None:
                    item.setCheckState(target)

        select_all_btn = QPushButton("Select all")
        select_all_btn.clicked.connect(_toggle_all)
        toolbar.insertWidget(0, select_all_btn)

        wrap.addLayout(toolbar)
        wrap.addWidget(table, 1)

        info_label = QLabel(
            f"{len(rows)} incident(s) cached &middot; click an ID to open the slide-over detail dialog."
        )
        info_label.setStyleSheet("color:#7a8a9c;font-size:11px;")
        wrap.addWidget(info_label)

        # Wire ID column click → open detail dialog
        def _on_cell_clicked(row: int, col: int):
            if col == 1:  # ID column
                item = table.item(row, 1)
                if item:
                    self._open_incident_detail_dialog(item.text().strip())
        table.cellClicked.connect(_on_cell_clicked)

        app._open_panel_window("Dashboard: Incident Queue (bulk ops)", panel)

    # ------------------------------------------------------------------ #
    # Inline triage (P0-5)
    # ------------------------------------------------------------------ #

    def _triage_incident(self, id_input: QLineEdit, *,
                         status: str | None = None,
                         owner_prompt: bool = False,
                         note_prompt: bool = False) -> None:
        app = self.app
        incident_id = id_input.text().strip()
        if not incident_id:
            self._set_triage_status("Provide an incident_id first.", error=True)
            return

        payload: dict[str, Any] = {}
        if status:
            payload["status"] = status
        if owner_prompt:
            owner, ok = QInputDialog.getText(self._triage_panel, "Assign owner",
                                             "Owner (operator handle):")
            if not ok or not owner.strip():
                return
            payload["owner"] = owner.strip()
        if note_prompt:
            note, ok = QInputDialog.getMultiLineText(self._triage_panel, "Add note",
                                                     "Investigation note:")
            if not ok or not note.strip():
                return
            payload["notes"] = note.strip()

        if not payload:
            self._set_triage_status("Nothing to update.", error=True)
            return

        try:
            response = app._patch(f"/incidents/{incident_id}", json=payload, timeout=8)
        except Exception as exc:
            self._set_triage_status(f"PATCH failed: {self._summarise_error(exc)}", error=True)
            return
        try:
            status_code = int(getattr(response, "status_code", 500))
        except (TypeError, ValueError):
            status_code = 500
        if status_code >= 400:
            try:
                detail = response.json().get("detail", "")
            except Exception:
                detail = response.text if hasattr(response, "text") else ""
            self._set_triage_status(f"PATCH {status_code} - {str(detail)[:120]}", error=True)
            return

        action_label = (
            ("status=" + payload["status"]) if "status" in payload else
            ("owner="  + payload["owner"])  if "owner"  in payload else
            "note added"
        )
        self._set_triage_status(
            f"OK - incident {incident_id}: {action_label}. Refreshing dashboard...",
            error=False,
        )
        try:
            self.refresh_dashboard_panels()
        except Exception:
            pass

    def _inline_triage_action(self, incident_id: str, verb: str) -> None:
        """Quick-action triage handler triggered by per-row anchors (#3).

        Verbs: ack | close | assign | note. Same `PATCH /incidents/{id}`
        endpoint as the full triage console — just a one-click path so
        the operator doesn't open the pop-up for an obvious ack/close.
        """
        app = self.app
        verb = (verb or "").strip().lower()
        incident_id = (incident_id or "").strip()
        if not incident_id:
            return

        payload: dict[str, Any] = {}
        if verb == "ack":
            payload["status"] = "acknowledged"
        elif verb == "close":
            payload["status"] = "closed"
        elif verb == "assign":
            owner, ok = QInputDialog.getText(
                app, f"Assign incident {incident_id}", "Owner (operator handle):"
            )
            if not ok or not owner.strip():
                return
            payload["owner"] = owner.strip()
        elif verb == "note":
            note, ok = QInputDialog.getMultiLineText(
                app, f"Add note to {incident_id}", "Investigation note:"
            )
            if not ok or not note.strip():
                return
            payload["notes"] = note.strip()
        else:
            return

        try:
            response = app._patch(f"/incidents/{incident_id}", json=payload, timeout=8)
        except Exception as exc:
            try:
                app.statusBar().showMessage(
                    f"Triage PATCH failed for {incident_id}: {self._summarise_error(exc)}", 6000
                )
            except Exception:
                pass
            return
        try:
            status_code = int(getattr(response, "status_code", 500))
        except (TypeError, ValueError):
            status_code = 500
        if status_code >= 400:
            try:
                detail = response.json().get("detail", "")
            except Exception:
                detail = response.text if hasattr(response, "text") else ""
            try:
                app.statusBar().showMessage(
                    f"Triage {status_code} for {incident_id}: {str(detail)[:120]}", 6000
                )
            except Exception:
                pass
            return
        try:
            app.statusBar().showMessage(
                f"OK - {incident_id}: {verb} applied. Refreshing...", 4000
            )
        except Exception:
            pass
        try:
            self.refresh_dashboard_panels()
        except Exception:
            pass

    def _open_incident_detail_dialog(self, incident_id: str) -> None:
        """Slide-over detail dialog (#4) — opens a non-modal QDialog
        with the full incident detail (header, summary, attack chain,
        recommended actions, findings, MITRE mapping) so the operator
        can investigate without leaving Dashboards.

        Triage actions (Ack / Assign / Note / Close) are inline at the
        bottom of the dialog. An "Open in Enterprise tab" escape hatch
        button switches to the full Enterprise workspace if needed.
        """
        app = self.app
        # Look up the cached incident
        incident: dict | None = None
        for cached in self._latest_incidents or []:
            if str(cached.get("incident_id") or cached.get("id") or "").strip() == incident_id:
                incident = cached
                break
        if incident is None:
            # Fall back to monitor result's incident if id matches
            latest = (getattr(app, "latest_monitor_result", {}) or {}).get("incident", {})
            if isinstance(latest, dict) and str(latest.get("incident_id") or "").strip() == incident_id:
                incident = latest

        dlg = QDialog(app)
        dlg.setWindowTitle(f"Incident detail — {incident_id or '(unknown)'}")
        dlg.setModal(False)
        dlg.resize(820, 620)
        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(8)

        if incident is None:
            empty = QLabel(
                f"No cached detail for incident {incident_id}. "
                "Click Refresh on the Dashboards header and try again."
            )
            empty.setStyleSheet("color:#96a5b8;font-size:12px;")
            empty.setWordWrap(True)
            layout.addWidget(empty)
            close_btn = QPushButton("Close")
            close_btn.clicked.connect(dlg.reject)
            layout.addWidget(close_btn, 0, Qt.AlignRight)
            dlg.show()
            return

        viewer = QTextBrowser()
        viewer.setOpenLinks(False)
        viewer.setHtml(self._render_incident_detail_html(incident))
        layout.addWidget(viewer, 1)

        # Inline triage action strip — same verbs as quick-actions
        actions_row = QHBoxLayout()
        actions_row.setSpacing(6)
        for label, verb in (("Acknowledge", "ack"),
                            ("Assign owner", "assign"),
                            ("Add note", "note"),
                            ("Close", "close")):
            btn = QPushButton(label)
            btn.clicked.connect(lambda _checked=False, _i=incident_id, _v=verb, _d=dlg:
                                (self._inline_triage_action(_i, _v), _d.close()))
            app._bind_capability(btn, "can_manage_incidents")
            actions_row.addWidget(btn)
        actions_row.addStretch(1)
        # Escape hatch — switch to the Enterprise tab for the full workspace
        enterprise_btn = QPushButton("Open in Enterprise →")
        enterprise_btn.clicked.connect(lambda: (
            setattr(app, "dashboard_drilldown_incident_id", incident_id),
            app._switch_to_tab("Enterprise") if hasattr(app, "_switch_to_tab") else None,
            dlg.close(),
        ))
        actions_row.addWidget(enterprise_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.close)
        actions_row.addWidget(close_btn)
        layout.addLayout(actions_row)

        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _render_incident_detail_html(self, incident: dict) -> str:
        """Compose a rich HTML summary of an incident for the slide-over
        dialog.  Uses the same severity / badge palette as the Dashboards
        cards for visual consistency.
        """
        if not isinstance(incident, dict):
            return self._dashboard_empty_html("Incident payload is empty.")
        sev = str(incident.get("severity", "unknown") or "unknown").lower()
        title = str(incident.get("title") or incident.get("incident_id") or "(untitled)")[:120]
        summary = str(incident.get("summary") or incident.get("notes") or "")[:1000]
        owner = str(incident.get("owner") or "unassigned")
        status = str(incident.get("status", "open") or "open").lower()
        inc_id = str(incident.get("incident_id") or incident.get("id") or "—")

        # Attack chain
        chain = incident.get("attack_chain", []) if isinstance(incident.get("attack_chain", []), list) else []
        chain_html = ""
        if chain:
            items = []
            for idx, step in enumerate(chain[:12], start=1):
                if isinstance(step, dict):
                    step_id = step.get("attack_id") or step.get("id") or f"step-{idx}"
                    step_name = step.get("name") or step.get("description") or ""
                    items.append(
                        f"<li><b style='color:#c98bff;'>{_esc(step_id)}</b> "
                        f"<span style='color:#c8d8ea;'>{_esc(str(step_name)[:120])}</span></li>"
                    )
                else:
                    items.append(f"<li><span style='color:#c8d8ea;'>{_esc(str(step)[:140])}</span></li>")
            chain_html = (
                "<h4 style='color:#7fd7ff;margin:12px 0 4px;font-size:12px;'>Attack chain</h4>"
                f"<ol style='padding-left:18px;font-size:11px;color:#c8d8ea;'>{''.join(items)}</ol>"
            )

        # Recommended actions
        actions = incident.get("recommended_actions", []) if isinstance(incident.get("recommended_actions", []), list) else []
        actions_html = ""
        if actions:
            items = []
            for action in actions[:8]:
                if isinstance(action, dict):
                    desc = str(action.get("description") or action.get("action") or "(action)")[:120]
                    pri = str(action.get("priority") or "medium").lower()
                    items.append(
                        f"<li>{_sev_pill(pri)} "
                        f"<span style='color:#c8d8ea;'>{_esc(desc)}</span></li>"
                    )
                else:
                    items.append(f"<li><span style='color:#c8d8ea;'>{_esc(str(action)[:140])}</span></li>")
            actions_html = (
                "<h4 style='color:#7fe39d;margin:12px 0 4px;font-size:12px;'>Recommended actions</h4>"
                f"<ul style='padding-left:18px;font-size:11px;'>{''.join(items)}</ul>"
            )

        # Findings
        findings = incident.get("findings", []) if isinstance(incident.get("findings", []), list) else []
        findings_html = ""
        if findings:
            items = []
            for f in findings[:8]:
                if isinstance(f, dict):
                    sev_f = str(f.get("severity") or "info").lower()
                    msg = str(f.get("message") or f.get("description") or "(finding)")[:140]
                    items.append(
                        f"<li>{_sev_pill(sev_f)} <span style='color:#c8d8ea;'>{_esc(msg)}</span></li>"
                    )
                else:
                    items.append(f"<li><span style='color:#c8d8ea;'>{_esc(str(f)[:160])}</span></li>")
            findings_html = (
                "<h4 style='color:#f4c26b;margin:12px 0 4px;font-size:12px;'>Findings</h4>"
                f"<ul style='padding-left:18px;font-size:11px;'>{''.join(items)}</ul>"
            )

        # MITRE mapping
        mitre = incident.get("mitre_mapping")
        mitre_html = ""
        if isinstance(mitre, dict) and mitre:
            items = []
            for key, value in list(mitre.items())[:10]:
                items.append(
                    f"<li><b style='color:#c98bff;'>{_esc(str(key))}</b> "
                    f"<span style='color:#c8d8ea;'>{_esc(str(value)[:140])}</span></li>"
                )
            mitre_html = (
                "<h4 style='color:#c98bff;margin:12px 0 4px;font-size:12px;'>MITRE mapping</h4>"
                f"<ul style='padding-left:18px;font-size:11px;'>{''.join(items)}</ul>"
            )
        elif isinstance(mitre, list) and mitre:
            items = "".join(f"<li><span style='color:#c8d8ea;'>{_esc(str(m)[:140])}</span></li>" for m in mitre[:10])
            mitre_html = (
                "<h4 style='color:#c98bff;margin:12px 0 4px;font-size:12px;'>MITRE mapping</h4>"
                f"<ul style='padding-left:18px;font-size:11px;'>{items}</ul>"
            )

        header = (
            f"<div style='border-left:4px solid {_severity_color(sev)};padding:6px 12px;margin-bottom:10px;'>"
            f"<div style='color:#f4f7fb;font-size:16px;font-weight:800;'>{_esc(title)}</div>"
            f"<div style='color:#96a5b8;font-size:11px;margin-top:2px;'>"
            f"{_esc(inc_id)} &middot; {_sev_pill(sev)} &middot; {_badge(status, status)} &middot; "
            f"owner <b style='color:#c8d8ea;'>{_esc(owner)}</b></div></div>"
        )

        summary_html = ""
        if summary:
            summary_html = (
                "<h4 style='color:#7fd7ff;margin:0 0 4px;font-size:12px;'>Summary</h4>"
                f"<p style='color:#c8d8ea;font-size:12px;margin:0 0 10px;'>{_esc(summary)}</p>"
            )

        return header + summary_html + chain_html + actions_html + findings_html + mitre_html

    def _set_triage_status(self, message: str, *, error: bool = False) -> None:
        panel = getattr(self, "_triage_panel", None)
        if panel is None:
            return
        label = getattr(panel, "_triage_status_label", None)
        if label is None:
            return
        color = "#ff8aa3" if error else "#7fe39d"
        label.setStyleSheet(f"color:{color};font-size:11px;font-weight:600;")
        label.setText(message)

    # ------------------------------------------------------------------ #
    # Critical-incident toast (P1-13)
    # ------------------------------------------------------------------ #

    def _maybe_emit_critical_toast(self, incidents: list[dict]) -> None:
        """Diff active high/critical incidents against the previous
        snapshot and emit a tray notification + bell entry for any
        newcomer. Also picks up high-severity alerts so the operator
        sees them in the in-app feed even if no system-tray fired.
        """
        current_critical: dict[str, dict] = {}
        for inc in incidents:
            if not isinstance(inc, dict):
                continue
            sev = str(inc.get("severity", "") or "").strip().lower()
            status = str(inc.get("status", "open") or "open").strip().lower()
            if status in {"closed", "resolved", "suppressed"}:
                continue
            if sev not in {"critical", "high"}:
                continue
            inc_id = str(inc.get("incident_id") or inc.get("id") or "").strip()
            if not inc_id:
                continue
            current_critical[inc_id] = inc

        new_ids = set(current_critical.keys()) - self._known_critical_ids
        primed = bool(self._known_critical_ids or self._last_dashboard_refresh)
        # Skip the very first refresh — don't flood toasts on app startup.
        if primed:
            for inc_id in sorted(new_ids):
                inc = current_critical[inc_id]
                title = f"New {str(inc.get('severity', 'high')).upper()} incident"
                body  = f"{inc_id} - {str(inc.get('title') or inc.get('summary') or '(no title)')[:120]}"
                self._show_toast(title=title, body=body)
                self._push_notification("incident",
                    str(inc.get("severity") or "high"),
                    title, body,
                )
        self._known_critical_ids = set(current_critical.keys())

    def _maybe_emit_alert_notifications(self, alerts: list[dict]) -> None:
        """Diff dispatched alerts against the previous snapshot and push
        bell-notification entries for any new high-severity ones.  We
        deliberately keep the system-tray toast restricted to incidents
        (so the operator's desktop doesn't get spammed when the alert
        rate is high) and surface alerts only inside the in-app bell.
        """
        primed = bool(self._known_alert_ids or self._last_dashboard_refresh)
        current: set[str] = set()
        new_alerts: list[dict] = []
        for alert in alerts or []:
            if not isinstance(alert, dict):
                continue
            sev = str(alert.get("severity", "") or "").strip().lower()
            if sev not in {"critical", "high"}:
                continue
            # Best-effort identity: id / title+timestamp combo
            key = (
                str(alert.get("id") or "")
                or f"{alert.get('title','')}|{alert.get('created_at','')}|{alert.get('destination','')}"
            )
            if not key:
                continue
            current.add(key)
            if primed and key not in self._known_alert_ids:
                new_alerts.append(alert)
        for alert in new_alerts[:10]:
            self._push_notification(
                "alert",
                str(alert.get("severity") or "high"),
                str(alert.get("title") or "(alert)")[:80],
                str(alert.get("detail") or alert.get("destination") or "")[:120],
            )
        self._known_alert_ids = current

    def _show_toast(self, title: str, body: str) -> None:
        try:
            tray = self._ensure_tray()
            if tray is None:
                return
            tray.showMessage(title, body, QSystemTrayIcon.Critical, 6000)
        except Exception:
            return

    def _ensure_tray(self) -> "QSystemTrayIcon | None":
        if self._tray_initialised:
            return self._tray_icon
        self._tray_initialised = True
        try:
            if not QSystemTrayIcon.isSystemTrayAvailable():
                self._tray_icon = None
                return None
            tray = QSystemTrayIcon(self.app)
            tray.setToolTip("ShadowLab SOC")
            window_icon = self.app.windowIcon() if hasattr(self.app, "windowIcon") else QIcon()
            if window_icon and not window_icon.isNull():
                tray.setIcon(window_icon)
            tray.show()
            self._tray_icon = tray
            return tray
        except Exception:
            self._tray_icon = None
            return None

    def open_dashboard_threat_panel(self) -> None:
        self._open_browser_panel("Dashboard: Threat Intel Pulse", self.app.dash_threat)

    def open_dashboard_auth_panel(self) -> None:
        self._open_browser_panel("Dashboard: Access & Policy", self.app.dash_auth)

    def open_dashboard_timeline_panel(self) -> None:
        self._open_browser_panel("Dashboard: Timeline Story", self.app.dash_timeline)

    def open_dashboard_engines_panel(self) -> None:
        self._open_browser_panel("Dashboard: Engine Posture", self.app.dash_engines)

    def open_dashboard_mitre_panel(self) -> None:
        self._open_browser_panel("Dashboard: MITRE Coverage", self.app.dash_mitre)

    def open_dashboard_alerts_panel(self) -> None:
        self._open_browser_panel("Dashboard: Recent Alerts", self.app.dash_alerts)

    def open_dashboard_rules_panel(self) -> None:
        self._open_browser_panel("Dashboard: Detection Rules", self.app.dash_rules)

    def open_dashboard_fleet_panel(self) -> None:
        self._open_browser_panel("Dashboard: Fleet & Hosts", self.app.dash_fleet)

    def open_dashboard_gaps_panel(self) -> None:
        self._open_browser_panel("Dashboard: Telemetry Gaps", self.app.dash_gaps)

    def open_dashboard_connectors_panel(self) -> None:
        self._open_browser_panel("Dashboard: Integrations", self.app.dash_connectors)

    def open_dashboard_heatmap_panel(self) -> None:
        self._open_browser_panel("Dashboard: Severity Heatmap", self.app.dash_heatmap)

    def open_dashboard_sla_panel(self) -> None:
        self._open_browser_panel("Dashboard: Compliance & SLA", self.app.dash_sla)

    def open_dashboard_audit_panel(self) -> None:
        self._open_browser_panel("Dashboard: Audit Trail", self.app.dash_audit)

    # ------------------------------------------------------------------ #
    # P2-18 — View presets
    # ------------------------------------------------------------------ #

    _VIEW_PRESETS = {
        "Default":  {"incidents", "engines", "mitre", "rules", "fleet", "heatmap",
                     "alerts", "gaps", "connectors", "sla"},
        "Compact":  {"incidents", "engines", "rules", "fleet", "alerts"},
        "Detailed": {"incidents", "engines", "mitre", "rules", "fleet", "heatmap",
                     "alerts", "gaps", "connectors", "sla", "auth", "audit"},
    }

    # Stable display order — visible cards are packed row-major into the
    # per-view column count so there are never empty/gappy cells.
    _DASH_PANEL_ORDER = (
        "incidents", "engines", "mitre", "rules", "fleet", "heatmap",
        "alerts", "gaps", "connectors", "sla", "auth", "audit",
    )

    # Columns per view, all uniform equal-size grids.
    #   Default  = 4 cols → 10 panels flow 4 / 4 / 2 (operator's layout).
    #   Detailed = 4 cols → 12 panels → a clean 4×3 grid.
    #   Compact  = 2 cols → dense two-up.
    _VIEW_COLUMNS = {"Default": 4, "Compact": 2, "Detailed": 4}

    # P3-21 — minimum role required to see each panel.  When the
    # operator's role doesn't meet the bar, the card is hidden even if
    # the active view-preset requests it.  This is layered on TOP of
    # the backend's role checks (defence in depth) — the API still
    # returns 403 for under-privileged callers, but the panel doesn't
    # bother showing a "Couldn't load — Locked" card to a viewer who
    # can never have access.
    _PANEL_MIN_ROLE = {
        "incidents":  "analyst",   # /incidents
        "engines":    "analyst",   # /antivirus/status
        "mitre":      "analyst",   # /enterprise/mitre/summary
        "rules":      "analyst",   # /enterprise/detections/lifecycle
        "fleet":      "analyst",   # /hosts
        "heatmap":    "analyst",   # client-side, but data sources are analyst-gated
        "alerts":     "analyst",   # /history/alerts
        "gaps":       "analyst",   # /enterprise/telemetry/gaps
        "connectors": "admin",     # /enterprise/connectors
        "sla":        "analyst",   # /antivirus/sla
        "auth":       "admin",     # access & policy detail
        "audit":      "admin",     # /history/auth + /history/actions
    }
    _ROLE_RANK = {"locked": 0, "viewer": 1, "analyst": 2, "admin": 3}

    def _on_view_changed(self, _index: int) -> None:
        if self._view_combo is None:
            return
        view = self._view_combo.currentText().strip() or "Default"
        try:
            self.app.settings.setValue("dashboard_view", view)
        except Exception:
            pass
        self._apply_current_view()

    def _apply_current_view(self) -> None:
        if not self._panel_card_refs:
            return
        view = self._view_combo.currentText().strip() if self._view_combo else "Default"
        visible = self._VIEW_PRESETS.get(view, self._VIEW_PRESETS["Default"])
        # P3-21 — strip panels the current role can't see.  When the
        # session is locked we deliberately DON'T filter — operators
        # should see the layout (with soft empty-state hints) before
        # they apply a key.  Filtering only kicks in once authenticated
        # so we don't surface admin-only panels to viewers / analysts.
        role = str((self.app.auth_context or {}).get("role", "locked")).strip().lower()
        rank = self._ROLE_RANK.get(role, 0)
        session_ready = bool(getattr(self.app, "auth_session_ready", False))
        if session_ready:
            rbac_filtered = {
                key for key in visible
                if rank >= self._ROLE_RANK.get(self._PANEL_MIN_ROLE.get(key, "analyst"), 2)
            }
        else:
            rbac_filtered = set(visible)
        self._relayout_dashboard(view, rbac_filtered)

    def _relayout_dashboard(self, view: str, visible_keys: set[str]) -> None:
        """Pack the visible cards into a uniform N-column grid.

        Every view is now a clean equal-cell grid with NO QSplitter
        nesting: visible panels (in stable display order) flow
        row-major into `_VIEW_COLUMNS[view]` columns, so there are never
        gappy/empty cells regardless of which panels RBAC or the preset
        hides. Detailed = 4 equal columns (12 panels → 4×3).
        """
        grid = self._dash_grid
        if grid is None:
            # Layout not built yet — just toggle visibility so state is
            # consistent when the grid is created.
            for key, card in self._panel_card_refs.items():
                card.setVisible(key in visible_keys)
            return

        cols = self._VIEW_COLUMNS.get(view, 3)

        # Persistent bottom spacer — absorbs leftover vertical space so
        # cards stay at their COMPACT min height instead of every row
        # stretching to fill the viewport. Without it a partially-filled
        # last row (e.g. a lone "Compliance & SLA" when 10 panels don't
        # divide evenly by 3) ballooned to a full empty row height and
        # looked broken.
        if getattr(self, "_dash_spacer", None) is None:
            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            spacer.setMinimumHeight(0)
            self._dash_spacer = spacer

        # Detach every card + the spacer first, then re-place only the
        # visible ones. removeWidget keeps the widget alive (no reparent
        # / no QtCharts churn) — we just reposition.
        for key, card in self._panel_card_refs.items():
            grid.removeWidget(card)
            card.setVisible(False)
        grid.removeWidget(self._dash_spacer)

        ordered_visible = [
            k for k in self._DASH_PANEL_ORDER
            if k in visible_keys and k in self._panel_card_refs
        ]
        n = len(ordered_visible)
        full_rows = n // cols
        remainder = n % cols
        rows = full_rows + (1 if remainder else 0)

        for index, key in enumerate(ordered_visible):
            card = self._panel_card_refs[key]
            r = index // cols
            if r < full_rows:
                # A complete row — one card per column.
                grid.addWidget(card, r, index % cols, 1, 1)
            else:
                # The final, partially-filled row: stretch its cards to
                # span the FULL width so no dead space is left on the
                # right (e.g. Default's last row of 2 → each spans 2
                # columns = equal full halves). Columns are split as
                # evenly as possible across the remaining cards.
                pos = index - full_rows * cols
                base, extra = divmod(cols, remainder)
                col_start = pos * base + min(pos, extra)
                span = base + (1 if pos < extra else 0)
                grid.addWidget(card, r, col_start, 1, span)
            card.setVisible(True)

        # Equal column widths so every cell is the same size across.
        max_cols = max(self._VIEW_COLUMNS.values())
        for c in range(max_cols):
            grid.setColumnStretch(c, 1 if c < cols else 0)
        # Content rows take their natural (compact) height — NOT an equal
        # share of the viewport. All leftover height drops into the
        # spacer row at the bottom, so a half-empty final row no longer
        # inflates its lone card.
        for r in range(64):
            grid.setRowStretch(r, 0)
        grid.addWidget(self._dash_spacer, rows, 0, 1, max(cols, 1))
        grid.setRowStretch(rows, 1)
        self._dash_spacer.setVisible(True)

    # ------------------------------------------------------------------ #
    # P1-13 — Notification stream (bell + extended high-sev toast)
    # ------------------------------------------------------------------ #

    def _push_notification(self, kind: str, severity: str, title: str, body: str = "") -> None:
        entry = {
            "ts": time.time(),
            "kind": kind,
            "severity": str(severity or "info").lower(),
            "title": title,
            "body": body,
        }
        # Newest-first; cap at 30
        self._notifications.insert(0, entry)
        del self._notifications[30:]
        self._notifications_unread += 1
        self._refresh_bell_badge()

    def _refresh_bell_badge(self) -> None:
        if self._notification_button is None:
            return
        count = self._notifications_unread
        text = f"🔔 {count}" if count else "🔔"
        self._notification_button.setText(text)
        # Color the button border red when there are unread events
        accent = "#ff6b8a" if count else "#2c4260"
        self._notification_button.setStyleSheet(
            f"QPushButton {{border:1px solid {accent};border-radius:10px;"
            f"padding:4px 10px;color:#f4f7fb;font-weight:700;font-size:12px;}}"
        )

    def _open_notification_panel(self, anchor: QPushButton) -> None:
        from PySide6.QtWidgets import QMenu
        # Mark all read on open
        self._notifications_unread = 0
        self._refresh_bell_badge()

        if not self._notifications:
            menu = QMenu(anchor)
            placeholder = menu.addAction("No notifications yet")
            placeholder.setEnabled(False)
            menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))
            return

        menu = QMenu(anchor)
        menu.setStyleSheet(
            "QMenu { background:#101824; color:#c8d8ea; border:1px solid #2c4260; padding:6px; }"
            "QMenu::item { padding:6px 14px; border-radius:6px; }"
            "QMenu::item:selected { background:#1d2733; }"
        )
        now = time.time()
        for entry in self._notifications[:12]:
            sev = entry["severity"]
            color = _severity_color(sev)
            age = _format_age(entry["ts"], now=now)
            label = f"[{sev.upper():<8}] {entry['title'][:60]}   ·   {age} ago"
            action = menu.addAction(label)
            # Style the action — Qt action label can't have rich text in
            # QMenu; we colour the key with the underlying severity text.
            action.setData(entry)
            try:
                action.setIcon(self._coloured_dot_icon(color))
            except Exception:
                pass
        menu.addSeparator()
        clear = menu.addAction("Clear all")
        clear.triggered.connect(self._clear_notifications)
        menu.exec(anchor.mapToGlobal(anchor.rect().bottomLeft()))

    def _coloured_dot_icon(self, color: str) -> QIcon:
        from PySide6.QtGui import QPainter, QPixmap
        pixmap = QPixmap(12, 12)
        pixmap.fill(QColor("transparent"))
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(color))
        painter.setPen(QColor(color))
        painter.drawEllipse(2, 2, 8, 8)
        painter.end()
        return QIcon(pixmap)

    def _clear_notifications(self) -> None:
        self._notifications.clear()
        self._notifications_unread = 0
        self._refresh_bell_badge()

    # ------------------------------------------------------------------ #
    # Anchor click routing — drill-down + retry
    # ------------------------------------------------------------------ #

    def _on_panel_anchor_clicked(self, url: QUrl) -> None:
        """Handle inline anchor clicks within Dashboard panel browsers.

        Routes:
          - `incident://<incident_id>` -> open slide-over detail dialog (#4)
          - `action://retry`           -> re-run refresh_dashboard_panels
          - `action://triage:<id>:<verb>` -> inline ack/assign/close (#3)
          - `action://filter:<panel>:<axis>:<value>` -> filter chip
          - `action://open:<panel>`    -> "See all" pagination
        """
        app = self.app
        try:
            scheme = url.scheme()
            if scheme == "incident":
                incident_id = (url.host() or url.path().lstrip("/") or "").strip()
                if incident_id:
                    setattr(app, "dashboard_drilldown_incident_id", incident_id)
                    # #4 Slide-over detail dialog — replaces the old
                    # tab-switch behaviour so the operator stays in
                    # context. The dialog itself has an "Open in
                    # Enterprise" escape hatch button.
                    self._open_incident_detail_dialog(incident_id)
                return
            if scheme == "action":
                action = (url.host() or url.path().lstrip("/") or "").strip().lower()
                if action in {"retry", "refresh", ""}:
                    # Clear errors and re-fetch — gives Retry button real teeth.
                    self._last_errors.clear()
                    self.refresh_dashboard_panels()
                    return
                # `action://triage:<incident_id>:<verb>` — inline quick
                # action (#3). Verbs: ack / assign / close / note.
                if action.startswith("triage:"):
                    parts = action.split(":")
                    if len(parts) >= 3:
                        _, inc_id, verb = parts[0], parts[1], parts[2]
                        self._inline_triage_action(inc_id, verb)
                    return
                # `action://filter:<panel>:<axis>:<value>` — inline
                # filter chip click. Mutate `_panel_filters` and
                # re-render using cached data (no fresh fetch).
                if action.startswith("filter:"):
                    parts = action.split(":")
                    if len(parts) == 4:
                        _, panel_key, axis, value = parts
                        bucket = self._panel_filters.setdefault(panel_key, {})
                        bucket[axis] = value or "all"
                        self._rerender_panels_from_cache()
                    return
                # `action://open:<panel>` — pagination "See all" links.
                if action.startswith("open:"):
                    panel_key = action.split(":", 1)[1]
                    opener = {
                        "incidents":  getattr(self.app, "_open_dashboard_metrics_panel", None),
                        "alerts":     self.open_dashboard_alerts_panel,
                        "rules":      self.open_dashboard_rules_panel,
                        "fleet":      self.open_dashboard_fleet_panel,
                        "gaps":       self.open_dashboard_gaps_panel,
                        "connectors": self.open_dashboard_connectors_panel,
                        "audit":      self.open_dashboard_audit_panel,
                    }.get(panel_key)
                    if callable(opener):
                        try:
                            opener()
                        except Exception:
                            pass
                return
        except Exception:
            # Don't let an anchor click ever crash the dashboard.
            return

    def open_dashboard_actions_panel(self) -> None:
        app = self.app
        panel = QWidget()
        row = QHBoxLayout(panel)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(10)
        capabilities = {
            "Run Monitor":       "can_run_monitor",
            "Load Processes":    "can_run_hunt",
            "Refresh History":   "can_view_history",
            "Refresh Dashboard": "can_view_history",
            "Enterprise Triage": "can_manage_incidents",
        }
        for text, fn in [
            ("Refresh Dashboard", app.refresh_overview),
            ("Run Monitor",       app.run_monitor),
            ("Load Processes",    app.refresh_processes),
            ("Refresh History",   app.refresh_history),
            ("Enterprise Triage", app.refresh_enterprise_workspace),
        ]:
            btn = QPushButton(text)
            btn.clicked.connect(fn)
            cap = capabilities.get(text)
            if cap:
                app._bind_capability(btn, cap)
            row.addWidget(btn)
        row.addStretch(1)
        app._open_panel_window("Dashboard: Quick Actions", panel)

    def _open_browser_panel(self, title: str, source: QTextBrowser) -> None:
        app = self.app
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setOpenExternalLinks(False)
        viewer.setHtml(source.toHtml())
        app._open_panel_window(title, viewer)

    # ================================================================== #
    # Overview tab (preserved)
    # ================================================================== #

    def build_overview_tab(self) -> QWidget:
        """Production-grade SOC Overview.

        Layout:

            ┌─ Header (title + Refresh / Run / Expand Chart / Expand Brief)
            ├─ KPI strip (5 tiles): Severity / Confidence / Events / Findings / Actions
            ├─ Top split (horizontal):
            │     Telemetry Trend (multi-series CPU+MEM line chart)
            │     Signal Coverage (collector / sensor health table)
            ├─ Mid split (horizontal):
            │     Attack Chain (ordered MITRE TTP steps)
            │     Response Queue (recommended actions table)
            └─ Executive Detection Brief (full width narrative)
        """
        app = self.app
        w = QWidget()
        # Disable the parent QScrollArea wrapper so the Overview tab fits
        # the viewport exactly — no horizontal/vertical page scroll.
        w.setProperty("no_vertical_scroll", True)
        w.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        l = QVBoxLayout(w)
        l.setContentsMargins(6, 6, 6, 6)
        l.setSpacing(8)

        l.addWidget(self._build_overview_header())
        l.addWidget(self._build_overview_kpi_row())

        # ── Top row: Telemetry Trend + Signal Coverage ──────────────── #
        top_split = QSplitter(Qt.Horizontal)
        top_split.setHandleWidth(6)
        top_split.addWidget(app._panel_card(
            "Telemetry Trend", self._build_overview_chart_view(),
            app._open_overview_chart_panel,
        ))
        top_split.addWidget(app._panel_card(
            "Signal Coverage", self._build_overview_signal_view(), None,
        ))
        top_split.setStretchFactor(0, 3)   # chart wider — primary visual
        top_split.setStretchFactor(1, 2)   # signal coverage
        top_split.setSizes([1200, 700])
        l.addWidget(top_split, 4)

        # ── Bottom row: Attack Chain + Response Queue + Brief ───────── #
        bottom_split = QSplitter(Qt.Horizontal)
        bottom_split.setHandleWidth(6)
        bottom_split.addWidget(app._panel_card(
            "Attack Chain", self._build_overview_chain_view(),
            self.open_overview_chain_panel,
        ))
        bottom_split.addWidget(app._panel_card(
            "Response Queue", self._build_overview_queue_view(),
            self.open_overview_queue_panel,
        ))
        bottom_split.addWidget(app._panel_card(
            "Executive Detection Brief", self._build_overview_brief_view(),
            app._open_overview_brief_panel,
        ))
        bottom_split.setStretchFactor(0, 2)   # attack chain
        bottom_split.setStretchFactor(1, 2)   # response queue
        bottom_split.setStretchFactor(2, 3)   # brief — slightly wider for narrative
        bottom_split.setSizes([650, 650, 900])
        l.addWidget(bottom_split, 4)
        return w

    # ------------------------------------------------------------------ #
    # Overview building blocks
    # ------------------------------------------------------------------ #

    def _build_overview_header(self) -> QWidget:
        app = self.app
        header = QWidget()
        header_row = QHBoxLayout(header)
        header_row.setContentsMargins(0, 0, 0, 0)
        header_row.setSpacing(10)
        title_block = QWidget()
        title_layout = QVBoxLayout(title_block)
        title_layout.setContentsMargins(0, 0, 0, 0)
        title_layout.setSpacing(2)
        title = QLabel("SOC Overview")
        title.setStyleSheet("font-size:18px;font-weight:800;color:#f4f7fb;")
        subtitle = QLabel(
            "Live host telemetry, detection confidence, attack chain, and response priorities."
        )
        subtitle.setStyleSheet("color:#96a5b8;font-size:12px;")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        header_row.addWidget(title_block, 1)

        app.overview_status_label = QLabel("waiting for monitor")
        app.overview_status_label.setStyleSheet(
            "color:#96a5b8;font-size:11px;padding:0 6px;font-weight:600;"
        )
        header_row.addWidget(app.overview_status_label)

        refresh_btn = QPushButton("Refresh Overview")
        refresh_btn.clicked.connect(app.refresh_overview)
        # Drop the can_view_history binding — that capability isn't built
        # by the backend, so the binding silently disabled the button
        # for every authenticated role.
        run_btn = QPushButton("Run Monitor")
        run_btn.clicked.connect(app.run_monitor)
        app._bind_capability(run_btn, "can_run_monitor")
        expand_chart_btn = QPushButton("Expand Chart")
        expand_chart_btn.clicked.connect(app._open_overview_chart_panel)
        expand_brief_btn = QPushButton("Expand Brief")
        expand_brief_btn.clicked.connect(app._open_overview_brief_panel)
        for btn in (refresh_btn, run_btn, expand_chart_btn, expand_brief_btn):
            header_row.addWidget(btn)
        return header

    def _build_overview_kpi_row(self) -> QWidget:
        app = self.app
        kpi_row = QWidget()
        kpi_layout = QHBoxLayout(kpi_row)
        kpi_layout.setContentsMargins(0, 0, 0, 0)
        kpi_layout.setSpacing(8)

        # Severity / Confidence / Events / Findings / Actions
        app.overview_kpi_severity         = QLabel("--")
        app.overview_kpi_severity_sub     = QLabel("no incident loaded")
        app.overview_kpi_confidence       = QLabel("--")
        app.overview_kpi_confidence_sub   = QLabel("monitor not run")
        app.overview_kpi_events           = QLabel("--")
        app.overview_kpi_events_sub       = QLabel("Defender / Sysmon")
        app.overview_kpi_findings         = QLabel("--")
        app.overview_kpi_findings_sub     = QLabel("correlation findings")
        app.overview_kpi_actions          = QLabel("--")
        app.overview_kpi_actions_sub      = QLabel("response queue")

        kpi_layout.addWidget(self._overview_kpi_tile(
            "SEVERITY",   app.overview_kpi_severity,   app.overview_kpi_severity_sub,   "#ff6b8a"), 1)
        kpi_layout.addWidget(self._overview_kpi_tile(
            "CONFIDENCE", app.overview_kpi_confidence, app.overview_kpi_confidence_sub, "#7fd7ff"), 1)
        kpi_layout.addWidget(self._overview_kpi_tile(
            "EVENTS",     app.overview_kpi_events,     app.overview_kpi_events_sub,     "#f4c26b"), 1)
        kpi_layout.addWidget(self._overview_kpi_tile(
            "FINDINGS",   app.overview_kpi_findings,   app.overview_kpi_findings_sub,   "#c98bff"), 1)
        kpi_layout.addWidget(self._overview_kpi_tile(
            "ACTIONS",    app.overview_kpi_actions,    app.overview_kpi_actions_sub,    "#7fe39d"), 1)
        return kpi_row

    def _build_overview_chart_view(self) -> QChartView:
        """Build a multi-series telemetry chart (CPU primary, MEM secondary).

        Critically, we keep `app.cpu_series`, `app.cpu_chart`,
        `app.cpu_axis_x`, `app.cpu_axis_y` intact because
        `monitor_ops.update_cpu_chart` writes to them directly. The MEM
        series is populated by `refresh_overview_widgets` whenever a
        monitor result lands.
        """
        app = self.app

        chart = QChart()
        chart.setTheme(QChart.ChartThemeDark)
        chart.setBackgroundVisible(False)
        chart.setPlotAreaBackgroundVisible(True)
        chart.setPlotAreaBackgroundBrush(QColor("#121b27"))
        chart.setMargins(QMargins(8, 8, 8, 8))
        chart.setTitle("Telemetry CPU Trend")

        # CPU series (existing contract)
        cpu_series = QLineSeries()
        cpu_series.setName("CPU %")
        cpu_pen = QPen(QColor("#28a0ff"))
        cpu_pen.setWidth(3)
        cpu_series.setPen(cpu_pen)
        cpu_series.setColor(QColor("#28a0ff"))
        cpu_series.setPointsVisible(True)
        chart.addSeries(cpu_series)

        # MEM series (new — same Y axis so legend reads as a single % chart)
        mem_series = QLineSeries()
        mem_series.setName("MEM %")
        mem_pen = QPen(QColor("#f4c26b"))
        mem_pen.setWidth(2)
        mem_pen.setStyle(Qt.DashLine)
        mem_series.setPen(mem_pen)
        mem_series.setColor(QColor("#f4c26b"))
        chart.addSeries(mem_series)

        axis_x = QValueAxis()
        axis_x.setTitleText("Samples")
        axis_x.setLabelFormat("%d")
        axis_y = QValueAxis()
        axis_y.setTitleText("Utilisation %")
        axis_y.setRange(0, 100)

        chart.addAxis(axis_x, Qt.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignLeft)
        cpu_series.attachAxis(axis_x); cpu_series.attachAxis(axis_y)
        mem_series.attachAxis(axis_x); mem_series.attachAxis(axis_y)

        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignBottom)
        chart.legend().setLabelColor(QColor("#c8d8ea"))

        chart_view = QChartView(chart)
        chart_view.setRenderHint(chart_view.renderHints())  # keep antialias defaults
        chart_view.setProperty("panel_expand", True)
        chart_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        chart_view.setMinimumHeight(180)

        # Expose to other modules
        app.cpu_series = cpu_series
        app.mem_series = mem_series
        app.cpu_chart = chart
        app.cpu_axis_x = axis_x
        app.cpu_axis_y = axis_y
        app.cpu_chart_view = chart_view
        return chart_view

    def _build_overview_signal_view(self) -> QTextBrowser:
        app = self.app
        view = QTextBrowser()
        view.setProperty("role", "brief")
        view.setOpenExternalLinks(False)
        view.setMinimumWidth(280)
        view.setMinimumHeight(160)
        view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        view.setHtml(self._overview_empty_signal_html())
        app.overview_signal_view = view
        return view

    def _build_overview_chain_view(self) -> QTextBrowser:
        app = self.app
        view = QTextBrowser()
        view.setProperty("role", "brief")
        view.setOpenExternalLinks(False)
        view.setMinimumHeight(160)
        view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        view.setHtml(self._overview_empty_chain_html())
        app.overview_chain_view = view
        return view

    def _build_overview_queue_view(self) -> QTextBrowser:
        app = self.app
        view = QTextBrowser()
        view.setProperty("role", "brief")
        view.setOpenExternalLinks(False)
        view.setMinimumHeight(140)
        view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        view.setHtml(self._overview_empty_queue_html())
        app.overview_queue_view = view
        return view

    def _build_overview_brief_view(self) -> QTextBrowser:
        app = self.app
        view = QTextBrowser()
        view.setReadOnly(True)
        view.setProperty("role", "brief")
        view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        view.setMinimumHeight(140)
        view.setOpenExternalLinks(True)
        view.setHtml(self._overview_empty_brief_html())
        app.monitor_out = view
        return view

    def _overview_kpi_tile(self, title: str, value: QLabel, sub: QLabel, accent: str) -> QWidget:
        tile = QFrame()
        tile.setProperty("card", True)
        tile.setMinimumHeight(64)
        tile.setMaximumHeight(74)
        tile.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        layout = QVBoxLayout(tile)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(0)
        label = QLabel(title)
        label.setStyleSheet("color:#96a5b8;font-size:10px;font-weight:800;letter-spacing:0.4px;")
        value.setStyleSheet(f"color:{accent};font-size:18px;font-weight:800;")
        sub.setStyleSheet("color:#c8d8ea;font-size:10px;")
        sub.setWordWrap(False)
        layout.addWidget(label)
        layout.addWidget(value)
        layout.addWidget(sub)
        return tile

    # ------------------------------------------------------------------ #
    # Empty-state HTML
    # ------------------------------------------------------------------ #

    def _overview_empty_signal_html(self) -> str:
        return (
            "<p style='color:#96a5b8;margin:0 0 8px;font-size:11px;'>"
            "Run Monitor to calculate event pressure, endpoint telemetry quality, "
            "timeline confidence, and ATT&amp;CK hints.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<tr><td style='padding:3px 6px;color:#96a5b8;'>Defender events</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('idle', 'unknown')}</td></tr>"
            "<tr><td style='padding:3px 6px;color:#96a5b8;'>Sysmon events</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('idle', 'unknown')}</td></tr>"
            "<tr><td style='padding:3px 6px;color:#96a5b8;'>Process inventory</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('idle', 'unknown')}</td></tr>"
            "<tr><td style='padding:3px 6px;color:#96a5b8;'>Network telemetry</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('idle', 'unknown')}</td></tr>"
            "<tr><td style='padding:3px 6px;color:#96a5b8;'>Collector export</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('off', 'unknown')}</td></tr>"
            "</table>"
        )

    def _overview_empty_chain_html(self) -> str:
        return (
            "<p style='color:#96a5b8;margin:0;font-size:11px;'>"
            "Run a monitor session to populate the MITRE ATT&amp;CK kill-chain. "
            "Steps will appear ordered by execution / scoring sequence.</p>"
        )

    def _overview_empty_queue_html(self) -> str:
        return (
            "<p style='color:#96a5b8;margin:0;font-size:11px;'>"
            "Recommended response actions will appear here once the incident "
            "scorer produces a triage plan.</p>"
        )

    def _overview_empty_brief_html(self) -> str:
        return (
            "<p style='color:#96a5b8;margin:0;font-size:11px;'>"
            "Run a monitor session or refresh history to populate severity, "
            "likelihood, findings, ATT&amp;CK mapping, artifacts, and response "
            "recommendations.</p>"
        )

    # ------------------------------------------------------------------ #
    # Refresh
    # ------------------------------------------------------------------ #

    def refresh_overview_widgets(self, result: dict | None = None) -> None:
        app = self.app
        # Re-entrancy guard. This is now invoked from several call sites
        # (monitor_ops.run_monitor / update_cpu_chart, the post-drain
        # hook in _apply_refresh_data, and the Refresh Overview button).
        # If one invocation is still mutating the QtCharts QLineSeries
        # when another fires (e.g. a QTimer tick landing during a
        # synchronous monitor-run refresh), the overlapping clear/replace
        # on a series that Qt is mid-paint on segfaults the process.
        # A plain bool flag serialises them — the loser just skips this
        # cycle; the data is already current for the next legitimate
        # refresh.
        if getattr(self, "_overview_refresh_active", False):
            return
        self._overview_refresh_active = True
        try:
            self._refresh_overview_widgets_impl(result)
        finally:
            self._overview_refresh_active = False

    def _refresh_overview_widgets_impl(self, result: dict | None = None) -> None:
        app = self.app
        result = result if isinstance(result, dict) else getattr(app, "latest_monitor_result", {}) or {}
        incident = result.get("incident", {}) if isinstance(result.get("incident", {}), dict) else {}
        final_score = result.get("final_score", {}) if isinstance(result.get("final_score", {}), dict) else {}
        event_summaries = result.get("event_summaries", {}) if isinstance(result.get("event_summaries", {}), dict) else {}
        rows = result.get("telemetry_rows", getattr(app, "latest_monitor_rows", []))
        if not isinstance(rows, list):
            rows = []
        from_live_monitor = bool(rows)
        if not rows:
            rows = getattr(app, "latest_history_telemetry_rows", []) or []
            rows = rows if isinstance(rows, list) else []

        defender = event_summaries.get("defender", {}) if isinstance(event_summaries.get("defender", {}), dict) else {}
        sysmon   = event_summaries.get("sysmon", {})   if isinstance(event_summaries.get("sysmon", {}),   dict) else {}
        actions  = incident.get("recommended_actions", []) if isinstance(incident.get("recommended_actions", []), list) else []
        findings = incident.get("findings", [])             if isinstance(incident.get("findings", []),             list) else []
        attack_chain = incident.get("attack_chain", [])     if isinstance(incident.get("attack_chain", []),         list) else []
        timeline_scores = result.get("timeline_scores", []) if isinstance(result.get("timeline_scores", []),        list) else []
        collector = result.get("collector_export") or {}
        collector_on = bool(collector.get("enabled")) if isinstance(collector, dict) else False

        # --- KPIs ----------------------------------------------------- #
        severity_raw = str(incident.get("severity", "unknown") or "unknown").strip().lower()
        severity_text = severity_raw.upper() if incident else "--"
        try:
            likelihood = final_score.get("likelihood", incident.get("likelihood", 0))
            likelihood_val = float(likelihood)
        except (TypeError, ValueError):
            likelihood_val = 0.0
        if likelihood_val <= 1:
            confidence_text = f"{likelihood_val:.0%}" if likelihood_val > 0 else "--"
        else:
            confidence_text = f"{likelihood_val:.0f}%"
        event_total = _coerce_int(defender.get("total")) + _coerce_int(sysmon.get("total"))

        if hasattr(app, "overview_kpi_severity"):
            app.overview_kpi_severity.setText(severity_text)
            app.overview_kpi_severity.setStyleSheet(
                f"color:{_severity_color(severity_raw if incident else 'unknown')};font-size:22px;font-weight:800;"
            )
            app.overview_kpi_severity_sub.setText(
                str(incident.get("incident_id", "no incident loaded")) if incident else "no incident loaded"
            )
            app.overview_kpi_confidence.setText(confidence_text)
            confidence_color = "#7fe39d" if likelihood_val < 0.4 else ("#f4c26b" if likelihood_val < 0.7 else "#ff6b8a")
            app.overview_kpi_confidence.setStyleSheet(
                f"color:{confidence_color};font-size:22px;font-weight:800;"
            )
            app.overview_kpi_confidence_sub.setText(
                f"{len(rows)} telemetry sample(s)" if rows else "monitor not run"
            )
            app.overview_kpi_events.setText(str(event_total))
            app.overview_kpi_events_sub.setText(
                f"Defender {_coerce_int(defender.get('total'))} / Sysmon {_coerce_int(sysmon.get('total'))}"
            )
            app.overview_kpi_findings.setText(str(len(findings)))
            app.overview_kpi_findings_sub.setText(
                f"{len(timeline_scores)} score step(s)" if timeline_scores else "correlation findings"
            )
            app.overview_kpi_actions.setText(str(len(actions)))
            app.overview_kpi_actions_sub.setText(
                f"{len([a for a in actions if isinstance(a, dict) and str(a.get('priority','')).lower() in {'high','critical'}])} priority"
                if actions else "response queue"
            )

        # --- Telemetry Trend series --------------------------------- #
        # For a LIVE monitor session, monitor_ops.update_cpu_chart owns
        # the CPU series (with spike-sanitisation + title) and we only
        # add the MEM overlay. But for the history / dashboard fallback
        # path, update_cpu_chart is driven by a DIFFERENT dataset
        # (history_ops' reversed [:200] slice) than the rows resolved
        # here (latest_history_telemetry_rows, up to 300 from
        # /history/telemetry). Rebuilding only MEM there left CPU and
        # MEM sourced from two different windows — different lengths and
        # X scaling on the same chart. When the data is NOT live, drive
        # BOTH series from the SAME `recent` slice so the trend is
        # internally consistent regardless of which pipeline filled it.
        if hasattr(app, "mem_series") and hasattr(app, "cpu_axis_x"):
            try:
                recent = [item for item in rows[-60:] if isinstance(item, dict)] if rows else []
                # Atomic `replace(list[QPointF])` instead of clear() +
                # per-point append(). The clear()+append loop forces
                # QtCharts to recompute geometry and repaint on every
                # single point; doing that on a series Qt may be mid-
                # paint on is the classic PySide6 QtCharts segfault.
                # replace() swaps the whole point vector in one call.
                mem_points = [
                    QPointF(idx, float(item.get("mem_percent", 0) or 0))
                    for idx, item in enumerate(recent)
                ]
                app.mem_series.replace(mem_points)
                if recent and not from_live_monitor and hasattr(app, "cpu_series"):
                    cpu_vals = [
                        max(0.0, min(100.0, float(item.get("cpu", 0) or 0)))
                        for item in recent
                    ]
                    app.cpu_series.replace([
                        QPointF(idx, value) for idx, value in enumerate(cpu_vals)
                    ])
                    app.cpu_axis_x.setRange(0, max(1, len(recent) - 1))
                    if hasattr(app, "cpu_axis_y"):
                        # Shared axis with the MEM series — scale to
                        # whichever peaks so a low CPU / high MEM mix
                        # doesn't clip the MEM line off-chart.
                        mem_y = [p.y() for p in mem_points]
                        max_util = max(cpu_vals + mem_y) if mem_y else max(cpu_vals)
                        app.cpu_axis_y.setRange(0, max(25, min(100, max_util + 10)))
                    if hasattr(app, "cpu_chart"):
                        avg_cpu = sum(cpu_vals) / max(1, len(cpu_vals))
                        app.cpu_chart.setTitle(
                            f"Telemetry CPU Trend - {len(recent)} samples | avg {avg_cpu:.1f}%"
                        )
            except Exception:
                pass

        # --- Signal Coverage ---------------------------------------- #
        if hasattr(app, "overview_signal_view"):
            app.overview_signal_view.setHtml(self._render_signal_coverage(
                rows, defender, sysmon, timeline_scores, collector_on, likelihood_val,
            ))

        # --- Attack Chain ------------------------------------------- #
        if hasattr(app, "overview_chain_view"):
            app.overview_chain_view.setHtml(self._render_attack_chain(attack_chain, incident))

        # --- Response Queue ----------------------------------------- #
        if hasattr(app, "overview_queue_view"):
            app.overview_queue_view.setHtml(self._render_response_queue(actions, findings))

        # --- Status pill -------------------------------------------- #
        if hasattr(app, "overview_status_label"):
            stamp = time.strftime("%H:%M:%S", time.localtime())
            if not rows and not incident:
                app.overview_status_label.setText("waiting for monitor")
            else:
                app.overview_status_label.setText(
                    f"refreshed {stamp}  -  rows:{len(rows)} events:{event_total} findings:{len(findings)}"
                )

    # ------------------------------------------------------------------ #
    # Renderers
    # ------------------------------------------------------------------ #

    def _render_signal_coverage(
        self,
        rows: list[dict],
        defender: dict,
        sysmon: dict,
        timeline_scores: list,
        collector_on: bool,
        likelihood_val: float,
    ) -> str:
        avg_cpu = sum(float(item.get("cpu", 0) or 0) for item in rows) / max(1, len(rows)) if rows else 0.0
        avg_mem = sum(float(item.get("mem_percent", 0) or 0) for item in rows) / max(1, len(rows)) if rows else 0.0
        avg_tcp = sum(float(item.get("tcp_conns", 0) or 0) for item in rows) / max(1, len(rows)) if rows else 0.0
        # Telemetry rows (both live monitor and `/history/telemetry`)
        # carry `proc_threads` — there is NO `process_count` field
        # anywhere in `TelemetrySample`/`insert_telemetry`. The old key
        # silently coerced to 0 for EVERY row, so this tile always read
        # "0" with a "ready" badge regardless of real activity.
        proc_avg = sum(_coerce_int(item.get("proc_threads")) for item in rows) / max(1, len(rows)) if rows else 0.0

        def_total = _coerce_int(defender.get("total"))
        sys_total = _coerce_int(sysmon.get("total"))

        def _src_status(count: int) -> str:
            if count == 0:
                return "idle"
            if count < 5:
                return "warning"
            return "healthy"

        # `timeline_scores` is a list[float] on the happy path
        # (api/routes/monitor.py), but refresh_overview_widgets has no
        # outer try/except — a single non-numeric element from a
        # corrupted/hostile payload would otherwise crash the entire
        # Overview render (chart + KPIs + panels). Coerce defensively to
        # match the isinstance-guarded style used everywhere else here.
        numeric_scores: list[float] = []
        for _score in timeline_scores:
            try:
                numeric_scores.append(float(_score or 0))
            except (TypeError, ValueError):
                continue
        peak = max(numeric_scores, default=0.0)
        readiness = "ready" if rows else "idle"

        rows_html = (
            "<tr>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;'>Defender events</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{def_total}</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge(_src_status(def_total), _src_status(def_total))}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;'>Sysmon events</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{sys_total}</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge(_src_status(sys_total), _src_status(sys_total))}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;'>Process threads (avg)</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{proc_avg:.0f}</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge(readiness, readiness)}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;'>Network (TCP avg)</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{avg_tcp:.1f}</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge(readiness, readiness)}</td>"
            "</tr>"
            "<tr>"
            f"<td style='padding:3px 6px;color:#c8d8ea;font-size:11px;'>Collector export</td>"
            f"<td style='padding:3px 6px;color:#f4f7fb;font-size:11px;text-align:right;'>{'on' if collector_on else 'off'}</td>"
            f"<td style='padding:3px 6px;text-align:right;'>{_badge('active' if collector_on else 'off', 'active' if collector_on else 'unknown')}</td>"
            "</tr>"
        )

        baseline_color = "#7fe39d" if max(avg_cpu, avg_mem) < 50 else ("#f4c26b" if max(avg_cpu, avg_mem) < 80 else "#ff6b8a")
        likelihood_color = "#7fe39d" if likelihood_val < 0.4 else ("#f4c26b" if likelihood_val < 0.7 else "#ff6b8a")

        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"Peak likelihood <b style='color:{likelihood_color};'>{peak:.0%}</b> across "
            f"<b>{len(timeline_scores)}</b> scoring step(s). "
            f"Host baseline: CPU <b style='color:{baseline_color};'>{avg_cpu:.1f}%</b> "
            f"&middot; MEM <b style='color:{baseline_color};'>{avg_mem:.1f}%</b>.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            f"{rows_html}</table>"
        )

    def _render_attack_chain(self, chain: list, incident: dict) -> str:
        if not chain:
            mitre_mapping = incident.get("mitre_mapping") if isinstance(incident.get("mitre_mapping"), (dict, list)) else None
            if isinstance(mitre_mapping, dict) and mitre_mapping:
                chain = [f"{key}: {value}" for key, value in list(mitre_mapping.items())[:8]]
            elif isinstance(mitre_mapping, list):
                chain = mitre_mapping
        if not chain:
            return self._overview_empty_chain_html()

        steps: list[str] = []
        for idx, item in enumerate(chain[:8], start=1):
            if isinstance(item, dict):
                attack_id = item.get("attack_id") or item.get("id") or item.get("technique_id") or f"step-{idx}"
                name = item.get("name") or item.get("title") or item.get("description") or ""
                tactic = item.get("tactic") or item.get("phase") or ""
                badge = _badge(str(tactic)[:18], "active") if tactic else ""
                line = (
                    f"<span style='color:#c98bff;font-weight:700;'>{_esc(attack_id)}</span> "
                    f"<span style='color:#f4f7fb;'>{_esc(str(name)[:80])}</span> {badge}"
                )
            else:
                line = f"<span style='color:#f4f7fb;'>{_esc(str(item)[:120])}</span>"
            steps.append(
                "<div style='display:block;padding:4px 0;border-bottom:1px solid #1d2733;'>"
                f"<span style='display:inline-block;width:18px;color:#7fd7ff;font-weight:800;'>{idx:02d}</span>"
                f"{line}</div>"
            )

        shown = min(len(chain), 8)
        coverage = (
            f"{len(chain)} step(s) in the kill-chain"
            if shown >= len(chain)
            else f"showing top {shown} of {len(chain)} kill-chain step(s)"
        )
        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"{coverage} &middot; ordered by scoring sequence.</p>"
            + "".join(steps)
        )

    def _render_response_queue(self, actions: list, findings: list) -> str:
        if not actions and not findings:
            return self._overview_empty_queue_html()

        action_rows: list[str] = []
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        normalised: list[dict] = []
        for item in actions:
            if isinstance(item, dict):
                normalised.append(item)
            elif isinstance(item, str):
                normalised.append({"description": item, "priority": "medium"})
        normalised.sort(key=lambda a: priority_order.get(str(a.get("priority", "medium")).lower(), 2))

        for item in normalised[:6]:
            priority = str(item.get("priority", "medium") or "medium").strip().lower()
            description = str(item.get("description") or item.get("action") or item.get("title") or "(action)")[:80]
            owner = str(item.get("owner") or item.get("assignee") or "operator")[:18]
            status = str(item.get("status") or "queued").strip().lower()
            action_rows.append(
                "<tr>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;width:14px;'>"
                f"<span style='display:inline-block;width:6px;height:14px;background:{_severity_color(priority)};border-radius:2px;'></span></td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#f4f7fb;font-size:11px;'>{_esc(description)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_sev_pill(priority)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;'>{_badge(status, status)}</td>"
                f"<td style='padding:3px 6px;border-bottom:1px solid #1d2733;color:#c8d8ea;font-size:11px;'>{_esc(owner)}</td>"
                "</tr>"
            )

        finding_summary = ""
        if findings:
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for f in findings:
                if isinstance(f, dict):
                    sev = str(f.get("severity", "info")).lower()
                    if sev in sev_counts:
                        sev_counts[sev] += 1
            finding_summary = (
                "<p style='color:#96a5b8;margin:6px 0 0;font-size:11px;'>"
                f"<b>{len(findings)}</b> correlated finding(s): "
                f"<span style='color:#ff4d6d;'>{sev_counts['critical']}c</span> "
                f"<span style='color:#ff6b8a;'>{sev_counts['high']}h</span> "
                f"<span style='color:#f4c26b;'>{sev_counts['medium']}m</span> "
                f"<span style='color:#7fd7ff;'>{sev_counts['low']}l</span></p>"
            )

        if not action_rows:
            return (
                "<p style='color:#96a5b8;margin:0;font-size:11px;'>"
                "No recommended actions yet — incident scorer has not produced a triage plan.</p>"
                + finding_summary
            )

        # Count the *valid* normalised actions (raw `actions` may carry
        # non-dict/non-str junk that was filtered out), and flag when the
        # table is truncated to the top 6 so the header isn't misleading.
        total_actions = len(normalised)
        shown_actions = len(action_rows)
        action_coverage = (
            f"{total_actions} recommended action(s)"
            if shown_actions >= total_actions
            else f"showing top {shown_actions} of {total_actions} recommended action(s)"
        )
        return (
            f"<p style='color:#96a5b8;margin:0 0 6px;font-size:11px;'>"
            f"{action_coverage} &middot; sorted by priority.</p>"
            "<table width='100%' cellspacing='0' cellpadding='0' style='border-collapse:collapse;font-size:11px;'>"
            "<thead><tr style='color:#96a5b8;text-align:left;'>"
            "<th></th><th style='padding:0 6px 4px;'>Action</th>"
            "<th style='padding:0 6px 4px;'>Priority</th>"
            "<th style='padding:0 6px 4px;'>Status</th>"
            "<th style='padding:0 6px 4px;'>Owner</th></tr></thead>"
            f"<tbody>{''.join(action_rows)}</tbody></table>"
            + finding_summary
        )

    # ------------------------------------------------------------------ #
    # Open-in-panel callbacks (Overview)
    # ------------------------------------------------------------------ #

    def copy_cpu_chart(self) -> QChartView:
        app = self.app
        copied_cpu = QLineSeries()
        copied_cpu.setName("CPU %")
        for point in app.cpu_series.pointsVector():
            copied_cpu.append(point)
        copied_mem = QLineSeries()
        copied_mem.setName("MEM %")
        if hasattr(app, "mem_series"):
            for point in app.mem_series.pointsVector():
                copied_mem.append(point)

        copied_chart = QChart()
        copied_chart.setTheme(QChart.ChartThemeDark)
        copied_chart.setBackgroundVisible(False)
        copied_chart.setPlotAreaBackgroundVisible(True)
        copied_chart.setPlotAreaBackgroundBrush(QColor("#121b27"))
        copied_chart.legend().setVisible(True)
        copied_chart.legend().setAlignment(Qt.AlignBottom)
        copied_chart.legend().setLabelColor(QColor("#c8d8ea"))
        copied_chart.setTitle(app.cpu_chart.title() or "Telemetry CPU Trend")
        copied_chart.addSeries(copied_cpu)
        copied_chart.addSeries(copied_mem)

        cpu_pen = QPen(QColor("#28a0ff")); cpu_pen.setWidth(3)
        copied_cpu.setPen(cpu_pen); copied_cpu.setColor(QColor("#28a0ff"))
        mem_pen = QPen(QColor("#f4c26b")); mem_pen.setWidth(2); mem_pen.setStyle(Qt.DashLine)
        copied_mem.setPen(mem_pen); copied_mem.setColor(QColor("#f4c26b"))

        axis_x = QValueAxis(); axis_x.setTitleText("Samples"); axis_x.setLabelFormat("%d")
        axis_y = QValueAxis(); axis_y.setTitleText("Utilisation %"); axis_y.setRange(0, 100)
        copied_chart.addAxis(axis_x, Qt.AlignBottom)
        copied_chart.addAxis(axis_y, Qt.AlignLeft)
        copied_cpu.attachAxis(axis_x); copied_cpu.attachAxis(axis_y)
        copied_mem.attachAxis(axis_x); copied_mem.attachAxis(axis_y)

        chart_view = QChartView(copied_chart)
        chart_view.setMinimumHeight(600)
        return chart_view

    def open_overview_chart_panel(self) -> None:
        self.app._open_panel_window("Overview: Telemetry Trend", self.copy_cpu_chart())

    def open_overview_brief_panel(self) -> None:
        app = self.app
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(app.monitor_out.toHtml())
        app._open_panel_window("Overview: Incident Brief", viewer)

    def open_overview_chain_panel(self) -> None:
        app = self.app
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(app.overview_chain_view.toHtml())
        app._open_panel_window("Overview: Attack Chain", viewer)

    def open_overview_queue_panel(self) -> None:
        app = self.app
        viewer = QTextBrowser()
        viewer.setProperty("role", "brief")
        viewer.setHtml(app.overview_queue_view.toHtml())
        app._open_panel_window("Overview: Response Queue", viewer)

    # ================================================================== #
    # Hunt / threat panel passthroughs (other tabs — untouched logic)
    # ================================================================== #

    def open_hunt_tree_panel(self) -> None:
        app = self.app
        tree = QTreeWidget()
        tree.setHeaderLabels(["Process Tree", "PID"])
        for i in range(app.tree_view.topLevelItemCount()):
            root = app.tree_view.topLevelItem(i)
            cloned = QTreeWidgetItem(root)
            tree.addTopLevelItem(cloned)
        app._open_panel_window("Advanced Hunt: Process Tree", tree)

    def open_hunt_internals_panel(self) -> None:
        self.app._open_panel_window("Advanced Hunt: Internals", self.app._clone_table(self.app.internals_table))

    def open_hunt_output_panel(self) -> None:
        app = self.app
        output = QTextEdit()
        output.setReadOnly(True)
        output.setPlainText(app.hunt_out.toPlainText())
        app._open_panel_window("Advanced Hunt: Output", output)

    def open_threat_history_panel(self) -> None:
        self.app._open_panel_window("Threat Intel: History", self.app._clone_table(self.app.threat_history_table))

    def open_threat_output_panel(self) -> None:
        app = self.app
        output = QTextEdit()
        output.setReadOnly(True)
        output.setPlainText(app.threat_out.toPlainText())
        app._open_panel_window("Threat Intel: Analysis", output)
