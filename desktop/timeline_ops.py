"""Product-grade Timeline / Investigation Workbench.

Replaces the previous flat-table Timeline view with a proper forensic
reconstruction surface:

* **Swimlane chart** - events render as colour-coded dots on a horizontal
  time axis, partitioned by lane (Telemetry / Response / Incident /
  Alert / Remediation). Click a dot to pivot into the detail panel.
* **KPI strip** - total events, by-type / by-severity breakdown, time
  span, latest event.
* **Filter row** - search + event-type chips + severity chips +
  time-window selector.
* **Event table** - sortable fallback view with copy-to-clipboard.
* **Detail panel** - selected event raw payload, redacted via
  `_panel_kit.redact_payload`.

History vs Timeline:
    History  = "what incidents exist + their status" (inventory)
    Timeline = "how did this incident unfold over time" (forensic story)
"""
from __future__ import annotations

import html
import json
import time
from typing import Any

from PySide6.QtCore import Qt, QPointF, QRectF, QTimer
from PySide6.QtGui import QBrush, QColor, QFont, QKeySequence, QPainter, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFrame,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


# ----- Lane palette --------------------------------------------------------

LANES = ["telemetry", "response", "incident", "alert", "remediation"]
LANE_COLORS = {
    "telemetry":   "#5d7d9d",
    "response":    "#3a6ea8",
    "incident":    "#d64550",
    "alert":       "#f08c00",
    "remediation": "#5d8a6a",
}
SEVERITY_COLORS = {
    "critical": "#d64550",
    "high":     "#e0a640",
    "medium":   "#5d8aa8",
    "low":      "#5d7d9d",
    "info":     "#3a4a5a",
    "unknown":  "#3a4a5a",
}
# Color-blind-safe alternates - blues + yellows + magenta tuned so the
# Deuteranopia / Protanopia / Tritanopia simulator distinguishes every
# severity level without leaning on red/green contrast. Based on the
# Wong (2011) qualitative colour palette.
SEVERITY_COLORS_CB = {
    "critical": "#cc79a7",   # magenta
    "high":     "#e69f00",   # orange
    "medium":   "#0072b2",   # blue
    "low":      "#56b4e9",   # sky blue
    "info":     "#999999",   # neutral grey
    "unknown":  "#999999",
}
LANE_COLORS_CB = {
    "telemetry":   "#56b4e9",
    "response":    "#0072b2",
    "incident":    "#cc79a7",
    "alert":       "#e69f00",
    "remediation": "#009e73",
}

# Mode toggle is process-level so the swimlane + table + legend all
# read the same palette without threading a `mode` parameter through
# every helper.
_PALETTE_MODE = {"colour_blind": False}


def _enable_colour_blind_palette(enabled: bool) -> None:
    _PALETTE_MODE["colour_blind"] = bool(enabled)


def _severity_colour(severity: str) -> str:
    palette = SEVERITY_COLORS_CB if _PALETTE_MODE["colour_blind"] else SEVERITY_COLORS
    return palette.get(str(severity or "unknown").lower(), palette["unknown"])


def _lane_colour(lane: str) -> str:
    palette = LANE_COLORS_CB if _PALETTE_MODE["colour_blind"] else LANE_COLORS
    return palette.get(str(lane or "").lower(), "#3a4a5a")


def _lane_index(event_type: str) -> int:
    try:
        return LANES.index(str(event_type or "").lower())
    except ValueError:
        return -1


# ----- Swimlane visualisation ---------------------------------------------


class _SwimlaneView(QGraphicsView):
    """Custom horizontal swimlane chart for timeline events.

    One row per event type (telemetry / response / incident / alert /
    remediation). Events that share a lane + time bucket are clustered
    into a single dot whose size scales with the group count; the
    tooltip lists the underlying event titles.

    Implementation notes:
    * Direct QGraphicsScene rendering (no QtCharts dep) keeps the lab
      build slim and the custom paint compact.
    * `_dot_targets` carries (rect, primary_idx, member_idxs) tuples
      so click → primary event detail and tooltip → all member titles.
    """

    # Cluster-bucket size in seconds. Events that fall into the same
    # lane + (timestamp // BUCKET) merge into one dot. 1 second is the
    # most common analyst pivot; tune via `set_cluster_seconds()`.
    CLUSTER_BUCKET_SECONDS = 1

    def __init__(self, parent: QWidget | None = None) -> None:
        scene = QGraphicsScene(parent)
        super().__init__(scene, parent)
        self._scene = scene
        self.setRenderHint(QPainter.Antialiasing, True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setFrameShape(QFrame.NoFrame)
        self.setStyleSheet("background:#0a1018;")
        self.setMinimumHeight(220)
        self.setMouseTracking(True)
        self._events: list[dict[str, Any]] = []
        # Each entry: (rect, primary_idx, member_idxs, tooltip)
        self._dot_targets: list[tuple[QRectF, int, list[int], str]] = []
        self.on_event_clicked = None  # callable(idx)
        # P2: zoom / pan / brush select state.
        # `_zoom_window` is (t_min, t_max) - when set, the renderer clips
        # the visible range to this window so wheel-zoom + brush-select
        # operate without an extra HTTP refresh.
        self._zoom_window: tuple[float, float] | None = None
        # Brush state - track an in-progress rectangle drag from
        # mousePress to mouseRelease so the operator can drag a time
        # range and emit a window selection callback.
        self._brush_active = False
        self._brush_anchor: QPointF | None = None
        self._brush_rect_item = None
        self.on_brush_selected = None  # callable(t_min, t_max)
        # Bookmark callbacks - operator pins / annotates a dot.
        self.on_bookmark_toggle = None  # callable(event_idx)
        self.on_annotate_event = None   # callable(event_idx)
        # Visual bookmarks - controller pushes list of event identities
        # ({time, type, title}) so we can render a star above the dot.
        self._bookmarked_idents: set[tuple[str, str, str]] = set()

    def set_events(self, events: list[dict[str, Any]]) -> None:
        self._events = list(events or [])
        self._render()

    def resizeEvent(self, event):  # type: ignore[override]
        super().resizeEvent(event)
        self._render()

    def mousePressEvent(self, event):  # type: ignore[override]
        # Shift + left-drag starts a brush selection across the time
        # axis. Plain left-click falls through to the dot-click handler
        # in mouseReleaseEvent.
        if event.button() == Qt.LeftButton and event.modifiers() & Qt.ShiftModifier:
            self._brush_active = True
            self._brush_anchor = self.mapToScene(event.position().toPoint())
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        # Finalize a brush selection if one was in progress.
        if self._brush_active and self._brush_anchor is not None:
            self._brush_active = False
            end = self.mapToScene(event.position().toPoint())
            self._finalize_brush(self._brush_anchor, end)
            self._brush_anchor = None
            return
        # Otherwise treat as a dot click.
        click_pos = self.mapToScene(event.position().toPoint())
        for rect, primary_idx, _members, _tip in self._dot_targets:
            if rect.contains(click_pos):
                # Right-click → context menu (bookmark / annotate /
                # detail). Left-click → straight to detail.
                if event.button() == Qt.RightButton:
                    self._open_dot_context_menu(primary_idx, event.globalPosition().toPoint())
                else:
                    if self.on_event_clicked is not None:
                        try:
                            self.on_event_clicked(primary_idx)
                        except Exception:
                            pass
                break
        super().mouseReleaseEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        # Live-paint the brush rectangle while a Shift-drag is in progress.
        if self._brush_active and self._brush_anchor is not None:
            current = self.mapToScene(event.position().toPoint())
            self._draw_brush_rect(self._brush_anchor, current)
            event.accept()
            return
        # Surface the cluster tooltip while the cursor hovers over a dot.
        pos = self.mapToScene(event.position().toPoint())
        cursor_tip = ""
        for rect, _idx, _members, tip in self._dot_targets:
            if rect.contains(pos):
                cursor_tip = tip
                break
        if cursor_tip:
            self.setToolTip(cursor_tip)
        else:
            self.setToolTip("")
        super().mouseMoveEvent(event)

    def wheelEvent(self, event):  # type: ignore[override]
        # Ctrl + wheel = zoom into the time axis around the cursor.
        # Plain wheel scrolls vertically (default behaviour).
        if not (event.modifiers() & Qt.ControlModifier):
            super().wheelEvent(event)
            return
        if not self._events:
            return
        # Figure out the cursor's timestamp so zoom stays centred on it.
        view_pos = self.mapToScene(event.position().toPoint())
        t_min, t_max = self._effective_window()
        span = max(1.0, t_max - t_min)
        rect = self._scene.sceneRect()
        margin_left, margin_right = 110, 20
        chart_left = rect.x() + margin_left
        chart_w = max(1.0, rect.width() - margin_left - margin_right)
        cursor_frac = max(0.0, min(1.0, (view_pos.x() - chart_left) / chart_w))
        cursor_ts = t_min + span * cursor_frac
        # Scale: wheel up zooms in (smaller span), down zooms out.
        delta = event.angleDelta().y()
        scale = 0.8 if delta > 0 else 1.25
        new_span = max(1.0, span * scale)
        new_min = cursor_ts - new_span * cursor_frac
        new_max = new_min + new_span
        # Clamp to the data range so we can't pan past the dataset.
        data_min, data_max = self._data_range()
        if data_max > data_min:
            new_min = max(data_min, new_min)
            new_max = min(data_max, new_max)
            if new_max - new_min < 1.0:
                new_max = new_min + 1.0
        # Reset zoom entirely when scrolled out past the full data range.
        if new_min <= data_min and new_max >= data_max:
            self._zoom_window = None
        else:
            self._zoom_window = (new_min, new_max)
        self._render()
        event.accept()

    def mouseDoubleClickEvent(self, event):  # type: ignore[override]
        # Reset zoom on double-click - convenient escape hatch when the
        # operator gets lost after a sequence of wheel-zooms.
        if event.button() == Qt.LeftButton:
            self._zoom_window = None
            self._render()
            return
        super().mouseDoubleClickEvent(event)

    def _draw_brush_rect(self, anchor: QPointF, current: QPointF) -> None:
        """Re-render the in-progress brush rectangle on every mouse move."""
        if self._brush_rect_item is not None:
            try:
                self._scene.removeItem(self._brush_rect_item)
            except Exception:
                pass
            self._brush_rect_item = None
        # Constrain Y to the chart band so the rectangle never strays
        # into the time-axis label row.
        rect = self._scene.sceneRect()
        margin_top, margin_bottom = 20, 30
        chart_top = rect.y() + margin_top
        chart_bottom = rect.y() + rect.height() - margin_bottom
        x1, x2 = sorted([anchor.x(), current.x()])
        y1, y2 = chart_top, chart_bottom
        from PySide6.QtCore import QRectF as _QRect
        brush_rect = _QRect(x1, y1, max(2.0, x2 - x1), y2 - y1)
        pen = QPen(QColor("#f6e05e"), 1)
        pen.setStyle(Qt.DashLine)
        self._brush_rect_item = self._scene.addRect(
            brush_rect,
            pen,
            QBrush(QColor(246, 224, 94, 40)),
        )

    def _finalize_brush(self, anchor: QPointF, end: QPointF) -> None:
        """Translate the brush rectangle into a time-window selection."""
        if self._brush_rect_item is not None:
            try:
                self._scene.removeItem(self._brush_rect_item)
            except Exception:
                pass
            self._brush_rect_item = None
        if not self._events:
            return
        t_min, t_max = self._effective_window()
        span = max(1.0, t_max - t_min)
        rect = self._scene.sceneRect()
        margin_left, margin_right = 110, 20
        chart_left = rect.x() + margin_left
        chart_w = max(1.0, rect.width() - margin_left - margin_right)

        def _x_to_ts(x: float) -> float:
            frac = max(0.0, min(1.0, (x - chart_left) / chart_w))
            return t_min + span * frac

        ts_a = _x_to_ts(anchor.x())
        ts_b = _x_to_ts(end.x())
        lo, hi = sorted((ts_a, ts_b))
        if hi - lo < 1.0:
            return  # accidental click, ignore
        self._zoom_window = (lo, hi)
        self._render()
        if self.on_brush_selected is not None:
            try:
                self.on_brush_selected(lo, hi)
            except Exception:
                pass

    def _open_dot_context_menu(self, idx: int, global_pos) -> None:
        """Right-click menu on a dot - bookmark, annotate, open detail."""
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        bookmark = menu.addAction("⭐ Toggle Bookmark")
        annotate = menu.addAction("📝 Add Annotation")
        menu.addSeparator()
        open_detail = menu.addAction("🔍 Open Detail")
        action = menu.exec(global_pos)
        if action is bookmark and self.on_bookmark_toggle is not None:
            try:
                self.on_bookmark_toggle(idx)
            except Exception:
                pass
        elif action is annotate and self.on_annotate_event is not None:
            try:
                self.on_annotate_event(idx)
            except Exception:
                pass
        elif action is open_detail and self.on_event_clicked is not None:
            try:
                self.on_event_clicked(idx)
            except Exception:
                pass

    def _data_range(self) -> tuple[float, float]:
        times = [self._to_epoch(e.get("time")) for e in self._events]
        times = [t for t in times if t > 0]
        if not times:
            return (0.0, 0.0)
        return (min(times), max(times))

    def _effective_window(self) -> tuple[float, float]:
        if self._zoom_window is not None:
            return self._zoom_window
        return self._data_range()

    def set_bookmarks(self, idents: set[tuple[str, str, str]]) -> None:
        """Controller pushes the active bookmark identity set."""
        self._bookmarked_idents = set(idents or set())
        self._render()

    def reset_zoom(self) -> None:
        self._zoom_window = None
        self._render()

    def _render(self) -> None:
        scene = self._scene
        scene.clear()
        self._dot_targets = []

        viewport_w = max(400, self.viewport().width() - 20)
        viewport_h = max(180, self.viewport().height() - 20)
        scene.setSceneRect(0, 0, viewport_w, viewport_h)

        # Empty state hint.
        if not self._events:
            hint = scene.addText(
                "No timeline events captured yet.\n\n"
                "Run Monitor or trigger a hunt - telemetry, responses, incidents,\n"
                "alerts and remediations will all populate this chart.",
                QFont("Segoe UI", 11),
            )
            hint.setDefaultTextColor(QColor("#7a8694"))
            hint.setPos(20, viewport_h / 2 - 30)
            return

        # Compute time bounds - honour the zoom window if the operator
        # has wheel-zoomed or brush-selected into a sub-range.
        if self._zoom_window is not None:
            t_min, t_max = self._zoom_window
        else:
            times: list[float] = []
            for item in self._events:
                ts = self._to_epoch(item.get("time"))
                if ts > 0:
                    times.append(ts)
            if not times:
                return
            t_min = min(times)
            t_max = max(times)
        if t_max <= t_min:
            t_max = t_min + 1.0
        span = t_max - t_min

        lane_count = len(LANES)
        margin_left = 110
        margin_right = 20
        margin_top = 20
        margin_bottom = 30
        chart_w = viewport_w - margin_left - margin_right
        chart_h = viewport_h - margin_top - margin_bottom
        lane_h = chart_h / lane_count

        # Draw lane backgrounds + labels.
        font = QFont("Segoe UI", 9)
        for i, lane in enumerate(LANES):
            y0 = margin_top + i * lane_h
            # Alternating background for readability.
            bg_brush = QBrush(QColor("#0e1720" if i % 2 == 0 else "#101a24"))
            scene.addRect(QRectF(margin_left, y0, chart_w, lane_h), QPen(Qt.NoPen), bg_brush)
            # Lane title pill on the left margin.
            pill_rect = QRectF(8, y0 + lane_h / 2 - 10, margin_left - 16, 20)
            scene.addRect(
                pill_rect,
                QPen(QColor(_lane_colour(lane))),
                QBrush(QColor("#121b27")),
            )
            text = scene.addText(lane.upper(), font)
            text.setDefaultTextColor(QColor(_lane_colour(lane)))
            text.setPos(pill_rect.left() + 8, pill_rect.top() + 1)

        # X-axis tick marks - first / mid / last timestamps.
        tick_brush = QPen(QColor("#3a4452"))
        tick_brush.setStyle(Qt.DashLine)
        for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
            x = margin_left + chart_w * frac
            scene.addLine(x, margin_top, x, margin_top + chart_h, tick_brush)
            ts_value = t_min + span * frac
            label = scene.addText(time.strftime("%H:%M:%S", time.localtime(ts_value)), font)
            label.setDefaultTextColor(QColor("#7a8694"))
            label.setPos(x - 24, margin_top + chart_h + 4)

        # ---- Cluster events that share the same lane + time bucket so
        # five-events-in-a-second don't render as one overlapping smear.
        # `clusters[(lane_idx, bucket)] = [member_idx, ...]`
        clusters: dict[tuple[int, int], list[int]] = {}
        for idx, event in enumerate(self._events):
            lane = str(event.get("type", "") or "").lower()
            lane_idx = _lane_index(lane)
            if lane_idx < 0:
                continue
            ts = self._to_epoch(event.get("time"))
            if ts <= 0:
                continue
            # Skip events outside the zoom window so the chart stays
            # focused on the operator's chosen slice.
            if ts < t_min or ts > t_max:
                continue
            bucket = int(ts) // max(1, int(self.CLUSTER_BUCKET_SECONDS))
            clusters.setdefault((lane_idx, bucket), []).append(idx)

        # Plot each cluster - radius scales with member count so 12
        # events render as a noticeably larger dot than a singleton.
        for (lane_idx, bucket), members in clusters.items():
            # Pick the highest-severity event as the cluster's primary
            # so click → detail shows the worst case, not the first.
            severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
            primary_idx = max(
                members,
                key=lambda i: severity_rank.get(str(self._events[i].get("severity", "")).lower(), 0),
            )
            primary_event = self._events[primary_idx]
            ts = self._to_epoch(primary_event.get("time"))
            x = margin_left + chart_w * ((ts - t_min) / span)
            y = margin_top + lane_idx * lane_h + lane_h / 2
            count = len(members)
            radius = 6.0 + min(8.0, (count - 1) * 1.6)
            colour = QColor(_severity_colour(primary_event.get("severity", "")))
            dot_rect = QRectF(x - radius, y - radius, radius * 2, radius * 2)
            scene.addEllipse(
                dot_rect,
                QPen(QColor("#f4f7fb"), 1.0),
                QBrush(colour),
            )
            # Count badge for clusters > 1 - keeps the operator from
            # underestimating density.
            if count > 1:
                badge = scene.addText(str(count), font)
                badge.setDefaultTextColor(QColor("#0a1018"))
                badge_rect = badge.boundingRect()
                badge.setPos(x - badge_rect.width() / 2, y - badge_rect.height() / 2)
            # Tooltip lists every member title for analyst situational
            # awareness without having to click each dot.
            tooltip_lines: list[str] = [
                f"{LANES[lane_idx].upper()}  ·  {time.strftime('%H:%M:%S', time.localtime(ts))}  ·  {count} event(s)",
                "",
            ]
            for member_idx in members[:6]:
                ev = self._events[member_idx]
                tooltip_lines.append(
                    f"[{ev.get('severity', '?')}] {ev.get('title', '')[:80]}"
                )
            if count > 6:
                tooltip_lines.append(f"(+{count - 6} more — click to inspect)")
            self._dot_targets.append((
                dot_rect.adjusted(-3, -3, 3, 3),
                primary_idx,
                members,
                "\n".join(tooltip_lines),
            ))
            # Bookmark star - render above any dot whose cluster contains
            # at least one bookmarked event. Yellow ★ on a transparent
            # background, positioned just above the dot.
            if any(self._event_identity(self._events[m]) in self._bookmarked_idents for m in members):
                star = scene.addText("★", QFont("Segoe UI Symbol", 10))
                star.setDefaultTextColor(QColor("#f6e05e"))
                star_rect = star.boundingRect()
                star.setPos(x - star_rect.width() / 2, y - radius - star_rect.height())

    @staticmethod
    def _event_identity(event: dict[str, Any]) -> tuple[str, str, str]:
        return (str(event.get("time", "")), str(event.get("type", "")), str(event.get("title", "")))

    @staticmethod
    def _to_epoch(raw: Any) -> float:
        if raw in (None, ""):
            return 0.0
        if isinstance(raw, (int, float)):
            return float(raw)
        candidate = str(raw).strip()
        if not candidate:
            return 0.0
        try:
            return float(candidate)
        except ValueError:
            pass
        from datetime import datetime
        for parser in (
            lambda v: datetime.fromisoformat(v.replace("Z", "+00:00")),
            datetime.fromisoformat,
        ):
            try:
                return parser(candidate).timestamp()
            except Exception:
                continue
        return 0.0


# ----- Controller ---------------------------------------------------------


class TimelineWorkspaceController:
    def __init__(self, app) -> None:
        self.app = app
        self._all_events: list[dict[str, Any]] = []
        self._filtered_events: list[dict[str, Any]] = []
        # P2: bookmarks + annotations live in-memory + flushed to a
        # local JSONL ledger so they survive desktop restarts.
        self._bookmarks: set[tuple[str, str, str]] = set()
        self._annotations: dict[tuple[str, str, str], str] = {}
        self._load_bookmarks_from_disk()
        # Anomaly tracking — identity set of every high/critical event
        # we've seen across refreshes. Anything that appears for the
        # first time on a subsequent refresh is "new" and gets the
        # flash treatment.
        self._known_high_idents: set[tuple[str, str, str]] = set()
        self._color_blind_mode = False

    # ------------------------------------------------------------------ #
    # Tab construction
    # ------------------------------------------------------------------ #

    def build_timeline_tab(self) -> QWidget:
        try:
            from _panel_kit import build_kpi_strip, BusyController
        except ImportError:
            from desktop._panel_kit import build_kpi_strip, BusyController

        app = self.app
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        app._tab_header(
            layout,
            "Investigation Timeline",
            "Reconstruct the chronological event flow across telemetry, response, incidents, alerts, and remediation. Each dot is one event; click for raw detail.",
        )

        # --- Header strip
        header_row = QWidget()
        h = QHBoxLayout(header_row)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(12)
        self._last_refresh = QLabel("Last refreshed: never")
        self._last_refresh.setStyleSheet("color:#9aa5b1; font-size:12px;")
        h.addWidget(self._last_refresh)
        self._workspace_badge = QLabel("workspace: -")
        self._workspace_badge.setStyleSheet(
            "color:#cbd5e0; background:#1f2933; padding:4px 10px; border-radius:8px;"
            " font-size:11px; font-weight:600;"
        )
        h.addWidget(self._workspace_badge)
        h.addStretch(1)
        win_label = QLabel("Window:")
        win_label.setStyleSheet("color:#9aa5b1;font-size:11px;")
        self._window_combo = QComboBox()
        self._window_combo.addItems(["1h", "24h", "7d", "All"])
        self._window_combo.setCurrentText("24h")
        self._window_combo.currentTextChanged.connect(lambda _: self._apply_filters())
        h.addWidget(win_label)
        h.addWidget(self._window_combo)
        self._auto_refresh = QCheckBox("Auto-refresh 30s")
        self._auto_refresh.setStyleSheet("color:#cbd5e0;font-size:11px;")
        self._auto_refresh.toggled.connect(self._toggle_auto_refresh)
        h.addWidget(self._auto_refresh)
        # Live SSE feed toggle - subscribes to /timeline/stream and
        # merges new events into the view without polling the whole
        # endpoint. The server emits a heartbeat comment every 30s so
        # proxies don't close the idle connection.
        self._live_feed = QCheckBox("Live feed (SSE)")
        self._live_feed.setStyleSheet("color:#cbd5e0;font-size:11px;")
        self._live_feed.setToolTip(
            "Subscribe to the server's /timeline/stream Server-Sent Events feed.\n"
            "Newly-recorded events merge into the swimlane automatically,\n"
            "no manual Refresh All needed during an active investigation."
        )
        self._live_feed.toggled.connect(self._toggle_live_feed)
        h.addWidget(self._live_feed)
        # Color-blindness mode toggle — flips the lane + severity
        # palette to a Wong-2011 colour-blind-safe variant. State is
        # persisted via QSettings so analysts don't have to re-enable
        # it on every relaunch.
        self._cb_toggle = QCheckBox("Colour-blind safe")
        self._cb_toggle.setStyleSheet("color:#cbd5e0;font-size:11px;")
        self._cb_toggle.setToolTip(
            "Switch lane + severity palette to a Deuteranopia/Protanopia/Tritanopia-safe variant\n"
            "based on the Wong (2011) qualitative colour scheme."
        )
        self._cb_toggle.toggled.connect(self._toggle_colour_blind)
        self._restore_colour_blind_pref()
        h.addWidget(self._cb_toggle)
        refresh_all_btn = QPushButton("Refresh All (Ctrl+R)")
        refresh_all_btn.setShortcut(QKeySequence("Ctrl+R"))
        refresh_all_btn.clicked.connect(self.refresh_timeline)
        h.addWidget(refresh_all_btn)
        layout.addWidget(header_row)

        # --- KPI strip
        kpi_strip, self._kpis = build_kpi_strip(
            w, ("Total Events", "Critical / High", "Active Lanes", "Time Span", "Latest"),
        )
        layout.addWidget(kpi_strip)

        # --- MITRE technique chip strip - top T-id frequencies for the
        # current filter view. Populated by _update_mitre_strip() on
        # every refresh / filter change so analysts spot the dominant
        # attack-chain steps without scrolling the table.
        mitre_row = QHBoxLayout()
        mitre_row.setContentsMargins(2, 0, 2, 0)
        mitre_row.setSpacing(6)
        self._mitre_label = QLabel("MITRE")
        self._mitre_label.setStyleSheet(
            "color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;"
        )
        mitre_row.addWidget(self._mitre_label)
        self._mitre_strip = QLabel("press Refresh to surface technique frequencies")
        self._mitre_strip.setStyleSheet("color:#9aa5b1; font-size:11px; font-style:italic;")
        self._mitre_strip.setWordWrap(False)
        mitre_row.addWidget(self._mitre_strip, 1)
        layout.addLayout(mitre_row)

        # --- Filter row
        filter_card = QFrame()
        filter_card.setProperty("card", True)
        fo = QVBoxLayout(filter_card)
        fo.setContentsMargins(8, 6, 8, 6)
        fo.setSpacing(6)
        # Row 1: search
        f1 = QHBoxLayout()
        f1.setContentsMargins(0, 0, 0, 0)
        f1.setSpacing(6)
        search_lbl = QLabel("🔍")
        search_lbl.setStyleSheet("color:#9aa5b1;font-size:12px;")
        self._search = QLineEdit()
        self._search.setPlaceholderText("filter by title, type, severity, or detail body…")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._apply_filters)
        f1.addWidget(search_lbl)
        f1.addWidget(self._search)
        fo.addLayout(f1)
        # Row 2: lane chips + severity chips
        f2 = QHBoxLayout()
        f2.setContentsMargins(0, 0, 0, 0)
        f2.setSpacing(6)
        type_lbl = QLabel("LANES")
        type_lbl.setStyleSheet("color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;")
        f2.addWidget(type_lbl)
        self._lane_chips: dict[str, QCheckBox] = {}
        for lane in LANES:
            chk = QCheckBox(lane.upper())
            chk.setChecked(True)
            chk.setStyleSheet("QCheckBox { color:#cbd5e0; font-size:11px; padding:2px 6px; }")
            chk.toggled.connect(self._apply_filters)
            self._lane_chips[lane] = chk
            f2.addWidget(chk)
        f2.addSpacing(20)
        sev_lbl = QLabel("SEVERITY")
        sev_lbl.setStyleSheet("color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;")
        f2.addWidget(sev_lbl)
        self._severity_chips: dict[str, QCheckBox] = {}
        for sev in ("critical", "high", "medium", "low", "info"):
            chk = QCheckBox(sev.upper())
            chk.setChecked(True)
            chk.setStyleSheet("QCheckBox { color:#cbd5e0; font-size:11px; padding:2px 6px; }")
            chk.toggled.connect(self._apply_filters)
            self._severity_chips[sev] = chk
            f2.addWidget(chk)
        f2.addStretch(1)
        reset_btn = QPushButton("Reset Filters")
        reset_btn.setMaximumWidth(110)
        reset_btn.clicked.connect(self._reset_filters)
        f2.addWidget(reset_btn)
        fo.addLayout(f2)
        layout.addWidget(filter_card)

        # --- Forensic action row: snapshot save / diff + export PNG / JSON.
        action_row = QHBoxLayout()
        action_row.setContentsMargins(2, 0, 2, 0)
        action_row.setSpacing(6)
        action_label = QLabel("FORENSIC")
        action_label.setStyleSheet(
            "color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;"
        )
        action_row.addWidget(action_label)
        self._snapshot_save_btn = QPushButton("Save Snapshot")
        self._snapshot_save_btn.setToolTip(
            "Persist the active filter view (events + filters + window) to disk for later diff."
        )
        self._snapshot_save_btn.clicked.connect(self._save_snapshot)
        action_row.addWidget(self._snapshot_save_btn)
        self._snapshot_diff_btn = QPushButton("Diff vs Snapshot")
        self._snapshot_diff_btn.setToolTip(
            "Load a previously-saved timeline snapshot and report added / removed events."
        )
        self._snapshot_diff_btn.clicked.connect(self._diff_snapshot)
        action_row.addWidget(self._snapshot_diff_btn)
        self._export_png_btn = QPushButton("Export PNG")
        self._export_png_btn.setToolTip(
            "Render the current swimlane to a PNG image suitable for case attachments."
        )
        self._export_png_btn.clicked.connect(self._export_png)
        action_row.addWidget(self._export_png_btn)
        self._export_json_btn = QPushButton("Export JSON")
        self._export_json_btn.setToolTip(
            "Export the active event list (after filters) as a redacted JSON bundle."
        )
        self._export_json_btn.clicked.connect(self._export_json)
        action_row.addWidget(self._export_json_btn)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        # --- Body: two-column splitter
        #     Left column  (≈60%): swimlane (top) + sortable event log (bottom)
        #     Right column (≈40%): event detail full height
        #
        # The previous layout stacked swimlane + detail horizontally and
        # parked the table at the very bottom, leaving 500+ px of dead
        # space below the empty-state swimlane on first paint. Putting
        # the table beneath the swimlane reuses that vertical real-estate
        # and lets the detail panel grow to fill the right column.
        body_splitter = QSplitter(Qt.Horizontal)

        left_col = QWidget()
        left_layout = QVBoxLayout(left_col)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        self._swimlane = _SwimlaneView()
        self._swimlane.on_event_clicked = self._on_swimlane_event_clicked
        self._swimlane.on_brush_selected = self._on_brush_selected
        self._swimlane.on_bookmark_toggle = self._toggle_bookmark
        self._swimlane.on_annotate_event = self._annotate_event
        self._swimlane.setMinimumHeight(180)
        # Tell `panel_card` the swimlane is an expanding surface (it's a
        # QGraphicsView, not in the helper's built-in "expandable" list)
        # so the card stretches the widget to fill its allotted height
        # instead of pinning it to the top and leaving 200+ px of dead
        # space below.
        self._swimlane.setProperty("panel_expand", True)
        self._swimlane.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        swimlane_card = app._panel_card(
            "Swimlane",
            self._swimlane,
            lambda: app._open_panel_window("Swimlane (large)", self._cloned_swimlane()),
        )
        left_layout.addWidget(swimlane_card, 2)

        # Legend strip — interpret the lane + severity colour palette.
        legend = QLabel(self._legend_html())
        legend.setTextFormat(Qt.RichText)
        legend.setStyleSheet("color:#9aa5b1; font-size:11px; padding:2px 6px;")
        legend.setWordWrap(True)
        left_layout.addWidget(legend, 0)

        # P2: zoom hint + replay scrubber.
        from PySide6.QtWidgets import QSlider
        scrubber_row = QHBoxLayout()
        scrubber_row.setContentsMargins(2, 0, 2, 0)
        scrubber_row.setSpacing(6)
        scrub_label = QLabel("REPLAY")
        scrub_label.setStyleSheet(
            "color:#7a8694; font-size:10px; letter-spacing:1.2px; font-weight:700;"
        )
        scrubber_row.addWidget(scrub_label)
        self._scrubber = QSlider(Qt.Horizontal)
        self._scrubber.setRange(0, 100)
        self._scrubber.setValue(100)
        self._scrubber.setToolTip(
            "Drag to replay the investigation - only events up to the slider position are shown."
        )
        self._scrubber.valueChanged.connect(self._on_scrubber_changed)
        scrubber_row.addWidget(self._scrubber, 1)
        self._scrubber_label = QLabel("100% (live)")
        self._scrubber_label.setStyleSheet("color:#9aa5b1; font-size:11px; min-width:90px;")
        scrubber_row.addWidget(self._scrubber_label)
        reset_zoom_btn = QPushButton("Reset Zoom")
        reset_zoom_btn.setMaximumWidth(110)
        reset_zoom_btn.setToolTip(
            "Clear any wheel-zoom or brush selection so the swimlane covers the whole dataset.\n"
            "Tip: shift-drag on the swimlane to brush a window; ctrl-wheel to zoom; double-click to reset."
        )
        reset_zoom_btn.clicked.connect(self._reset_zoom)
        scrubber_row.addWidget(reset_zoom_btn)
        left_layout.addLayout(scrubber_row)

        app.timeline_table = QTableWidget(0, 5)
        app.timeline_table.setHorizontalHeaderLabels(["Time", "Lane", "Severity", "Title", "MITRE"])
        app._style_table(app.timeline_table)
        app.timeline_table.setSortingEnabled(True)
        app.timeline_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        app.timeline_table.itemSelectionChanged.connect(self.show_selected_timeline)
        app.timeline_table.setMinimumHeight(180)
        left_layout.addWidget(app._panel_card("Event Log (sortable)", app.timeline_table), 1)
        body_splitter.addWidget(left_col)

        # Right column: pivot row + detail viewer.
        right_col = QWidget()
        right_layout = QVBoxLayout(right_col)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        # Pivot buttons — DFIR drill-down without leaving the timeline.
        pivot_row = QWidget()
        pivot_layout = QHBoxLayout(pivot_row)
        pivot_layout.setContentsMargins(0, 0, 0, 0)
        pivot_layout.setSpacing(6)
        self._pivot_graph_btn = QPushButton("Pivot to Graph")
        self._pivot_graph_btn.setToolTip(
            "Rebuild the Entity Graph focused on the selected event's PID or host."
        )
        self._pivot_graph_btn.clicked.connect(self._pivot_selected_to_graph)
        self._pivot_graph_btn.setEnabled(False)
        self._pivot_process_btn = QPushButton("Pivot to Process")
        self._pivot_process_btn.setToolTip(
            "Open the Processes tab and focus on the PID embedded in the selected event."
        )
        self._pivot_process_btn.clicked.connect(self._pivot_selected_to_process)
        self._pivot_process_btn.setEnabled(False)
        pivot_layout.addWidget(self._pivot_graph_btn)
        pivot_layout.addWidget(self._pivot_process_btn)
        pivot_layout.addStretch(1)
        right_layout.addWidget(pivot_row, 0)

        app.timeline_detail = QTextEdit()
        app.timeline_detail.setReadOnly(True)
        app.timeline_detail.setPlainText(
            "Pick a dot on the swimlane (or a row in the table) to surface "
            "the raw event payload. Sensitive fields are redacted before display."
        )
        right_layout.addWidget(
            app._panel_card(
                "Event Detail",
                app.timeline_detail,
                lambda: app._open_panel_window("Event Detail", app._clone_text_view(app.timeline_detail)),
            ),
            1,
        )
        body_splitter.addWidget(right_col)
        body_splitter.setStretchFactor(0, 3)
        body_splitter.setStretchFactor(1, 2)
        body_splitter.setSizes([900, 600])
        layout.addWidget(body_splitter, 1)

        # Busy controller for refresh runs. Forensic actions also share
        # the lock so a snapshot save during refresh doesn't interleave
        # with the in-flight HTTP call.
        self._busy = BusyController(
            app,
            [
                refresh_all_btn,
                self._snapshot_save_btn,
                self._snapshot_diff_btn,
                self._export_png_btn,
                self._export_json_btn,
            ],
        )
        self._update_workspace_badge()
        return w

    # ------------------------------------------------------------------ #
    # Refresh / data plumbing
    # ------------------------------------------------------------------ #

    def refresh_timeline(self) -> None:
        app = self.app
        try:
            self._busy.set_busy(True, "Building investigation timeline…")
        except Exception:
            pass
        # Skeleton overlay - swimlane shows a "Loading…" placeholder
        # while the HTTP call is in flight.
        try:
            self._swimlane.set_events([])  # clears + repaints empty state
            scene = self._swimlane.scene()
            scene.addText(
                "Loading investigation timeline…",
                QFont("Segoe UI", 12),
            ).setDefaultTextColor(QColor("#9aa5b1"))
        except Exception:
            pass
        try:
            try:
                items = app._get("/timeline", timeout=20).json()
            except Exception as exc:
                self._all_events = []
                app.timeline_items = []
                app._show_error(app.timeline_detail, "Timeline load failed", exc)
                self._apply_filters()
                return
            if not isinstance(items, list):
                items = []
            self._all_events = items
            app.timeline_items = items
            self._update_workspace_badge()
            self._last_refresh.setText(
                f"Last refreshed: {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            # Anomaly detection - find new high / critical events that
            # weren't in the previous refresh and flash them on the
            # swimlane / table. Skip on the first ever refresh to avoid
            # painting the whole dataset yellow.
            new_anomalies = self._detect_new_anomalies(items)
            self._apply_filters()
            if new_anomalies and self._known_high_idents:
                # `_known_high_idents` is non-empty → we've done at
                # least one prior refresh, so flashing is meaningful.
                self._flash_anomalies(new_anomalies)
            # Update the known set for the next pass.
            self._known_high_idents = {
                self._event_identity(e) for e in items
                if str(e.get("severity", "")).lower() in {"critical", "high"}
            }
            # Audit successful refresh into the timeline-specific chain
            # so investigators can later prove who pulled which slice
            # of the chronology.
            self._record_audit(
                "refresh",
                target=f"window={self._window_combo.currentText() if hasattr(self, '_window_combo') else ''}",
                payload_size=len(items),
            )
        finally:
            try:
                self._busy.set_busy(False)
            except Exception:
                pass

    def _toggle_auto_refresh(self, checked: bool) -> None:
        if not hasattr(self, "_auto_refresh_timer"):
            self._auto_refresh_timer = QTimer(self.app)
            self._auto_refresh_timer.setInterval(30_000)
            self._auto_refresh_timer.timeout.connect(self.refresh_timeline)
        if checked:
            self._auto_refresh_timer.start()
            self.app.statusBar().showMessage("Timeline auto-refresh enabled (30s)", 4000)
        else:
            self._auto_refresh_timer.stop()
            self.app.statusBar().showMessage("Timeline auto-refresh disabled", 4000)

    def _update_workspace_badge(self) -> None:
        try:
            wid = ""
            if hasattr(self.app, "workspace_id") and hasattr(self.app.workspace_id, "text"):
                wid = self.app.workspace_id.text().strip()
            wid = wid or (getattr(self.app, "current_auth_context", {}) or {}).get("workspace_id", "default")
            self._workspace_badge.setText(f"workspace: {wid}")
        except Exception:
            self._workspace_badge.setText("workspace: default")

    # ------------------------------------------------------------------ #
    # Filters
    # ------------------------------------------------------------------ #

    def _reset_filters(self) -> None:
        self._search.clear()
        for chk in self._lane_chips.values():
            chk.setChecked(True)
        for chk in self._severity_chips.values():
            chk.setChecked(True)
        self._window_combo.setCurrentText("24h")
        self._apply_filters()

    def _apply_filters(self) -> None:
        needle = (self._search.text() if hasattr(self, "_search") else "").strip().lower()
        active_lanes = {slug for slug, c in self._lane_chips.items() if c.isChecked()}
        active_sev = {slug for slug, c in self._severity_chips.items() if c.isChecked()}
        window = self._window_combo.currentText()
        cutoff = self._window_cutoff(window)

        filtered: list[dict[str, Any]] = []
        for item in self._all_events:
            lane = str(item.get("type", "") or "").lower()
            sev = str(item.get("severity", "") or "").lower() or "unknown"
            ts = _SwimlaneView._to_epoch(item.get("time"))
            if active_lanes and lane not in active_lanes:
                continue
            if active_sev and sev not in active_sev and sev != "unknown":
                continue
            if cutoff and ts and ts < cutoff:
                continue
            if needle:
                blob = " ".join([
                    str(item.get("title", "")),
                    str(item.get("type", "")),
                    str(item.get("severity", "")),
                    json.dumps(item.get("details", {}), default=str),
                ]).lower()
                if needle not in blob:
                    continue
            filtered.append(item)

        # Replay scrubber - if the slider is below 100%, drop events
        # whose timestamp falls past the cutoff so the operator can
        # walk through an incident step by step.
        if hasattr(self, "_scrubber") and self._scrubber.value() < 100 and filtered:
            times = [_SwimlaneView._to_epoch(e.get("time")) for e in filtered]
            times = [t for t in times if t > 0]
            if times:
                ts_lo, ts_hi = min(times), max(times)
                if ts_hi > ts_lo:
                    cutoff = ts_lo + (ts_hi - ts_lo) * (self._scrubber.value() / 100.0)
                    filtered = [
                        e for e in filtered
                        if _SwimlaneView._to_epoch(e.get("time")) <= cutoff
                    ]
        self._filtered_events = filtered
        self._render_table(filtered)
        # Push the bookmark identity set into the swimlane so the star
        # markers render alongside the dots.
        try:
            self._swimlane.set_bookmarks(self._bookmarks)
        except AttributeError:
            pass
        self._swimlane.set_events(filtered)
        self._update_kpis(filtered)
        self._update_mitre_strip(filtered)

    @staticmethod
    def _window_cutoff(window: str) -> float:
        now = time.time()
        return {
            "1h":  now - 3600,
            "24h": now - 86400,
            "7d":  now - 7 * 86400,
        }.get(window, 0.0)

    # ------------------------------------------------------------------ #
    # Table + KPI
    # ------------------------------------------------------------------ #

    def _render_table(self, items: list[dict[str, Any]]) -> None:
        table = self.app.timeline_table
        table.setSortingEnabled(False)
        table.clearSpans()
        table.setRowCount(len(items))
        for row, item in enumerate(items):
            details = item.get("details", {}) if isinstance(item.get("details"), dict) else {}
            mitre = details.get("mitre_mapping") or details.get("mitre_techniques") or ""
            if isinstance(mitre, list):
                mitre = ", ".join(str(t) for t in mitre[:4])
            cells = [
                self._format_time(item.get("time")),
                str(item.get("type", "")),
                str(item.get("severity", "")),
                str(item.get("title", "")),
                str(mitre or ""),
            ]
            for c, value in enumerate(cells):
                table_item = QTableWidgetItem(value)
                if c == 2:
                    table_item.setForeground(QBrush(QColor(_severity_colour(value))))
                if c == 0:
                    # Anchor the index into _filtered_events on the row.
                    # The table is sortable, so a visual row no longer
                    # maps to _filtered_events[row] after a header sort —
                    # selection/pivot would otherwise act on the wrong
                    # event. Qt keeps item data with the item across sorts.
                    table_item.setData(Qt.UserRole, row)
                table.setItem(row, c, table_item)
        table.setSortingEnabled(True)
        if not items:
            self.app._install_empty_table_placeholder(table, "No events match current filters - widen the window or clear filters.") if hasattr(self.app, "_install_empty_table_placeholder") else None

    def _update_kpis(self, items: list[dict[str, Any]]) -> None:
        total = len(items)
        crit_high = sum(1 for i in items if str(i.get("severity", "")).lower() in {"critical", "high"})
        active_lanes = {str(i.get("type", "")).lower() for i in items if i.get("type")}
        times = [
            _SwimlaneView._to_epoch(i.get("time")) for i in items
            if _SwimlaneView._to_epoch(i.get("time")) > 0
        ]
        span_text = "n/a"
        if times:
            span_sec = int(max(times) - min(times))
            if span_sec >= 86400:
                span_text = f"{span_sec // 86400}d"
            elif span_sec >= 3600:
                span_text = f"{span_sec // 3600}h"
            elif span_sec >= 60:
                span_text = f"{span_sec // 60}m"
            else:
                span_text = f"{span_sec}s"
        # The HTTP refresh path does not sort `items`, so items[0] is an
        # arbitrary (often oldest) event. Pick the chronologically newest
        # by parsed timestamp; fall back to items[0] only if no event has
        # a usable time.
        latest_ev = None
        if items:
            timed = [e for e in items if _SwimlaneView._to_epoch(e.get("time")) > 0]
            latest_ev = (
                max(timed, key=lambda e: _SwimlaneView._to_epoch(e.get("time")))
                if timed else items[0]
            )
        latest_event = latest_ev.get("title", "") if latest_ev else "—"

        self._kpis["total_events"].update(
            str(total),
            "ok" if total else "neutral",
            "post-filter",
        )
        self._kpis["critical_/_high"].update(
            str(crit_high),
            "ok" if crit_high == 0 else ("warn" if crit_high < 5 else "crit"),
            "elevated severity",
        )
        self._kpis["active_lanes"].update(
            str(len(active_lanes)),
            "ok" if active_lanes else "neutral",
            "/".join(sorted(active_lanes)) or "none",
        )
        self._kpis["time_span"].update(
            span_text,
            "neutral",
            "min → max event",
        )
        latest_short = latest_event if len(latest_event) <= 40 else latest_event[:38] + "…"
        self._kpis["latest"].update(
            latest_short or "—",
            "neutral",
            self._format_time(latest_ev.get("time")) if latest_ev else "no events",
        )

    # ------------------------------------------------------------------ #
    # Selection / interaction
    # ------------------------------------------------------------------ #

    def _data_index_for_visual_row(self, row: int) -> int:
        """Map a visual table row to its _filtered_events index via the
        Qt.UserRole anchor (sort-safe). Falls back to the raw row."""
        if row < 0:
            return -1
        anchor = self.app.timeline_table.item(row, 0)
        if anchor is not None:
            di = anchor.data(Qt.UserRole)
            if isinstance(di, int) and 0 <= di < len(self._filtered_events):
                return di
        return row if row < len(self._filtered_events) else -1

    def _visual_row_for_data_index(self, idx: int) -> int:
        table = self.app.timeline_table
        for r in range(table.rowCount()):
            anchor = table.item(r, 0)
            if anchor is not None and anchor.data(Qt.UserRole) == idx:
                return r
        return idx  # best effort if no anchor matched

    def show_selected_timeline(self) -> None:
        di = self._data_index_for_visual_row(self.app.timeline_table.currentRow())
        if di < 0 or di >= len(self._filtered_events):
            return
        event = self._filtered_events[di]
        self.app._show_json(self.app.timeline_detail, event)
        self._refresh_pivot_buttons(event)

    def _on_swimlane_event_clicked(self, idx: int) -> None:
        if idx < 0 or idx >= len(self._filtered_events):
            return
        # Sync the table selection so the table view and swimlane never
        # disagree about the highlighted event. After a header sort the
        # visual row != data index, so map back through the anchor.
        try:
            self.app.timeline_table.selectRow(self._visual_row_for_data_index(idx))
        except Exception:
            pass
        event = self._filtered_events[idx]
        self.app._show_json(self.app.timeline_detail, event)
        self._refresh_pivot_buttons(event)

    # ------------------------------------------------------------------ #
    # Pivot helpers — drill from a timeline event to Graph / Process
    # ------------------------------------------------------------------ #

    def _extract_pivot_targets(self, event: dict[str, Any]) -> dict[str, Any]:
        """Pull `pid` / `host` / `incident_id` out of an event's details
        (or top-level fields when present) so the pivot helpers know
        what to focus on. Returns whatever was findable."""
        details = event.get("details", {}) if isinstance(event.get("details"), dict) else {}
        pid = details.get("pid") or event.get("pid")
        host = details.get("host") or details.get("hostname") or event.get("host")
        incident_id = details.get("incident_id") or event.get("incident_id")
        try:
            pid_int = int(pid) if pid not in (None, "", 0) else None
        except (TypeError, ValueError):
            pid_int = None
        return {
            "pid": pid_int,
            "host": str(host or "").strip(),
            "incident_id": str(incident_id or "").strip(),
        }

    def _refresh_pivot_buttons(self, event: dict[str, Any]) -> None:
        """Enable / label the pivot buttons based on what's available."""
        targets = self._extract_pivot_targets(event)
        pid = targets.get("pid")
        host = targets.get("host")
        if hasattr(self, "_pivot_graph_btn"):
            self._pivot_graph_btn.setEnabled(bool(pid or host))
            label_bits = []
            if pid:
                label_bits.append(f"PID {pid}")
            if host:
                label_bits.append(host)
            suffix = " (" + " · ".join(label_bits) + ")" if label_bits else ""
            self._pivot_graph_btn.setText(f"Pivot to Graph{suffix}")
        if hasattr(self, "_pivot_process_btn"):
            self._pivot_process_btn.setEnabled(bool(pid))
            self._pivot_process_btn.setText(
                f"Pivot to Process{f' (PID {pid})' if pid else ''}"
            )

    def _selected_event(self) -> dict[str, Any] | None:
        di = self._data_index_for_visual_row(self.app.timeline_table.currentRow())
        if di < 0 or di >= len(self._filtered_events):
            return None
        return self._filtered_events[di]

    def _pivot_selected_to_graph(self) -> None:
        event = self._selected_event()
        if event is None:
            self.app.statusBar().showMessage("Select an event first.", 4000)
            return
        targets = self._extract_pivot_targets(event)
        pid = targets.get("pid")
        # Switch to the Graph tab and trigger a focused refresh on the
        # extracted PID (host pivot is best-effort - the existing
        # entity-map endpoint already partitions by host).
        try:
            for idx in range(self.app.tabs.count()):
                if self.app.tabs.tabText(idx) == "Graph":
                    self.app.tabs.setCurrentIndex(idx)
                    break
        except Exception:
            pass
        if pid is not None:
            self.app.refresh_entity_graph(pid)
        else:
            self.app.refresh_entity_graph()
        self.app.statusBar().showMessage(
            f"Pivoted to Graph (PID {pid})" if pid else "Pivoted to Graph", 4000,
        )

    def _pivot_selected_to_process(self) -> None:
        event = self._selected_event()
        if event is None:
            self.app.statusBar().showMessage("Select an event first.", 4000)
            return
        targets = self._extract_pivot_targets(event)
        pid = targets.get("pid")
        if pid is None:
            self.app.statusBar().showMessage("Selected event has no PID to focus.", 5000)
            return
        # Switch to Processes tab + populate the search/focus widget if
        # one exists; otherwise just surface the PID in the status bar.
        try:
            for idx in range(self.app.tabs.count()):
                if self.app.tabs.tabText(idx) == "Processes":
                    self.app.tabs.setCurrentIndex(idx)
                    break
        except Exception:
            pass
        if hasattr(self.app, "antivirus_target_path") and hasattr(self.app.antivirus_target_path, "setText"):
            # Best-effort: stick the PID into the search field as a hint.
            try:
                self.app.antivirus_target_path.setText(str(pid))
            except Exception:
                pass
        self.app.statusBar().showMessage(f"Pivoted to Processes (PID {pid})", 4000)

    def _cloned_swimlane(self) -> QWidget:
        """Build a duplicate swimlane for the Open Panel window."""
        clone = _SwimlaneView()
        clone.set_events(self._filtered_events)
        return clone

    @staticmethod
    def _format_time(raw: Any) -> str:
        ts = _SwimlaneView._to_epoch(raw)
        if ts <= 0:
            return str(raw or "")
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    # ------------------------------------------------------------------ #
    # Live SSE feed (/timeline/stream)
    # ------------------------------------------------------------------ #

    def _toggle_live_feed(self, enabled: bool) -> None:
        if enabled:
            self._start_live_feed()
        else:
            self._stop_live_feed()

    def _start_live_feed(self) -> None:
        from PySide6.QtCore import QObject, QThread, Signal
        # Lazy define the worker class so the thread plumbing only loads
        # if the operator actually enables the feed.
        controller = self
        outer_app = self.app

        class _LiveFeedWorker(QObject):
            event_received = Signal(dict)  # type: ignore[assignment]
            stream_failed = Signal(str)    # type: ignore[assignment]

            def __init__(self) -> None:
                super().__init__()
                self._stop = False

            def stop(self) -> None:
                self._stop = True

            def run(self) -> None:
                import requests as _requests
                from urllib.parse import urljoin, urlparse
                base = outer_app.base.text().strip() if hasattr(outer_app, "base") else ""
                url = urljoin((base or "http://127.0.0.1:8000").rstrip("/") + "/", "timeline/stream")
                api_key = outer_app.api_key.text().strip() if hasattr(outer_app, "api_key") else ""
                # The API key rides this connection for the lifetime of
                # the SSE stream — long-lived plaintext credentials on
                # the wire to anything other than loopback is a hard no.
                parsed = urlparse(url)
                host = (parsed.hostname or "").lower()
                if parsed.scheme.lower() == "http" and host not in {"127.0.0.1", "localhost", "::1"}:
                    self.stream_failed.emit(
                        "Refusing to stream timeline events over plaintext HTTP to a "
                        "non-loopback host. Switch the API base URL to https://."
                    )
                    return
                headers = {"X-API-Key": api_key, "Accept": "text/event-stream"}
                try:
                    with _requests.get(url, headers=headers, stream=True, timeout=(8, None)) as resp:
                        if not resp.ok:
                            self.stream_failed.emit(f"HTTP {resp.status_code}")
                            return
                        event_name = "message"
                        data_buf: list[str] = []
                        for raw in resp.iter_lines(decode_unicode=True):
                            if self._stop:
                                return
                            if raw is None:
                                continue
                            line = raw.rstrip("\r")
                            if not line:
                                # Dispatch the buffered event.
                                if data_buf:
                                    payload = "\n".join(data_buf)
                                    try:
                                        decoded = json.loads(payload)
                                    except Exception:
                                        decoded = {"raw": payload}
                                    self.event_received.emit({"event": event_name, "data": decoded})
                                event_name = "message"
                                data_buf = []
                                continue
                            if line.startswith(":"):
                                continue  # heartbeat / comment
                            if line.startswith("event:"):
                                event_name = line[len("event:"):].strip()
                            elif line.startswith("data:"):
                                data_buf.append(line[len("data:"):].lstrip())
                except Exception as exc:
                    self.stream_failed.emit(str(exc))

        self._live_thread = QThread(self.app)
        self._live_worker = _LiveFeedWorker()
        self._live_worker.moveToThread(self._live_thread)
        self._live_worker.event_received.connect(self._on_live_event)
        self._live_worker.stream_failed.connect(self._on_live_stream_failed)
        self._live_thread.started.connect(self._live_worker.run)
        self._live_thread.start()
        self.app.statusBar().showMessage("Live feed (SSE) connected.", 4000)

    def _stop_live_feed(self) -> None:
        worker = getattr(self, "_live_worker", None)
        thread = getattr(self, "_live_thread", None)
        if worker is not None:
            try:
                worker.stop()
            except Exception:
                pass
        if thread is not None:
            try:
                thread.quit()
                thread.wait(2000)
            except Exception:
                pass
        self._live_worker = None
        self._live_thread = None
        self.app.statusBar().showMessage("Live feed (SSE) disconnected.", 4000)

    def _on_live_event(self, envelope: dict[str, Any]) -> None:
        """Merge an SSE event into the in-memory dataset + re-render."""
        kind = envelope.get("event", "message")
        data = envelope.get("data")
        if kind == "init" and isinstance(data, list):
            # Initial snapshot from the server - replaces the local list.
            self._all_events = data
            self.app.timeline_items = data
            self._known_high_idents = {
                self._event_identity(e) for e in data
                if str(e.get("severity", "")).lower() in {"critical", "high"}
            }
            self._apply_filters()
            self._last_refresh.setText(
                f"Last refreshed (live): {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )
            return
        if kind == "delta" and isinstance(data, list):
            # Append-only delta - merge by identity to avoid duplicates.
            existing_ids = {self._event_identity(e) for e in self._all_events}
            new = [e for e in data if self._event_identity(e) not in existing_ids]
            if not new:
                return
            self._all_events.extend(new)
            # Re-sort newest first so the table head shows the latest.
            self._all_events.sort(
                key=lambda it: _SwimlaneView._to_epoch(it.get("time")),
                reverse=True,
            )
            self.app.timeline_items = self._all_events
            self._apply_filters()
            new_anomalies = {
                self._event_identity(e) for e in new
                if str(e.get("severity", "")).lower() in {"critical", "high"}
            }
            if new_anomalies and self._known_high_idents:
                self._flash_anomalies(new_anomalies)
            self._known_high_idents.update(new_anomalies)
            self._last_refresh.setText(
                f"Last refreshed (live): {time.strftime('%Y-%m-%d %H:%M:%S')}"
            )

    def _on_live_stream_failed(self, message: str) -> None:
        self.app.statusBar().showMessage(f"Live feed dropped: {message[:120]}", 7000)
        # Auto-toggle the checkbox back off so the operator sees the
        # disconnect and can re-enable when ready.
        if hasattr(self, "_live_feed"):
            try:
                self._live_feed.blockSignals(True)
                self._live_feed.setChecked(False)
            finally:
                self._live_feed.blockSignals(False)
        self._stop_live_feed()

    # ------------------------------------------------------------------ #
    # Colour-blind palette toggle
    # ------------------------------------------------------------------ #

    _CB_SETTINGS_KEY = "shadowlab/timeline/colour_blind"

    def _toggle_colour_blind(self, enabled: bool) -> None:
        _enable_colour_blind_palette(enabled)
        self._color_blind_mode = bool(enabled)
        # Persist preference + re-render everything that paints with
        # the palette (swimlane, legend, table severity column).
        try:
            from PySide6.QtCore import QSettings
            QSettings("ShadowLab", "Desktop").setValue(self._CB_SETTINGS_KEY, bool(enabled))
        except Exception:
            pass
        self._apply_filters()

    def _restore_colour_blind_pref(self) -> None:
        try:
            from PySide6.QtCore import QSettings
            stored = QSettings("ShadowLab", "Desktop").value(self._CB_SETTINGS_KEY, False, type=bool)
        except Exception:
            stored = False
        if stored:
            self._cb_toggle.setChecked(True)
            _enable_colour_blind_palette(True)
            self._color_blind_mode = True

    # ------------------------------------------------------------------ #
    # Anomaly detection / flash (refresh delta highlight)
    # ------------------------------------------------------------------ #

    @staticmethod
    def _event_identity(event: dict[str, Any]) -> tuple[str, str, str]:
        return (str(event.get("time", "")), str(event.get("type", "")), str(event.get("title", "")))

    def _detect_new_anomalies(self, items: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
        """Return identities of high/critical events that weren't in the
        previous refresh. Empty on the first ever refresh."""
        if not self._known_high_idents:
            return set()  # nothing to compare against - skip flashing
        current = {
            self._event_identity(e) for e in items
            if str(e.get("severity", "")).lower() in {"critical", "high"}
        }
        return current - self._known_high_idents

    def _flash_anomalies(self, idents: set[tuple[str, str, str]]) -> None:
        """Briefly recolour matching rows in the event table + show a
        status banner. The swimlane already paints high-severity dots
        in red; the table is where the text title lives, so flashing
        it draws the analyst's eye to the actual change.
        """
        if not idents:
            return
        table = self.app.timeline_table
        if table is None:
            return
        rows_to_flash: list[int] = []
        for r in range(table.rowCount()):
            di = self._data_index_for_visual_row(r)
            if di < 0 or di >= len(self._filtered_events):
                continue
            ev = self._filtered_events[di]
            if self._event_identity(ev) in idents:
                rows_to_flash.append(r)
        if not rows_to_flash:
            # The anomaly may be filtered out of the current view -
            # still surface a status message so the analyst knows it
            # exists and can clear the filter to see it.
            self.app.statusBar().showMessage(
                f"⚠ {len(idents)} new high-severity event(s) detected outside the active filter — Reset Filters to surface.",
                7000,
            )
            return

        # Snapshot original brushes so we can restore them.
        from PySide6.QtGui import QBrush, QColor
        flash_brush = QBrush(QColor("#f6e05e"))
        originals: list[tuple[int, list]] = []
        for r in rows_to_flash:
            row_originals = []
            for c in range(table.columnCount()):
                cell = table.item(r, c)
                if cell is None:
                    row_originals.append(None)
                    continue
                row_originals.append(cell.background())
                cell.setBackground(flash_brush)
            originals.append((r, row_originals))

        def _restore():
            for r, brushes in originals:
                for c, brush in enumerate(brushes):
                    cell = table.item(r, c)
                    if cell is not None and brush is not None:
                        cell.setBackground(brush)
        from PySide6.QtCore import QTimer as _QT
        _QT.singleShot(1200, _restore)
        self.app.statusBar().showMessage(
            f"⚠ {len(idents)} new high-severity event(s) detected.",
            7000,
        )
        self._record_audit("anomaly-flash", target=f"{len(idents)} events", payload_size=len(idents))

    # ------------------------------------------------------------------ #
    # P2 helpers - zoom / brush / bookmark / annotation / replay scrubber
    # ------------------------------------------------------------------ #

    def _on_brush_selected(self, t_min: float, t_max: float) -> None:
        """Swimlane reports a Shift-drag time-range; surface the range
        in the status bar + audit it. The swimlane has already zoomed
        itself into the brush window."""
        self.app.statusBar().showMessage(
            f"Brushed window: {time.strftime('%H:%M:%S', time.localtime(t_min))} "
            f"- {time.strftime('%H:%M:%S', time.localtime(t_max))}",
            6000,
        )
        self._record_audit(
            "brush-select",
            target=f"{int(t_min)}-{int(t_max)}",
            payload_size=len(self._filtered_events),
        )

    def _reset_zoom(self) -> None:
        try:
            self._swimlane.reset_zoom()
            self.app.statusBar().showMessage("Swimlane zoom reset.", 3000)
        except Exception:
            pass

    def _toggle_bookmark(self, idx: int) -> None:
        """Pin or unpin an event by its (time, type, title) identity."""
        if idx < 0 or idx >= len(self._filtered_events):
            return
        event = self._filtered_events[idx]
        ident = (str(event.get("time", "")), str(event.get("type", "")), str(event.get("title", "")))
        if ident in self._bookmarks:
            self._bookmarks.discard(ident)
            self._annotations.pop(ident, None)
            action = "bookmark-remove"
        else:
            self._bookmarks.add(ident)
            action = "bookmark-add"
        self._persist_bookmarks_to_disk()
        self._swimlane.set_bookmarks(self._bookmarks)
        self._record_audit(action, target=ident[2][:80], payload_size=1)
        self.app.statusBar().showMessage(
            f"{'★ Bookmarked' if action == 'bookmark-add' else 'Removed bookmark on'}: {ident[2][:60]}",
            5000,
        )

    def _annotate_event(self, idx: int) -> None:
        """Prompt the operator for a one-line investigation note on the event."""
        if idx < 0 or idx >= len(self._filtered_events):
            return
        from PySide6.QtWidgets import QInputDialog
        event = self._filtered_events[idx]
        ident = (str(event.get("time", "")), str(event.get("type", "")), str(event.get("title", "")))
        existing = self._annotations.get(ident, "")
        text, ok = QInputDialog.getMultiLineText(
            self.app,
            "Annotate event",
            f"Investigation note for `{ident[2][:80]}`:",
            existing,
        )
        if not ok:
            return
        text = (text or "").strip()
        if text:
            self._annotations[ident] = text
            self._bookmarks.add(ident)  # an annotated event is implicitly bookmarked
            self._swimlane.set_bookmarks(self._bookmarks)
        else:
            self._annotations.pop(ident, None)
        self._persist_bookmarks_to_disk()
        self._record_audit("annotate", target=ident[2][:80], payload_size=len(text))
        # Reflect the annotation into the detail pane so the operator
        # immediately sees what they just typed.
        try:
            from _panel_kit import redact_payload
        except ImportError:
            from desktop._panel_kit import redact_payload
        rendered = redact_payload({
            "event": event,
            "bookmarked": ident in self._bookmarks,
            "annotation": self._annotations.get(ident, ""),
        })
        self.app._show_json(self.app.timeline_detail, rendered)

    def _on_scrubber_changed(self, value: int) -> None:
        """Slider position → keep only events up to `percent` of the data span.

        100% = live (show everything). 0% = before any event. Useful for
        replaying an incident step by step during a briefing.
        """
        percent = max(0, min(100, int(value)))
        self._scrubber_label.setText(
            f"{percent}% {'(live)' if percent >= 100 else '(replay)'}"
        )
        # Re-apply filters so the new cutoff feeds into swimlane + KPI + table.
        self._apply_filters()

    def _load_bookmarks_from_disk(self) -> None:
        """Hydrate the in-memory set from `shadowlab_out/timeline-bookmarks.jsonl`."""
        try:
            from pathlib import Path as _Path
            log_path = _Path.cwd() / "shadowlab_out" / "timeline-bookmarks.jsonl"
            if not log_path.exists():
                return
            with log_path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    ident = (
                        str(rec.get("time", "")),
                        str(rec.get("type", "")),
                        str(rec.get("title", "")),
                    )
                    self._bookmarks.add(ident)
                    note = rec.get("annotation")
                    if note:
                        self._annotations[ident] = str(note)
        except Exception:
            return

    def _persist_bookmarks_to_disk(self) -> None:
        try:
            from pathlib import Path as _Path
            log_path = _Path.cwd() / "shadowlab_out" / "timeline-bookmarks.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("w", encoding="utf-8") as handle:
                for ident in self._bookmarks:
                    rec = {
                        "time": ident[0],
                        "type": ident[1],
                        "title": ident[2],
                        "annotation": self._annotations.get(ident, ""),
                    }
                    handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            return

    # ------------------------------------------------------------------ #
    # P1 forensic helpers - snapshot, export, audit
    # ------------------------------------------------------------------ #

    def _reject_unsafe_export_path(self, path: str) -> bool:
        """Return True (and surface an error) if `path` resolves into the
        Windows tree, Program Files, or a Startup folder. Resolving the
        real path first defeats `..` traversal and 8.3 short names.
        Mirrors the File-Analysis export hardening."""
        import os
        from pathlib import Path as _Path
        try:
            dest = str(_Path(path).resolve()).lower().replace("/", "\\")
        except Exception:
            dest = str(path).lower().replace("/", "\\")
        system_root = str(
            _Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()
        ).lower().replace("/", "\\")
        blocked = [
            system_root + "\\",
            os.environ.get("ProgramFiles", r"C:\Program Files").lower().replace("/", "\\") + "\\",
            os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower().replace("/", "\\") + "\\",
        ]
        if any(dest.startswith(p) for p in blocked) or "\\start menu\\programs\\startup\\" in dest:
            self.app._show_error(
                self.app.timeline_detail,
                "Export destination blocked",
                Exception(f"Refusing to write into a Windows system / Startup folder: {path}"),
            )
            self._record_audit("export-blocked", target=str(path), payload_size=0)
            return True
        return False

    def _save_snapshot(self) -> None:
        """Persist the current filtered timeline + filter state to disk.

        Filename suggestion includes a timestamp so back-to-back saves
        don't overwrite. The payload is redacted via `_panel_kit.
        redact_payload` before write so secrets never reach the JSON file.
        """
        if not self._filtered_events:
            self.app.statusBar().showMessage("Refresh first - nothing to snapshot.", 4000)
            return
        try:
            from _panel_kit import redact_payload
        except ImportError:
            from desktop._panel_kit import redact_payload
        from PySide6.QtWidgets import QFileDialog
        default = f"shadowlab_out/timeline_snapshot_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Save Timeline Snapshot", default, "JSON (*.json)",
        )
        if not path:
            return
        if self._reject_unsafe_export_path(path):
            return
        payload = {
            "saved_at": time.time(),
            "saved_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "window": self._window_combo.currentText() if hasattr(self, "_window_combo") else "",
            "search": self._search.text() if hasattr(self, "_search") else "",
            "active_lanes": [s for s, c in self._lane_chips.items() if c.isChecked()],
            "active_severities": [s for s, c in self._severity_chips.items() if c.isChecked()],
            "event_count": len(self._filtered_events),
            "events": redact_payload(self._filtered_events),
        }
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False, default=str)
            self.app.statusBar().showMessage(
                f"Snapshot saved: {path} ({len(self._filtered_events)} events)", 6000,
            )
            self._record_audit("snapshot-save", target=path, payload_size=len(self._filtered_events))
        except Exception as exc:
            self.app._show_error(self.app.timeline_detail, "Snapshot save failed", exc)

    def _diff_snapshot(self) -> None:
        """Load a snapshot file and report added / removed events vs the
        live filtered view. Output renders into the Event Detail pane."""
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getOpenFileName(
            self.app, "Open Timeline Snapshot", "shadowlab_out/", "JSON (*.json)",
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as handle:
                snapshot = json.load(handle)
        except Exception as exc:
            self.app._show_error(self.app.timeline_detail, "Snapshot load failed", exc)
            return
        snap_events = snapshot.get("events", []) if isinstance(snapshot, dict) else []
        # Use (time, type, title) as a coarse identity tuple - the
        # combination is stable across refreshes for the same underlying
        # event even when the server reorders the list.
        def _ident(ev: dict[str, Any]) -> tuple[str, str, str]:
            return (
                str(ev.get("time", "")),
                str(ev.get("type", "")),
                str(ev.get("title", "")),
            )
        live_ids = {_ident(e) for e in self._filtered_events}
        snap_ids = {_ident(e) for e in snap_events}
        added = sorted(live_ids - snap_ids)
        removed = sorted(snap_ids - live_ids)

        lines: list[str] = [
            "═══ Timeline Diff ═══",
            f"Snapshot file:  {path}",
            f"Snapshot saved: {snapshot.get('saved_at_iso', '?')} "
            f"({snapshot.get('event_count', 0)} events)",
            f"Live view:      {len(self._filtered_events)} events "
            f"(window={self._window_combo.currentText() if hasattr(self, '_window_combo') else ''})",
            "",
            f"Added   ({len(added):3d}):",
        ]
        for ident in added[:25]:
            lines.append(f"  + [{ident[1]}] {ident[2][:80]}  @ {ident[0]}")
        if len(added) > 25:
            lines.append(f"  … (+{len(added) - 25} more)")
        lines.append("")
        lines.append(f"Removed ({len(removed):3d}):")
        for ident in removed[:25]:
            lines.append(f"  - [{ident[1]}] {ident[2][:80]}  @ {ident[0]}")
        if len(removed) > 25:
            lines.append(f"  … (+{len(removed) - 25} more)")
        self.app.timeline_detail.setPlainText("\n".join(lines))
        self.app.statusBar().showMessage(
            f"Diff: +{len(added)} / -{len(removed)} events vs snapshot", 6000,
        )
        self._record_audit(
            "snapshot-diff",
            target=path,
            payload_size=len(self._filtered_events),
            extra={"added": len(added), "removed": len(removed)},
        )

    def _export_png(self) -> None:
        """Render the swimlane scene to a PNG file for case attachments."""
        from PySide6.QtCore import QSize
        from PySide6.QtGui import QImage, QPainter as _QPainter
        from PySide6.QtWidgets import QFileDialog
        default = f"shadowlab_out/timeline_{time.strftime('%Y%m%d_%H%M%S')}.png"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Export Timeline PNG", default, "PNG (*.png)",
        )
        if not path:
            return
        if self._reject_unsafe_export_path(path):
            return
        try:
            scene = self._swimlane.scene()
            rect = scene.sceneRect()
            if rect.isEmpty():
                self.app.statusBar().showMessage("Swimlane is empty - nothing to export.", 4000)
                return
            image = QImage(QSize(int(rect.width()), int(rect.height())), QImage.Format_ARGB32)
            image.fill(QColor("#0a1018"))
            painter = _QPainter(image)
            painter.setRenderHint(_QPainter.Antialiasing, True)
            scene.render(painter)
            painter.end()
            image.save(path)
            self.app.statusBar().showMessage(f"Swimlane exported: {path}", 6000)
            self._record_audit("export-png", target=path, payload_size=len(self._filtered_events))
        except Exception as exc:
            self.app._show_error(self.app.timeline_detail, "PNG export failed", exc)

    def _export_json(self) -> None:
        """Dump the active event list (filtered + redacted) as a JSON bundle."""
        if not self._filtered_events:
            self.app.statusBar().showMessage("Refresh first - nothing to export.", 4000)
            return
        try:
            from _panel_kit import redact_payload
        except ImportError:
            from desktop._panel_kit import redact_payload
        from PySide6.QtWidgets import QFileDialog
        default = f"shadowlab_out/timeline_events_{time.strftime('%Y%m%d_%H%M%S')}.json"
        path, _ = QFileDialog.getSaveFileName(
            self.app, "Export Timeline JSON", default, "JSON (*.json)",
        )
        if not path:
            return
        if self._reject_unsafe_export_path(path):
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "exported_at": time.time(),
                        "exported_at_iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "window": self._window_combo.currentText() if hasattr(self, "_window_combo") else "",
                        "events": redact_payload(self._filtered_events),
                    },
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    default=str,
                )
            self.app.statusBar().showMessage(
                f"Exported {len(self._filtered_events)} events to {path}", 6000,
            )
            self._record_audit("export-json", target=path, payload_size=len(self._filtered_events))
        except Exception as exc:
            self.app._show_error(self.app.timeline_detail, "JSON export failed", exc)

    def _record_audit(
        self,
        action: str,
        *,
        target: str,
        payload_size: int,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Best-effort audit chain emission for forensic timeline actions.

        Falls back to a local JSON-lines log under shadowlab_out/ when
        the backend audit endpoint isn't reachable, so the chain-of-
        custody trail never goes dark during an investigation.
        """
        record = {
            "ts": time.time(),
            "iso": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "category": "timeline",
            "action": action,
            "target": target,
            "payload_size": int(payload_size or 0),
            "actor": "",
            "workspace": "",
        }
        try:
            ctx = getattr(self.app, "current_auth_context", {}) or {}
            record["actor"] = str(ctx.get("actor") or ctx.get("subject") or "")
            record["workspace"] = str(ctx.get("workspace_id") or "default")
        except Exception:
            pass
        if extra:
            record.update(extra)
        # Server-side mirror (best effort) so SOC managers see the
        # action in the central audit dashboard.
        try:
            self.app._post(
                "/audit/desktop",
                json={"source": "desktop:timeline", "entry": record},
                timeout=8,
                raise_for_status=False,
            )
        except Exception:
            pass
        # Local fallback - always succeeds (or silently skipped).
        try:
            from pathlib import Path as _Path
            log_path = _Path.cwd() / "shadowlab_out" / "timeline-audit-log.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            return

    @staticmethod
    def _legend_html() -> str:
        """Compact colour-key for the swimlane palette."""
        def dot(colour: str, label: str) -> str:
            return (
                f"<span style='color:{colour};font-size:14px;'>●</span> "
                f"<span style='color:#cbd5e0;'>{label}</span>"
            )
        lane_chips = "  ·  ".join(dot(_lane_colour(lane), lane.title()) for lane in LANES)
        sev_chips = "  ·  ".join(
            dot(_severity_colour(s), s.title()) for s in ("critical", "high", "medium", "low", "info")
        )
        return (
            "<b style='color:#7a8694;letter-spacing:1px;'>LANES:</b>  " + lane_chips +
            "  &nbsp;&nbsp;&nbsp;  <b style='color:#7a8694;letter-spacing:1px;'>SEVERITY:</b>  " + sev_chips +
            "  &nbsp;&nbsp;&nbsp;  <i style='color:#7a8694;'>dot size = cluster count, click = open detail / pivot</i>"
        )

    # ------------------------------------------------------------------ #
    # MITRE strip rendering
    # ------------------------------------------------------------------ #

    def _update_mitre_strip(self, items: list[dict[str, Any]]) -> None:
        """Aggregate MITRE T-id frequencies across the filtered events
        and render the top 8 as inline chips.

        Both the legacy `mitre_mapping` (string) and the newer
        `mitre_techniques` (list) shapes are accepted - the server-side
        builders use both depending on the source endpoint.
        """
        if not hasattr(self, "_mitre_strip"):
            return
        from collections import Counter
        counter: Counter[str] = Counter()
        for ev in items:
            details = ev.get("details", {}) if isinstance(ev.get("details"), dict) else {}
            raw = details.get("mitre_mapping") or details.get("mitre_techniques") or ev.get("mitre_techniques") or ""
            if isinstance(raw, str):
                for tok in raw.replace(",", " ").split():
                    tok = tok.strip()
                    if tok.upper().startswith("T") and any(ch.isdigit() for ch in tok):
                        counter[tok.upper()] += 1
            elif isinstance(raw, list):
                for tok in raw:
                    tok = str(tok).strip()
                    if tok:
                        counter[tok.upper()] += 1
        top = counter.most_common(8)
        if not top:
            self._mitre_strip.setText(
                "no ATT&CK techniques surfaced in the active filter view"
            )
            self._mitre_strip.setStyleSheet(
                "color:#7a8694; font-size:11px; font-style:italic;"
            )
            return
        # Inline HTML chips - one per technique with frequency count.
        chip_html = "".join(
            f"<span style='background:#1f2933;color:#cbd5e0;padding:2px 8px;border-radius:8px;"
            f"font-size:11px;font-weight:600;margin-right:4px;'>{html.escape(tid)} · {count}</span>"
            for tid, count in top
        )
        self._mitre_strip.setText(chip_html)
        self._mitre_strip.setStyleSheet("color:#cbd5e0; font-size:11px;")
        self._mitre_strip.setTextFormat(Qt.RichText)
