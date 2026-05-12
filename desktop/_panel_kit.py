"""Shared product-grade UI primitives reused across desktop tabs.

Each tab in ShadowLab had grown its own ad-hoc dashboard scaffolding -
empty tables, raw JSON dumps, no busy state, inconsistent colour
language. This module factors out the pieces every tab needs:

* `KpiChip` - rounded, tone-coded indicator card.
* `redact_payload` / `redact_url_for_display` - secret scrubbing before
  any response lands in an on-screen Detail pane.
* `BusyController` - flips a list of buttons disabled + busy cursor
  + status-bar message in unison.
* `SudoModeChip` - 5-minute MFA grace-window indicator that ticks down
  in real time and can gate destructive actions.
* `install_empty_table_placeholder` - italic-grey "no data" row.
* `compliance_strip_html` - single-line ✓/✗ posture line.
"""
from __future__ import annotations

import json
import re
import time
from typing import Callable, Iterable

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


# ----- Secret redaction -----------------------------------------------------

SECRET_FIELDS: frozenset[str] = frozenset({
    "secret", "secret_id", "secret_value", "new_secret", "raw_secret",
    "token", "access_token", "refresh_token", "bearer", "api_key",
    "client_secret", "shared_key", "authorization", "password",
    "signing_key", "signing_secret", "private_key", "credential",
})
_URL_TOKEN_RE = re.compile(
    r"(https?://[^/\s]+/[^/\s]+/[^/\s]+/)([^\s\"']+)"
)


def redact_payload(obj):
    """Recursive deep-copy that masks secret-bearing keys and webhook tokens."""
    if isinstance(obj, dict):
        out: dict = {}
        for key, value in obj.items():
            if str(key).lower() in SECRET_FIELDS and value not in (None, "", 0):
                out[key] = "***redacted***"
            else:
                out[key] = redact_payload(value)
        return out
    if isinstance(obj, list):
        return [redact_payload(item) for item in obj]
    if isinstance(obj, str):
        return _URL_TOKEN_RE.sub(r"\1***redacted***", obj)
    return obj


def redact_url_for_display(url: str) -> str:
    """Show scheme://host + a hint of the path, mask the token."""
    if not url:
        return "<no destination configured>"
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path[:24]
        return f"{parsed.scheme}://{host}/***redacted***"
    except Exception:
        return url[:24] + "..."


# ----- KPI palette & widget ------------------------------------------------

KPI_OK = "#1b4332"
KPI_WARN = "#5c4400"
KPI_CRIT = "#5f1d1d"
KPI_NEUTRAL = "#1f2933"
KPI_TEXT_OK = "#9ae6b4"
KPI_TEXT_WARN = "#f6e05e"
KPI_TEXT_CRIT = "#feb2b2"
KPI_TEXT_NEUTRAL = "#cbd5e0"

_KPI_TONE_PALETTE = {
    "ok": (KPI_OK, KPI_TEXT_OK),
    "warn": (KPI_WARN, KPI_TEXT_WARN),
    "crit": (KPI_CRIT, KPI_TEXT_CRIT),
    "neutral": (KPI_NEUTRAL, KPI_TEXT_NEUTRAL),
}


def tone_for_count(value: int, *, warn_at: int = 1, crit_at: int = 5) -> str:
    """Map an integer to one of {ok, warn, crit} using inclusive thresholds."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "neutral"
    if n <= 0:
        return "ok"
    if n < crit_at:
        return "warn" if n >= warn_at else "ok"
    return "crit"


class _SparklineWidget(QWidget):
    """Tiny inline trend strip — last ~30 numeric samples, no QtCharts dep."""

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


class KpiChip(QFrame):
    """Compact KPI chip — label / big value / hint / sparkline, tone-coded.

    Empty-state treatment: washed-out value ('·') + italic 'awaiting
    refresh' hint + sparkline layout slot collapsed. First call to
    `update()` flips the chip into its data state — bright value
    colour, regular hint typography, sparkline revealed.
    """

    def __init__(self, label: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("kpiChip")
        self.setFrameShape(QFrame.NoFrame)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        # No `card='true'` border on individual chips — the strip itself
        # is the visual unit. Each chip is plain padding + labels so the
        # five tiles read as one strip rather than five mini-cards.
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
        # Collapse the sparkline entirely until we have data; the chip is
        # now SOC-Overview-sized so we keep the sparkline as a stretch
        # surface only after `update()` fires.
        self._spark.setVisible(False)
        self._spark.setMaximumHeight(0)
        outer.addWidget(self._label)
        outer.addWidget(self._value)
        outer.addWidget(self._hint)
        outer.addWidget(self._spark)
        self._on_click: Callable[[], None] | None = None
        self._has_data = False
        self.set_tone("neutral")

    def set_click_handler(self, handler: Callable[[], None]) -> None:
        self._on_click = handler
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Click to drill into the related panel")

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._on_click is not None:
            try:
                self._on_click()
            except Exception:
                pass
        super().mouseReleaseEvent(event)

    def set_tone(self, tone: str) -> None:
        # Background + border come from the global `card='true'` QSS so
        # every chip shares one chrome palette. Only the value label
        # colour shifts with tone, mirroring SOC Overview tiles where
        # the big number carries the severity / confidence signal.
        _, fg = _KPI_TONE_PALETTE.get(tone, _KPI_TONE_PALETTE["neutral"])
        value_colour = fg if self._has_data else "#5a6675"
        self._value.setStyleSheet(f"color:{value_colour};font-size:18px;font-weight:800;")

    def update(self, value: str, tone: str = "neutral", hint: str = "") -> None:
        self._has_data = True
        self._value.setText(str(value))
        self._hint.setText(hint or "")
        # In the data state the hint uses the same #c8d8ea readable
        # contrast SOC Overview tiles do — the italic 'awaiting refresh'
        # treatment is reserved for the empty state.
        self._hint.setStyleSheet("color:#c8d8ea;font-size:10px;")
        self.set_tone(tone)
        try:
            numeric = float(str(value).replace(",", "").split()[0])
            self._spark.push(numeric, tone)
            # Grow the chip just enough to host the sparkline strip
            # without breaking the row layout. The min/max bounds are
            # released here because the chip now owns its own height.
            self._spark.setMaximumHeight(14)
            self._spark.setVisible(True)
            self.setMinimumHeight(64)
            self.setMaximumHeight(92)
        except (TypeError, ValueError, IndexError):
            pass


def build_kpi_strip(parent: QWidget, labels: Iterable[str]) -> tuple[QWidget, dict[str, KpiChip]]:
    """Build a horizontal strip of equal-width KPI chips.

    Returns the container widget and a `{key: chip}` map keyed by the
    snake_case version of each label, so callers can write
    `chips["dead_letters"].update(...)` without recomputing slugs.
    """
    strip = QWidget(parent)
    layout = QHBoxLayout(strip)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(8)
    chips: dict[str, KpiChip] = {}
    for label in labels:
        key = label.lower().replace(" ", "_").replace("-", "_")
        chip = KpiChip(label)
        chips[key] = chip
        layout.addWidget(chip, 1)
    return strip, chips


# ----- Busy controller -----------------------------------------------------


class BusyController:
    """Toggles a set of buttons + the parent window cursor in unison.

    Each tab keeps a list of every mutating-action button and hands it
    to a controller. `set_busy(True, "Working…")` disables every one
    plus flips the cursor; `set_busy(False)` restores them.
    """

    def __init__(self, parent_window: QWidget, buttons: list[QPushButton] | None = None) -> None:
        self._parent = parent_window
        self._buttons: list[QPushButton] = list(buttons or [])
        self._message: str = ""

    def track(self, button: QPushButton) -> QPushButton:
        self._buttons.append(button)
        return button

    def track_many(self, buttons: Iterable[QPushButton]) -> None:
        self._buttons.extend(list(buttons))

    def set_busy(self, busy: bool, message: str = "") -> None:
        for btn in self._buttons:
            try:
                btn.setEnabled(not busy)
            except Exception:
                continue
        if busy:
            self._parent.setCursor(Qt.WaitCursor)
            self._message = message or "Working…"
            try:
                self._parent.statusBar().showMessage(self._message)
            except Exception:
                pass
        else:
            self._parent.unsetCursor()
            if self._message:
                try:
                    self._parent.statusBar().clearMessage()
                except Exception:
                    pass
            self._message = ""


# ----- Sudo Mode chip ------------------------------------------------------


class SudoModeChip(QLabel):
    """Real-time MFA-grace countdown chip.

    Default window is 5 minutes - mirrors `api/security.SUDO_WINDOW`.
    Tabs call `mark_verified()` after a successful authenticated mutation
    to bump the deadline, and `required()` / `ensure_or_warn()` before
    destructive actions to gate them.
    """

    WINDOW_SECONDS = 5 * 60

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__("🔒 Sudo: re-verify required", parent)
        self.setStyleSheet(
            "color:#feb2b2; background:#5f1d1d; padding:4px 10px; border-radius:8px; font-size:12px;"
        )
        self.setToolTip(
            "Destructive actions require a fresh MFA verification within the "
            "last 5 minutes. POST /auth/mfa/verify to refresh."
        )
        self._expires_at: float = 0.0
        self._timer = QTimer(parent or self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self._tick()

    def mark_verified(self) -> None:
        self._expires_at = time.time() + self.WINDOW_SECONDS
        self._tick()

    def remaining_seconds(self) -> int:
        return max(0, int(self._expires_at - time.time()))

    def required(self) -> bool:
        return self.remaining_seconds() == 0

    def ensure_or_warn(self, action_label: str) -> bool:
        if not self.required():
            return True
        warn = QMessageBox(self.parent() if isinstance(self.parent(), QWidget) else None)
        warn.setWindowTitle("Re-verify recommended")
        warn.setText(f"Sudo window expired - proceed with {action_label}?")
        warn.setInformativeText(
            "It has been more than 5 minutes since the last verified action on this "
            "session. Stepping away and coming back creates a window for an "
            "unattended workstation. Click OK only if you intend to proceed."
        )
        warn.setIcon(QMessageBox.Warning)
        warn.setStandardButtons(QMessageBox.Cancel | QMessageBox.Ok)
        return warn.exec() == QMessageBox.Ok

    def _tick(self) -> None:
        remaining = self.remaining_seconds()
        if remaining <= 0:
            self.setText("🔒 Sudo: re-verify required")
            self.setStyleSheet(
                "color:#feb2b2; background:#5f1d1d; padding:4px 10px; border-radius:8px; font-size:12px;"
            )
        else:
            mins, secs = divmod(remaining, 60)
            self.setText(f"🔓 Sudo active · {mins}m {secs:02d}s")
            self.setStyleSheet(
                "color:#9ae6b4; background:#1b4332; padding:4px 10px; border-radius:8px; font-size:12px;"
            )


# ----- Empty-state placeholder --------------------------------------------


def install_empty_table_placeholder(table: QTableWidget, message: str) -> None:
    """Render a single italic-grey placeholder row across all columns."""
    table.setRowCount(1)
    item = QTableWidgetItem(message)
    item.setForeground(QBrush(QColor("#9aa5b1")))
    font = QFont()
    font.setItalic(True)
    item.setFont(font)
    item.setFlags(item.flags() & ~Qt.ItemIsEditable & ~Qt.ItemIsSelectable)
    table.setItem(0, 0, item)
    if table.columnCount() > 1:
        table.setSpan(0, 0, 1, table.columnCount())


# ----- Compliance strip ---------------------------------------------------


def compliance_chip_html(ok: bool, label: str) -> str:
    colour = "#9ae6b4" if ok else "#feb2b2"
    mark = "✓" if ok else "✗"
    return f"<span style='color:{colour}'>{mark} {label}</span>"


def relative_time(value) -> str:
    """`12m ago` / `3h ago` / `2d ago` formatter that accepts epoch or ISO."""
    import datetime as _dt
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
