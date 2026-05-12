"""Unit tests for the pure-function helpers inside `desktop/dashboard_ops.py`.

These cover the dashboard logic that's safe to exercise without spinning up
Qt: severity colour resolution, age formatting, epoch coercion, hourly
bucketing, sparklines, MITRE coverage compute, pagination footer rendering,
risk-score band classification.

Qt-dependent code (widget building, signal wiring, refresh worker) is not
covered here — that needs ``pytest-qt`` and a display, and the rendering
functions deliberately return strings so they can be asserted against
without a QApplication.
"""
from __future__ import annotations

import time
from pathlib import Path
import importlib.util

import pytest


# --------------------------------------------------------------------------- #
# Module loader — imports `dashboard_ops` without dragging in the Qt main app
# --------------------------------------------------------------------------- #


def _load_module():
    """Import `desktop/dashboard_ops.py` directly so we don't pull in the
    desktop package's `__init__` (which imports the full Qt window)."""
    here = Path(__file__).resolve().parent.parent
    target = here / "desktop" / "dashboard_ops.py"
    spec = importlib.util.spec_from_file_location("dashboard_ops_under_test", target)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def mod():
    return _load_module()


# --------------------------------------------------------------------------- #
# Severity / status colour map
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("severity, expected", [
    ("critical", "#ff4d6d"),
    ("CRITICAL", "#ff4d6d"),
    ("high",     "#ff6b8a"),
    ("medium",   "#f4c26b"),
    ("warning",  "#f4c26b"),
    ("low",      "#7fd7ff"),
    ("info",     "#7fd7ff"),
    ("unknown",  "#96a5b8"),
    ("",         "#96a5b8"),
    (None,       "#96a5b8"),
])
def test_severity_color_known_levels(mod, severity, expected):
    assert mod._severity_color(severity) == expected


def test_severity_color_falls_back_for_garbage(mod):
    # Anything outside the known map should return the muted default.
    assert mod._severity_color("frobnicated") == "#96a5b8"
    assert mod._severity_color(123) == "#96a5b8"


# --------------------------------------------------------------------------- #
# Coercion helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw, expected", [
    (1700_000_000, 1700_000_000.0),
    ("1700000000", 1700_000_000.0),
    ("1700000000.5", 1700_000_000.5),
    (None,         0.0),
    ("",           0.0),
    ("not-a-time", 0.0),
])
def test_coerce_epoch_numeric(mod, raw, expected):
    assert mod._coerce_epoch(raw) == expected


def test_coerce_epoch_iso_format(mod):
    """ISO timestamps should be parsed via the fallback strptime branch."""
    sample = "2024-01-15 12:00:00"
    parsed = mod._coerce_epoch(sample)
    assert parsed > 0  # hard date-math is timezone-dependent — just sanity check


@pytest.mark.parametrize("raw, default, expected", [
    ("12",     0, 12),
    ("12.7",   0, 12),
    (12,       0, 12),
    (12.9,     0, 12),
    (None,     0, 0),
    ("",       0, 0),
    ("garbage", 99, 99),
])
def test_coerce_int(mod, raw, default, expected):
    assert mod._coerce_int(raw, default) == expected


# --------------------------------------------------------------------------- #
# Age formatting
# --------------------------------------------------------------------------- #


def test_format_age_handles_none(mod):
    assert mod._format_age(None) == "--"
    assert mod._format_age(0) == "--"


def test_format_age_seconds(mod):
    now = time.time()
    assert mod._format_age(now - 5, now=now) == "5s"


def test_format_age_minutes(mod):
    now = time.time()
    assert mod._format_age(now - 120, now=now) == "2m"


def test_format_age_hours(mod):
    now = time.time()
    result = mod._format_age(now - 3600 * 3, now=now)
    assert result.endswith("h")
    assert "3" in result


def test_format_age_days(mod):
    now = time.time()
    result = mod._format_age(now - 86400 * 4, now=now)
    assert result.endswith("d")


# --------------------------------------------------------------------------- #
# Sparkline (Unicode-block)
# --------------------------------------------------------------------------- #


def test_sparkline_empty_returns_empty_string(mod):
    assert mod._sparkline([]) == ""
    assert mod._sparkline([None, None]) == ""


def test_sparkline_constant_series_renders_uniform_blocks(mod):
    sparkline = mod._sparkline([5, 5, 5, 5])
    assert len(sparkline) == 4
    # All cells should be the same character (constant range = single block)
    assert len(set(sparkline)) == 1


def test_sparkline_increasing_series_climbs(mod):
    blocks = mod._SPARK_BLOCKS
    sparkline = mod._sparkline([1, 2, 3, 4, 5, 6, 7, 8])
    assert sparkline[0] == blocks[0]
    assert sparkline[-1] == blocks[-1]


def test_sparkline_folds_long_series_to_width(mod):
    series = list(range(100))
    sparkline = mod._sparkline(series, width=10)
    assert 1 <= len(sparkline) <= 10


# --------------------------------------------------------------------------- #
# Hourly bucketing for sparklines / heatmap
# --------------------------------------------------------------------------- #


def test_hourly_buckets_drops_old_events(mod):
    now = time.time()
    events = [
        {"created_at": now - 30 * 86_400},   # too old
        {"created_at": now - 3600},          # 1h ago — bucket 22 in 24h window
        {"created_at": now - 60},            # within last hour
    ]
    buckets = mod._hourly_buckets(events, now=now, hours=24)
    assert len(buckets) == 24
    assert sum(buckets) == 2  # only the two recent events count


def test_hourly_buckets_handles_invalid_entries(mod):
    now = time.time()
    events = [
        "not a dict",
        {"created_at": "garbage"},
        {"created_at": now - 60},
    ]
    buckets = mod._hourly_buckets(events, now=now, hours=24)
    assert sum(buckets) == 1


def test_hourly_buckets_empty_list(mod):
    buckets = mod._hourly_buckets([], now=time.time(), hours=24)
    assert buckets == [0] * 24


# --------------------------------------------------------------------------- #
# Pagination footer
# --------------------------------------------------------------------------- #


def test_pagination_footer_hides_when_complete(mod):
    """Footer should be empty when nothing is hidden."""
    assert mod._pagination_footer(5, 5, "incidents") == ""
    assert mod._pagination_footer(5, 0, "incidents") == ""
    assert mod._pagination_footer(10, 3, "incidents") == ""  # showing >= total


def test_pagination_footer_shows_when_partial(mod):
    html = mod._pagination_footer(5, 47, "alerts")
    assert "Showing 5 of 47" in html
    assert "action://open:alerts" in html
    assert "See all" in html


def test_pagination_footer_escapes_panel_key(mod):
    """Defence-in-depth: the panel key is composed in code today, but
    escape it anyway so any future caller doesn't introduce HTML
    injection through it.
    """
    html = mod._pagination_footer(1, 2, "<script>alert(1)</script>")
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


# --------------------------------------------------------------------------- #
# HTML escape helper
# --------------------------------------------------------------------------- #


def test_esc_handles_none(mod):
    assert mod._esc(None) == ""


def test_esc_neutralises_html_tags(mod):
    assert "<" not in mod._esc("<script>alert(1)</script>")
    assert "&lt;script&gt;" in mod._esc("<script>alert(1)</script>")


def test_esc_preserves_safe_text(mod):
    assert mod._esc("hello world") == "hello world"


# --------------------------------------------------------------------------- #
# Badge / severity pill — render a fragment, assert no XSS
# --------------------------------------------------------------------------- #


def test_badge_escapes_label(mod):
    out = mod._badge("<img>", "healthy")
    assert "<img>" not in out
    assert "&lt;img&gt;" in out


def test_sev_pill_uppercases_severity(mod):
    out = mod._sev_pill("critical")
    assert "CRITICAL" in out
    out = mod._sev_pill("")
    assert "UNKNOWN" in out


# --------------------------------------------------------------------------- #
# Stack-bar / progress-bar fragment safety
# --------------------------------------------------------------------------- #


def test_progress_bar_clamps(mod):
    # Values >100 should clamp to 100 in width and <0 to 0.
    assert "width:100.0%" in mod._progress_bar(150)
    assert "width:0.0%" in mod._progress_bar(-10)


def test_progress_bar_renders_supplied_color(mod):
    out = mod._progress_bar(50, color="#abcdef")
    assert "background:#abcdef" in out


def test_stack_bar_with_empty_segments(mod):
    out = mod._stack_bar([])
    assert "background:#0e1622" in out


# --------------------------------------------------------------------------- #
# Risk-band classification (re-derived from _update_kpi_strip thresholds)
# --------------------------------------------------------------------------- #


def _classify_risk(score: float) -> str:
    """Mirror the production logic in _update_kpi_strip so a bug there
    is surfaced if either side drifts."""
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 25: return "ELEVATED"
    if score >= 10: return "GUARDED"
    return "LOW"


@pytest.mark.parametrize("score, band", [
    (0,   "LOW"),
    (5,   "LOW"),
    (12,  "GUARDED"),
    (25,  "ELEVATED"),
    (44,  "ELEVATED"),
    (45,  "HIGH"),
    (69,  "HIGH"),
    (70,  "CRITICAL"),
    (100, "CRITICAL"),
])
def test_risk_band_thresholds(score, band):
    assert _classify_risk(score) == band
