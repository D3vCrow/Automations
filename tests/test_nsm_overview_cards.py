"""NSM Overview status classification + chart-axis logic (direction-A P0 redesign).

The App builds a Tk root, so it can't be instantiated headless; the pure
classification helpers are exercised on a bare object via ``object.__new__(App)``
(they read only their arguments). ``_axis_ceiling`` is a staticmethod, callable
straight off the class.
"""
from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.network_stability_monitor import App
from tools._common import ui_theme
from tools._common.verdict import VerdictState


def _app():
    return object.__new__(App)  # bare instance; the helpers use args only


# ---------- status classification ----------

def test_rtt_status_thresholds():
    a = _app()
    assert a._rtt_status(30) is VerdictState.GREEN
    assert a._rtt_status(120) is VerdictState.AMBER
    assert a._rtt_status(250) is VerdictState.RED
    assert a._rtt_status(None) is VerdictState.RED
    assert a._rtt_status(10, ok=False) is VerdictState.RED


def test_rtt_status_boundaries():
    a = _app()
    assert a._rtt_status(59.9) is VerdictState.GREEN
    assert a._rtt_status(60) is VerdictState.AMBER    # 60 is not < 60
    assert a._rtt_status(199) is VerdictState.AMBER
    assert a._rtt_status(200) is VerdictState.RED     # the 200 ms "slow" line


def test_signal_status_thresholds():
    a = _app()
    assert a._signal_status(80) is VerdictState.GREEN
    assert a._signal_status(55) is VerdictState.AMBER
    assert a._signal_status(20) is VerdictState.RED


def test_loss_status_thresholds():
    a = _app()
    assert a._loss_status(1) is VerdictState.GREEN
    assert a._loss_status(10) is VerdictState.AMBER
    assert a._loss_status(40) is VerdictState.RED


def test_dns_status_mapping():
    a = _app()
    assert a._dns_status("OK") is VerdictState.GREEN
    assert a._dns_status("SLOW") is VerdictState.AMBER
    assert a._dns_status("FAIL") is VerdictState.RED


def test_colour_shims_resolve_to_the_shared_palette():
    # The Diagnostics-tab shims must return the unified on-dark hexes (via the
    # _*_status helpers), so every surface agrees with the Overview + banner.
    a = _app()
    assert a._signal_color(80) == ui_theme.status_style(VerdictState.GREEN).text
    assert a._signal_color(20) == ui_theme.status_style(VerdictState.RED).text
    assert a._loss_bar_color(1) == ui_theme.status_style(VerdictState.GREEN).text
    assert a._loss_bar_color(40) == ui_theme.status_style(VerdictState.RED).text


# ---------- chart axis (the "spikes but 0 incidents" fix) ----------

def test_axis_ceiling_keeps_threshold_visible():
    # Low readings but a 200 ms threshold -> ceiling stays >= 220, so the slow
    # line is on-screen and a harmless spike no longer fills the auto-zoom.
    assert App._axis_ceiling([10, 20, 30], 200) >= 220


def test_axis_ceiling_expands_for_real_spikes():
    # A genuine spike past the threshold expands the axis above it.
    assert App._axis_ceiling([800], 200) > 800


def test_axis_ceiling_without_threshold_is_peak_plus_headroom():
    assert App._axis_ceiling([100], None) == pytest.approx(115.0)


def test_axis_ceiling_empty_and_floor():
    assert App._axis_ceiling([], None) == 100   # no data -> default
    assert App._axis_ceiling([1], None) == 10   # tiny peak floored to 10
