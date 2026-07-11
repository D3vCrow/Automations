"""Shared Canvas line-chart painter in tools._common.ui_theme.

The painter was lifted off NSM's App so NID reaches the same code (audits
2026-04-17 §shadow-copy). These tests pin the axis-ceiling maths and the
single-vs-dual-axis rendering that lets NID draw a count chart without a
phantom right-hand percentage scale. A recording ``FakeCanvas`` stands in for
``tkinter.Canvas`` so the tests run headless.
"""
from pathlib import Path
import sys

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common import ui_theme


class FakeCanvas:
    """Records draw calls so tests can assert on what was painted."""

    def __init__(self):
        self.texts = []
        self.lines = []
        self.rects = []

    def delete(self, *_args):
        pass

    def create_text(self, x, y, text="", **_kw):
        self.texts.append(text)

    def create_line(self, *coords, **_kw):
        self.lines.append(coords)

    def create_rectangle(self, *coords, **_kw):
        self.rects.append(coords)


# ---------- axis ceiling ----------

def test_axis_ceiling_keeps_threshold_visible():
    assert ui_theme.axis_ceiling([10, 20, 30], 200) >= 220


def test_axis_ceiling_expands_for_real_spikes():
    assert ui_theme.axis_ceiling([800], 200) > 800


def test_axis_ceiling_without_threshold_is_peak_plus_headroom():
    assert ui_theme.axis_ceiling([100], None) == pytest.approx(115.0)


def test_axis_ceiling_empty_and_floor():
    assert ui_theme.axis_ceiling([], None) == 100   # no data -> default
    assert ui_theme.axis_ceiling([1], None) == 10    # tiny peak floored to 10


# ---------- draw_line_chart ----------

def _left_series():
    return [{"label": "Active", "axis": "left", "color": "#5aa9e6",
             "points": [(0.0, 1), (60.0, 3)]}]


def test_no_points_shows_placeholder():
    c = FakeCanvas()
    ui_theme.draw_line_chart(c, [{"label": "A", "axis": "left",
                                  "color": "#fff", "points": []}], 400, 200)
    assert any("No data" in t for t in c.texts)


def test_single_axis_omits_right_scale_and_unit():
    # NID draws counts on one axis; no phantom 0-100 % scale on the right.
    c = FakeCanvas()
    ui_theme.draw_line_chart(c, _left_series(), 400, 200, left_unit="conns")
    assert "conns" in c.texts       # left unit honoured
    assert "%" not in c.texts       # right unit not drawn
    assert "ms" not in c.texts      # left unit overridden, default gone


def test_dual_axis_draws_both_units():
    # NSM's defaults: latency (ms) left, signal (%) right.
    c = FakeCanvas()
    series = _left_series() + [{"label": "Signal", "axis": "right",
                               "color": "#5bbf60", "points": [(0.0, 10), (60.0, 90)]}]
    ui_theme.draw_line_chart(c, series, 400, 200)
    assert "ms" in c.texts
    assert "%" in c.texts


def test_threshold_draws_band_rectangle():
    c = FakeCanvas()
    ui_theme.draw_line_chart(c, _left_series(), 400, 200,
                             threshold={"axis": "left", "value": 200.0,
                                        "label": "slow above 200 ms"})
    assert c.rects, "threshold band rectangle should be drawn"
    assert any("slow above 200 ms" in t for t in c.texts)
