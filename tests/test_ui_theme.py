"""The shared UI token layer resolves every status from the one verdict palette.

The whole point of the network-tools redesign is that the banner, the cards, and
the chart stop using three different "greens". These tests pin that: a status
style's fill is *the* verdict colour, never a second hardcoded set.
"""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common import ui_theme
from tools._common.verdict import VerdictState, state_style


def test_status_style_fill_is_the_verdict_palette():
    # Cards/chart/banner must share ONE palette: fill == verdict._STATE_STYLE.
    for st in VerdictState:
        assert ui_theme.status_style(st).fill == state_style(st)[0]


def test_status_style_ink_contrasts_the_fill():
    # Light fills (amber, gray) take black ink; dark fills take white.
    assert ui_theme.status_style(VerdictState.AMBER).ink == "#000000"
    assert ui_theme.status_style(VerdictState.GRAY).ink == "#000000"
    assert ui_theme.status_style(VerdictState.GREEN).ink == "#ffffff"
    assert ui_theme.status_style(VerdictState.BLUE).ink == "#ffffff"
    assert ui_theme.status_style(VerdictState.RED).ink == "#ffffff"


def test_status_style_carries_icon_and_label_from_verdict():
    for st in VerdictState:
        fill, icon, label = state_style(st)
        style = ui_theme.status_style(st)
        assert style.icon == icon
        assert style.label == label


def test_status_style_on_dark_text_is_defined_for_every_state():
    for st in VerdictState:
        assert ui_theme.status_style(st).text.startswith("#")


def test_card_word_is_metric_neutral():
    # A single slow metric is a "Problem", not the banner's "Possible attack".
    assert ui_theme.card_word(VerdictState.RED) == "Problem"
    assert ui_theme.card_word(VerdictState.GREEN) == "Good"
    assert ui_theme.card_word(VerdictState.AMBER) == "Worth a look"


def test_card_word_covers_every_state():
    for st in VerdictState:
        assert ui_theme.card_word(st)


def test_dashboard_tokens_are_hex_and_distinct_from_treeview():
    # New dashboard tokens exist alongside the untouched Treeview palette.
    for token in (ui_theme.BG, ui_theme.SURFACE, ui_theme.SURFACE_ALT,
                  ui_theme.BORDER, ui_theme.TEXT, ui_theme.TEXT_MUTED,
                  ui_theme.TEXT_FAINT):
        assert token.startswith("#") and len(token) == 7
    assert ui_theme.TREE_BG == "#2b2b2b"  # existing palette preserved
