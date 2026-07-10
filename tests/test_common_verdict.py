"""Tests for tools._common.verdict — shared plain-language verdict layer.

Focus is the two safety-critical arbitration rules: attack (RED) must outrank
outage (BLUE), and the reassuring BLUE "not your fault" must degrade to AMBER
below a confidence floor. A wrong verdict is the network tools' worst failure.
"""

import pytest

from tools._common.verdict import (
    DEFAULT_CONFIDENCE_FLOOR,
    Verdict,
    VerdictState,
    arbitrate,
    enforce_confidence_floor,
    state_style,
)


def _v(state, confidence=1.0, **kw):
    return Verdict(state=state, headline=kw.pop("headline", state.value), confidence=confidence, **kw)


# ── arbitrate: precedence when signals conflict ──────────────────────────────

def test_arbitrate_red_outranks_blue():
    # The load-bearing rule: an attack that presents as an outage must win.
    attack = _v(VerdictState.RED, headline="Router impersonated")
    outage = _v(VerdictState.BLUE, headline="Looks like an ISP outage")
    assert arbitrate([outage, attack]) is attack
    assert arbitrate([attack, outage]) is attack  # order-independent


def test_arbitrate_picks_highest_precedence():
    green = _v(VerdictState.GREEN)
    amber = _v(VerdictState.AMBER)
    blue = _v(VerdictState.BLUE)
    # RED > BLUE > AMBER > GREEN > GRAY
    assert arbitrate([green, amber, blue]).state is VerdictState.BLUE
    assert arbitrate([_v(VerdictState.GRAY), green]).state is VerdictState.GREEN


def test_arbitrate_tie_keeps_first_listed():
    a = _v(VerdictState.AMBER, headline="first")
    b = _v(VerdictState.AMBER, headline="second")
    assert arbitrate([a, b]) is a


def test_arbitrate_empty_raises():
    with pytest.raises(ValueError):
        arbitrate([])


# ── enforce_confidence_floor: BLUE must be earned ────────────────────────────

def test_blue_below_floor_downgrades_to_amber():
    blue = _v(
        VerdictState.BLUE,
        confidence=0.5,
        headline="It's your provider, not you",
        evidence="internet down 40s",
        action="wait for your provider",
        detail="{...}",
        capability_note="only this PC",
    )
    out = enforce_confidence_floor(blue, floor=0.7)
    assert out.state is VerdictState.AMBER
    assert out.headline != blue.headline          # hedged wording
    # Everything except state + headline is preserved.
    assert out.evidence == "internet down 40s"
    assert out.action == "wait for your provider"
    assert out.detail == "{...}"
    assert out.capability_note == "only this PC"
    assert out.confidence == 0.5


def test_blue_at_or_above_floor_unchanged():
    blue = _v(VerdictState.BLUE, confidence=0.7)
    assert enforce_confidence_floor(blue, floor=0.7) is blue
    blue_high = _v(VerdictState.BLUE, confidence=0.95)
    assert enforce_confidence_floor(blue_high, floor=0.7) is blue_high


def test_non_blue_never_downgraded_even_at_low_confidence():
    # A low-confidence RED must NOT be softened — only BLUE is gated.
    red = _v(VerdictState.RED, confidence=0.1)
    assert enforce_confidence_floor(red) is red
    amber = _v(VerdictState.AMBER, confidence=0.1)
    assert enforce_confidence_floor(amber) is amber


def test_default_floor_is_conservative():
    assert DEFAULT_CONFIDENCE_FLOOR >= 0.7


# ── styling: colour never stands alone ───────────────────────────────────────

def test_every_state_has_color_icon_and_label():
    for state in VerdictState:
        color, icon, label = state_style(state)
        assert color.startswith("#") and len(color) == 7
        assert icon and icon.strip()      # a glyph, so colour-blind users see state
        assert label and label.strip()


def test_verdict_style_properties_match_state_style():
    v = _v(VerdictState.RED)
    color, icon, label = state_style(VerdictState.RED)
    assert (v.color, v.icon, v.short_label) == (color, icon, label)


def test_verdict_defaults():
    v = Verdict(state=VerdictState.GREEN, headline="all good")
    assert v.evidence == "" and v.action == "" and v.detail == ""
    assert v.confidence == 1.0 and v.capability_note == ""
