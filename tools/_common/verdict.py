"""Shared plain-language verdict layer for the network tools.

Both the Network Stability Monitor (NSM) and the Network Intrusion Detector
(NID) exist to answer one question for a non-technical user: *is my network
fine, is it my provider, or is someone attacking me?* This module holds the
shared vocabulary so both tools speak one language — the traffic-light state,
its colour/icon/wording, and the safety-critical arbitration rules — while each
tool supplies its own evidence and wording through an adapter.

See ``plans/2026-07-10-network-tools-audit.md`` §6 and §8.

A verdict has five slots, always in this order when rendered:
    state · plain meaning (headline) · evidence + freshness · one action ·
    "why we think this" detail (technical, hidden behind a toggle).

Two arbitration rules are enforced here because a wrong verdict is the tools'
worst failure mode:
    * :func:`arbitrate` — when signals conflict, "possible attack" (RED)
      outranks "looks like an ISP outage" (BLUE). An ARP-spoof often *presents*
      as an outage, so the reassuring verdict must never mask the dangerous one.
    * :func:`enforce_confidence_floor` — the reassuring BLUE "it's not you"
      verdict suppresses vigilance, so it may only stand above a confidence
      floor; below it, it degrades to AMBER ("worth a look").

Colour is always paired with an icon and text (never colour alone) so the
states stay distinguishable for colour-blind users.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable, Tuple


class VerdictState(str, Enum):
    """Traffic-light state, lowest to highest urgency.

    ``str`` mix-in keeps members directly comparable/serialisable as their
    lowercase string value (``VerdictState.RED == "red"``).
    """

    GRAY = "gray"    # initializing / no data / detector unavailable
    GREEN = "green"  # healthy
    BLUE = "blue"    # looks like a provider outage — not your fault
    AMBER = "amber"  # worth a look (benign-first)
    RED = "red"      # confirmed high-confidence harm — possible attack


# Precedence for :func:`arbitrate`: higher wins when signals conflict. RED over
# BLUE is the load-bearing rule (attack must outrank outage). GRAY is lowest so
# a "can't see" fallback never masks a real signal.
_PRECEDENCE = {
    VerdictState.GRAY: 0,
    VerdictState.GREEN: 1,
    VerdictState.AMBER: 2,
    VerdictState.BLUE: 3,
    VerdictState.RED: 4,
}

# (color hex, icon, short label). Icon + label carry the meaning without color.
_STATE_STYLE = {
    VerdictState.GRAY: ("#8a8a8a", "…", "Checking"),
    VerdictState.GREEN: ("#2e7d32", "✓", "Healthy"),
    VerdictState.BLUE: ("#1565c0", "ℹ", "Provider outage"),
    VerdictState.AMBER: ("#f9a825", "⚠", "Worth a look"),
    VerdictState.RED: ("#c62828", "⛔", "Possible attack"),
}

# Default confidence floor below which a BLUE "not your fault" verdict is
# downgraded to AMBER. Tuned conservatively: the reassurance must be earned.
DEFAULT_CONFIDENCE_FLOOR = 0.7


def state_style(state: VerdictState) -> Tuple[str, str, str]:
    """Return ``(color_hex, icon, short_label)`` for *state*.

    Args:
        state: The verdict state.

    Returns:
        A 3-tuple; colour is always paired with the icon and label so the
        state is legible without relying on colour alone.
    """
    return _STATE_STYLE[state]


def contrast_text_color(hex_color: str, *, threshold: float = 135.0) -> str:
    """Return black or white — whichever stays legible on *hex_color*.

    Uses perceptual luminance (ITU-R BT.601 weights). Colour is never the only
    signal on the banner (an icon and label carry the meaning too), but the text
    painted on the state swatch must still be readable, so both banners pick
    their text colour from the background this way.

    Args:
        hex_color: ``#rrggbb`` (leading ``#`` optional).
        threshold: Luminance (0..255) above which black text wins; the default
            keeps mid-grey and amber on black, and green/blue/red on white.

    Returns:
        ``"#000000"`` or ``"#ffffff"``. Malformed input falls back to white.
    """
    h = hex_color.lstrip("#")
    try:
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    except (ValueError, IndexError):
        return "#ffffff"
    luminance = 0.299 * r + 0.587 * g + 0.114 * b
    return "#000000" if luminance > threshold else "#ffffff"


@dataclass
class Verdict:
    """One plain-language verdict — the five banner slots plus confidence.

    Attributes:
        state: Traffic-light state.
        headline: Plain meaning, one sentence, no jargon.
        evidence: What we saw and how fresh it is (one line).
        action: The single opinionated next step; ``""`` when none is needed
            (e.g. a healthy GREEN).
        detail: Technical "why we think this" text, hidden behind a toggle.
        confidence: 0..1 certainty in *state*; gates the BLUE floor.
        capability_note: What the tool currently *cannot* check (missing
            Npcap/admin, "only this PC", etc.); ``""`` when coverage is full.
            Keeps GREEN from silently meaning "blind".
    """

    state: VerdictState
    headline: str
    evidence: str = ""
    action: str = ""
    detail: str = ""
    confidence: float = 1.0
    capability_note: str = ""

    @property
    def color(self) -> str:
        """Hex colour for :attr:`state`."""
        return _STATE_STYLE[self.state][0]

    @property
    def icon(self) -> str:
        """Icon glyph for :attr:`state`."""
        return _STATE_STYLE[self.state][1]

    @property
    def short_label(self) -> str:
        """Short state label (e.g. ``"Worth a look"``)."""
        return _STATE_STYLE[self.state][2]


def arbitrate(verdicts: Iterable[Verdict]) -> Verdict:
    """Pick the verdict that must win when signals conflict.

    Highest precedence wins (see ``_PRECEDENCE``): a RED "possible attack"
    outranks a BLUE "ISP outage" because an attack frequently presents as an
    outage and the dangerous reading must never be masked by the reassuring
    one. Ties keep the first-listed verdict (callers list the more specific
    signal first).

    Args:
        verdicts: One or more candidate verdicts.

    Returns:
        The winning verdict.

    Raises:
        ValueError: If *verdicts* is empty.
    """
    winner = None
    best = -1
    for v in verdicts:
        rank = _PRECEDENCE[v.state]
        if rank > best:
            best = rank
            winner = v
    if winner is None:
        raise ValueError("arbitrate() requires at least one verdict")
    return winner


def enforce_confidence_floor(
    verdict: Verdict,
    floor: float = DEFAULT_CONFIDENCE_FLOOR,
    *,
    hedge: str = "Possibly your provider — worth a look.",
) -> Verdict:
    """Downgrade a low-confidence BLUE verdict to AMBER.

    The BLUE "it's an outage, not your fault, not an attacker" verdict tells the
    user to stand down, so it may only stand when we are confident. Below
    *floor* it becomes AMBER with a hedged headline, preserving the evidence,
    action, detail, and capability note. Non-BLUE verdicts, and BLUE verdicts at
    or above the floor, are returned unchanged.

    Args:
        verdict: The candidate verdict.
        floor: Minimum confidence for BLUE to stand (0..1).
        hedge: Replacement headline used when downgrading.

    Returns:
        The original verdict, or an AMBER-downgraded copy.
    """
    if verdict.state is not VerdictState.BLUE or verdict.confidence >= floor:
        return verdict
    return Verdict(
        state=VerdictState.AMBER,
        headline=hedge,
        evidence=verdict.evidence,
        action=verdict.action,
        detail=verdict.detail,
        confidence=verdict.confidence,
        capability_note=verdict.capability_note,
    )


__all__ = [
    "DEFAULT_CONFIDENCE_FLOOR",
    "Verdict",
    "VerdictState",
    "arbitrate",
    "contrast_text_color",
    "enforce_confidence_floor",
    "state_style",
]
