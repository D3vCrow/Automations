"""Shared ttk styling for the toolbox dark palette.

Every tool currently sets up its own ``ttk.Style()`` with nearly-identical
Treeview colours (see audits/2026-04-17-debt-review.md §B0). This module
centralises the dark palette so a palette tweak touches one file instead
of ten.

Typical use inside a tool's ``_build_ui``::

    from tools._common.ui_theme import apply_dark_treeview_style
    apply_dark_treeview_style(self)
"""

from __future__ import annotations

from dataclasses import dataclass
from tkinter import ttk
from typing import Optional

from tools._common.verdict import VerdictState, contrast_text_color, state_style

# Colours match the customtkinter "dark blue" preset already used by the
# toolbox. Keep the constants so callers can reference the same palette
# when configuring non-Treeview widgets.
TREE_BG: str = "#2b2b2b"
TREE_FG: str = "white"
TREE_HEADING_BG: str = "#565b5e"
TREE_HEADING_FONT: tuple[str, int, str] = ("Arial", 10, "bold")


def apply_dark_treeview_style(
    master: Optional[object] = None,
    base_theme: str = "clam",
) -> ttk.Style:
    """Configure a :class:`ttk.Style` with the toolbox dark-Treeview palette.

    Args:
        master: Optional widget to scope the style to. Pass ``None`` to
            configure the global (root-owned) style.
        base_theme: ttk base theme to switch to before applying overrides.
            ``"clam"`` exposes the most configuration knobs on Windows;
            fall through silently if the theme is unavailable.

    Returns:
        The configured :class:`ttk.Style`. Callers that need extra
        overrides can chain additional ``configure`` calls.
    """
    style = ttk.Style(master) if master is not None else ttk.Style()

    try:
        style.theme_use(base_theme)
    except Exception:
        # Rare on stripped Python builds (e.g. some CI runners) — the
        # default theme is still usable, so carry on.
        pass

    style.configure(
        "Treeview",
        background=TREE_BG,
        foreground=TREE_FG,
        fieldbackground=TREE_BG,
        borderwidth=0,
    )
    style.configure(
        "Treeview.Heading",
        background=TREE_HEADING_BG,
        foreground=TREE_FG,
        relief="flat",
        font=TREE_HEADING_FONT,
    )
    return style


# ---------------------------------------------------------------------------
# Dashboard tokens (network tools' Overview screens)
#
# The Treeview palette above styles the toolbox's tables. The tokens below are
# for the network dashboards' card/chart surfaces. The five *status* colours
# are NOT redefined here — they are the verdict states from
# :mod:`tools._common.verdict`, so the plain-language banner, the metric cards
# and the live chart all read from one palette. Everything else is a semantic
# token, so a future light theme is a value swap, not a screen-by-screen rewrite.
# ---------------------------------------------------------------------------

# surfaces / text (dark theme)
BG = "#121212"
SURFACE = "#1e1e1e"
SURFACE_ALT = "#1a1a1a"
BORDER = "#2a2a2a"
TEXT = "#f1f1f1"
TEXT_MUTED = "#9a9a9a"
TEXT_FAINT = "#6a6a6a"

# typography
FONT_FAMILY = "Segoe UI"

# On-dark text/accent variant of each status hue. The verdict fills are tuned
# for a solid banner background under contrast text; as thin text on a near-black
# card the darker green/blue/red read muddy, so text uses a lifted variant of the
# SAME hue. Fills (pills, banner, chart band) stay exactly the verdict palette.
_ON_DARK_TEXT = {
    VerdictState.GRAY: "#8a8a8a",
    VerdictState.GREEN: "#5bbf60",
    VerdictState.BLUE: "#5aa9e6",
    VerdictState.AMBER: "#f9a825",
    VerdictState.RED: "#ef5350",
}

# Metric-neutral card word per state. Distinct from the banner's short label
# ("Possible attack" etc.), which is the whole-network verdict; a single slow
# metric is just a "Problem", not an attack.
_CARD_WORD = {
    VerdictState.GRAY: "No data",
    VerdictState.GREEN: "Good",
    VerdictState.BLUE: "Provider",
    VerdictState.AMBER: "Worth a look",
    VerdictState.RED: "Problem",
}


@dataclass(frozen=True)
class StatusStyle:
    """Everything a surface needs to paint one status, from one source.

    Attributes:
        state: The verdict state this style is for.
        fill: Exact verdict hex — pill/banner background, chart band.
        ink: Contrast text colour to use *on* ``fill``.
        text: On-dark text/accent hex (lifted hue) for values on a dark card.
        icon: The state's glyph (paired with a word so colour is never alone).
        label: The verdict short label (e.g. ``"Healthy"``).
    """

    state: VerdictState
    fill: str
    ink: str
    text: str
    icon: str
    label: str


def status_style(state: VerdictState) -> StatusStyle:
    """Resolve *state* to its paint bits, deriving colour from the verdict palette.

    Args:
        state: The verdict state.

    Returns:
        A :class:`StatusStyle` whose ``fill`` is the shared verdict colour, so
        cards and chart agree with the banner by construction.
    """
    fill, icon, label = state_style(state)
    return StatusStyle(
        state=state,
        fill=fill,
        ink=contrast_text_color(fill),
        text=_ON_DARK_TEXT[state],
        icon=icon,
        label=label,
    )


def card_word(state: VerdictState) -> str:
    """Metric-neutral status word for a dashboard card (e.g. ``"Worth a look"``).

    Args:
        state: The metric's verdict state.

    Returns:
        A short, non-alarming word suitable for a single metric.
    """
    return _CARD_WORD[state]


__all__ = [
    "TREE_BG",
    "TREE_FG",
    "TREE_HEADING_BG",
    "TREE_HEADING_FONT",
    "apply_dark_treeview_style",
    "BG",
    "SURFACE",
    "SURFACE_ALT",
    "BORDER",
    "TEXT",
    "TEXT_MUTED",
    "TEXT_FAINT",
    "FONT_FAMILY",
    "StatusStyle",
    "status_style",
    "card_word",
]
