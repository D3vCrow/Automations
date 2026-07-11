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
from datetime import datetime
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


# ---------------------------------------------------------------------------
# Shared Canvas line chart
#
# Both network dashboards draw a small live line chart on their Overview
# (NSM's latency/signal trace, NID's connection-activity trace). The drawing
# logic lived on NSM's App as ``_draw_line_chart``; it is a pure Canvas
# painter that reads only its arguments, so it belongs here where both tools
# reach it (audits/2026-04-17-debt-review.md flags the shadow-copy risk of
# duplicating it per tool). NSM keeps thin method wrappers for call-site and
# test stability; NID calls these module functions directly.
# ---------------------------------------------------------------------------


def axis_ceiling(vals, threshold=None) -> float:
    """Upper bound for a chart axis.

    15% above the peak, but never below a *threshold* reference (with 10%
    headroom) when one is given, so a threshold line such as the 200 ms
    "slow" mark stays on-screen even when every reading is well under it.
    That is what stops a harmless sub-threshold spike from filling the
    auto-zoomed chart and looking like an incident.

    Args:
        vals: The values plotted on this axis (may be empty).
        threshold: Optional reference value to keep visible.

    Returns:
        The axis ceiling (never below 10).
    """
    hi = max(vals) * 1.15 if vals else 100
    if threshold is not None:
        hi = max(hi, threshold * 1.1)
    return hi if hi >= 10 else 10


def draw_line_chart(canvas, series_list, width, height, show_legend=True,
                    threshold=None, left_unit="ms", right_unit="%"):
    """Draw a multi-series line chart on a tkinter Canvas.

    Args:
        canvas: The target :class:`tkinter.Canvas`.
        series_list: list of dicts with keys ``label`` (str), ``color`` (str),
            ``points`` (list of ``(float_ts, float_val)``; ``None`` breaks the
            line) and ``axis`` (``"left"`` or ``"right"``).
        width: Canvas width in pixels.
        height: Canvas height in pixels.
        show_legend: Draw the top-left colour/label legend.
        threshold: optional dict ``{"axis", "value", "label"}`` drawing a
            reference line + shaded "over the limit" band on that axis.
        left_unit: Unit label for the left axis (e.g. ``"ms"``; ``""`` to omit).
        right_unit: Unit label for the right axis. Only drawn when a series
            actually uses the right axis.
    """
    canvas.delete("all")
    if width < 80 or height < 40:
        return

    # A right axis is only reserved when a series needs it, so a single-axis
    # chart (NID's counts) doesn't paint a phantom 0-100 scale on the right.
    has_right = any(s.get("axis", "left") == "right" for s in series_list)

    ml, mr, mt, mb = 50, (50 if has_right else 20), 18, 22  # margins
    dw = width - ml - mr
    dh = height - mt - mb
    if dw < 20 or dh < 20:
        return

    # Collect all timestamps for X range
    all_ts = []
    for s in series_list:
        for t, _ in s["points"]:
            all_ts.append(t)
    if not all_ts:
        canvas.create_text(width // 2, height // 2, text="No data yet",
                           fill="#666666", font=("Segoe UI", 10))
        return

    t_min, t_max = min(all_ts), max(all_ts)
    if t_max - t_min < 1:
        t_max = t_min + 1

    # Compute Y ranges per axis
    def y_range(axis):
        vals = [v for s in series_list if s.get("axis", "left") == axis
                for _, v in s["points"] if v is not None]
        thr = (threshold["value"] if threshold
               and threshold.get("axis", "left") == axis else None)
        return 0, axis_ceiling(vals, thr)

    left_lo, left_hi = y_range("left")
    right_lo, right_hi = y_range("right")

    def map_x(t):
        return ml + (t - t_min) / (t_max - t_min) * dw

    def map_y(v, axis="left"):
        lo, hi = (left_lo, left_hi) if axis == "left" else (right_lo, right_hi)
        if hi == lo:
            return mt + dh // 2
        return mt + (1 - (v - lo) / (hi - lo)) * dh

    # Grid lines (horizontal)
    for i in range(5):
        y = mt + i * dh // 4
        canvas.create_line(ml, y, ml + dw, y, fill="#333333", dash=(2, 4))
        # Left axis labels
        val = left_hi - i * (left_hi - left_lo) / 4
        canvas.create_text(ml - 4, y, text=f"{val:.0f}", anchor="e",
                           fill="#888888", font=("Segoe UI", 7))
        # Right axis labels (only when a series uses the right axis)
        if has_right:
            val_r = right_hi - i * (right_hi - right_lo) / 4
            canvas.create_text(ml + dw + 4, y, text=f"{val_r:.0f}", anchor="w",
                               fill="#888888", font=("Segoe UI", 7))

    # Axis unit labels
    if left_unit:
        canvas.create_text(ml - 4, mt - 8, text=left_unit, anchor="e",
                           fill="#888888", font=("Segoe UI", 7))
    if has_right and right_unit:
        canvas.create_text(ml + dw + 4, mt - 8, text=right_unit, anchor="w",
                           fill="#888888", font=("Segoe UI", 7))

    # X-axis time labels (~5 labels)
    span = t_max - t_min
    step = max(1, span / 5)
    t_cur = t_min
    while t_cur <= t_max:
        x = map_x(t_cur)
        try:
            lbl = datetime.fromtimestamp(t_cur).strftime("%H:%M:%S")
        except (OSError, ValueError, OverflowError):
            lbl = ""
        canvas.create_text(x, mt + dh + 12, text=lbl,
                           fill="#888888", font=("Segoe UI", 7))
        canvas.create_line(x, mt, x, mt + dh, fill="#2a2a2a", dash=(1, 6))
        t_cur += step

    # Threshold band + line, drawn under the series. The shaded zone above
    # the line is "too slow"; everything below it is healthy. Colour comes
    # from the shared RED verdict, so it matches the banner and cards.
    if threshold:
        taxis = threshold.get("axis", "left")
        ty = map_y(threshold["value"], taxis)
        red = status_style(VerdictState.RED).fill
        canvas.create_rectangle(ml, mt, ml + dw, ty, fill=red, outline="",
                                stipple="gray12")
        canvas.create_line(ml, ty, ml + dw, ty, fill=red, dash=(5, 4))
        tlabel = threshold.get("label", "")
        if tlabel:
            canvas.create_text(ml + dw - 2, ty - 5, text=tlabel, anchor="se",
                               fill=red, font=("Segoe UI", 7))

    # Draw series
    for s in series_list:
        pts = s["points"]
        axis = s.get("axis", "left")
        color = s["color"]
        coords = []
        for t, v in pts:
            if v is None:
                # Break the line at None values
                if len(coords) >= 4:
                    canvas.create_line(*coords, fill=color, width=2, smooth=False)
                coords = []
                continue
            coords.extend([map_x(t), map_y(v, axis)])
        if len(coords) >= 4:
            canvas.create_line(*coords, fill=color, width=2, smooth=False)

    # Legend
    if show_legend:
        lx = ml + 6
        ly = mt + 4
        for s in series_list:
            canvas.create_rectangle(lx, ly, lx + 10, ly + 8, fill=s["color"], outline="")
            canvas.create_text(lx + 14, ly + 4, text=s["label"], anchor="w",
                               fill="#cccccc", font=("Segoe UI", 7))
            lx += len(s["label"]) * 6 + 28


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
    "axis_ceiling",
    "draw_line_chart",
]
