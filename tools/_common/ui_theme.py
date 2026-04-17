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

from tkinter import ttk
from typing import Optional

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


__all__ = [
    "TREE_BG",
    "TREE_FG",
    "TREE_HEADING_BG",
    "TREE_HEADING_FONT",
    "apply_dark_treeview_style",
]
