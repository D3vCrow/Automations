"""Shared helpers used by toolbox tools and the launcher.

Submodules
----------
logging     Configured rotating-file loggers + ``get_log_dir()``.
threadsafe  ``BoundedDeque`` and ``SnapshotDict`` primitives.
paths       Repo-layout path constants (``REPO_ROOT`` etc.).
subprocess  Hidden-window subprocess helpers (``run_hidden`` etc.).
ui_theme    Shared ttk dark-theme styling.
exceptions  Narrow-except decorator + context manager.
config      Environment + ``.env`` configuration lookups.

Commonly-used names are re-exported at package level so callers can
write ``from tools._common import TOOLS_DIR, run_hidden`` without
reaching into the submodule layout. Submodule imports remain valid
and are preferred when a caller only needs one or two names from a
single module.
"""

from tools._common.config import get_bool, get_config, get_path
from tools._common.exceptions import narrow_excepts, suppress_and_log
from tools._common.paths import (
    AUDITS_DIR,
    COMMON_DIR,
    PLANS_DIR,
    PORTABLE_DIR,
    REPO_ROOT,
    TESTS_DIR,
    TOOLS_DIR,
)
from tools._common.subprocess import CREATE_NO_WINDOW, popen_hidden, run_hidden
from tools._common.ui_theme import apply_dark_treeview_style

__all__ = [
    "AUDITS_DIR",
    "COMMON_DIR",
    "CREATE_NO_WINDOW",
    "PLANS_DIR",
    "PORTABLE_DIR",
    "REPO_ROOT",
    "TESTS_DIR",
    "TOOLS_DIR",
    "apply_dark_treeview_style",
    "get_bool",
    "get_config",
    "get_path",
    "narrow_excepts",
    "popen_hidden",
    "run_hidden",
    "suppress_and_log",
]
