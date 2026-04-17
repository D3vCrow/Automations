"""Repository-layout path constants.

Every helper module that needs to know where the repo root, the tools
package, or the tests live imports from here instead of re-deriving the
path from ``Path(__file__)``. Keeping the derivation in one place means
a layout change only has to be reflected once.

Typical use::

    from tools._common.paths import TOOLS_DIR, REPO_ROOT
    settings_file = REPO_ROOT / "config" / "settings.json"
"""

from __future__ import annotations

from pathlib import Path

# This file lives at ``<repo>/tools/_common/paths.py``; climbing three
# parents gets us the repo root.
_THIS = Path(__file__).resolve()

REPO_ROOT: Path = _THIS.parent.parent.parent
TOOLS_DIR: Path = REPO_ROOT / "tools"
COMMON_DIR: Path = TOOLS_DIR / "_common"
TESTS_DIR: Path = REPO_ROOT / "tests"
PLANS_DIR: Path = REPO_ROOT / "plans"
AUDITS_DIR: Path = REPO_ROOT / "audits"
PORTABLE_DIR: Path = REPO_ROOT / "portable"

__all__ = [
    "AUDITS_DIR",
    "COMMON_DIR",
    "PLANS_DIR",
    "PORTABLE_DIR",
    "REPO_ROOT",
    "TESTS_DIR",
    "TOOLS_DIR",
]
