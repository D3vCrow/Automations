"""Subprocess helpers that suppress the Windows console popup.

Every tool that shells out currently duplicates the
``creationflags=0x08000000`` incantation (sometimes as ``_CNW``,
sometimes as ``_CREATE_NO_WINDOW``, sometimes via
``subprocess.CREATE_NO_WINDOW``). This module centralises the constant
and offers two thin wrappers that merge the flag with any
caller-provided ``creationflags`` so a custom flag set never silently
drops the no-window bit.

On non-Windows platforms the flag is ``0`` and the wrappers behave
exactly like their stdlib counterparts — safe to import everywhere.
"""

from __future__ import annotations

import subprocess as _stdlib_subprocess
import sys
from typing import Any

# Absolute value of WinAPI ``CREATE_NO_WINDOW``. On non-Windows it is
# meaningless; zero keeps the OR-merging below a no-op.
CREATE_NO_WINDOW: int = 0x08000000 if sys.platform == "win32" else 0


def run_hidden(cmd: Any, **kwargs: Any) -> _stdlib_subprocess.CompletedProcess:
    """Run ``cmd`` via :func:`subprocess.run` without popping a console.

    Any ``creationflags`` the caller passes are OR'd with
    :data:`CREATE_NO_WINDOW` so the hidden-window bit is never dropped.

    Args:
        cmd: Command sequence (list) or string — passed straight through.
        **kwargs: Forwarded to :func:`subprocess.run` unchanged, except
            ``creationflags`` which is merged.

    Returns:
        The :class:`subprocess.CompletedProcess` from stdlib.
    """
    flags = kwargs.pop("creationflags", 0) | CREATE_NO_WINDOW
    return _stdlib_subprocess.run(cmd, creationflags=flags, **kwargs)


def popen_hidden(cmd: Any, **kwargs: Any) -> _stdlib_subprocess.Popen:
    """Spawn ``cmd`` via :class:`subprocess.Popen` without popping a console.

    Same flag-merging contract as :func:`run_hidden`; useful when the
    caller needs to interact with the process (read stdout, send signals)
    rather than wait for completion.

    Args:
        cmd: Command sequence or string.
        **kwargs: Forwarded to :class:`subprocess.Popen` unchanged, except
            ``creationflags`` which is merged.

    Returns:
        The :class:`subprocess.Popen` instance.
    """
    flags = kwargs.pop("creationflags", 0) | CREATE_NO_WINDOW
    return _stdlib_subprocess.Popen(cmd, creationflags=flags, **kwargs)


__all__ = ["CREATE_NO_WINDOW", "popen_hidden", "run_hidden"]
