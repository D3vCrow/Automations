"""Environment + ``.env`` configuration lookups.

Tools in the toolbox have historically stored per-user or per-environment
values (paths, schedules, feature flags) as module-level literals. The
``CLAUDE.md`` project rules require these to move to environment
variables with optional ``.env`` fallback, and this module provides the
single read path.

Usage
-----
    from tools._common.config import get_config, get_bool, get_path

    output_dir = get_path("AUTOMATIONS_FFMPEG_OUTPUT_DIR",
                          default=Path.home() / "Videos")
    auto_export = get_bool("AUTOMATIONS_NSM_AUTO_EXPORT", default=True)
    token = get_config("AUTOMATIONS_VT_API_KEY", default=None)

Precedence (highest wins)
-------------------------
1. ``os.environ`` at call time.
2. Values loaded from ``<repo>/.env`` via :mod:`python-dotenv` (optional
   dependency). ``load_dotenv`` is called once, lazily, on the first
   :func:`get_config` call. If ``python-dotenv`` is not installed, the
   ``.env`` file is ignored and only real environment variables apply.
3. The ``default`` argument.

Only real environment variables override an already-set key, so shell
``export AUTOMATIONS_FOO=x`` always wins over ``AUTOMATIONS_FOO=y`` in
``.env``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Union

from tools._common.paths import REPO_ROOT

_log = logging.getLogger(__name__)

_DOTENV_LOADED = False
_TRUTHY = {"1", "true", "yes", "on", "y", "t"}
_FALSY = {"0", "false", "no", "off", "n", "f", ""}


def _load_dotenv_once() -> None:
    """Load ``<repo>/.env`` via python-dotenv exactly once per process.

    No-op if ``python-dotenv`` is not installed or the file is missing.
    Real environment variables take precedence over ``.env`` entries.
    """
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    _DOTENV_LOADED = True

    env_path = REPO_ROOT / ".env"
    if not env_path.is_file():
        return

    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]
    except ImportError:
        _log.debug(
            "found %s but python-dotenv is not installed; ignoring", env_path
        )
        return

    load_dotenv(env_path, override=False)


def get_config(key: str, default: Optional[str] = None) -> Optional[str]:
    """Return the string value for ``key`` from env or ``.env``.

    Args:
        key: Environment variable name. Convention: ``AUTOMATIONS_<AREA>_<NAME>``.
        default: Returned when neither ``os.environ`` nor ``.env`` provide
            a value. ``None`` means "no default; caller handles missing".

    Returns:
        The resolved string, or ``default`` when unset.
    """
    _load_dotenv_once()
    value = os.environ.get(key)
    if value is not None:
        return value
    return default


def get_bool(key: str, default: bool = False) -> bool:
    """Return a boolean value for ``key`` from env or ``.env``.

    Accepted truthy tokens (case-insensitive): ``1 true yes on y t``.
    Accepted falsy tokens: ``0 false no off n f`` plus empty string.
    Unknown values fall back to ``default`` and emit a WARNING.

    Args:
        key: Environment variable name.
        default: Value returned when unset or unparseable.

    Returns:
        Parsed boolean.
    """
    raw = get_config(key)
    if raw is None:
        return default
    token = raw.strip().lower()
    if token in _TRUTHY:
        return True
    if token in _FALSY:
        return False
    _log.warning(
        "config %s=%r is not a recognized bool; using default %r",
        key, raw, default,
    )
    return default


def get_path(key: str, default: Union[str, Path]) -> Path:
    """Return a :class:`~pathlib.Path` value for ``key``.

    ``~`` is expanded. The path is NOT required to exist; callers that
    need directory creation should use ``mkdir(parents=True, exist_ok=True)``
    themselves.

    Args:
        key: Environment variable name.
        default: Fallback path when unset. ``str`` or ``Path`` accepted.

    Returns:
        Resolved ``Path`` (user-expanded, not absolutized).
    """
    raw = get_config(key)
    if raw is None:
        return Path(default).expanduser() if isinstance(default, str) else default
    return Path(raw).expanduser()


__all__ = ["get_bool", "get_config", "get_path"]
