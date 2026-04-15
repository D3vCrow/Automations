"""Shared logging setup for launcher and tools.

Provides a consistent rotating-file logger configuration so every tool
and the launcher write to the same log directory with a uniform format.

Log files live in ``%APPDATA%/toolbox/logs`` on Windows, or
``$XDG_STATE_HOME/toolbox/logs`` (fallback: ``~/.local/state/toolbox/logs``)
elsewhere. The ``TOOLBOX_LOG_DIR`` environment variable overrides the
default location — useful for tests.

Typical use from a tool::

    from tools._common.logging import get_logger
    log = get_logger(__name__)
    log.info("starting")

From the launcher (bootstrap once)::

    from tools._common.logging import configure_root
    configure_root("launcher")
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

# ── Configuration constants ──────────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_BYTES = 2_000_000
BACKUP_COUNT = 3
DEFAULT_FILE_LEVEL = logging.INFO
DEFAULT_STDERR_LEVEL = logging.WARNING

# ── Internal state ───────────────────────────────────────────────────────────

# Track loggers we have configured so get_logger is idempotent.
_configured: set[str] = set()


def get_log_dir() -> Path:
    """Return the directory where log files are written.

    Honors ``TOOLBOX_LOG_DIR`` if set. Otherwise uses
    ``%APPDATA%/toolbox/logs`` on Windows, or an XDG-style fallback
    on other platforms. The directory is created if missing.

    Returns:
        Path to the log directory (guaranteed to exist).
    """
    override = os.environ.get("TOOLBOX_LOG_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        if appdata:
            base = Path(appdata) / "toolbox" / "logs"
        else:
            base = Path.home() / "AppData" / "Roaming" / "toolbox" / "logs"
    else:
        xdg = os.environ.get("XDG_STATE_HOME")
        if xdg:
            base = Path(xdg) / "toolbox" / "logs"
        else:
            base = Path.home() / ".local" / "state" / "toolbox" / "logs"

    base.mkdir(parents=True, exist_ok=True)
    return base


def _build_file_handler(log_file: Path) -> RotatingFileHandler:
    """Create a RotatingFileHandler with the shared settings."""
    handler = RotatingFileHandler(
        str(log_file),
        maxBytes=MAX_BYTES,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setLevel(DEFAULT_FILE_LEVEL)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    return handler


def _build_stderr_handler() -> logging.StreamHandler:
    """Create a stderr StreamHandler at WARNING level."""
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(DEFAULT_STDERR_LEVEL)
    handler.setFormatter(logging.Formatter(LOG_FORMAT, DATE_FORMAT))
    return handler


def _safe_filename(name: str) -> str:
    """Convert a logger name into a safe filename component."""
    # Replace path separators and other hostile characters with underscores.
    out = []
    for ch in name:
        if ch.isalnum() or ch in "-_.":
            out.append(ch)
        else:
            out.append("_")
    return "".join(out) or "toolbox"


def get_logger(name: str, log_file_name: Optional[str] = None) -> logging.Logger:
    """Return a configured logger writing to ``<log_dir>/<name>.log``.

    Calling this twice with the same ``name`` returns the same logger
    without duplicate handlers. Propagation to the root logger is
    disabled so messages do not duplicate via ``logging.basicConfig``.

    Args:
        name: Logger name. Also used to derive the log filename.
        log_file_name: Optional override for the log filename (without
            directory). Defaults to ``<safe(name)>.log``.

    Returns:
        A ``logging.Logger`` configured with a rotating file handler and
        a stderr handler.
    """
    logger = logging.getLogger(name)

    if name in _configured:
        return logger

    logger.setLevel(DEFAULT_FILE_LEVEL)
    logger.propagate = False

    file_name = log_file_name or f"{_safe_filename(name)}.log"
    log_path = get_log_dir() / file_name

    logger.addHandler(_build_file_handler(log_path))
    logger.addHandler(_build_stderr_handler())

    _configured.add(name)
    return logger


def configure_root(app_name: str = "toolbox") -> logging.Logger:
    """Configure the root logger once for a process-wide log sink.

    Intended for the launcher (``Launch.pyw``) which wants crashes and
    warnings from unconfigured code paths to land in a single file.

    Safe to call multiple times: extra invocations are no-ops.

    Args:
        app_name: Name to use for the log file (``<app_name>.log``) and
            for tracking idempotency.

    Returns:
        The root logger.
    """
    marker = f"__root__:{app_name}"
    root = logging.getLogger()

    if marker in _configured:
        return root

    root.setLevel(DEFAULT_FILE_LEVEL)

    log_path = get_log_dir() / f"{_safe_filename(app_name)}.log"
    root.addHandler(_build_file_handler(log_path))
    root.addHandler(_build_stderr_handler())

    _configured.add(marker)
    return root


def reset_for_tests() -> None:
    """Clear internal state so tests can re-configure cleanly.

    Not intended for production code.
    """
    _configured.clear()
