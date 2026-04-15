"""
Launch.pyw — Console-free toolbox launcher.
Double-click this file to start the toolbox without a CMD window.
Uses pythonw.exe automatically (.pyw extension).
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _bootstrap_paths() -> Path:
    """Set cwd to this file's dir and insert project + venv site-packages on path.

    Returns:
        The project root directory.
    """
    project_root = Path(__file__).resolve().parent
    os.chdir(project_root)

    project_root_str = str(project_root)
    if project_root_str not in sys.path:
        sys.path.insert(0, project_root_str)

    venv_site = project_root / "venv" / "Lib" / "site-packages"
    if venv_site.is_dir():
        sys.path.insert(0, str(venv_site))

    return project_root


def _configure_logging(project_root: Path) -> None:
    """Install a RotatingFileHandler on the root logger.

    Captures warnings/errors from unconfigured libraries (and anything
    written via ``logging``) into ``toolbox_crash.log`` in the project
    root. Caps file growth at 2MB with 3 backups.
    """
    log_path = project_root / "toolbox_crash.log"
    handler = RotatingFileHandler(
        str(log_path),
        maxBytes=2_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s",
            "%Y-%m-%d %H:%M:%S",
        )
    )
    logging.basicConfig(level=logging.INFO, handlers=[handler])


def _main() -> int:
    project_root = _bootstrap_paths()
    _configure_logging(project_root)

    log = logging.getLogger("launcher.bootstrap")
    try:
        import customtkinter as ctk

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        from Main import ToolboxApp

        app = ToolboxApp()
        app.mainloop()
        return 0
    except Exception:
        log.exception("launcher crashed")
        return 1


if __name__ == "__main__":
    try:
        sys.exit(_main())
    finally:
        logging.shutdown()
