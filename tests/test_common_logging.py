"""Tests for tools._common.logging — rotating file logger setup."""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common import logging as tlog  # noqa: E402


@pytest.fixture(autouse=True)
def _isolate_log_dir(tmp_path, monkeypatch):
    """Route every test's logs to tmp_path and clear global state."""
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path))
    tlog.reset_for_tests()
    # Clear handlers on loggers we might touch to avoid cross-test leakage.
    for name in ("test_alpha", "test_beta", "test_idempotent", "test_files"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
    root = logging.getLogger()
    # Snapshot root handlers so we can restore afterwards.
    saved = list(root.handlers)
    yield
    # Clean up loggers we created.
    tlog.reset_for_tests()
    for name in ("test_alpha", "test_beta", "test_idempotent", "test_files"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
    # Restore root handlers.
    root.handlers[:] = saved


def test_get_log_dir_honors_override(tmp_path, monkeypatch):
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(tmp_path / "custom"))
    tlog.reset_for_tests()
    p = tlog.get_log_dir()
    assert p == tmp_path / "custom"
    assert p.is_dir()


def test_get_log_dir_creates_directory(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "logs"
    assert not target.exists()
    monkeypatch.setenv("TOOLBOX_LOG_DIR", str(target))
    p = tlog.get_log_dir()
    assert p == target
    assert p.is_dir()


def test_get_logger_returns_configured_logger(tmp_path):
    logger = tlog.get_logger("test_alpha")
    assert logger.name == "test_alpha"
    # Must have both file and stderr handlers.
    file_handlers = [h for h in logger.handlers if isinstance(h, RotatingFileHandler)]
    stream_handlers = [
        h for h in logger.handlers
        if isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler)
    ]
    assert len(file_handlers) == 1
    assert len(stream_handlers) == 1
    assert not logger.propagate


def test_get_logger_is_idempotent(tmp_path):
    """Calling get_logger twice must not duplicate handlers."""
    a = tlog.get_logger("test_idempotent")
    handler_count = len(a.handlers)
    b = tlog.get_logger("test_idempotent")
    assert a is b
    assert len(b.handlers) == handler_count


def test_rotating_file_handler_params(tmp_path):
    logger = tlog.get_logger("test_beta")
    rfh = next(h for h in logger.handlers if isinstance(h, RotatingFileHandler))
    assert rfh.maxBytes == 2_000_000
    assert rfh.backupCount == 3


def test_log_file_is_written(tmp_path):
    logger = tlog.get_logger("test_files")
    logger.info("hello world")
    # Force flush by closing handlers.
    for h in logger.handlers:
        h.flush()
    log_path = Path(tmp_path) / "test_files.log"
    assert log_path.exists()
    content = log_path.read_text(encoding="utf-8")
    assert "hello world" in content
    assert "test_files" in content


def test_configure_root_is_idempotent(tmp_path):
    root = tlog.configure_root("myapp")
    handler_count = len(root.handlers)
    root2 = tlog.configure_root("myapp")
    assert root is root2
    # Calling twice with the same marker should not add more handlers.
    assert len(root2.handlers) == handler_count
