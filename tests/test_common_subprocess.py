"""Tests for tools._common.subprocess — hidden-window helpers.

Uses monkeypatch over the stdlib to assert flag merging without
spawning real processes (keeps the suite fast and sandbox-friendly).
"""

import subprocess as _stdlib_subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools._common import subprocess as common_subprocess  # noqa: E402
from tools._common.subprocess import (  # noqa: E402
    CREATE_NO_WINDOW,
    popen_hidden,
    run_hidden,
)


# ── CREATE_NO_WINDOW constant ─────────────────────────────────────────

def test_create_no_window_matches_winapi_on_windows():
    """On Windows the constant equals the documented WinAPI value."""
    if sys.platform == "win32":
        assert CREATE_NO_WINDOW == 0x08000000
    else:
        assert CREATE_NO_WINDOW == 0


# ── run_hidden flag merging ───────────────────────────────────────────

def test_run_hidden_sets_create_no_window(monkeypatch):
    """run_hidden OR-merges CREATE_NO_WINDOW into creationflags."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    monkeypatch.setattr(common_subprocess._stdlib_subprocess, "run", fake_run)

    run_hidden(["echo", "hi"])

    assert captured["cmd"] == ["echo", "hi"]
    assert captured["kwargs"]["creationflags"] == CREATE_NO_WINDOW


def test_run_hidden_merges_caller_flags(monkeypatch):
    """Caller-supplied creationflags are preserved alongside CREATE_NO_WINDOW."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(common_subprocess._stdlib_subprocess, "run", fake_run)

    # CREATE_NEW_PROCESS_GROUP is 0x00000200 — unrelated to CREATE_NO_WINDOW.
    extra = 0x00000200
    run_hidden(["echo"], creationflags=extra)

    flags = captured["kwargs"]["creationflags"]
    assert flags & CREATE_NO_WINDOW == CREATE_NO_WINDOW
    assert flags & extra == extra


def test_run_hidden_passes_through_other_kwargs(monkeypatch):
    """Non-creationflags kwargs (timeout, capture_output...) reach stdlib."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(common_subprocess._stdlib_subprocess, "run", fake_run)

    run_hidden(["x"], timeout=5, capture_output=True, text=True)

    assert captured["kwargs"]["timeout"] == 5
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True


# ── popen_hidden mirrors run_hidden ───────────────────────────────────

def test_popen_hidden_sets_create_no_window(monkeypatch):
    """popen_hidden applies the same creationflags merge as run_hidden."""
    captured = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs

    monkeypatch.setattr(common_subprocess._stdlib_subprocess, "Popen", FakePopen)

    popen_hidden(["echo"])

    assert captured["cmd"] == ["echo"]
    assert captured["kwargs"]["creationflags"] == CREATE_NO_WINDOW


# ── stdlib subprocess remains the stdlib one ─────────────────────────

def test_stdlib_subprocess_still_resolves_from_top_level():
    """Importing tools._common.subprocess must not clobber the stdlib
    module for other callers (absolute-imports sanity check)."""
    assert hasattr(_stdlib_subprocess, "run")
    assert hasattr(_stdlib_subprocess, "Popen")
