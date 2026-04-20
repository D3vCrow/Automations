"""Tests for _validate_output_dir + L1 path-traversal regression.

Covers the validator's core rejection rules and runs the L1 PoC as an
end-to-end regression guard. If either the unit tests or the PoC
regression fails, the L1 vulnerability is back.

Related audit: audits/2026-04-17-security-probe.md §L1.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.ffmpeg_studio import (  # noqa: E402
    OutputDirError,
    _validate_output_dir,
)


# ── Validator unit tests ────────────────────────────────────────────


def test_empty_string_rejected():
    with pytest.raises(OutputDirError):
        _validate_output_dir("")


def test_whitespace_only_rejected():
    with pytest.raises(OutputDirError):
        _validate_output_dir("   ")


def test_none_rejected():
    with pytest.raises(OutputDirError):
        _validate_output_dir(None)


def test_backslash_traversal_rejected():
    with pytest.raises(OutputDirError, match=r"'\.\.'"):
        _validate_output_dir("..\\..\\..\\Windows\\System32")


def test_forward_slash_traversal_rejected():
    with pytest.raises(OutputDirError, match=r"'\.\.'"):
        _validate_output_dir("../../Windows/System32")


def test_relative_path_rejected():
    with pytest.raises(OutputDirError, match="absolute"):
        _validate_output_dir("my_videos")


def test_absolute_path_without_traversal_accepted(tmp_path):
    result = _validate_output_dir(str(tmp_path))
    assert result == tmp_path.resolve()


def test_allowed_bases_accept_inside(tmp_path):
    inside = tmp_path / "inside"
    inside.mkdir()
    result = _validate_output_dir(str(inside), allowed_bases=[tmp_path])
    assert result == inside.resolve()


def test_allowed_bases_reject_outside(tmp_path):
    base = tmp_path / "legit"
    outside = tmp_path / "victim"
    base.mkdir()
    outside.mkdir()
    with pytest.raises(OutputDirError, match="must be inside"):
        _validate_output_dir(str(outside), allowed_bases=[base])


# ── L1 PoC regression guard ─────────────────────────────────────────


def test_l1_poc_is_blocked():
    """End-to-end: L1 PoC must print EXPLOIT BLOCKED + exit 1 after fix."""
    poc = PROJECT_ROOT / "security" / "poc" / "L1_2026-04-17.py"
    assert poc.exists(), f"PoC missing at {poc}"

    result = subprocess.run(
        [sys.executable, str(poc)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "EXPLOIT BLOCKED" in result.stdout, (
        f"L1 PoC did not block:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert result.returncode == 1, (
        f"L1 PoC exit code was {result.returncode}, expected 1. "
        f"stdout={result.stdout}"
    )
