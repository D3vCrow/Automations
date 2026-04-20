"""Tests for L2 screenshot-path-traversal regression.

Validator is shared with L1 (see ``test_ffmpeg_path_validation.py`` for
the full validator unit-test matrix). This file focuses on the L2 PoC
regression + L2-specific payloads from the audit.

Related audit: audits/2026-04-17-security-probe.md §L2.
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


def test_l2_documented_payload_rejected():
    """The exact '../../Windows/Temp' string from the audit must be rejected."""
    with pytest.raises(OutputDirError):
        _validate_output_dir("../../Windows/Temp")


def test_l2_sandbox_containment(tmp_path):
    """Sibling-of-base traversal (same shape as the PoC) must be rejected."""
    sandbox = tmp_path / "sandbox_pictures"
    outside = tmp_path / "outside_victim"
    sandbox.mkdir()
    outside.mkdir()

    traversal = f"{sandbox}{chr(92)}..{chr(92)}outside_victim"
    with pytest.raises(OutputDirError):
        _validate_output_dir(traversal, allowed_bases=[sandbox])


def test_l2_poc_is_blocked():
    """End-to-end: L2 PoC must print EXPLOIT BLOCKED + exit 1 after fix."""
    poc = PROJECT_ROOT / "security" / "poc" / "L2_2026-04-17.py"
    assert poc.exists(), f"PoC missing at {poc}"

    result = subprocess.run(
        [sys.executable, str(poc)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert "EXPLOIT BLOCKED" in result.stdout, (
        f"L2 PoC did not block:\nstdout={result.stdout}\nstderr={result.stderr}"
    )
    assert result.returncode == 1, (
        f"L2 PoC exit code was {result.returncode}, expected 1. "
        f"stdout={result.stdout}"
    )
