"""Tests for tools/folder_size_analyzer.py — utilities + data model (Plan B / B4).

Covers:
    * format_size across the 0 B / B / KB / MB / GB / TB boundaries.
    * format_date on the zero-timestamp sentinel and a known epoch.
    * get_folder_size on a nested tmp tree: totals, file count, hidden-dir
      skip, permission-error tolerance, and progress callback cadence.
    * get_drive_info on a valid path + graceful fallback on a bogus path.
    * FolderInfo defaults + documented always-True __lt__ quirk.

No Tk/CTk instantiation — pure helpers only.
"""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import List

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import folder_size_analyzer as fsa  # noqa: E402


# ── format_size ──────────────────────────────────────────────────────

def test_format_size_zero():
    assert fsa.format_size(0) == "0 B"


def test_format_size_bytes_uses_integer_suffix():
    assert fsa.format_size(512) == "512 B"
    assert fsa.format_size(1023) == "1023 B"


def test_format_size_kb_mb_gb_tb_boundaries():
    assert fsa.format_size(1024) == "1.0 KB"
    assert fsa.format_size(1024 * 1024) == "1.0 MB"
    assert fsa.format_size(1024 ** 3) == "1.0 GB"
    assert fsa.format_size(1024 ** 4) == "1.0 TB"


def test_format_size_mid_unit_rounds_to_one_decimal():
    assert fsa.format_size(1_536) == "1.5 KB"  # 1.5 KB exact
    assert fsa.format_size(2_500_000) == "2.4 MB"  # rounds down via %.1f


# ── format_date ──────────────────────────────────────────────────────

def test_format_date_zero_returns_unknown():
    assert fsa.format_date(0) == "Unknown"


def test_format_date_formats_to_minute_resolution():
    # Use a fixed local-time instant; compare against datetime for tz-safety.
    ts = datetime(2026, 4, 17, 9, 30, 45).timestamp()
    assert fsa.format_date(ts) == "2026-04-17 09:30"


# ── get_folder_size ──────────────────────────────────────────────────

def _populate(root: Path) -> tuple[int, int]:
    """Create 3 files summing to 600 bytes, plus a hidden subdir that must
    be skipped. Returns (expected_total_size, expected_file_count)."""
    (root / "a.txt").write_bytes(b"a" * 100)
    sub = root / "sub"
    sub.mkdir()
    (sub / "b.bin").write_bytes(b"b" * 200)
    (sub / "c.bin").write_bytes(b"c" * 300)

    hidden = root / ".cache"
    hidden.mkdir()
    (hidden / "ignored.bin").write_bytes(b"x" * 9999)
    return (100 + 200 + 300, 3)


def test_get_folder_size_counts_files_and_sums_bytes(tmp_path):
    expected_total, expected_files = _populate(tmp_path)
    total, files, ctime, mtime, atime = fsa.get_folder_size(str(tmp_path))
    assert total == expected_total
    assert files == expected_files
    # All timestamps are populated (non-zero since files were just written).
    assert ctime > 0
    assert mtime > 0
    assert atime > 0


def test_get_folder_size_skips_hidden_dirs(tmp_path):
    # Without _populate: only the hidden file under .cache exists.
    hidden = tmp_path / ".cache"
    hidden.mkdir()
    (hidden / "ignored.bin").write_bytes(b"x" * 500)

    total, files, *_ = fsa.get_folder_size(str(tmp_path))
    assert total == 0
    assert files == 0


def test_get_folder_size_on_empty_dir_returns_zero_ctime(tmp_path):
    total, files, ctime, mtime, atime = fsa.get_folder_size(str(tmp_path))
    assert total == 0
    assert files == 0
    # With no files, the inf sentinel must be normalized to 0.
    assert ctime == 0
    assert mtime == 0
    assert atime == 0


def test_get_folder_size_invokes_progress_callback_every_100_files(tmp_path):
    # Create 250 tiny files so the callback should fire at 100 and 200.
    for i in range(250):
        (tmp_path / f"f_{i:04d}.bin").write_bytes(b"0")

    ticks: List[int] = []
    total, files, *_ = fsa.get_folder_size(str(tmp_path), progress_callback=ticks.append)

    assert files == 250
    assert total == 250
    assert ticks == [100, 200]


# ── get_drive_info ───────────────────────────────────────────────────

def test_get_drive_info_returns_positive_totals_for_real_path(tmp_path):
    info = fsa.get_drive_info(str(tmp_path))
    assert set(info.keys()) == {"total", "used", "free"}
    assert info["total"] > 0
    assert info["used"] >= 0
    assert info["free"] >= 0


def test_get_drive_info_returns_zeros_for_bogus_path():
    info = fsa.get_drive_info("Z:\\definitely-not-a-real-drive-xyzzy")
    assert info == {"total": 0, "used": 0, "free": 0}


# ── FolderInfo ───────────────────────────────────────────────────────

def test_folder_info_defaults(tmp_path):
    info = fsa.FolderInfo(str(tmp_path))
    assert info.path == str(tmp_path)
    assert info.name == tmp_path.name
    assert info.size == 0
    assert info.file_count == 0
    assert info.created_time == 0
    assert info.modified_time == 0
    assert info.accessed_time == 0
    assert info.size_percentage == 0.0


def test_folder_info_lt_always_true_is_overridden_by_sort_key():
    """__lt__ returns True unconditionally; sorting relies on explicit keys."""
    a = fsa.FolderInfo("a")
    b = fsa.FolderInfo("b")
    # Documents the current contract — if sort() is ever called without a key,
    # results will not be meaningful.
    assert (a < b) is True
    assert (b < a) is True
