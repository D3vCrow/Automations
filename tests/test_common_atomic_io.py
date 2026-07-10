"""Tests for tools._common.atomic_io (crash-safe writes, safe JSON reads)."""

import json

import pytest

from tools._common.atomic_io import (
    atomic_write,
    atomic_write_json,
    read_json,
    sweep_stale_tmp,
)


def _tmp_files(directory):
    """Temp files atomic_write would leave behind: dot-prefixed, .tmp suffix."""
    return [p for p in directory.iterdir() if p.name.startswith(".") and p.name.endswith(".tmp")]


# ── atomic_write ─────────────────────────────────────────────────────────────

def test_atomic_write_str_round_trip(tmp_path):
    target = tmp_path / "out.txt"
    atomic_write(target, "hello world")
    assert target.read_text(encoding="utf-8") == "hello world"


def test_atomic_write_bytes_round_trip(tmp_path):
    target = tmp_path / "out.bin"
    atomic_write(target, b"\x00\x01\x02payload")
    assert target.read_bytes() == b"\x00\x01\x02payload"


def test_atomic_write_creates_parent_dirs(tmp_path):
    target = tmp_path / "deep" / "nested" / "out.txt"
    atomic_write(target, "made the path")
    assert target.read_text(encoding="utf-8") == "made the path"


def test_atomic_write_overwrites_existing(tmp_path):
    target = tmp_path / "out.txt"
    target.write_text("old", encoding="utf-8")
    atomic_write(target, "new")
    assert target.read_text(encoding="utf-8") == "new"


def test_atomic_write_leaves_no_temp_file(tmp_path):
    # The temp file must be renamed away, never left as litter.
    target = tmp_path / "out.txt"
    atomic_write(target, "clean")
    assert _tmp_files(tmp_path) == []


def test_atomic_write_rejects_bad_type_without_touching_target(tmp_path):
    target = tmp_path / "out.txt"
    target.write_text("intact", encoding="utf-8")
    with pytest.raises(TypeError):
        atomic_write(target, 12345)  # not str/bytes
    assert target.read_text(encoding="utf-8") == "intact"
    assert _tmp_files(tmp_path) == []


# ── atomic_write_json ────────────────────────────────────────────────────────

def test_atomic_write_json_round_trip(tmp_path):
    target = tmp_path / "state.json"
    obj = {"trusted": {"aa:bb": {"label": "router"}}, "n": 3, "flag": True}
    atomic_write_json(target, obj)
    assert json.loads(target.read_text(encoding="utf-8")) == obj


def test_atomic_write_json_preserves_unicode(tmp_path):
    target = tmp_path / "state.json"
    atomic_write_json(target, {"name": "Ω router café"})
    text = target.read_text(encoding="utf-8")
    assert "Ω router café" in text  # ensure_ascii=False by default


def test_atomic_write_json_bad_object_leaves_target_intact(tmp_path):
    target = tmp_path / "state.json"
    atomic_write_json(target, {"good": 1})
    with pytest.raises(TypeError):
        atomic_write_json(target, {"bad": {1, 2, 3}})  # set is not JSON-serializable
    # dumps fails before any file write, so the good value survives.
    assert json.loads(target.read_text(encoding="utf-8")) == {"good": 1}
    assert _tmp_files(tmp_path) == []


# ── read_json ────────────────────────────────────────────────────────────────

def test_read_json_valid(tmp_path):
    target = tmp_path / "state.json"
    target.write_text('{"a": 1}', encoding="utf-8")
    assert read_json(target) == {"a": 1}


def test_read_json_missing_returns_default_no_quarantine(tmp_path):
    target = tmp_path / "absent.json"
    assert read_json(target, default={}) == {}
    # A missing file is normal, not corruption — nothing is quarantined.
    assert not (tmp_path / "absent.json.corrupt").exists()


def test_read_json_corrupt_is_quarantined(tmp_path):
    target = tmp_path / "state.json"
    target.write_text("{ this is not valid json", encoding="utf-8")
    result = read_json(target, default={"reset": True})
    # Caller gets the default...
    assert result == {"reset": True}
    # ...but the bad data is preserved aside, not silently discarded.
    assert not target.exists()
    corrupt = tmp_path / "state.json.corrupt"
    assert corrupt.exists()
    assert corrupt.read_text(encoding="utf-8") == "{ this is not valid json"


def test_read_json_corrupt_quarantine_overwrites_prior(tmp_path):
    target = tmp_path / "state.json"
    (tmp_path / "state.json.corrupt").write_text("older corrupt", encoding="utf-8")
    target.write_text("newer corrupt {", encoding="utf-8")
    read_json(target)
    assert (tmp_path / "state.json.corrupt").read_text(encoding="utf-8") == "newer corrupt {"


def test_write_then_read_round_trip(tmp_path):
    target = tmp_path / "state.json"
    atomic_write_json(target, {"baseline_gateway_mac": "aa:bb:cc:dd:ee:ff"})
    assert read_json(target) == {"baseline_gateway_mac": "aa:bb:cc:dd:ee:ff"}


# ── sweep_stale_tmp ──────────────────────────────────────────────────────────

def test_sweep_removes_stale_tmp_only(tmp_path):
    # Simulate leftovers from a crashed atomic_write, plus unrelated files.
    (tmp_path / ".state.json.abc123.tmp").write_text("half", encoding="utf-8")
    (tmp_path / ".other.xyz.tmp").write_text("half", encoding="utf-8")
    keep_json = tmp_path / "state.json"
    keep_json.write_text("{}", encoding="utf-8")
    keep_plain_tmp = tmp_path / "report.tmp"  # not dot-prefixed -> not ours
    keep_plain_tmp.write_text("keep", encoding="utf-8")

    removed = sweep_stale_tmp(tmp_path)

    assert removed == 2
    assert _tmp_files(tmp_path) == []
    assert keep_json.exists()
    assert keep_plain_tmp.exists()


def test_sweep_missing_dir_returns_zero(tmp_path):
    assert sweep_stale_tmp(tmp_path / "does-not-exist") == 0
