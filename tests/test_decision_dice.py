"""Tests for tools/decision_dice.py — pure helpers + JSON persistence (Plan B / B4).

Covers:
    * Color helpers: hex_to_rgb, rgb_to_hex (with clamp), lerp_color.
    * build_pool: weighted sampling list + zero-total fallback.
    * load_profiles / save_profiles / load_journal / save_journal:
      missing-file, happy roundtrip, corrupt-JSON, and the journal cap.

No Tk/CTk instantiation — only import-level side-effects are exercised.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import decision_dice as dd  # noqa: E402


# ── Color helpers ────────────────────────────────────────────────────

def test_hex_to_rgb_accepts_with_and_without_hash():
    assert dd.hex_to_rgb("#ff0000") == (255, 0, 0)
    assert dd.hex_to_rgb("00ff00") == (0, 255, 0)
    assert dd.hex_to_rgb("#0000ff") == (0, 0, 255)


def test_rgb_to_hex_clamps_out_of_range_values():
    assert dd.rgb_to_hex(300, -10, 128) == "#ff0080"
    assert dd.rgb_to_hex(0, 0, 0) == "#000000"
    assert dd.rgb_to_hex(255, 255, 255) == "#ffffff"


def test_rgb_to_hex_floors_floats():
    assert dd.rgb_to_hex(127.9, 127.1, 127.5) == "#7f7f7f"


def test_lerp_color_endpoints_and_midpoint():
    assert dd.lerp_color("#000000", "#ffffff", 0.0) == "#000000"
    assert dd.lerp_color("#000000", "#ffffff", 1.0) == "#ffffff"
    mid = dd.lerp_color("#000000", "#ffffff", 0.5)
    # Midpoint rounds down via int(); 127 is expected.
    assert mid == "#7f7f7f"


# ── build_pool ───────────────────────────────────────────────────────

def test_build_pool_expands_by_weight():
    outcomes = [
        {"label": "A", "weight": 3},
        {"label": "B", "weight": 1},
    ]
    pool = dd.build_pool(outcomes)
    labels = [o["label"] for o in pool]
    assert labels.count("A") == 3
    assert labels.count("B") == 1
    assert len(pool) == 4


def test_build_pool_all_zero_weights_falls_back_to_first():
    outcomes = [
        {"label": "A", "weight": 0},
        {"label": "B", "weight": 0},
    ]
    pool = dd.build_pool(outcomes)
    assert pool == [outcomes[0]]


def test_build_pool_treats_negative_weight_as_zero():
    outcomes = [
        {"label": "A", "weight": -5},
        {"label": "B", "weight": 2},
    ]
    pool = dd.build_pool(outcomes)
    assert [o["label"] for o in pool] == ["B", "B"]


# ── Profile persistence ──────────────────────────────────────────────

def test_load_profiles_returns_defaults_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "PROFILES_PATH", str(tmp_path / "missing.json"))
    profiles = dd.load_profiles()
    assert profiles == dict(dd.DEFAULT_PROFILES)
    # Returned dict must be independent of the module-level constant.
    profiles["new"] = [1, 2, 3, 4]
    assert "new" not in dd.DEFAULT_PROFILES


def test_save_and_load_profiles_roundtrip(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(dd, "PROFILES_PATH", str(path))
    payload = {"Custom": [10, 20, 30, 40]}
    dd.save_profiles(payload)
    assert path.is_file()
    assert dd.load_profiles() == payload


def test_load_profiles_returns_defaults_on_corrupt_json(tmp_path, monkeypatch):
    path = tmp_path / "profiles.json"
    path.write_text("{not valid json", encoding="utf-8")
    monkeypatch.setattr(dd, "PROFILES_PATH", str(path))
    assert dd.load_profiles() == dict(dd.DEFAULT_PROFILES)


# ── Journal persistence ──────────────────────────────────────────────

def test_load_journal_returns_empty_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(dd, "JOURNAL_PATH", str(tmp_path / "missing.json"))
    assert dd.load_journal() == []


def test_save_journal_caps_history_at_500_entries(tmp_path, monkeypatch):
    path = tmp_path / "journal.json"
    monkeypatch.setattr(dd, "JOURNAL_PATH", str(path))
    entries = [{"i": i} for i in range(750)]
    dd.save_journal(entries)
    persisted = json.loads(path.read_text(encoding="utf-8"))
    assert len(persisted) == 500
    # Cap keeps the tail, not the head.
    assert persisted[0] == {"i": 250}
    assert persisted[-1] == {"i": 749}


def test_load_journal_returns_empty_on_corrupt_json(tmp_path, monkeypatch):
    path = tmp_path / "journal.json"
    path.write_text("garbage", encoding="utf-8")
    monkeypatch.setattr(dd, "JOURNAL_PATH", str(path))
    assert dd.load_journal() == []


# ── play_sound ───────────────────────────────────────────────────────

def test_play_sound_unknown_kind_is_noop():
    # Unknown kind returns before spawning a thread; must not raise.
    dd.play_sound("not-a-real-sound-kind")


def test_play_sound_known_kind_spawns_daemon_thread(monkeypatch):
    """Known kind spawns a background thread — patched Beep keeps the test silent."""
    calls: list[tuple[int, int]] = []

    def fake_beep(freq: int, dur: int) -> None:
        calls.append((freq, dur))

    monkeypatch.setattr(dd, "_beep_thread", fake_beep)
    dd.play_sound("tick")
    # Thread is daemon; join via a tight poll so test stays fast.
    import threading
    import time
    deadline = time.time() + 1.0
    while not calls and time.time() < deadline:
        time.sleep(0.01)
    assert calls, "expected _beep_thread to be invoked by play_sound"
    # The only 'tick' note is (600, 15).
    assert calls[0] == (600, 15)
    # No leaked non-daemon threads.
    for t in threading.enumerate():
        if t is not threading.main_thread():
            assert t.daemon
