"""Tests for tools/security_audit.py — helpers + Finding + Engine (Plan B / B4).

Covers:
    * now_ts format, _age_days on tmp file + missing-path sentinel.
    * _is_suspicious_path: empty, SAFE_PROCESS_PATHS, suspicious buckets.
    * Finding.key() determinism + dedup across identical instances.
    * SecurityAuditEngine: load/save state, baseline lifecycle, get_checks.

check_* methods hit the real registry/psutil/subprocess and are out of
scope for smoke tests — they need a full mock harness (Plan A/B8 work).
"""

from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import security_audit as sa  # noqa: E402
from tools.security_audit import Finding, SecurityAuditEngine  # noqa: E402


# ── now_ts ───────────────────────────────────────────────────────────

def test_now_ts_matches_iso_minute_shape():
    """Format is YYYY-MM-DD HH:MM:SS (local time)."""
    assert re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$", sa.now_ts())


# ── _age_days ────────────────────────────────────────────────────────

def test_age_days_recent_file_is_near_zero(tmp_path):
    f = tmp_path / "fresh.txt"
    f.write_text("x")
    # Newly-written file: age is well under a day.
    # abs() tolerates Windows clock jitter that can produce tiny
    # negative values (~1e-12) when reads outpace the timer tick.
    assert abs(sa._age_days(str(f))) < 0.01


def test_age_days_missing_path_returns_sentinel(tmp_path):
    assert sa._age_days(str(tmp_path / "does-not-exist")) == 9999


# ── _is_suspicious_path ──────────────────────────────────────────────

def test_is_suspicious_path_empty_returns_false():
    assert sa._is_suspicious_path("") is False


def test_is_suspicious_path_safe_system_paths():
    assert sa._is_suspicious_path(r"C:\Windows\System32\svchost.exe") is False
    assert sa._is_suspicious_path(r"C:\Program Files\Foo\foo.exe") is False
    assert sa._is_suspicious_path(r"C:\Program Files (x86)\Bar\bar.exe") is False


def test_is_suspicious_path_flags_temp_and_downloads():
    assert sa._is_suspicious_path(r"C:\Users\foo\AppData\Local\Temp\weird.exe") is True
    assert sa._is_suspicious_path(r"C:\Users\foo\Downloads\installer.exe") is True
    assert sa._is_suspicious_path(r"C:\Temp\payload.exe") is True
    assert sa._is_suspicious_path(r"C:\Users\Public\dropped.exe") is True


def test_is_suspicious_path_safe_override_wins_over_suspicious():
    """SAFE_PROCESS_PATHS short-circuits before the suspicious check."""
    # System32 path that also contains 'temp' — safe list must win.
    assert sa._is_suspicious_path(
        r"C:\Windows\System32\TempSomething\thing.exe"
    ) is False


# ── Finding.key ──────────────────────────────────────────────────────

def test_finding_key_is_stable_for_identical_fields():
    a = Finding("startup", "CRITICAL", "t", "detail")
    b = Finding("startup", "CRITICAL", "t", "detail")
    assert a.key() == b.key()
    # Key is a 16-char hex digest prefix.
    assert re.match(r"^[0-9a-f]{16}$", a.key())


def test_finding_key_changes_with_category_title_or_detail_head():
    base = Finding("startup", "INFO", "title", "detail")
    assert base.key() != Finding("processes", "INFO", "title", "detail").key()
    assert base.key() != Finding("startup", "INFO", "other", "detail").key()
    assert base.key() != Finding("startup", "INFO", "title", "different").key()


def test_finding_key_ignores_detail_beyond_first_120_chars():
    shared_prefix = "x" * 120
    a = Finding("c", "INFO", "t", shared_prefix + "AAAAA")
    b = Finding("c", "INFO", "t", shared_prefix + "BBBBB")
    assert a.key() == b.key()


def test_finding_key_unaffected_by_severity_or_remediation():
    """key() is a dedup token — not a full fingerprint."""
    a = Finding("c", "INFO", "t", "d", remediation="one")
    b = Finding("c", "CRITICAL", "t", "d", remediation="two")
    assert a.key() == b.key()


# ── SecurityAuditEngine state persistence ───────────────────────────

def test_engine_loads_default_state_when_file_missing(tmp_path):
    engine = SecurityAuditEngine(str(tmp_path / "missing.json"))
    assert engine.state == {"baseline": None, "last_scan": None, "last_findings": []}


def test_engine_loads_default_state_on_corrupt_json(tmp_path):
    state_path = tmp_path / "state.json"
    state_path.write_text("{not json", encoding="utf-8")
    engine = SecurityAuditEngine(str(state_path))
    assert engine.state["baseline"] is None
    assert engine.state["last_findings"] == []


def test_save_and_reload_state_roundtrip(tmp_path):
    state_path = tmp_path / "state.json"
    engine = SecurityAuditEngine(str(state_path))
    engine.state["last_scan"] = "2026-04-17 09:00:00"
    engine.save_state()

    reopened = SecurityAuditEngine(str(state_path))
    assert reopened.state["last_scan"] == "2026-04-17 09:00:00"


# ── Baseline lifecycle ───────────────────────────────────────────────

def test_save_baseline_stores_keys_and_clears(tmp_path):
    engine = SecurityAuditEngine(str(tmp_path / "state.json"))
    findings = [
        Finding("startup", "CRITICAL", "A", "detail-a"),
        Finding("processes", "WARN", "B", "detail-b"),
    ]
    engine.save_baseline(findings)

    keys = engine.get_baseline_keys()
    assert keys == {f.key() for f in findings}
    # Persisted shape matches the expected schema.
    on_disk = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert on_disk["baseline"]["finding_keys"] == [f.key() for f in findings]
    assert "saved_at" in on_disk["baseline"]

    engine.clear_baseline()
    assert engine.get_baseline_keys() == set()


def test_get_baseline_keys_returns_empty_set_when_no_baseline(tmp_path):
    engine = SecurityAuditEngine(str(tmp_path / "state.json"))
    assert engine.get_baseline_keys() == set()


# ── Engine wiring ────────────────────────────────────────────────────

def test_get_checks_returns_all_10_categories(tmp_path):
    engine = SecurityAuditEngine(str(tmp_path / "state.json"))
    checks = engine.get_checks()
    assert len(checks) == 10
    names = [name for name, _fn in checks]
    assert names == [
        "startup", "processes", "ports", "filesystem", "dns",
        "accounts", "wifi", "usb", "browser", "eventlogs",
    ]
    # All check callables are bound methods on the engine.
    for _name, fn in checks:
        assert callable(fn)
        assert getattr(fn, "__self__", None) is engine
