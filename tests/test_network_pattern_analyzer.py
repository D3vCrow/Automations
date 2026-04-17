"""Tests for tools/network_pattern_analyzer.py (Plan B / B4).

Covers pure-logic methods on NetworkPatternAnalyzer without instantiating
its Tk root. Bypass __init__ via __new__ and drive the analyzers directly
on in-memory fixtures.

Covered:
    * _parse_timestamp: valid, empty, garbage.
    * _calculate_duration_seconds: valid pair, either side invalid.
    * _get_date_range: empty, single-day, multi-day, all-invalid.
    * _analyze_summary / _analyze_time_distribution /
      _analyze_category_frequency / _analyze_average_duration /
      _analyze_repeating_time_windows / _analyze_sequential_correlations.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.network_pattern_analyzer import NetworkPatternAnalyzer  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def npa() -> NetworkPatternAnalyzer:
    """Bare analyzer with no Tk root — only pure helpers are exercised."""
    return NetworkPatternAnalyzer.__new__(NetworkPatternAnalyzer)


def _inc(start: str, end: str = "", category: str = "TIMEOUT") -> dict:
    return {"start_time": start, "end_time": end, "category": category}


# ── Timestamp parsing ────────────────────────────────────────────────

def test_parse_timestamp_valid(npa):
    dt = npa._parse_timestamp("2026-04-17 09:30:45")
    assert dt is not None
    assert (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) == (
        2026, 4, 17, 9, 30, 45,
    )


def test_parse_timestamp_empty_and_garbage_return_none(npa):
    assert npa._parse_timestamp("") is None
    assert npa._parse_timestamp("not-a-timestamp") is None
    # Missing seconds — strict format rejects.
    assert npa._parse_timestamp("2026-04-17 09:30") is None


def test_calculate_duration_seconds_valid(npa):
    seconds = npa._calculate_duration_seconds(
        "2026-04-17 09:00:00", "2026-04-17 09:05:30",
    )
    assert seconds == 330.0


def test_calculate_duration_seconds_invalid_returns_none(npa):
    assert npa._calculate_duration_seconds("", "2026-04-17 09:00:00") is None
    assert npa._calculate_duration_seconds("2026-04-17 09:00:00", "") is None
    assert npa._calculate_duration_seconds("", "") is None


# ── Date range ───────────────────────────────────────────────────────

def test_get_date_range_empty(npa):
    assert npa._get_date_range([]) == "No data"


def test_get_date_range_all_invalid_returns_sentinel(npa):
    incidents = [_inc(""), _inc("garbage")]
    assert npa._get_date_range(incidents) == "No valid timestamps"


def test_get_date_range_single_day(npa):
    incidents = [
        _inc("2026-04-17 09:00:00"),
        _inc("2026-04-17 18:30:00"),
    ]
    assert npa._get_date_range(incidents) == "2026-04-17"


def test_get_date_range_multi_day(npa):
    incidents = [
        _inc("2026-04-17 09:00:00"),
        _inc("2026-04-19 10:00:00"),
        _inc("2026-04-18 11:00:00"),
    ]
    assert npa._get_date_range(incidents) == "2026-04-17 to 2026-04-19"


# ── Summary ──────────────────────────────────────────────────────────

def test_analyze_summary_shape_and_counts(npa):
    incidents = [
        _inc("2026-04-17 09:00:00", category="TIMEOUT"),
        _inc("2026-04-17 10:00:00", category="DNS_FAIL"),
        _inc("2026-04-17 11:00:00", category="TIMEOUT"),
    ]
    events = [{"ts": "x"}, {"ts": "y"}]
    summary = npa._analyze_summary(incidents, events)
    assert summary["total_incidents"] == 3
    assert summary["total_events"] == 2
    assert summary["unique_categories"] == 2
    assert summary["date_range"] == "2026-04-17"


def test_analyze_summary_treats_missing_category_as_unknown(npa):
    incidents = [{"start_time": "2026-04-17 09:00:00"}]
    summary = npa._analyze_summary(incidents, [])
    assert summary["unique_categories"] == 1  # 'UNKNOWN'


# ── Time distribution ────────────────────────────────────────────────

def test_analyze_time_distribution_returns_24_buckets(npa):
    dist = npa._analyze_time_distribution([])
    assert len(dist) == 24
    assert all(v == 0 for v in dist.values())
    assert set(dist.keys()) == {f"{h:02d}" for h in range(24)}


def test_analyze_time_distribution_counts_by_hour(npa):
    incidents = [
        _inc("2026-04-17 09:05:00"),
        _inc("2026-04-17 09:55:00"),
        _inc("2026-04-17 14:00:00"),
        _inc("bad-timestamp"),  # ignored
    ]
    dist = npa._analyze_time_distribution(incidents)
    assert dist["09"] == 2
    assert dist["14"] == 1
    assert dist["00"] == 0


# ── Category frequency ──────────────────────────────────────────────

def test_analyze_category_frequency(npa):
    incidents = [
        _inc("2026-04-17 09:00:00", category="TIMEOUT"),
        _inc("2026-04-17 10:00:00", category="TIMEOUT"),
        _inc("2026-04-17 11:00:00", category="DNS_FAIL"),
        {"start_time": "2026-04-17 12:00:00"},  # UNKNOWN
    ]
    freq = npa._analyze_category_frequency(incidents)
    assert freq == {"TIMEOUT": 2, "DNS_FAIL": 1, "UNKNOWN": 1}


# ── Average duration ─────────────────────────────────────────────────

def test_analyze_average_duration_averages_per_category(npa):
    incidents = [
        {"start_time": "2026-04-17 09:00:00", "end_time": "2026-04-17 09:01:00",
         "category": "TIMEOUT"},  # 60s
        {"start_time": "2026-04-17 10:00:00", "end_time": "2026-04-17 10:02:00",
         "category": "TIMEOUT"},  # 120s → avg 90
        {"start_time": "2026-04-17 11:00:00", "end_time": "2026-04-17 11:05:00",
         "category": "DNS_FAIL"},  # 300s
        {"start_time": "", "end_time": "", "category": "NOISE"},  # skipped
    ]
    avg = npa._analyze_average_duration(incidents)
    assert avg["TIMEOUT"] == 90.0
    assert avg["DNS_FAIL"] == 300.0
    assert "NOISE" not in avg


# ── Repeating time windows ──────────────────────────────────────────

def test_analyze_repeating_time_windows_flags_above_average_hours(npa):
    incidents = (
        [_inc("2026-04-17 09:10:00")] * 5  # hour 09 → 5
        + [_inc("2026-04-17 14:00:00")] * 3  # hour 14 → 3
        + [_inc("2026-04-17 22:00:00")]      # hour 22 → 1
    )
    # Average = (5+3+1)/3 = 3.0 → only hour 09 is strictly above average.
    result = npa._analyze_repeating_time_windows(incidents)
    assert len(result) == 1
    assert result[0]["hour"] == 9
    assert result[0]["incidents"] == 5
    assert result[0]["above_average"] is True


def test_analyze_repeating_time_windows_empty_when_no_incidents(npa):
    assert npa._analyze_repeating_time_windows([]) == []


# ── Sequential correlations ─────────────────────────────────────────

def test_analyze_sequential_correlations_detects_sub10min_pairs(npa):
    incidents = [
        _inc("2026-04-17 09:00:00", category="DNS_FAIL"),
        _inc("2026-04-17 09:05:00", category="TIMEOUT"),     # 5min after — pair
        _inc("2026-04-17 09:12:00", category="DNS_FAIL"),    # 7min after — pair
        _inc("2026-04-17 10:30:00", category="TIMEOUT"),     # 78min — skipped
    ]
    result = npa._analyze_sequential_correlations(incidents)
    patterns = {item["pattern"]: item for item in result}

    assert "DNS_FAIL → TIMEOUT" in patterns
    assert "TIMEOUT → DNS_FAIL" in patterns
    assert patterns["DNS_FAIL → TIMEOUT"]["occurrences"] == 1
    assert patterns["TIMEOUT → DNS_FAIL"]["occurrences"] == 1
    # Two pairs total → each is 50%.
    assert patterns["DNS_FAIL → TIMEOUT"]["percentage"] == 50.0
    assert patterns["TIMEOUT → DNS_FAIL"]["percentage"] == 50.0


def test_analyze_sequential_correlations_empty_input(npa):
    assert npa._analyze_sequential_correlations([]) == []
    assert npa._analyze_sequential_correlations([_inc("2026-04-17 09:00:00")]) == []
