"""Tests for pure helper functions in claude_usage_monitor."""
from pathlib import Path
import sys

# Make 'tools' importable when running pytest from project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.claude_usage_monitor import (  # noqa: E402
    _is_cold_turn,
    _cache_efficiency,
    _cache_trend,
    _cold_turn_count,
    _cold_turns_cluster_end,
)


# ---------- _is_cold_turn ----------

def test_is_cold_turn_true_when_mostly_fresh_input():
    # 5000 input, 1000 cache_read -> ratio = 1000 / 6000 = 0.167 < 0.5, and input >= 2000
    assert _is_cold_turn(5000, 1000) is True


def test_is_cold_turn_false_when_cache_dominates():
    # 3000 input, 20000 cache_read -> ratio = 20000 / 23000 = 0.87 >= 0.5
    assert _is_cold_turn(3000, 20000) is False


def test_is_cold_turn_false_for_tiny_turns_regardless_of_ratio():
    # 500 input (below 2000 floor) -> always False
    assert _is_cold_turn(500, 0) is False


def test_is_cold_turn_false_when_both_zero():
    assert _is_cold_turn(0, 0) is False


# ---------- _cache_efficiency ----------

def test_cache_efficiency_zero_when_no_tokens():
    assert _cache_efficiency(0, 0, 0) == 0.0


def test_cache_efficiency_ratio_formula():
    # cache_read=7000, total denom = 1000 + 7000 + 2000 = 10000 -> 0.7
    assert _cache_efficiency(1000, 7000, 2000) == 0.7


# ---------- _cache_trend ----------

def test_cache_trend_none_when_too_few_turns():
    turns = [("t", 0.0, 100, 50, 0, 0, "m")] * 9
    assert _cache_trend(turns) is None


def test_cache_trend_negative_when_cache_degrades():
    # First 5: strong cache (90% eff). Last 5: weak cache (10% eff).
    warm = [("t", 0.0, 1000, 50, 9000, 0, "m")] * 5
    cold = [("t", 0.0, 9000, 50, 1000, 0, "m")] * 5
    trend = _cache_trend(warm + cold)
    assert trend is not None
    assert trend < -0.5


def test_cache_trend_near_zero_when_stable():
    turns = [("t", 0.0, 1000, 50, 5000, 0, "m")] * 10
    trend = _cache_trend(turns)
    assert trend is not None
    assert abs(trend) < 0.01


# ---------- _cold_turn_count ----------

def test_cold_turn_count_mixed():
    turns = [
        ("t", 0.0, 5000, 50, 500, 0, "m"),    # cold (big input, low cache)
        ("t", 0.0, 3000, 50, 10000, 0, "m"),  # warm
        ("t", 0.0, 500, 50, 0, 0, "m"),       # tiny - not cold
        ("t", 0.0, 6000, 50, 100, 0, "m"),    # cold
    ]
    assert _cold_turn_count(turns) == 2


# ---------- _cold_turns_cluster_end ----------

def test_cold_turns_cluster_end_false_with_few_turns():
    turns = [("t", 0.0, 5000, 50, 0, 0, "m")] * 3
    assert _cold_turns_cluster_end(turns) is False


def test_cold_turns_cluster_end_true_when_3_of_last_5_are_cold():
    warm = ("t", 0.0, 2000, 50, 10000, 0, "m")
    cold = ("t", 0.0, 5000, 50, 100, 0, "m")
    turns = [warm, warm, warm, cold, cold, warm, cold]  # last 5: warm, cold, cold, warm, cold
    assert _cold_turns_cluster_end(turns) is True


def test_cold_turns_cluster_end_false_when_only_2_of_last_5_are_cold():
    warm = ("t", 0.0, 2000, 50, 10000, 0, "m")
    cold = ("t", 0.0, 5000, 50, 100, 0, "m")
    turns = [warm, warm, warm, warm, cold, warm, cold]  # last 5: warm, warm, cold, warm, cold
    assert _cold_turns_cluster_end(turns) is False
