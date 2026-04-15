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


from tools.claude_usage_monitor import (  # noqa: E402
    _estimate_tool_tokens,
    _estimate_tool_cost,
)


def test_estimate_tool_tokens_none_and_empty():
    assert _estimate_tool_tokens(None) == 0
    assert _estimate_tool_tokens("") == 0
    assert _estimate_tool_tokens({}) > 0  # "{}" -> 1 token min


def test_estimate_tool_tokens_uses_4_chars_per_token_heuristic():
    # A 40-char JSON string should be ~10 tokens
    payload = {"x": "a" * 30}   # serialized as {"x": "aaaa...a"} -> 40-ish chars
    tokens = _estimate_tool_tokens(payload)
    assert 8 <= tokens <= 14


def test_estimate_tool_cost_uses_pricing():
    pricing = {"input": 3.0, "output": 15.0}
    # 1M in tokens -> $3, 1M out tokens -> $15, combined $18
    assert _estimate_tool_cost(1_000_000, 1_000_000, pricing) == 18.0


def test_estimate_tool_cost_zero_tokens_zero_cost():
    pricing = {"input": 3.0, "output": 15.0}
    assert _estimate_tool_cost(0, 0, pricing) == 0.0


from tools.claude_usage_monitor import (  # noqa: E402
    _rotate_subscores,
    _rotate_pill_state,
    _rotate_explanation,
)


def _make_session(turn_costs, *, assistant_turns=None, cluster_end=False, trend=None):
    """Build a minimal session dict for score tests."""
    return {
        "turn_costs": turn_costs,
        "assistant_turns": assistant_turns or len(turn_costs),
        "cold_turns_cluster_end": cluster_end,
        "cache_trend": trend,
    }


def _turn(cost, inp=2000, out=500, cr=10_000, cw=0, model="claude-sonnet-4-6"):
    return ("t", cost, inp, out, cr, cw, model)


def test_rotate_subscores_none_below_5_turns():
    assert _rotate_subscores(_make_session([_turn(0.1)] * 4)) is None


def test_rotate_pill_state_thresholds():
    assert _rotate_pill_state(0)[0] == "KEEP GOING"
    assert _rotate_pill_state(29.9)[0] == "KEEP GOING"
    assert _rotate_pill_state(30)[0] == "CONSIDER ROTATING"
    assert _rotate_pill_state(59.9)[0] == "CONSIDER ROTATING"
    assert _rotate_pill_state(60)[0] == "ROTATE NOW"
    assert _rotate_pill_state(100)[0] == "ROTATE NOW"


def test_rotate_total_is_zero_for_uniform_cheap_session():
    # 10 identical turns, nothing bad -> all subscores 0
    session = _make_session([_turn(0.05)] * 10, assistant_turns=10, trend=0.0)
    sub = _rotate_subscores(session)
    assert sub is not None
    assert sub["total"] < 1.0


def test_rotate_total_red_for_severe_signals():
    # Small cold-start turns, bloated bloated late turns, degrading cache.
    # Waste factor must be > 1, so early-turn token totals are smaller than late.
    first5 = [_turn(cost=0.05, inp=1500, out=200, cr=800, cw=0)] * 5
    last5 = [_turn(cost=0.80, inp=8000, out=500, cr=1500, cw=0)] * 5
    session = _make_session(
        first5 + last5,
        assistant_turns=50,
        cluster_end=True,
        trend=-0.2,
    )
    sub = _rotate_subscores(session)
    assert sub is not None
    # savings ~94, waste ~75, trend 40, turns 50, cluster 100
    # -> 0.50*94 + 0.20*75 + 0.15*40 + 0.10*50 + 0.05*100 ~= 78
    assert sub["total"] >= 60   # red territory


def test_rotate_explanation_picks_dominant_factor():
    first5 = [_turn(cost=0.05)] * 5
    last5 = [_turn(cost=0.50)] * 5
    session = _make_session(first5 + last5, assistant_turns=20, trend=0.0)
    sub = _rotate_subscores(session)
    assert sub is not None
    text = _rotate_explanation(sub)
    # Savings should dominate (huge cost delta, nothing else triggered)
    assert "projected fresh" in text
