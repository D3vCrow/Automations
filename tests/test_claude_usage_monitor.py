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


# =============================================================================
# A6 — Peak-hours timezone & model prefix fixes
# =============================================================================

from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from tools.claude_usage_monitor import (  # noqa: E402
    _parse_timestamp,
    _get_pricing,
    LOCAL_TZ,
)


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    """Build a UTC ISO-8601 string the way JSONL logs write them."""
    dt = datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


class TestParseTimestamp:
    """_parse_timestamp must always return a tz-aware datetime in UTC."""

    def test_z_suffix_returns_utc_aware(self):
        ts = _parse_timestamp("2024-06-01T14:00:00Z")
        assert ts is not None
        assert ts.tzinfo is not None
        assert ts.utcoffset() == timedelta(0)

    def test_explicit_offset_preserved(self):
        ts = _parse_timestamp("2024-06-01T14:00:00+05:00")
        assert ts is not None
        assert ts.utcoffset() == timedelta(hours=5)

    def test_empty_string_returns_none(self):
        assert _parse_timestamp("") is None

    def test_garbage_returns_none(self):
        assert _parse_timestamp("not-a-date") is None


class TestPeakHoursTZ:
    """UTC->local roundtrip for hour bucketing must be correct across offsets."""

    def _local_hour(self, ts_str: str, tz: ZoneInfo) -> int:
        """Parse ts_str and convert to local hour in the given tz."""
        ts = _parse_timestamp(ts_str)
        assert ts is not None
        return ts.astimezone(tz).hour

    def test_utc_minus_5_14z_is_9_local(self):
        # 14:00 UTC = 09:00 America/New_York (EST, UTC-5)
        tz = ZoneInfo("America/New_York")
        iso = _utc_iso(2024, 1, 15, 14)  # January = EST (no DST)
        assert self._local_hour(iso, tz) == 9

    def test_utc_zero_hour_unchanged(self):
        tz = ZoneInfo("UTC")
        iso = _utc_iso(2024, 6, 1, 17)
        assert self._local_hour(iso, tz) == 17

    def test_utc_plus_5_14z_is_19_local(self):
        # 14:00 UTC = 19:00 Asia/Karachi (PKT, UTC+5)
        tz = ZoneInfo("Asia/Karachi")
        iso = _utc_iso(2024, 6, 1, 14)
        assert self._local_hour(iso, tz) == 19

    def test_dst_spring_forward_us(self):
        # 2024-03-10 07:00 UTC = 02:00 EST → clocks spring to 03:00 EDT
        # Just before: 06:59 UTC = 01:59 EST
        # Just after:  07:01 UTC = 03:01 EDT
        tz = ZoneInfo("America/New_York")
        before = _parse_timestamp("2024-03-10T06:59:00Z")
        after = _parse_timestamp("2024-03-10T07:01:00Z")
        assert before is not None and after is not None
        assert before.astimezone(tz).hour == 1
        assert after.astimezone(tz).hour == 3  # jumped from 2->3

    def test_peak_hours_pill_same_tz_reference(self):
        # Simulate what _render_peak_hours does: build hour_costs from UTC stamps,
        # compare now_hour from LOCAL_TZ. Both must use the same offset.
        # We don't run the GUI; just verify the key expressions agree.
        import datetime as dt_mod
        now_aware = dt_mod.datetime.now().astimezone(LOCAL_TZ)
        now_naive_fallback = dt_mod.datetime.now()
        # On a non-UTC host these will differ; on UTC they're equal.
        # The important thing: both are integers in 0-23.
        assert 0 <= now_aware.hour <= 23
        # Aware version must match wall-clock hour (tested via offset arithmetic)
        utc_now = dt_mod.datetime.now(tz=timezone.utc)
        local_offset = now_aware.utcoffset()
        expected_hour = (utc_now + local_offset).hour % 24
        assert now_aware.hour == expected_hour


class TestMonthsSpanned:
    """_months_spanned uses tz-aware subtraction — no DST confusion."""

    def _make_monitor_with_sessions(self, sessions: list):
        """Return a minimal object whose _sessions attr lets _months_spanned run."""
        import types
        # Patch just the method onto a plain object — no GUI needed.
        from tools.claude_usage_monitor import ClaudeUsageMonitor
        obj = object.__new__(ClaudeUsageMonitor)
        obj._sessions = sessions
        return obj

    def test_cross_year_boundary(self):
        sessions = [
            {"first_timestamp": "2023-12-01T00:00:00Z",
             "last_timestamp":  "2024-01-31T00:00:00Z"},
        ]
        m = self._make_monitor_with_sessions(sessions)
        result = m._months_spanned()
        # 61 days -> 2.03 months
        assert result > 2.0

    def test_same_day_returns_one(self):
        sessions = [
            {"first_timestamp": "2024-06-15T10:00:00Z",
             "last_timestamp":  "2024-06-15T22:00:00Z"},
        ]
        m = self._make_monitor_with_sessions(sessions)
        assert m._months_spanned() == 1.0

    def test_across_dst_spring_forward(self):
        # Spans US spring-forward; tz-aware subtraction gives exact days.
        sessions = [
            {"first_timestamp": "2024-03-09T12:00:00Z",
             "last_timestamp":  "2024-03-11T12:00:00Z"},
        ]
        m = self._make_monitor_with_sessions(sessions)
        # 2 days -> 2/30 = 0.067 < 1 -> clamped to 1.0
        assert m._months_spanned() == 1.0

    def test_missing_timestamps_returns_one(self):
        m = self._make_monitor_with_sessions([{}])
        assert m._months_spanned() == 1.0


class TestGetPricing:
    """Model prefix matching must not cross version boundaries."""

    def test_exact_match_wins(self):
        p = _get_pricing("claude-sonnet-4-6")
        assert p["input"] == 3.0

    def test_unknown_model_returns_default(self):
        p = _get_pricing("claude-unknown-99")
        # Default is sonnet-4-6 rates
        assert p["input"] == 3.0

    def test_opus5_does_not_match_opus4_pricing(self):
        # "claude-opus-5" must NOT fall through to claude-opus-4-x pricing.
        # It's not in MODEL_PRICING so it gets _DEFAULT_PRICING, not opus-4 rates.
        # Old rsplit bug: rsplit("-",1)[0] of "claude-opus-4-6" = "claude-opus-4"
        # which would match "claude-opus-5" if startswith("claude-opus-4") -> False.
        # New bug we guard: if "claude-opus-5" were added, sorted-longest-first
        # means no shorter "claude-opus-4" prefix ever captures it.
        p_opus4 = _get_pricing("claude-opus-4-6")
        p_unknown = _get_pricing("claude-opus-5")
        # opus-5 not in pricing dict -> falls back to default (sonnet rates)
        assert p_unknown is not p_opus4
        assert p_unknown["input"] != p_opus4["input"] or p_unknown is _get_pricing("")

    def test_versioned_suffix_matches_longest_key(self):
        # "claude-sonnet-4-6-something" should match "claude-sonnet-4-6", not "claude-sonnet-4"
        p = _get_pricing("claude-sonnet-4-6-something")
        assert p["input"] == 3.0  # sonnet-4-6 rates, not some shorter match

    def test_empty_model_returns_default(self):
        assert _get_pricing("") is not None
        assert _get_pricing("") == _get_pricing("claude-sonnet-4-6")


# =============================================================================
# T1 — mtime-cache for JSONL parsing
# =============================================================================

from tools.claude_usage_monitor import (  # noqa: E402
    _parse_session_file_cached,
    _SESSION_CACHE,
)


class TestSessionMtimeCache:
    """_parse_session_file_cached must skip re-parse on unchanged mtime."""

    def _write_jsonl(self, path: Path) -> None:
        # Minimal assistant turn so _parse_session_file produces a session dict.
        line = {
            "type": "assistant",
            "timestamp": "2026-04-20T10:00:00Z",
            "sessionId": "sid-mtime",
            "cwd": str(path.parent),
            "message": {
                "model": "claude-sonnet-4-6",
                "usage": {
                    "input_tokens": 100, "output_tokens": 50,
                    "cache_read_input_tokens": 0,
                    "cache_creation_input_tokens": 0,
                },
            },
        }
        import json as _json
        path.write_text(_json.dumps(line) + "\n", encoding="utf-8")

    def test_cache_hit_returns_same_object(self, tmp_path):
        _SESSION_CACHE.clear()
        f = tmp_path / "s.jsonl"
        self._write_jsonl(f)
        first = _parse_session_file_cached(str(f))
        second = _parse_session_file_cached(str(f))
        assert first is second  # cached dict reused by identity

    def test_cache_invalidates_on_mtime_change(self, tmp_path):
        import os as _os, time as _time
        _SESSION_CACHE.clear()
        f = tmp_path / "s.jsonl"
        self._write_jsonl(f)
        first = _parse_session_file_cached(str(f))
        # Bump mtime by 2s to guarantee filesystem granularity picks it up.
        new_mtime = _os.path.getmtime(f) + 2
        _os.utime(f, (new_mtime, new_mtime))
        second = _parse_session_file_cached(str(f))
        assert first is not second  # re-parsed, fresh object

    def test_missing_file_falls_through_without_caching(self, tmp_path):
        _SESSION_CACHE.clear()
        missing = tmp_path / "nope.jsonl"
        result = _parse_session_file_cached(str(missing))
        # Missing files produce a session dict with 0 turns, not a crash.
        assert result["assistant_turns"] == 0
        assert str(missing) not in _SESSION_CACHE


# =============================================================================
# T4 — time-window filter bucketing
# =============================================================================

from tools.claude_usage_monitor import ClaudeUsageMonitor  # noqa: E402


class TestWindowFilter:
    """_session_in_window must bucket sessions against Today/Week/Month cutoffs."""

    def _monitor(self, window: str):
        obj = object.__new__(ClaudeUsageMonitor)
        obj._window = window
        return obj

    def _session(self, ts: datetime) -> dict:
        return {"last_timestamp": ts.isoformat().replace("+00:00", "Z")}

    def test_all_passes_everything(self):
        m = self._monitor("All")
        ancient = self._session(datetime(2000, 1, 1, tzinfo=timezone.utc))
        assert m._session_in_window(ancient) is True

    def test_today_excludes_yesterday(self):
        m = self._monitor("Today")
        now = datetime.now(timezone.utc)
        yesterday = self._session(now - timedelta(days=1))
        assert m._session_in_window(yesterday) is False

    def test_today_includes_current_hour(self):
        m = self._monitor("Today")
        now = datetime.now(timezone.utc)
        assert m._session_in_window(self._session(now)) is True

    def test_week_bucketing(self):
        m = self._monitor("Week")
        now = datetime.now(timezone.utc)
        assert m._session_in_window(self._session(now - timedelta(days=3))) is True
        assert m._session_in_window(self._session(now - timedelta(days=8))) is False

    def test_month_bucketing(self):
        m = self._monitor("Month")
        now = datetime.now(timezone.utc)
        assert m._session_in_window(self._session(now - timedelta(days=20))) is True
        assert m._session_in_window(self._session(now - timedelta(days=31))) is False

    def test_missing_timestamp_excluded_when_filtered(self):
        m = self._monitor("Today")
        assert m._session_in_window({}) is False

    def test_missing_timestamp_included_on_all(self):
        m = self._monitor("All")
        # 'All' short-circuits before timestamp parsing.
        assert m._session_in_window({}) is True


# =============================================================================
# T10 — notification dedup state
# =============================================================================

from tools.claude_usage_monitor import (  # noqa: E402
    _rotate_level,
    _should_notify,
    _record_notified,
    _evict_inactive_notifs,
)


class TestRotateLevel:
    def test_below_amber_is_none(self):
        assert _rotate_level(0) == "none"
        assert _rotate_level(29.9) == "none"

    def test_amber_threshold(self):
        assert _rotate_level(30) == "amber"
        assert _rotate_level(59.9) == "amber"

    def test_red_threshold(self):
        assert _rotate_level(60) == "red"
        assert _rotate_level(100) == "red"


class TestShouldNotify:
    """Fires only on tier upgrades; downgrades stay silent."""

    def test_first_alert_fires(self):
        state: dict = {}
        assert _should_notify(state, "s1", "amber") is True
        assert _should_notify(state, "s1", "red") is True

    def test_none_level_never_fires(self):
        assert _should_notify({}, "s1", "none") is False

    def test_same_level_no_refire(self):
        state = {"s1": {"level": "amber", "fired_at": "x"}}
        assert _should_notify(state, "s1", "amber") is False

    def test_upgrade_amber_to_red_fires(self):
        state = {"s1": {"level": "amber", "fired_at": "x"}}
        assert _should_notify(state, "s1", "red") is True

    def test_downgrade_red_to_amber_is_silent(self):
        state = {"s1": {"level": "red", "fired_at": "x"}}
        assert _should_notify(state, "s1", "amber") is False

    def test_downgrade_to_none_is_silent(self):
        state = {"s1": {"level": "red", "fired_at": "x"}}
        assert _should_notify(state, "s1", "none") is False

    def test_independent_sessions_tracked_separately(self):
        state = {"s1": {"level": "red", "fired_at": "x"}}
        assert _should_notify(state, "s2", "amber") is True


class TestRecordNotified:
    def test_record_stamps_level_and_timestamp(self):
        state: dict = {}
        _record_notified(state, "s1", "amber")
        assert state["s1"]["level"] == "amber"
        assert "fired_at" in state["s1"]

    def test_record_overwrites_prior_entry(self):
        state: dict = {}
        _record_notified(state, "s1", "amber")
        _record_notified(state, "s1", "red")
        assert state["s1"]["level"] == "red"


# =============================================================================
# Cost composition + turn stats (Session Detail)
# =============================================================================

from tools.claude_usage_monitor import (  # noqa: E402
    _cost_composition,
    _turn_cost_stats,
)


class TestCostComposition:
    """_cost_composition splits session cost into four token-type buckets."""

    def test_empty_session_returns_zero_total(self):
        comp = _cost_composition([])
        assert comp == {"input": 0.0, "output": 0.0, "cache_read": 0.0, "cache_write": 0.0, "total": 0.0}

    def test_single_turn_sonnet_46_pricing(self):
        # 1M input, 1M output, 1M cache_read, 1M cache_write (5m rate)
        # sonnet-4-6: 3 + 15 + 0.30 + 3.75 = $22.05
        turns = [("t", 0.0, 1_000_000, 1_000_000, 1_000_000, 1_000_000, "claude-sonnet-4-6")]
        comp = _cost_composition(turns)
        assert comp["input"] == 3.0
        assert comp["output"] == 15.0
        assert comp["cache_read"] == 0.30
        assert comp["cache_write"] == 3.75
        assert abs(comp["total"] - 22.05) < 1e-6

    def test_multi_model_sums_per_turn(self):
        turns = [
            ("t", 0.0, 1_000_000, 0, 0, 0, "claude-sonnet-4-6"),  # 3.0 input
            ("t", 0.0, 1_000_000, 0, 0, 0, "claude-opus-4-6"),    # 5.0 input
        ]
        comp = _cost_composition(turns)
        assert comp["input"] == 8.0
        assert comp["output"] == 0.0

    def test_unknown_model_uses_default_pricing(self):
        turns = [("t", 0.0, 1_000_000, 0, 0, 0, "claude-unknown-99")]
        comp = _cost_composition(turns)
        # Default falls back to sonnet-4-6 -> $3 for 1M input
        assert comp["input"] == 3.0


class TestTurnCostStats:
    def test_none_when_no_turns(self):
        assert _turn_cost_stats([]) is None

    def test_single_turn_all_same(self):
        turns = [("t", 0.75, 0, 0, 0, 0, "m")]
        stats = _turn_cost_stats(turns)
        assert stats == {"first": 0.75, "last": 0.75, "avg": 0.75, "peak": 0.75, "n": 1}

    def test_first_last_avg_peak(self):
        turns = [
            ("t", 0.1, 0, 0, 0, 0, "m"),
            ("t", 0.5, 0, 0, 0, 0, "m"),
            ("t", 0.2, 0, 0, 0, 0, "m"),
        ]
        stats = _turn_cost_stats(turns)
        assert stats["first"] == 0.1
        assert stats["last"] == 0.2
        assert stats["peak"] == 0.5
        assert abs(stats["avg"] - 0.2666) < 0.001
        assert stats["n"] == 3


class TestEvictInactiveNotifs:
    def test_keeps_live_sessions(self):
        state = {
            "s1": {"level": "red", "fired_at": "x"},
            "s2": {"level": "amber", "fired_at": "y"},
        }
        _evict_inactive_notifs(state, {"s1", "s2"})
        assert set(state) == {"s1", "s2"}

    def test_drops_sessions_no_longer_live(self):
        state = {
            "s1": {"level": "red", "fired_at": "x"},
            "s2": {"level": "amber", "fired_at": "y"},
        }
        _evict_inactive_notifs(state, {"s1"})
        assert set(state) == {"s1"}

    def test_mutates_in_place_and_returns_same_dict(self):
        state = {"s1": {"level": "red", "fired_at": "x"}}
        returned = _evict_inactive_notifs(state, set())
        assert returned is state
        assert state == {}
