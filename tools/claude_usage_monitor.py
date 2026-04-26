"""
Claude Usage Monitor — Live session cost tracker for Claude Code.
Reads JSONL session logs from ~/.claude/projects/ and calculates
token usage, costs, waste factor, and per-session breakdowns.
"""

import os
import json
import glob
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk

try:
    from winotify import Notification as _WinotifyNotification  # type: ignore
    _HAS_TOAST = True
except ImportError:
    _WinotifyNotification = None  # type: ignore
    _HAS_TOAST = False

TOOL_NAME = "Claude Usage Monitor"
TOOL_DESC = "Live monitor for Claude Code session costs, tokens & waste"

# ---------------------------------------------------------------------------
# Anthropic official pricing (USD per million tokens) — April 2026
# ---------------------------------------------------------------------------
MODEL_PRICING = {
    "claude-opus-4-6": {
        "input": 5.0, "output": 25.0,
        "cache_read": 0.50, "cache_write_5m": 6.25, "cache_write_1h": 10.0,
    },
    "claude-opus-4-5": {
        "input": 5.0, "output": 25.0,
        "cache_read": 0.50, "cache_write_5m": 6.25, "cache_write_1h": 10.0,
    },
    "claude-sonnet-4-6": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-sonnet-4-5": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-sonnet-4": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-haiku-4-5": {
        "input": 1.0, "output": 5.0,
        "cache_read": 0.10, "cache_write_5m": 1.25, "cache_write_1h": 2.0,
    },
}

# Fallback pricing (use Sonnet rates as conservative default)
_DEFAULT_PRICING = MODEL_PRICING["claude-sonnet-4-6"]

# Cold-turn detection
_COLD_INPUT_MIN = 2000
_COLD_CACHE_RATIO_MAX = 0.5

# Rotate Now score weights (sum to 1.0)
_ROTATE_W_SAVINGS = 0.50
_ROTATE_W_WASTE = 0.20
_ROTATE_W_CACHE_TREND = 0.15
_ROTATE_W_TURN_COUNT = 0.10
_ROTATE_W_COLD_CLUSTER = 0.05

# Rotate pill thresholds
_ROTATE_RED = 60
_ROTATE_AMBER = 30

# Tool-spend heuristic (chars per token, standard rule of thumb)
_TOOL_CHARS_PER_TOKEN = 4

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
SESSIONS_DIR = CLAUDE_DIR / "sessions"
ORDER_FILE = CLAUDE_DIR / "claude_usage_monitor_order.json"

# A session is considered "live" if its last activity is within this window.
# PID-based liveness was too sticky — stale session files kept rows marked LIVE
# long after the CLI exited.
_LIVE_WINDOW_SECONDS = 3600  # 1 hour

# Capture the local timezone once at import time so every comparison uses the
# same wall-clock reference — avoids DST shift mid-run ambiguity.
LOCAL_TZ = datetime.now().astimezone().tzinfo


# ---------------------------------------------------------------------------
# Data layer
# ---------------------------------------------------------------------------

def _get_pricing(model_name: str) -> dict:
    """Return pricing dict for a model, falling back to defaults."""
    if not model_name:
        return _DEFAULT_PRICING
    # Try exact match first, then prefix match
    if model_name in MODEL_PRICING:
        return MODEL_PRICING[model_name]
    # Longest-key-first so "claude-opus-4-6" wins over "claude-opus-4" when
    # matching a model like "claude-opus-4-6-something" (prevents cross-version bleed).
    for key in sorted(MODEL_PRICING, key=len, reverse=True):
        if model_name.startswith(key):
            return MODEL_PRICING[key]
    return _DEFAULT_PRICING


def _calc_turn_cost(usage: dict, pricing: dict) -> float:
    """Calculate dollar cost for a single API turn."""
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cache_read = usage.get("cache_read_input_tokens", 0)

    # Determine cache write breakdown
    cache_creation = usage.get("cache_creation", {})
    cache_5m = cache_creation.get("ephemeral_5m_input_tokens", 0)
    cache_1h = cache_creation.get("ephemeral_1h_input_tokens", 0)
    total_cache_write = usage.get("cache_creation_input_tokens", 0)

    # If no breakdown available, assume all cache writes are 5m.
    # Claude Code defaults to the 5-minute cache; defaulting to 1h was
    # inflating estimates by ~1.60x vs the API-billed cost.
    if total_cache_write > 0 and (cache_5m + cache_1h) == 0:
        cache_5m = total_cache_write

    cost = (
        (inp / 1_000_000) * pricing["input"]
        + (out / 1_000_000) * pricing["output"]
        + (cache_read / 1_000_000) * pricing["cache_read"]
        + (cache_5m / 1_000_000) * pricing["cache_write_5m"]
        + (cache_1h / 1_000_000) * pricing["cache_write_1h"]
    )
    return cost


def _extract_prompt_text(user_record: dict, max_len: int = 80) -> str | None:
    """Pull human-readable text from a user message record.

    Returns None if the record has no real user text (e.g. tool_result only).
    Skips blocks that start with '<' (system-reminder XML tags).
    """
    msg = user_record.get("message", {})
    content = msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "").strip()
                # Skip system/XML injected content
                if text and not text.startswith("<"):
                    content = text
                    break
        else:
            return None
    if not isinstance(content, str):
        content = str(content)
    text = " ".join(content.split()).strip()
    if not text or text.startswith("<"):
        return None
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "..."
    return text


def _parse_session_file(filepath: str) -> dict:
    """Parse a single JSONL session file and return aggregated stats."""
    session = {
        "file": filepath,
        "session_id": Path(filepath).stem,
        "project": Path(filepath).parent.name,
        "session_name": None,   # derived from first user prompt
        "model": None,
        "entrypoint": None,
        "version": None,
        "cwd": None,
        "git_branch": None,
        "first_timestamp": None,
        "last_timestamp": None,
        "user_turns": 0,
        "assistant_turns": 0,
        "total_input": 0,
        "total_output": 0,
        "total_cache_read": 0,
        "total_cache_write": 0,
        "total_cost": 0.0,
        "turn_costs": [],       # (timestamp, cost, input, output, cache_read, cache_write, model)
        "models_used": set(),
        "tool_stats": {},            # {name: {"calls": int, "est_tokens": int, "est_cost": float}}
        "cold_turn_count": 0,
        "cold_turns_cluster_end": False,
        "cache_trend": None,         # None until >= 10 turns
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            pending_tools: dict[str, tuple[str, int, dict]] = {}
            # maps tool_use_id -> (tool_name, out_tokens_estimate, pricing)
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rec_type = obj.get("type")
                ts_str = obj.get("timestamp")

                # Track timestamps
                if ts_str:
                    if session["first_timestamp"] is None:
                        session["first_timestamp"] = ts_str
                    session["last_timestamp"] = ts_str

                if rec_type == "user":
                    session["user_turns"] += 1
                    if not session["entrypoint"]:
                        session["entrypoint"] = obj.get("entrypoint")
                    if not session["version"]:
                        session["version"] = obj.get("version")
                    if not session["cwd"]:
                        session["cwd"] = obj.get("cwd")
                    if not session["git_branch"]:
                        session["git_branch"] = obj.get("gitBranch")
                    # Keep the last real user prompt as session name
                    prompt = _extract_prompt_text(obj)
                    if prompt:
                        session["session_name"] = prompt

                    # Match tool_result blocks back to prior tool_use calls
                    u_content = obj.get("message", {}).get("content", [])
                    if isinstance(u_content, list):
                        for block in u_content:
                            if not isinstance(block, dict):
                                continue
                            if block.get("type") != "tool_result":
                                continue
                            tid = block.get("tool_use_id") or ""
                            if tid not in pending_tools:
                                continue
                            name, _out_tok, pricing_for_turn = pending_tools.pop(tid)
                            in_tok = _estimate_tool_tokens(block.get("content"))
                            stats = session["tool_stats"].get(name)
                            if stats is None:
                                continue
                            stats["est_tokens"] += in_tok
                            stats["est_cost"] += _estimate_tool_cost(in_tok, 0, pricing_for_turn)

                elif rec_type == "assistant":
                    session["assistant_turns"] += 1
                    msg = obj.get("message", {})
                    model = msg.get("model")
                    if model:
                        session["models_used"].add(model)
                        if not session["model"]:
                            session["model"] = model

                    usage = msg.get("usage", {})
                    if usage:
                        inp = usage.get("input_tokens", 0)
                        out = usage.get("output_tokens", 0)
                        cr = usage.get("cache_read_input_tokens", 0)
                        cw = usage.get("cache_creation_input_tokens", 0)

                        session["total_input"] += inp
                        session["total_output"] += out
                        session["total_cache_read"] += cr
                        session["total_cache_write"] += cw

                        pricing = _get_pricing(model)
                        cost = _calc_turn_cost(usage, pricing)
                        session["total_cost"] += cost

                        session["turn_costs"].append((ts_str, cost, inp, out, cr, cw, model))

                        # Scan tool_use content blocks
                        content = msg.get("content", [])
                        if isinstance(content, list):
                            pricing_for_turn = _get_pricing(model)
                            for block in content:
                                if not isinstance(block, dict):
                                    continue
                                if block.get("type") != "tool_use":
                                    continue
                                name = block.get("name") or "unknown"
                                tool_id = block.get("id") or ""
                                out_tok = _estimate_tool_tokens(block.get("input"))
                                pending_tools[tool_id] = (name, out_tok, pricing_for_turn)

                                stats = session["tool_stats"].setdefault(
                                    name, {"calls": 0, "est_tokens": 0, "est_cost": 0.0}
                                )
                                stats["calls"] += 1
                                stats["est_tokens"] += out_tok
                                stats["est_cost"] += _estimate_tool_cost(0, out_tok, pricing_for_turn)

    except (OSError, KeyError, AttributeError, TypeError, ValueError):
        pass

    session["cold_turn_count"] = _cold_turn_count(session["turn_costs"])
    session["cold_turns_cluster_end"] = _cold_turns_cluster_end(session["turn_costs"])
    session["cache_trend"] = _cache_trend(session["turn_costs"])
    session["models_used"] = list(session["models_used"])
    return session


def _parse_timestamp(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _is_recently_active(last_timestamp: str | None) -> bool:
    """True if the session had activity within the last _LIVE_WINDOW_SECONDS."""
    ts = _parse_timestamp(last_timestamp)
    if not ts:
        return False
    return (datetime.now(timezone.utc) - ts).total_seconds() < _LIVE_WINDOW_SECONDS


def _latest_session_id_per_project(sessions: list[dict]) -> set[str]:
    """Return the session_id of the most recent session for each project."""
    latest: dict[str, tuple[str, str]] = {}  # proj -> (sid, ts)
    for s in sessions:
        proj = s.get("project") or ""
        ts = s.get("last_timestamp") or ""
        cur = latest.get(proj)
        if cur is None or ts > cur[1]:
            latest[proj] = (s["session_id"], ts)
    return {sid for sid, _ in latest.values()}


def _load_project_state() -> tuple[list[str], list[str], dict]:
    """Load persisted state: project order, collapsed projects, notification state.

    Shape (all keys optional for backward compat):
        {"order": [...], "collapsed": [...], "notif_state": {sid: level}}
    """
    try:
        data = json.loads(ORDER_FILE.read_text(encoding="utf-8"))
        order = [str(p) for p in data.get("order", []) if isinstance(p, str)]
        collapsed = [str(p) for p in data.get("collapsed", []) if isinstance(p, str)]
        notif = data.get("notif_state", {})
        if not isinstance(notif, dict):
            notif = {}
        return order, collapsed, notif
    except (OSError, json.JSONDecodeError, TypeError):
        return [], [], {}


def _save_project_state(order: list[str], collapsed: list[str],
                        notif_state: dict) -> None:
    """Persist ordered projects, collapsed set, and notification dedup state."""
    try:
        ORDER_FILE.write_text(
            json.dumps({
                "order": order,
                "collapsed": collapsed,
                "notif_state": notif_state,
            }, indent=2),
            encoding="utf-8",
        )
    except (OSError, TypeError):
        pass  # non-fatal

# Back-compat wrappers so existing call sites continue to work during refactor.
def _load_project_order() -> list[str]:
    return _load_project_state()[0]

def _save_project_order(order: list[str]) -> None:
    _, collapsed, notif = _load_project_state()
    _save_project_state(order, collapsed, notif)


def _format_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _format_cost(c: float) -> str:
    if c >= 1.0:
        return f"${c:.2f}"
    if c >= 0.01:
        return f"${c:.3f}"
    return f"${c:.4f}"


def _duration_str(first_ts: str, last_ts: str) -> str:
    t1 = _parse_timestamp(first_ts)
    t2 = _parse_timestamp(last_ts)
    if not t1 or not t2:
        return "—"
    delta = t2 - t1
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    hours = secs // 3600
    mins = (secs % 3600) // 60
    return f"{hours}h {mins}m"


def _waste_factor(turn_costs: list) -> float | None:
    """Waste factor: average tokens/turn in last 5 turns vs first 5 turns."""
    if len(turn_costs) < 6:
        return None
    first5 = [_turn_total_tokens(tc) for tc in turn_costs[:5]]
    last5 = [_turn_total_tokens(tc) for tc in turn_costs[-5:]]
    base = sum(first5) / len(first5)
    current = sum(last5) / len(last5)
    if base <= 0:
        return None
    return current / base


def _turn_total_tokens(tc: tuple) -> int:
    """Sum of input + output + cache_read + cache_write for a turn_costs entry."""
    return tc[2] + tc[3] + tc[4] + tc[5]


def _is_cold_turn(input_tokens: int, cache_read: int) -> bool:
    """A turn is cold when its fresh input dominates and the turn is non-trivial."""
    if input_tokens < _COLD_INPUT_MIN:
        return False
    denom = input_tokens + cache_read
    if denom == 0:
        return False
    return (cache_read / denom) < _COLD_CACHE_RATIO_MAX


def _cache_efficiency(input_tokens: int, cache_read: int, cache_write: int) -> float:
    """Cache efficiency = cache_read / (input + cache_read + cache_write). Range 0..1."""
    denom = input_tokens + cache_read + cache_write
    if denom <= 0:
        return 0.0
    return cache_read / denom


def _cache_trend(turn_costs: list) -> float | None:
    """Difference in cache efficiency between last-5 and first-5 windows.

    Returns None when fewer than 10 turns are available. Negative values
    mean the cache is getting less effective over time.
    """
    if len(turn_costs) < 10:
        return None

    def window_eff(window: list) -> float:
        inp = sum(tc[2] for tc in window)
        cr = sum(tc[4] for tc in window)
        cw = sum(tc[5] for tc in window)
        return _cache_efficiency(inp, cr, cw)

    return window_eff(turn_costs[-5:]) - window_eff(turn_costs[:5])


def _cold_turn_count(turn_costs: list) -> int:
    """Number of turns satisfying the cold rule."""
    return sum(1 for tc in turn_costs if _is_cold_turn(tc[2], tc[4]))


def _cold_turns_cluster_end(turn_costs: list) -> bool:
    """True when at least 3 of the last 5 turns are cold (recent cache invalidation)."""
    if len(turn_costs) < 5:
        return False
    last5 = turn_costs[-5:]
    return sum(1 for tc in last5 if _is_cold_turn(tc[2], tc[4])) >= 3


def _estimate_tool_tokens(payload: dict | list | str | None) -> int:
    """Approximate token count from a JSON-serializable payload.

    Uses the standard ~4 chars-per-token heuristic. Returns 0 for None / empty.
    """
    if payload is None:
        return 0
    if isinstance(payload, str) and not payload:
        return 0
    try:
        text = json.dumps(payload, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(payload)
    if not text:
        return 0
    return max(1, len(text) // _TOOL_CHARS_PER_TOKEN)


def _estimate_tool_cost(in_tokens: int, out_tokens: int, pricing: dict) -> float:
    """Dollar cost for the estimated in/out token split of a tool invocation."""
    return (
        (in_tokens / 1_000_000) * pricing["input"]
        + (out_tokens / 1_000_000) * pricing["output"]
    )


def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _rotate_subscores(session: dict) -> dict | None:
    """Compute the five weighted sub-scores for a session.

    Returns None when the session has fewer than 5 turns. Shape:
        {
            "cont_cost": float,
            "fresh_proj": float,
            "raw": {subscore: raw_0_100, ...},
            "weighted": {subscore: weighted_contribution, ...},
            "total": float,              # 0..100
            "extras": {                  # supporting values for the explanation
                "early_eff": float,
                "late_eff": float,
                "waste_factor": float | None,
                "turns": int,
                "cluster_end": bool,
            },
        }
    """
    tc = session["turn_costs"]
    if len(tc) < 5:
        return None

    first5_costs = [row[1] for row in tc[:5]]
    last5_costs = [row[1] for row in tc[-5:]]
    fresh_proj = sum(first5_costs) / len(first5_costs)
    cont_cost = sum(last5_costs) / len(last5_costs)

    # Savings
    if cont_cost <= 0:
        savings_raw = 0.0
    else:
        savings_raw = _clamp((cont_cost - fresh_proj) / cont_cost * 100)

    # Waste
    wf = _waste_factor(tc)
    waste_raw = _clamp((wf - 1) * 25) if wf is not None else 0.0

    # Cache trend (None when <10 turns)
    trend = session.get("cache_trend")
    cache_trend_raw = _clamp(-trend * 200) if trend is not None else 0.0

    # Turn count
    turns = session["assistant_turns"]
    turn_count_raw = _clamp(max(0, turns - 25) * 2)

    # Cold cluster
    cluster_end = bool(session.get("cold_turns_cluster_end"))
    cold_cluster_raw = 100.0 if cluster_end else 0.0

    raw = {
        "savings": savings_raw,
        "waste": waste_raw,
        "cache_trend": cache_trend_raw,
        "turn_count": turn_count_raw,
        "cold_cluster": cold_cluster_raw,
    }
    weighted = {
        "savings": _ROTATE_W_SAVINGS * savings_raw,
        "waste": _ROTATE_W_WASTE * waste_raw,
        "cache_trend": _ROTATE_W_CACHE_TREND * cache_trend_raw,
        "turn_count": _ROTATE_W_TURN_COUNT * turn_count_raw,
        "cold_cluster": _ROTATE_W_COLD_CLUSTER * cold_cluster_raw,
    }
    total = sum(weighted.values())

    # Early / late cache efficiency (recomputed for explanation text; cheap)
    def window_eff(window):
        inp = sum(row[2] for row in window)
        cr = sum(row[4] for row in window)
        cw = sum(row[5] for row in window)
        return _cache_efficiency(inp, cr, cw)

    return {
        "cont_cost": cont_cost,
        "fresh_proj": fresh_proj,
        "raw": raw,
        "weighted": weighted,
        "total": total,
        "extras": {
            "early_eff": window_eff(tc[:5]),
            "late_eff": window_eff(tc[-5:]),
            "waste_factor": wf,
            "turns": turns,
            "cluster_end": cluster_end,
        },
    }


def _rotate_pill_state(score: float) -> tuple[str, str]:
    """Return (label, hex_color) for a pill based on the score."""
    if score >= _ROTATE_RED:
        return ("ROTATE NOW", "#cc3333")
    if score >= _ROTATE_AMBER:
        return ("CONSIDER ROTATING", "#e09a1a")
    return ("KEEP GOING", "#2a8a2a")


def _rotate_bar(score: float, width: int = 10) -> str:
    """Percentage string for the Sessions tab Rotate column."""
    pct = max(0.0, min(100.0, score))
    return f"{int(round(pct))}%"


def _rotate_tag(score: float) -> str | None:
    """Row-tag name for the rotation threshold. None = no extra color."""
    if score >= _ROTATE_RED:
        return "rot_red"
    if score >= _ROTATE_AMBER:
        return "rot_amber"
    return None


# Notification tiers (higher = more urgent). "none" means below amber threshold.
_NOTIF_TIERS = {"none": 0, "amber": 1, "red": 2}


def _rotate_level(score: float) -> str:
    """Map a rotate score to a notification tier name."""
    if score >= _ROTATE_RED:
        return "red"
    if score >= _ROTATE_AMBER:
        return "amber"
    return "none"


def _should_notify(state: dict, session_id: str, new_level: str) -> bool:
    """Return True if a new_level alert should fire for this session.

    Fires only on upgrades: none→amber, none→red, amber→red. Downgrades
    (red→amber, amber→none) are silent so the banner doesn't re-trigger
    when a session drops below a threshold and climbs back.
    """
    if new_level == "none":
        return False
    last = state.get(session_id, {}).get("level", "none")
    return _NOTIF_TIERS.get(new_level, 0) > _NOTIF_TIERS.get(last, 0)


def _record_notified(state: dict, session_id: str, level: str) -> None:
    """Stamp the dedup state with the level just fired."""
    state[session_id] = {
        "level": level,
        "fired_at": datetime.now(timezone.utc).isoformat(),
    }


def _evict_inactive_notifs(state: dict, live_ids: set) -> dict:
    """Drop dedup entries for sessions that are no longer LIVE.

    Returns the pruned dict (same object, mutated in place) so callers can
    chain or reassign.
    """
    for sid in [s for s in state if s not in live_ids]:
        state.pop(sid, None)
    return state


def _cost_composition(turn_costs: list) -> dict:
    """Break session cost down by token type by re-applying per-turn model pricing.

    Returns {"input": $, "output": $, "cache_read": $, "cache_write": $, "total": $}.
    Walks turn-by-turn so sessions with multi-model turns are costed correctly.
    """
    buckets = {"input": 0.0, "output": 0.0, "cache_read": 0.0, "cache_write": 0.0}
    for tc in turn_costs:
        model = tc[6] if len(tc) > 6 else ""
        p = _get_pricing(model)
        buckets["input"]       += tc[2] * p.get("input", 0.0) / 1_000_000
        buckets["output"]      += tc[3] * p.get("output", 0.0) / 1_000_000
        buckets["cache_read"]  += tc[4] * p.get("cache_read", 0.0) / 1_000_000
        # Assume 5m cache-writes when breakdown is unknown (matches _calc_turn_cost).
        cw_rate = p.get("cache_write_5m", p.get("cache_write", 0.0))
        buckets["cache_write"] += tc[5] * cw_rate / 1_000_000
    buckets["total"] = sum(buckets.values())
    return buckets


def _turn_cost_stats(turn_costs: list) -> dict | None:
    """Return {first, last, avg, peak, n} turn costs, or None for empty sessions."""
    if not turn_costs:
        return None
    costs = [tc[1] for tc in turn_costs]
    return {
        "first": costs[0],
        "last": costs[-1],
        "avg": sum(costs) / len(costs),
        "peak": max(costs),
        "n": len(costs),
    }


def _rotate_explanation(sub: dict) -> str:
    """One-line explanation of the dominant weighted factor."""
    weighted = sub["weighted"]
    dominant = max(weighted, key=weighted.get)
    ex = sub["extras"]

    if dominant == "savings":
        return (
            f"Last 5 turns avg {_format_cost(sub['cont_cost'])} "
            f"vs projected fresh {_format_cost(sub['fresh_proj'])}"
        )
    if dominant == "waste" and ex["waste_factor"] is not None:
        return f"Context bloat: last-5 turns use {ex['waste_factor']:.1f}x tokens vs first-5"
    if dominant == "cache_trend":
        return (
            f"Cache efficiency falling: "
            f"{ex['early_eff'] * 100:.0f}% → {ex['late_eff'] * 100:.0f}%"
        )
    if dominant == "turn_count":
        return f"Long session: {ex['turns']} turns in"
    if dominant == "cold_cluster":
        return "Cold turns clustering at session end"
    return "—"


def _friendly_project(dirname: str, cwd: str | None = None) -> str:
    """Convert directory name or cwd path into a readable project name.

    Prefers the real cwd path (e.g. 'F:\\DevCrow\\Python\\Automations')
    over the encoded dirname ('F--DevCrow-Python-Automations').
    """
    if cwd:
        parts = Path(cwd).parts
        # Drop drive root like 'F:\\'
        if len(parts) > 1 and len(parts[0]) <= 3:
            parts = parts[1:]
        # Show last 3 segments max
        parts = parts[-3:] if len(parts) > 3 else parts
        return "/".join(parts)

    # Fallback: decode the dirname encoding
    segments = dirname.split("--")
    if len(segments) > 1 and len(segments[0]) <= 2:
        segments = segments[1:]
    return "/".join(segments)


# Cache parsed sessions by file path; keyed by mtime so unchanged files
# skip the JSONL re-parse on every 30s refresh.
_SESSION_CACHE: dict[str, tuple[float, dict]] = {}


def _parse_session_file_cached(filepath: str) -> dict:
    """_parse_session_file with an mtime-based cache."""
    try:
        mtime = os.path.getmtime(filepath)
    except OSError:
        return _parse_session_file(filepath)
    cached = _SESSION_CACHE.get(filepath)
    if cached is not None and cached[0] == mtime:
        return cached[1]
    sess = _parse_session_file(filepath)
    _SESSION_CACHE[filepath] = (mtime, sess)
    return sess


def load_all_sessions() -> list[dict]:
    """Scan all projects and return parsed session data, newest first."""
    sessions = []
    if not PROJECTS_DIR.exists():
        return sessions

    seen_paths: set[str] = set()
    for proj_dir in PROJECTS_DIR.iterdir():
        if not proj_dir.is_dir():
            continue
        for jsonl_file in proj_dir.glob("*.jsonl"):
            path = str(jsonl_file)
            seen_paths.add(path)
            sess = _parse_session_file_cached(path)
            if sess["assistant_turns"] > 0:
                sessions.append(sess)

    # Evict cache entries for files that have disappeared.
    for stale in [p for p in _SESSION_CACHE if p not in seen_paths]:
        _SESSION_CACHE.pop(stale, None)

    # Sort by last timestamp descending
    sessions.sort(
        key=lambda s: s.get("last_timestamp") or "",
        reverse=True,
    )
    return sessions


def _pid_alive(pid: int) -> bool:
    """Return True if the process *pid* is still running."""
    try:
        import psutil  # available via launcher requirements
        return psutil.pid_exists(pid)
    except ImportError:
        pass
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _get_active_session_ids() -> set:
    """Read ~/.claude/sessions/*.json and check pid liveness for each entry."""
    active = set()
    if not SESSIONS_DIR.exists():
        return active
    for f in SESSIONS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            sid = data.get("sessionId")
            pid = data.get("pid")
            if not sid:
                continue
            if pid and not _pid_alive(int(pid)):
                continue  # process is gone — session is not live
            active.add(sid)
        except (OSError, ValueError, json.JSONDecodeError, TypeError):
            pass
    return active


# ---------------------------------------------------------------------------
# Sessions-tab column spec (shared header + per-project Treeview)
# ---------------------------------------------------------------------------
# Fields: (col_id, heading_text, width_px, is_numeric)
# The shared heading row and every per-card Treeview iterate this tuple so
# pixel-widths stay aligned. Change here to change both sides at once.
_SESSION_COLUMNS = (
    ("status",       "",          30,  False),
    ("session_name", "Session",   200, False),
    ("model",        "Model",     110, False),
    ("turns",        "Turns",     55,  True),
    ("tokens",       "Tokens",    80,  True),
    ("init",         "Init",      60,  True),
    ("cost",         "Cost",      70,  True),
    ("last_turn",    "Last Turn", 75,  True),
    ("waste",        "Waste",     55,  True),
    ("rotate",       "Rotate",    70,  True),
    ("duration",     "Duration",  70,  True),
    ("date",         "Date",      110, False),
)


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class ClaudeUsageMonitor(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.title("Claude Usage Monitor")
        self.geometry("1100x720")
        self.minsize(900, 550)

        self._sessions: list[dict] = []
        self._active_ids: set = set()
        self._loading = False
        self._auto_refresh = True
        self._sort_col = "date"       # default sort column (kept for compat)
        self._sort_reverse = True     # newest first
        self._plan = "Max 5x ($100/mo)"  # default plan
        self._window = "All"  # time-window filter: Today / Week / Month / All
        order, collapsed, notif = _load_project_state()
        self._project_order: list[str] = order
        self._collapsed_projects: set[str] = set(collapsed)
        self._notif_state: dict = notif  # {session_id: "amber"|"red"}
        self._project_cards: dict = {}  # proj_name -> card widgets

        self._build_ui()
        self._start_load()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        # Top bar
        top = ctk.CTkFrame(self, height=50, corner_radius=0)
        top.pack(fill="x")

        ctk.CTkLabel(
            top, text="Claude Usage Monitor",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(side="left", padx=16, pady=10)

        self._status_label = ctk.CTkLabel(
            top, text="Loading...", text_color="gray",
            font=ctk.CTkFont(size=12),
        )
        self._status_label.pack(side="left", padx=10)

        btn_frame = ctk.CTkFrame(top, fg_color="transparent")
        btn_frame.pack(side="right", padx=12)

        # Time-window filter — affects dashboard totals and sessions list
        ctk.CTkLabel(btn_frame, text="Window:", font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 4))
        self._window_var = ctk.StringVar(value=self._window)
        window_seg = ctk.CTkSegmentedButton(
            btn_frame, values=["Today", "Week", "Month", "All"],
            variable=self._window_var, command=self._on_window_change,
            font=ctk.CTkFont(size=11), height=28,
        )
        window_seg.pack(side="left", padx=(0, 12))

        # Plan selector
        self._plan_var = ctk.StringVar(value=self._plan)
        ctk.CTkLabel(btn_frame, text="Plan:", font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 4))
        plan_menu = ctk.CTkOptionMenu(
            btn_frame, variable=self._plan_var,
            values=[
                "Max 5x ($100/mo)",
                "Max 20x ($200/mo)",
                "Pro ($20/mo)",
                "API (pay-per-token)",
            ],
            width=160, height=28,
            command=self._on_plan_change,
            font=ctk.CTkFont(size=11),
        )
        plan_menu.pack(side="left", padx=(0, 12))

        self._auto_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            btn_frame, text="Auto-refresh (30s)",
            variable=self._auto_var,
            command=self._toggle_auto_refresh,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame, text="Refresh Now", width=100,
            command=self._start_load,
            fg_color="#3a7ebf", hover_color="#2b6194",
        ).pack(side="left")

        # Rotate-alert banner — hidden until _fire_rotate_notification surfaces
        # one. Placed between the top bar and the tabs so it can't be scrolled
        # off the visible area.
        self._banner = ctk.CTkFrame(self, height=36, corner_radius=0, fg_color="#e09a1a")
        self._banner_msg = ctk.CTkLabel(
            self._banner, text="", font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#1e1e1e", anchor="w",
        )
        self._banner_msg.pack(side="left", padx=12, pady=6, fill="x", expand=True)
        self._banner_btn = ctk.CTkButton(
            self._banner, text="Jump to session", width=120, height=24,
            fg_color="#1e1e1e", hover_color="#333", text_color="#ffffff",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._banner_jump,
        )
        self._banner_btn.pack(side="right", padx=(4, 8), pady=6)
        self._banner_dismiss = ctk.CTkButton(
            self._banner, text="X", width=28, height=24,
            fg_color="transparent", hover_color="#3a3a3a",
            text_color="#1e1e1e",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._banner_dismiss_click,
        )
        self._banner_dismiss.pack(side="right", padx=(0, 6), pady=6)
        self._banner_target_sid: str | None = None  # which session Jump goes to
        # Not packed yet — _show_banner handles pack(fill="x") when firing.

        # Tabs
        self._tabs = ctk.CTkTabview(self, corner_radius=10)
        self._tabs.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self._tab_dash = self._tabs.add("Dashboard")
        self._tab_sessions = self._tabs.add("Sessions")
        self._tab_detail = self._tabs.add("Session Detail")

        self._build_dashboard()
        self._build_sessions_tab()
        self._build_detail_tab()

    # ------ Dashboard tab
    def _build_dashboard(self):
        parent = self._tab_dash

        # Summary cards row
        self._cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._cards_frame.pack(fill="x", pady=(8, 4))

        self._card_widgets = {}
        cards_def = [
            ("api_value", "API-Equivalent Value", "$0.00"),
            ("plan_cost", "Your Plan Cost", "$0.00"),
            ("savings", "You Saved", "$0.00"),
            ("value_ratio", "Value Ratio", "0x"),
        ]
        for i, (key, label, default) in enumerate(cards_def):
            card = ctk.CTkFrame(self._cards_frame, corner_radius=10, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=8, pady=4, sticky="nsew")
            self._cards_frame.grid_columnconfigure(i, weight=1)

            ctk.CTkLabel(
                card, text=label,
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(pady=(10, 2), padx=12, anchor="w")

            val_lbl = ctk.CTkLabel(
                card, text=default,
                font=ctk.CTkFont(size=22, weight="bold"),
            )
            val_lbl.pack(pady=(0, 10), padx=12, anchor="w")
            self._card_widgets[key] = val_lbl

        # Second row: usage stats
        self._stats_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._stats_frame.pack(fill="x", pady=(0, 4))

        stats_def = [
            ("total_sessions", "Sessions", "0"),
            ("total_turns", "Total Turns", "0"),
            ("total_tokens", "Total Tokens", "0"),
        ]
        for i, (key, label, default) in enumerate(stats_def):
            card = ctk.CTkFrame(self._stats_frame, corner_radius=10, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=8, pady=4, sticky="nsew")
            self._stats_frame.grid_columnconfigure(i, weight=1)

            ctk.CTkLabel(
                card, text=label,
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(pady=(8, 1), padx=12, anchor="w")

            val_lbl = ctk.CTkLabel(
                card, text=default,
                font=ctk.CTkFont(size=16, weight="bold"),
            )
            val_lbl.pack(pady=(0, 8), padx=12, anchor="w")
            self._card_widgets[key] = val_lbl

        # Peak hours panel
        peak_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        peak_frame.pack(fill="x", padx=8, pady=8)

        peak_header = ctk.CTkFrame(peak_frame, fg_color="transparent")
        peak_header.pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            peak_header, text="Usage by Hour of Day",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(side="left")
        self._peak_pill = ctk.CTkLabel(
            peak_header, text="—", corner_radius=10,
            fg_color="#444444", text_color="#ffffff",
            font=ctk.CTkFont(size=10, weight="bold"),
            width=90, height=20,
        )
        self._peak_pill.pack(side="right")

        self._peak_canvas = ctk.CTkCanvas(
            peak_frame, height=110, bg="#1e1e1e",
            highlightthickness=0,
        )
        self._peak_canvas.pack(fill="x", padx=12, pady=(4, 10))

        # Model breakdown
        breakdown_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        breakdown_frame.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            breakdown_frame, text="Cost by Model",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self._model_breakdown_frame = ctk.CTkFrame(breakdown_frame, fg_color="transparent")
        self._model_breakdown_frame.pack(fill="x", padx=12, pady=(0, 10))

        # Tool breakdown
        tool_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        tool_frame.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            tool_frame, text="Cost by Tool (est.)",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self._tool_breakdown_frame = ctk.CTkFrame(tool_frame, fg_color="transparent")
        self._tool_breakdown_frame.pack(fill="x", padx=12, pady=(0, 10))

        # Top projects
        proj_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        proj_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        proj_header = ctk.CTkFrame(proj_frame, fg_color="transparent")
        proj_header.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(
            proj_header, text="Cost by Project",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(side="left")

        # Toggle: Top 10 (default) vs Show all. Gets a dynamic label in _render_dashboard.
        self._proj_show_all = ctk.BooleanVar(value=False)
        self._proj_toggle_btn = ctk.CTkButton(
            proj_header, text="Show all", width=90, height=24,
            fg_color="#3a3a3a", hover_color="#4a4a4a",
            font=ctk.CTkFont(size=11),
            command=self._toggle_proj_show_all,
        )
        self._proj_toggle_btn.pack(side="right")

        self._project_breakdown_frame = ctk.CTkFrame(proj_frame, fg_color="transparent")
        self._project_breakdown_frame.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # ------ Sessions tab
    def _build_sessions_tab(self):
        parent = self._tab_sessions

        # Filter row
        filt = ctk.CTkFrame(parent, fg_color="transparent")
        filt.pack(fill="x", pady=(4, 8))

        self._sess_search_var = ctk.StringVar()
        ctk.CTkEntry(
            filt, textvariable=self._sess_search_var,
            placeholder_text="Filter by project, model, or session...",
            width=300, height=34,
        ).pack(side="left", padx=(0, 8))
        self._sess_search_var.trace_add("write", lambda *_: self._render_sessions())

        self._hide_archived_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            filt, text="Recent only (latest per project + <1h active)",
            variable=self._hide_archived_var,
            command=self._render_sessions,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(8, 0))

        # Treeview style shared across per-project cards
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview",
                        background="#1e1e1e", foreground="#e0e0e0",
                        fieldbackground="#1e1e1e", borderwidth=0,
                        font=("Segoe UI", 10), rowheight=22)
        style.configure("Dark.Treeview.Heading",
                        background="#2b2b2b", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"))
        style.map("Dark.Treeview",
                   background=[("selected", "#3a7ebf")],
                   foreground=[("selected", "#ffffff")])

        # Shared column header — one row at the top of the sessions tab.
        # Each per-project card drops its own heading so we save vertical space
        # and stop repeating column labels for every project.
        header_bar = ctk.CTkFrame(parent, fg_color="#2b2b2b", height=26)
        header_bar.pack(fill="x", padx=2, pady=(4, 0))
        header_bar.pack_propagate(False)
        x_px = 8  # matches per-card tree's padx
        for col_id, text, w, numeric in _SESSION_COLUMNS:
            lbl = ctk.CTkLabel(
                header_bar, text=text, width=w, height=26,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#ffffff",
                anchor=("e" if numeric else "w"),
            )
            lbl.place(x=x_px, y=0)
            x_px += w

        # Scrollable container — each project gets its own card inside.
        self._sess_scroll = ctk.CTkScrollableFrame(
            parent, fg_color="#151515", corner_radius=0,
        )
        self._sess_scroll.pack(fill="both", expand=True, padx=2, pady=(0, 2))

        hint = ctk.CTkLabel(
            parent,
            text="Double-click a session for detail  ·  ↑/↓ to reorder projects",
            font=ctk.CTkFont(size=10), text_color="gray",
        )
        hint.pack(pady=(2, 4))

    # ------ Detail tab
    def _build_detail_tab(self):
        # Wrap the entire detail body in a scrollable frame so cards + chart +
        # tools panel + turn table are reachable on small window sizes.
        outer = ctk.CTkScrollableFrame(self._tab_detail, fg_color="transparent")
        outer.pack(fill="both", expand=True)
        parent = outer
        self._detail_scroll = outer

        self._detail_header = ctk.CTkLabel(
            parent, text="Select a session from the Sessions tab",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self._detail_header.pack(pady=(10, 4))

        self._detail_info = ctk.CTkLabel(
            parent, text="", font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._detail_info.pack(pady=(0, 8))

        # Rotate Now pill — packed by _show_session_detail only when needed
        self._rotate_frame = ctk.CTkFrame(parent, corner_radius=12, fg_color="#2b2b2b")

        self._rotate_pill = ctk.CTkLabel(
            self._rotate_frame, text="—", corner_radius=12,
            fg_color="#444444", text_color="#ffffff",
            font=ctk.CTkFont(size=18, weight="bold"),
            height=40,
        )
        self._rotate_pill.pack(fill="x", padx=12, pady=(10, 2))

        self._rotate_explain = ctk.CTkLabel(
            self._rotate_frame, text="",
            text_color="gray", font=ctk.CTkFont(size=11),
        )
        self._rotate_explain.pack(pady=(0, 10))

        # Summary cards for selected session
        self._detail_cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._detail_cards_frame.pack(fill="x", padx=8, pady=(0, 4))

        self._detail_card_widgets = {}
        for i, (key, label) in enumerate([
            ("d_input", "Input Tokens"),
            ("d_output", "Output Tokens"),
            ("d_cache_read", "Cache Read"),
            ("d_cache_write", "Cache Write"),
            ("d_cost", "Total Cost"),
            ("d_last_turn", "Last Turn Tok"),
            ("d_waste", "Waste Factor"),
        ]):
            card = ctk.CTkFrame(self._detail_cards_frame, corner_radius=8, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            self._detail_cards_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10), text_color="gray").pack(pady=(6, 1), padx=6)
            v = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=15, weight="bold"))
            v.pack(pady=(0, 6), padx=6)
            self._detail_card_widgets[key] = v

        # Second cards row — rotation signals
        self._detail_cards2_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._detail_cards2_frame.pack(fill="x", padx=8, pady=(0, 4))

        for i, (key, label) in enumerate([
            ("d_cache_eff", "Cache Eff"),
            ("d_cold_turns", "Cold Turns"),
            ("d_cache_trend", "Cache Trend"),
        ]):
            card = ctk.CTkFrame(self._detail_cards2_frame, corner_radius=8, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            self._detail_cards2_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10), text_color="gray").pack(pady=(6, 1), padx=6)
            v = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=15, weight="bold"))
            v.pack(pady=(0, 6), padx=6)
            self._detail_card_widgets[key] = v

        # Cost composition — where the $ actually went (per token-type).
        cost_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        cost_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            cost_frame, text="Cost Composition",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self._cost_rows: dict[str, dict] = {}  # token-type -> {bar, label}
        cost_body = ctk.CTkFrame(cost_frame, fg_color="transparent")
        cost_body.pack(fill="x", padx=12, pady=(0, 6))
        # Visually distinct swatch per token-type so the reader scans quickly.
        palette = {
            "input":       "#3a7ebf",
            "output":      "#bf6a3a",
            "cache_read":  "#2a8a2a",
            "cache_write": "#9e6a3a",
        }
        for key, label in (
            ("input",       "Input"),
            ("output",      "Output"),
            ("cache_read",  "Cache Read"),
            ("cache_write", "Cache Write"),
        ):
            row = ctk.CTkFrame(cost_body, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(
                row, text=label, width=95, anchor="w",
                font=ctk.CTkFont(size=11),
            ).pack(side="left")
            bar = ctk.CTkProgressBar(
                row, height=12, progress_color=palette[key],
                fg_color="#1e1e1e",
            )
            bar.set(0.0)
            bar.pack(side="left", fill="x", expand=True, padx=(0, 8))
            val = ctk.CTkLabel(
                row, text="$0.00  (0%)", width=110, anchor="e",
                font=ctk.CTkFont(size=11),
            )
            val.pack(side="right")
            self._cost_rows[key] = {"bar": bar, "val": val}

        # Turn-cost stats (first / last / avg / peak) — spots session inflation.
        stats_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        stats_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            stats_frame, text="Turn Cost Stats",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        turn_stats_body = ctk.CTkFrame(stats_frame, fg_color="transparent")
        turn_stats_body.pack(fill="x", padx=12, pady=(0, 10))
        self._turn_stat_widgets: dict[str, ctk.CTkLabel] = {}
        for i, (key, label) in enumerate([
            ("first", "First Turn"),
            ("last",  "Last Turn"),
            ("avg",   "Avg Turn"),
            ("peak",  "Peak Turn"),
        ]):
            cell = ctk.CTkFrame(turn_stats_body, corner_radius=6, fg_color="#1e1e1e")
            cell.grid(row=0, column=i, padx=4, pady=2, sticky="nsew")
            turn_stats_body.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(
                cell, text=label, font=ctk.CTkFont(size=10), text_color="gray",
            ).pack(pady=(6, 1), padx=6)
            v = ctk.CTkLabel(cell, text="—", font=ctk.CTkFont(size=14, weight="bold"))
            v.pack(pady=(0, 6), padx=6)
            self._turn_stat_widgets[key] = v

        # Cost growth chart (text-based sparkline)
        chart_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        chart_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            chart_frame, text="Token Growth per Turn (cumulative)",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self._chart_canvas = ctk.CTkCanvas(
            chart_frame, height=120, bg="#1e1e1e",
            highlightthickness=0,
        )
        self._chart_canvas.pack(fill="x", padx=12, pady=(0, 10))

        # Top Tools panel
        tools_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        tools_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            tools_frame, text="Top Tools Used (est.)",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self._tools_body_frame = ctk.CTkFrame(tools_frame, fg_color="transparent")
        self._tools_body_frame.pack(fill="x", padx=12, pady=(0, 10))

        # Turn-by-turn table
        turn_cols = ("turn", "cw", "timestamp", "cost", "tokens", "cumulative")
        self._turn_tree = ttk.Treeview(
            parent, columns=turn_cols, show="headings",
            style="Dark.Treeview", height=10,
        )
        for col, text, w in [
            ("turn", "#", 50),
            ("cw", "C/W", 40),
            ("timestamp", "Time", 160),
            ("cost", "Cost", 90),
            ("tokens", "Tokens", 100),
            ("cumulative", "Cumulative $", 100),
        ]:
            self._turn_tree.heading(col, text=text)
            anchor = "e" if col in ("cost", "tokens", "cumulative") else "center" if col == "cw" else "w"
            self._turn_tree.column(col, width=w, anchor=anchor)
        self._turn_tree.tag_configure("cold", foreground="#ff6666")
        self._turn_tree.tag_configure("warm", foreground="#888888")
        # fill="x" (not "both" + expand) because we now live inside a
        # CTkScrollableFrame — the outer scroll handles vertical overflow.
        self._turn_tree.pack(fill="x", padx=8, pady=(0, 8))

    # ------------------------------------------------------------------ Data loading
    def _start_load(self):
        if self._loading:
            return
        self._loading = True
        self._status_label.configure(text="Scanning sessions...")
        threading.Thread(target=self._bg_load, daemon=True).start()

    def _bg_load(self):
        sessions = load_all_sessions()
        # Time-based liveness: PID-based detection was too sticky, leaving
        # LIVE badges on rows long after the CLI actually exited.
        self.after(0, lambda: self._on_loaded(sessions))

    def _on_loaded(self, sessions, _legacy=None):
        self._sessions = sessions
        self._active_ids = {
            s["session_id"] for s in sessions
            if _is_recently_active(s.get("last_timestamp"))
        }
        self._loading = False

        total = len(sessions)
        in_window = sum(1 for s in sessions if self._session_in_window(s))
        window_str = self._window
        if window_str == "All":
            status = f"{total} sessions"
        else:
            status = f"{in_window} in {window_str} (of {total})"
        self._status_label.configure(
            text=f"{status}  |  Last refresh: {datetime.now().strftime('%H:%M:%S')}"
        )

        self._render_dashboard()
        self._render_sessions()
        self._scan_rotate_notifications()

        # Schedule next auto-refresh
        if self._auto_refresh:
            self.after(30_000, self._auto_refresh_tick)

    def _toggle_auto_refresh(self):
        self._auto_refresh = self._auto_var.get()
        if self._auto_refresh:
            self.after(30_000, self._auto_refresh_tick)

    def _auto_refresh_tick(self):
        if not self._auto_refresh:
            return
        try:
            self.winfo_exists()
        except tk.TclError:
            return
        self._start_load()

    def _on_plan_change(self, _val=None):
        self._plan = self._plan_var.get()
        self._render_dashboard()

    def _toggle_proj_show_all(self):
        self._proj_show_all.set(not self._proj_show_all.get())
        self._render_dashboard()

    def _on_window_change(self, _val=None):
        self._window = self._window_var.get()
        self._render_dashboard()
        self._render_sessions()

    @staticmethod
    def _window_cutoff(window: str) -> datetime | None:
        """UTC cutoff timestamp for a time-window label. None = no filter."""
        if window == "All":
            return None
        now = datetime.now(timezone.utc)
        if window == "Today":
            return now.replace(hour=0, minute=0, second=0, microsecond=0)
        if window == "Week":
            return now - timedelta(days=7)
        if window == "Month":
            return now - timedelta(days=30)
        return None

    def _session_in_window(self, s: dict) -> bool:
        """True if the session's last activity falls within the active window."""
        cutoff = self._window_cutoff(self._window)
        if cutoff is None:
            return True
        ts = _parse_timestamp(s.get("last_timestamp"))
        if ts is None:
            return False
        return ts >= cutoff

    def _window_months(self) -> float:
        """Fraction of a month covered by the active window (for plan-cost scaling)."""
        if self._window == "Today":
            return 1.0 / 30.0
        if self._window == "Week":
            return 7.0 / 30.0
        if self._window == "Month":
            return 1.0
        return self._months_spanned()

    @staticmethod
    def _plan_monthly_cost(plan: str) -> float | None:
        """Return monthly $ cost for a plan, or None for API."""
        if "5x" in plan:
            return 100.0
        if "20x" in plan:
            return 200.0
        if "Pro" in plan:
            return 20.0
        return None  # API = pay-per-token

    def _months_spanned(self) -> float:
        """How many months the session data spans (min 1)."""
        first_ts, last_ts = None, None
        for s in self._sessions:
            t = _parse_timestamp(s.get("first_timestamp"))
            if t and (first_ts is None or t < first_ts):
                first_ts = t
            t = _parse_timestamp(s.get("last_timestamp"))
            if t and (last_ts is None or t > last_ts):
                last_ts = t
        if not first_ts or not last_ts:
            return 1.0
        # Both timestamps are tz-aware (UTC from _parse_timestamp), so subtraction
        # is unambiguous even across DST boundaries.
        days = max((last_ts - first_ts).days, 1)
        return max(days / 30.0, 1.0)

    # ------------------------------------------------------------------ Renderers
    def _render_dashboard(self):
        # Apply the time-window filter to the dashboard view.
        windowed = [s for s in self._sessions if self._session_in_window(s)]

        api_value = sum(s["total_cost"] for s in windowed)
        total_turns = sum(s["assistant_turns"] for s in windowed)
        total_tokens = sum(
            s["total_input"] + s["total_output"] + s["total_cache_read"] + s["total_cache_write"]
            for s in windowed
        )

        # Plan calculations — scale by the active window (Today / Week / Month / All).
        monthly = self._plan_monthly_cost(self._plan)
        months = self._window_months()

        if monthly is not None:
            plan_total = monthly * months
            savings = api_value - plan_total
            ratio = api_value / plan_total if plan_total > 0 else 0

            self._card_widgets["api_value"].configure(text=_format_cost(api_value))
            self._card_widgets["plan_cost"].configure(
                text=f"${plan_total:.0f}",
            )
            self._card_widgets["savings"].configure(
                text=_format_cost(savings) if savings >= 0 else f"-{_format_cost(abs(savings))}",
                text_color="#44cc44" if savings >= 0 else "#ff4444",
            )
            self._card_widgets["value_ratio"].configure(
                text=f"{ratio:.1f}x",
                text_color="#44cc44" if ratio >= 1 else "#ff9500",
            )
        else:
            # API mode: just show total cost
            self._card_widgets["api_value"].configure(text=_format_cost(api_value))
            self._card_widgets["plan_cost"].configure(text="Pay-per-token")
            self._card_widgets["savings"].configure(text="N/A", text_color="gray")
            self._card_widgets["value_ratio"].configure(text="N/A", text_color="gray")

        self._card_widgets["total_sessions"].configure(text=str(len(windowed)))
        self._card_widgets["total_turns"].configure(text=f"{total_turns:,}")
        self._card_widgets["total_tokens"].configure(text=_format_tokens(total_tokens))

        # Peak hours
        self._render_peak_hours(windowed)

        # Model breakdown
        for w in self._model_breakdown_frame.winfo_children():
            w.destroy()

        model_costs: dict[str, float] = {}
        for s in windowed:
            for m in s["models_used"]:
                model_costs[m] = model_costs.get(m, 0) + s["total_cost"]
        if not model_costs:
            model_costs["No data"] = 0

        max_cost = max(model_costs.values()) if model_costs else 1
        for model, cost in sorted(model_costs.items(), key=lambda x: -x[1]):
            row = ctk.CTkFrame(self._model_breakdown_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=model, font=ctk.CTkFont(size=11), width=180).pack(side="left")

            bar_width = max(4, int(300 * (cost / max_cost))) if max_cost > 0 else 4
            bar = ctk.CTkFrame(row, width=bar_width, height=16, corner_radius=4, fg_color="#3a7ebf")
            bar.pack(side="left", padx=(8, 4))
            bar.pack_propagate(False)

            ctk.CTkLabel(row, text=_format_cost(cost), font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

        # Tool breakdown (aggregate across all sessions)
        for w in self._tool_breakdown_frame.winfo_children():
            w.destroy()

        tool_costs: dict[str, float] = {}
        tool_calls: dict[str, int] = {}
        for s in windowed:
            for name, st in (s.get("tool_stats") or {}).items():
                tool_costs[name] = tool_costs.get(name, 0.0) + st["est_cost"]
                tool_calls[name] = tool_calls.get(name, 0) + st["calls"]

        if not tool_costs:
            ctk.CTkLabel(
                self._tool_breakdown_frame, text="No tool usage recorded yet.",
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(anchor="w", pady=4)
        else:
            max_tc = max(tool_costs.values()) if tool_costs else 1.0
            ranked = sorted(tool_costs.items(), key=lambda kv: -kv[1])[:10]
            for name, cost in ranked:
                row = ctk.CTkFrame(self._tool_breakdown_frame, fg_color="transparent")
                row.pack(fill="x", pady=2)

                ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=11), width=220, anchor="w").pack(side="left")

                bar_width = max(4, int(250 * (cost / max_tc))) if max_tc > 0 else 4
                bar = ctk.CTkFrame(row, width=bar_width, height=16, corner_radius=4, fg_color="#9e6a3a")
                bar.pack(side="left", padx=(8, 4))
                bar.pack_propagate(False)

                info = f"~{_format_cost(cost)}  ({tool_calls[name]} calls)"
                ctk.CTkLabel(row, text=info, font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

        # Project breakdown (2-col grid; Top 10 by default, Show all toggle)
        for w in self._project_breakdown_frame.winfo_children():
            w.destroy()

        proj_costs: dict[str, float] = {}
        proj_sessions: dict[str, int] = {}
        proj_cwd: dict[str, str | None] = {}
        for s in windowed:
            p = s["project"]
            proj_costs[p] = proj_costs.get(p, 0) + s["total_cost"]
            proj_sessions[p] = proj_sessions.get(p, 0) + 1
            if p not in proj_cwd:
                proj_cwd[p] = s.get("cwd")

        ranked = sorted(proj_costs.items(), key=lambda x: -x[1])
        total_projects = len(ranked)
        show_all = self._proj_show_all.get()
        visible = ranked if show_all else ranked[:10]

        # Update toggle label with accurate count
        if total_projects > 10:
            self._proj_toggle_btn.configure(
                text=f"Top 10" if show_all else f"Show all ({total_projects})"
            )
            self._proj_toggle_btn.pack(side="right")
        else:
            # Nothing to toggle — hide the button.
            self._proj_toggle_btn.pack_forget()

        max_pc = max((c for _, c in visible), default=1)
        self._project_breakdown_frame.grid_columnconfigure(0, weight=1, uniform="pcol")
        self._project_breakdown_frame.grid_columnconfigure(1, weight=1, uniform="pcol")
        for idx, (proj, cost) in enumerate(visible):
            row = ctk.CTkFrame(self._project_breakdown_frame, fg_color="transparent")
            row.grid(row=idx // 2, column=idx % 2, sticky="ew", padx=4, pady=2)

            friendly = _friendly_project(proj, proj_cwd.get(proj))
            ctk.CTkLabel(
                row, text=friendly, font=ctk.CTkFont(size=11),
                width=160, anchor="w",
            ).pack(side="left")

            bar_width = max(4, int(140 * (cost / max_pc))) if max_pc > 0 else 4
            bar = ctk.CTkFrame(row, width=bar_width, height=14, corner_radius=4, fg_color="#bf6a3a")
            bar.pack(side="left", padx=(6, 4))
            bar.pack_propagate(False)

            info = f"{_format_cost(cost)} ({proj_sessions[proj]})"
            ctk.CTkLabel(row, text=info, font=ctk.CTkFont(size=11)).pack(side="left", padx=2)

    def _render_peak_hours(self, sessions: list[dict] | None = None):
        """Draw 24-bar chart of total cost per hour-of-day and update peak pill.

        If `sessions` is omitted, aggregate across everything; the dashboard
        passes a window-filtered subset so the peak view honors Today/Week/Month.
        """
        sessions = sessions if sessions is not None else self._sessions
        # Aggregate cost per local hour across every turn
        hour_costs = [0.0] * 24
        for s in sessions:
            for tc in s["turn_costs"]:
                ts_str, cost = tc[0], tc[1]
                ts = _parse_timestamp(ts_str)
                if not ts:
                    continue
                # ts is UTC-aware from _parse_timestamp; convert to LOCAL_TZ for
                # wall-clock bucketing so non-UTC users see correct hour bars.
                local_hour = ts.astimezone(LOCAL_TZ).hour
                hour_costs[local_hour] += cost

        # Top 3 peak hours
        ranked = sorted(range(24), key=lambda h: hour_costs[h], reverse=True)
        peak_hours = {h for h in ranked[:3] if hour_costs[h] > 0}

        # Both sides use the same LOCAL_TZ reference — avoids naive/aware mismatch.
        now_hour = datetime.now().astimezone(LOCAL_TZ).hour
        if not peak_hours:
            self._peak_pill.configure(text="NO DATA", fg_color="#444444")
        elif now_hour in peak_hours:
            self._peak_pill.configure(text="PEAK HOUR", fg_color="#cc3333")
        else:
            self._peak_pill.configure(text="OFF-PEAK", fg_color="#2a8a2a")

        # Draw bars
        c = self._peak_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 1000
        h = c.winfo_height() or 110

        pad_l, pad_r, pad_t, pad_b = 30, 10, 8, 18
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b
        bar_slot = chart_w / 24
        bar_w = max(2, bar_slot * 0.7)

        max_cost = max(hour_costs) if any(hour_costs) else 1.0

        for hr in range(24):
            cost = hour_costs[hr]
            bar_h = (cost / max_cost) * chart_h if max_cost > 0 else 0
            x0 = pad_l + hr * bar_slot + (bar_slot - bar_w) / 2
            x1 = x0 + bar_w
            y0 = pad_t + chart_h - bar_h
            y1 = pad_t + chart_h

            if hr in peak_hours:
                color = "#e05a2a"  # peak highlight
            elif hr == now_hour:
                color = "#6a9ed5"  # current-hour tint
            else:
                color = "#3a6a94"

            if bar_h > 0:
                c.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

            # Hour labels (every 3 hours to reduce clutter)
            if hr % 3 == 0:
                c.create_text(
                    x0 + bar_w / 2, pad_t + chart_h + 2,
                    text=f"{hr:02d}", fill="#888888",
                    anchor="n", font=("Segoe UI", 8),
                )

        # Y-axis max label
        c.create_text(
            pad_l - 4, pad_t, text=_format_cost(max_cost),
            fill="#888888", anchor="ne", font=("Segoe UI", 8),
        )
        c.create_text(
            pad_l - 4, pad_t + chart_h, text="$0",
            fill="#888888", anchor="se", font=("Segoe UI", 8),
        )

    def _render_sessions(self):
        """Reconcile-by-key: update existing cards in place, only create/destroy deltas.

        Destroy-rebuild reset the outer scroll position every 30s whenever a
        new project appeared. Now we diff self._project_cards against the
        freshly-computed order, so scroll position is preserved.
        """
        # Belt-and-braces: save and restore outer scroll position (T7).
        try:
            saved_yview = self._sess_scroll._parent_canvas.yview()
        except tk.TclError:
            saved_yview = None

        query = self._sess_search_var.get().strip().lower()
        recent_only = self._hide_archived_var.get()

        # "Recent only" = latest session per project OR <1h since last activity.
        latest_ids = _latest_session_id_per_project(self._sessions)

        # Filter + enrich (with time-window filter from T9).
        enriched = []
        for s in self._sessions:
            if not self._session_in_window(s):
                continue
            is_live = s["session_id"] in self._active_ids  # time-based (<1h)
            is_latest = s["session_id"] in latest_ids

            if recent_only and not (is_live or is_latest):
                continue

            proj = _friendly_project(s["project"], s.get("cwd"))
            model = s["model"] or "unknown"
            sess_name = s.get("session_name") or "Untitled"

            if query and query not in proj.lower() and query not in model.lower() and query not in sess_name.lower():
                continue

            enriched.append({
                "s": s, "proj": proj, "model": model,
                "sess_name": sess_name, "is_live": is_live,
            })

        # Bucket by project
        buckets: dict[str, list[dict]] = {}
        for item in enriched:
            buckets.setdefault(item["proj"], []).append(item)

        # Resolve display order: user-saved first, then remaining by total cost desc.
        saved = [p for p in self._project_order if p in buckets]
        remaining = sorted(
            [p for p in buckets if p not in saved],
            key=lambda p: sum(i["s"]["total_cost"] for i in buckets[p]),
            reverse=True,
        )
        ordered = saved + remaining

        # Persist (merges newly-seen projects into the saved order).
        if ordered != self._project_order:
            self._project_order = ordered
            _save_project_state(
                ordered, sorted(self._collapsed_projects), self._notif_state,
            )

        # --- Reconcile ---
        # Destroy cards for projects that no longer appear.
        for proj in list(self._project_cards.keys()):
            if proj not in buckets:
                self._project_cards[proj]["card"].destroy()
                self._project_cards.pop(proj, None)

        # Create or update cards, in order.
        total = len(ordered)
        for index, proj in enumerate(ordered):
            items = buckets[proj]
            if proj in self._project_cards:
                self._update_project_card(proj, items, index, total)
            else:
                self._build_project_card(proj, items, index, total)

        # Re-pack in desired order. pack_forget + pack preserves widget
        # identity (scroll, selection, etc.) and only reshuffles layout.
        for proj in ordered:
            card = self._project_cards[proj]["card"]
            card.pack_forget()
            card.pack(fill="x", pady=6, padx=4)

        # Restore scroll position after layout settles.
        if saved_yview is not None:
            def _restore():
                try:
                    self._sess_scroll._parent_canvas.yview_moveto(saved_yview[0])
                except tk.TclError:
                    pass
            self.after_idle(_restore)

    def _build_project_card(self, proj: str, items: list[dict],
                            index: int, total: int) -> None:
        """Build one project card (header + embedded Treeview). Stores widget
        handles in self._project_cards[proj] so _update_project_card can refresh
        in place without destroy+rebuild.
        """
        card = ctk.CTkFrame(
            self._sess_scroll, fg_color="#1e1e1e",
            corner_radius=10, border_width=1, border_color="#333",
        )
        card.pack(fill="x", pady=6, padx=4)

        # ---- Header
        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=10, pady=(8, 4))

        # Collapse toggle (T8). Keeps tree hidden when user prefers.
        collapse_btn = ctk.CTkButton(
            header, text="▼", width=24, height=24,
            fg_color="transparent", hover_color="#3a3a3a",
            font=ctk.CTkFont(size=11),
            command=lambda p=proj: self._toggle_project_collapsed(p),
        )
        collapse_btn.pack(side="left", padx=(0, 4))

        title_lbl = ctk.CTkLabel(
            header, text=proj,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#ffd479",
        )
        title_lbl.pack(side="left")

        meta_lbl = ctk.CTkLabel(
            header, text="",
            font=ctk.CTkFont(size=11), text_color="gray",
        )
        meta_lbl.pack(side="left")

        live_lbl = ctk.CTkLabel(
            header, text="  LIVE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#44ee44",
        )
        # Packed/unpacked in _update_project_card based on any_live.

        # Reorder arrows (rightmost)
        down_btn = ctk.CTkButton(
            header, text="↓", width=26, height=26,
            fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=lambda p=proj: self._move_project(p, +1),
        )
        down_btn.pack(side="right", padx=2)
        up_btn = ctk.CTkButton(
            header, text="↑", width=26, height=26,
            fg_color="#2b2b2b", hover_color="#3a3a3a",
            command=lambda p=proj: self._move_project(p, -1),
        )
        up_btn.pack(side="right", padx=2)

        # ---- Body: Treeview (columns come from shared _SESSION_COLUMNS so the
        # hoisted header bar stays pixel-aligned). show="" hides the per-card
        # heading row — we rely on the shared bar above _sess_scroll instead.
        cols = tuple(c[0] for c in _SESSION_COLUMNS)
        tree = ttk.Treeview(
            card, columns=cols, show="",
            style="Dark.Treeview", height=1,
        )
        for col_id, _text, w, numeric in _SESSION_COLUMNS:
            tree.column(
                col_id, width=w, minwidth=40,
                anchor=("e" if numeric else "w"),
                stretch=False,
            )

        tree.pack(fill="x", padx=8, pady=(0, 8))
        tree.bind("<Double-1>", self._on_session_double_click)
        tree.tag_configure("active", foreground="#44ee44")
        tree.tag_configure("rot_red", background="#4a1a1a")
        tree.tag_configure("rot_amber", background="#4a3a1a")
        tree.tag_configure("group_model", background="#222222", foreground="#89c2ff")

        self._project_cards[proj] = {
            "card": card,
            "header": header,
            "title": title_lbl,
            "meta": meta_lbl,
            "live": live_lbl,
            "up": up_btn,
            "down": down_btn,
            "collapse": collapse_btn,
            "tree": tree,
            "tree_multi_model": False,  # show style may need swap on update
        }
        self._update_project_card(proj, items, index, total)

    def _update_project_card(self, proj: str, items: list[dict],
                             index: int, total: int) -> None:
        """Refresh an existing project card in place without destroying widgets.

        Preserves outer scroll position: we only mutate text, state, and
        Treeview rows — never destroy the card frame.
        """
        handles = self._project_cards[proj]
        card = handles["card"]
        meta_lbl = handles["meta"]
        live_lbl = handles["live"]
        up_btn = handles["up"]
        down_btn = handles["down"]
        tree = handles["tree"]

        n = len(items)
        turns = sum(i["s"]["assistant_turns"] for i in items)
        tokens = sum(
            i["s"]["total_input"] + i["s"]["total_output"]
            + i["s"]["total_cache_read"] + i["s"]["total_cache_write"]
            for i in items
        )
        cost = sum(i["s"]["total_cost"] for i in items)
        any_live = any(i["is_live"] for i in items)

        meta = (
            f"  ·  {n} session{'s' if n != 1 else ''}"
            f"  ·  {turns} turns"
            f"  ·  {_format_tokens(tokens)} tok"
            f"  ·  {_format_cost(cost)}"
        )
        meta_lbl.configure(text=meta)

        if any_live:
            # Pack after the meta label (which is `side="left"`), before the ↑↓ buttons.
            if not live_lbl.winfo_ismapped():
                live_lbl.pack(side="left")
        else:
            if live_lbl.winfo_ismapped():
                live_lbl.pack_forget()

        up_btn.configure(state="disabled" if index == 0 else "normal")
        down_btn.configure(state="disabled" if index == total - 1 else "normal")

        # Border tint by max live rotate score (T13).
        card.configure(border_color=self._project_border_color(items))

        # Re-populate the tree contents. We keep the Treeview widget alive
        # so its own state (scroll/selection) is intact within the card.
        self._populate_project_tree(tree, proj, items)

        # Collapse state (T8) — honor user preference.
        if proj in self._collapsed_projects:
            if tree.winfo_ismapped():
                tree.pack_forget()
            handles["collapse"].configure(text="▶")
        else:
            if not tree.winfo_ismapped():
                tree.pack(fill="x", padx=8, pady=(0, 8))
            handles["collapse"].configure(text="▼")

    def _populate_project_tree(self, tree: "ttk.Treeview", proj: str,
                               items: list[dict]) -> None:
        """Clear and re-fill the per-project Treeview with current items.

        Flat list (no model-grouping) — the model is shown in its own column,
        which keeps every row aligned with the hoisted header bar.
        """
        # Preserve selection inside this card if it survives the refresh.
        prior_sel = tree.selection()
        prior_focus = tree.focus()

        # show="" is enforced at build time; height follows row count.
        tree.configure(height=max(1, len(items)))

        # Clear old rows (flat — no nested children after the switch).
        for iid in tree.get_children():
            tree.delete(iid)

        # Newest first inside each project card.
        items_sorted = sorted(
            items, key=lambda i: i["s"]["last_timestamp"] or "", reverse=True,
        )

        for i in items_sorted:
            s = i["s"]
            is_live = i["is_live"]
            tok_in = s["total_input"]; tok_out = s["total_output"]
            tok_cr = s["total_cache_read"]; tok_cw = s["total_cache_write"]
            total_tokens = tok_in + tok_cr + tok_cw + tok_out

            wf = _waste_factor(s["turn_costs"])
            waste_str = f"{wf:.1f}x" if wf is not None else "—"
            init_tokens = _turn_total_tokens(s["turn_costs"][0]) if s["turn_costs"] else 0
            last_turn_tokens = _turn_total_tokens(s["turn_costs"][-1]) if s["turn_costs"] else 0
            duration = _duration_str(s["first_timestamp"], s["last_timestamp"])

            rot_sub = _rotate_subscores(s)
            if rot_sub:
                rot_display = _rotate_bar(rot_sub["total"])
                rot_tag_name = _rotate_tag(rot_sub["total"])
            else:
                rot_display = ""
                rot_tag_name = None

            date_str = ""
            ts = _parse_timestamp(s["last_timestamp"])
            if ts:
                date_str = ts.astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M")

            tags = []
            if is_live:
                tags.append("active")
            if rot_tag_name:
                tags.append(rot_tag_name)

            display = (
                "LIVE" if is_live else "",
                i["sess_name"], i["model"], s["assistant_turns"],
                _format_tokens(total_tokens),
                _format_tokens(init_tokens),
                _format_cost(s["total_cost"]),
                _format_tokens(last_turn_tokens),
                waste_str, rot_display, duration, date_str,
            )
            tree.insert(
                "", "end", iid=s["session_id"],
                text="", values=display, tags=tuple(tags),
            )

        # Restore selection if the iid still exists.
        try:
            survivors = [iid for iid in prior_sel if tree.exists(iid)]
            if survivors:
                tree.selection_set(survivors)
            if prior_focus and tree.exists(prior_focus):
                tree.focus(prior_focus)
        except tk.TclError:
            pass

    def _project_border_color(self, items: list[dict]) -> str:
        """Ambient rotation border: reflect worst LIVE rotate score for this project."""
        worst = 0.0
        for i in items:
            if not i["is_live"]:
                continue
            sub = _rotate_subscores(i["s"])
            if sub is None:
                continue
            if sub["total"] > worst:
                worst = sub["total"]
        if worst >= _ROTATE_RED:
            return "#cc3333"
        if worst >= _ROTATE_AMBER:
            return "#e09a1a"
        return "#333"

    def _toggle_project_collapsed(self, proj: str) -> None:
        if proj in self._collapsed_projects:
            self._collapsed_projects.discard(proj)
        else:
            self._collapsed_projects.add(proj)
        _save_project_state(
            self._project_order,
            sorted(self._collapsed_projects),
            self._notif_state,
        )
        self._render_sessions()

    def _move_project(self, proj: str, delta: int) -> None:
        """Swap project with its neighbour in the saved order, then re-render."""
        order = list(self._project_order)
        if proj not in order:
            return
        idx = order.index(proj)
        new_idx = idx + delta
        if new_idx < 0 or new_idx >= len(order):
            return
        order[idx], order[new_idx] = order[new_idx], order[idx]
        self._project_order = order
        _save_project_state(order, sorted(self._collapsed_projects), self._notif_state)
        self._render_sessions()

    # ------------------------------------------------------------------ Rotate banner + toast
    def _show_banner(self, level: str, proj: str, session_id: str) -> None:
        """Display the top-of-window rotate banner targeting a specific session."""
        color = "#cc3333" if level == "red" else "#e09a1a"
        label = "ROTATE NOW" if level == "red" else "CONSIDER ROTATING"
        self._banner.configure(fg_color=color)
        self._banner_msg.configure(text=f"{label} — {proj}")
        self._banner_target_sid = session_id
        try:
            self._banner.pack(fill="x", before=self._tabs)
        except tk.TclError:
            # Fallback if _tabs isn't packed yet; banner simply won't show.
            pass

    def _banner_jump(self) -> None:
        sid = self._banner_target_sid
        if not sid:
            return
        session = next((s for s in self._sessions if s["session_id"] == sid), None)
        if session is None:
            self._banner_dismiss_click()
            return
        self._show_session_detail(session)
        self._tabs.set("Session Detail")
        self._banner_dismiss_click()

    def _banner_dismiss_click(self) -> None:
        self._banner_target_sid = None
        try:
            self._banner.pack_forget()
        except tk.TclError:
            pass

    def _fire_toast(self, level: str, proj: str, explanation: str) -> None:
        """OS-level toast via winotify. No-op if the dep is missing."""
        if not _HAS_TOAST:
            return
        try:
            label = "ROTATE NOW" if level == "red" else "Consider rotating"
            toast = _WinotifyNotification(
                app_id="Claude Usage Monitor",
                title=f"{label} — {proj}",
                msg=explanation,
            )
            toast.show()
        except Exception:  # noqa: BLE001 - boundary: never let a flaky toast crash the refresh loop
            # Never let a flaky toast crash the refresh loop.
            pass

    def _scan_rotate_notifications(self) -> None:
        """Walk LIVE sessions, fire dedup'd toasts + banner on threshold upgrades."""
        live_sessions = [s for s in self._sessions if s["session_id"] in self._active_ids]
        live_ids = {s["session_id"] for s in live_sessions}
        _evict_inactive_notifs(self._notif_state, live_ids)

        # Find the single highest-tier unfired upgrade to surface in the banner.
        # Multiple hot sessions are still each toasted; banner shows the worst.
        banner_candidate: tuple[int, dict, str] | None = None  # (tier, session, level)
        fired = False

        for s in live_sessions:
            sub = _rotate_subscores(s)
            if sub is None:
                continue
            level = _rotate_level(sub["total"])
            sid = s["session_id"]
            if _should_notify(self._notif_state, sid, level):
                proj = _friendly_project(s["project"], s.get("cwd"))
                self._fire_toast(level, proj, _rotate_explanation(sub))
                _record_notified(self._notif_state, sid, level)
                fired = True
                tier = _NOTIF_TIERS[level]
                if banner_candidate is None or tier > banner_candidate[0]:
                    banner_candidate = (tier, s, level)

        if banner_candidate is not None:
            _, s, level = banner_candidate
            proj = _friendly_project(s["project"], s.get("cwd"))
            self._show_banner(level, proj, s["session_id"])

        if fired:
            _save_project_state(
                self._project_order,
                sorted(self._collapsed_projects),
                self._notif_state,
            )

    def _on_session_double_click(self, event):
        # Each project card owns its own Treeview — find the one that fired.
        tree = event.widget
        sel = tree.selection()
        if not sel:
            return
        sid = sel[0]
        session = next((s for s in self._sessions if s["session_id"] == sid), None)
        if not session:
            return
        self._show_session_detail(session)
        self._tabs.set("Session Detail")

    def _show_session_detail(self, s: dict):
        proj = _friendly_project(s["project"], s.get("cwd"))
        sess_name = s.get("session_name") or "Untitled"
        model = s["model"] or "unknown"
        is_active = s["session_id"] in self._active_ids
        status_str = "  [LIVE]" if is_active else ""
        self._detail_header.configure(text=f"{proj}{status_str}")

        info_parts = [
            f"Model: {model}",
            f"Branch: {s['git_branch'] or '—'}",
            f"Version: {s['version'] or '—'}",
            f"Duration: {_duration_str(s['first_timestamp'], s['last_timestamp'])}",
        ]
        self._detail_info.configure(text=f"\"{sess_name}\"\n{'  |  '.join(info_parts)}")

        # Rotate Now pill (LIVE sessions only)
        if is_active:
            self._rotate_frame.pack(fill="x", padx=8, pady=(0, 8), before=self._detail_cards_frame)
            sub = _rotate_subscores(s)
            if sub is None:
                self._rotate_pill.configure(
                    text="—  Too early to tell", fg_color="#444444",
                )
                self._rotate_explain.configure(
                    text="Need at least 5 turns for a rotation signal."
                )
            else:
                label, color = _rotate_pill_state(sub["total"])
                self._rotate_pill.configure(
                    text=f"{label}   ({sub['total']:.0f})", fg_color=color,
                )
                self._rotate_explain.configure(text=_rotate_explanation(sub))
        else:
            self._rotate_frame.pack_forget()

        # Cards
        self._detail_card_widgets["d_input"].configure(text=_format_tokens(s["total_input"]))
        self._detail_card_widgets["d_output"].configure(text=_format_tokens(s["total_output"]))
        self._detail_card_widgets["d_cache_read"].configure(text=_format_tokens(s["total_cache_read"]))
        self._detail_card_widgets["d_cache_write"].configure(text=_format_tokens(s["total_cache_write"]))
        self._detail_card_widgets["d_cost"].configure(text=_format_cost(s["total_cost"]))

        last_turn_tokens = _turn_total_tokens(s["turn_costs"][-1]) if s["turn_costs"] else 0
        self._detail_card_widgets["d_last_turn"].configure(text=_format_tokens(last_turn_tokens))

        # Cost composition + turn stats
        comp = _cost_composition(s["turn_costs"])
        comp_total = comp["total"] or 1e-9  # avoid div-by-zero when session is empty
        for key in ("input", "output", "cache_read", "cache_write"):
            amt = comp[key]
            pct = amt / comp_total
            row = self._cost_rows[key]
            row["bar"].set(pct)
            row["val"].configure(text=f"{_format_cost(amt)}  ({pct * 100:.0f}%)")

        stats = _turn_cost_stats(s["turn_costs"])
        if stats is None:
            for w in self._turn_stat_widgets.values():
                w.configure(text="—")
        else:
            self._turn_stat_widgets["first"].configure(text=_format_cost(stats["first"]))
            self._turn_stat_widgets["last"].configure(text=_format_cost(stats["last"]))
            self._turn_stat_widgets["avg"].configure(text=_format_cost(stats["avg"]))
            self._turn_stat_widgets["peak"].configure(text=_format_cost(stats["peak"]))

        wf = _waste_factor(s["turn_costs"])
        if wf is not None:
            waste_text = f"{wf:.1f}x"
            color = "#44cc44" if wf < 3 else "#ff9500" if wf < 8 else "#ff4444"
            self._detail_card_widgets["d_waste"].configure(text=waste_text, text_color=color)
        else:
            self._detail_card_widgets["d_waste"].configure(text="—", text_color="gray")

        # Cache Eff card
        cache_eff = _cache_efficiency(
            s["total_input"], s["total_cache_read"], s["total_cache_write"]
        )
        self._detail_card_widgets["d_cache_eff"].configure(
            text=f"{cache_eff * 100:.0f}%",
            text_color=("#44cc44" if cache_eff >= 0.6
                        else "#e0b020" if cache_eff >= 0.3
                        else "#ff4444"),
        )

        # Cold Turns card
        total_turns = s["assistant_turns"]
        cold_n = s["cold_turn_count"]
        cold_pct = (cold_n / total_turns * 100.0) if total_turns else 0.0
        self._detail_card_widgets["d_cold_turns"].configure(
            text=f"{cold_n} / {total_turns}  ({cold_pct:.0f}%)",
            text_color=("#ff4444" if cold_pct >= 40
                        else "#e0b020" if cold_pct >= 20
                        else "#44cc44"),
        )

        # Cache Trend card
        trend = s.get("cache_trend")
        if trend is None:
            self._detail_card_widgets["d_cache_trend"].configure(text="—", text_color="gray")
        elif trend > 0.02:
            self._detail_card_widgets["d_cache_trend"].configure(
                text=f"↑ {trend * 100:.0f}%", text_color="#44cc44",
            )
        elif trend < -0.02:
            self._detail_card_widgets["d_cache_trend"].configure(
                text=f"↓ {abs(trend) * 100:.0f}%", text_color="#ff4444",
            )
        else:
            self._detail_card_widgets["d_cache_trend"].configure(text="—", text_color="gray")

        # Chart
        self._draw_chart(s["turn_costs"])

        # Top tools (rebuild each time)
        for w in self._tools_body_frame.winfo_children():
            w.destroy()

        stats = s.get("tool_stats") or {}
        if not stats:
            ctk.CTkLabel(
                self._tools_body_frame, text="No tool usage recorded.",
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(anchor="w", pady=4)
        else:
            ranked = sorted(stats.items(), key=lambda kv: -kv[1]["est_cost"])[:8]
            max_cost = max((v["est_cost"] for _, v in ranked), default=1.0)
            for name, st in ranked:
                row = ctk.CTkFrame(self._tools_body_frame, fg_color="transparent")
                row.pack(fill="x", pady=2)

                ctk.CTkLabel(
                    row, text=name, font=ctk.CTkFont(size=11),
                    width=220, anchor="w",
                ).pack(side="left")

                bar_width = max(4, int(220 * (st["est_cost"] / max_cost))) if max_cost > 0 else 4
                bar = ctk.CTkFrame(row, width=bar_width, height=16, corner_radius=4, fg_color="#9e6a3a")
                bar.pack(side="left", padx=(8, 4))
                bar.pack_propagate(False)

                info = f"{st['calls']} calls   ~{_format_tokens(st['est_tokens'])} tok   ~{_format_cost(st['est_cost'])}"
                ctk.CTkLabel(row, text=info, font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

        # Turn table
        for item in self._turn_tree.get_children():
            self._turn_tree.delete(item)

        cum_cost = 0.0
        for i, tc in enumerate(s["turn_costs"]):
            ts_str, cost = tc[0], tc[1]
            inp, cr = tc[2], tc[4]
            tokens = _turn_total_tokens(tc)
            cum_cost += cost
            ts = _parse_timestamp(ts_str)
            time_str = ts.astimezone(LOCAL_TZ).strftime("%H:%M:%S") if ts else "—"
            cold = _is_cold_turn(inp, cr)
            marker = "●"
            tag = "cold" if cold else "warm"
            self._turn_tree.insert("", "end", values=(
                i + 1, marker, time_str, _format_cost(cost),
                _format_tokens(tokens), _format_cost(cum_cost),
            ), tags=(tag,))

    def _draw_chart(self, turn_costs: list):
        c = self._chart_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 600
        h = c.winfo_height() or 120

        if len(turn_costs) < 2:
            c.create_text(w // 2, h // 2, text="Not enough data", fill="gray", font=("Segoe UI", 10))
            return

        # Cumulative tokens
        cum = []
        total = 0
        for tc in turn_costs:
            total += _turn_total_tokens(tc)
            cum.append(total)

        max_val = max(cum) if cum else 1
        pad_x, pad_y = 10, 10
        chart_w = w - 2 * pad_x
        chart_h = h - 2 * pad_y

        points = []
        for i, val in enumerate(cum):
            x = pad_x + (i / (len(cum) - 1)) * chart_w
            y = pad_y + chart_h - (val / max_val) * chart_h
            points.append((x, y))

        # Fill area
        fill_pts = [(pad_x, pad_y + chart_h)] + points + [(pad_x + chart_w, pad_y + chart_h)]
        flat = [coord for pt in fill_pts for coord in pt]
        c.create_polygon(flat, fill="#1a3a5c", outline="")

        # Line
        line_flat = [coord for pt in points for coord in pt]
        c.create_line(line_flat, fill="#3a9eef", width=2, smooth=True)

        # Labels
        c.create_text(pad_x + 4, pad_y, text=_format_tokens(max_val), fill="gray",
                       anchor="nw", font=("Segoe UI", 8))
        c.create_text(pad_x + chart_w, pad_y + chart_h, text=f"{len(cum)} turns", fill="gray",
                       anchor="se", font=("Segoe UI", 8))


# ---------------------------------------------------------------------------
# Entry point for toolbox
# ---------------------------------------------------------------------------

def run_tool():
    ClaudeUsageMonitor()
