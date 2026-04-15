# Claude Usage Monitor — Rotate Now Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cache efficiency, tool-usage tracking, and a Rotate Now score pill to the Claude Usage Monitor so the user can decide at a glance whether to start a fresh session.

**Architecture:** All changes land in the single existing file `tools/claude_usage_monitor.py`. A new `tests/test_claude_usage_monitor.py` file tests pure helper functions (cold-turn rule, Rotate score, cache trend, tool cost estimation). GUI code is not unit-tested (smoke-tested manually by launching the tool). The spec for this plan lives at `docs/superpowers/specs/2026-04-15-claude-usage-monitor-rotate-now-design.md`.

**Tech Stack:** Python stdlib (`json`, `glob`, `pathlib`, `datetime`), `customtkinter`, `tkinter.ttk`, `pytest`.

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `tools/claude_usage_monitor.py` | Modify | All logic + UI changes. Single-module tool (existing pattern). |
| `tests/__init__.py` | Create | Empty file to make `tests` a package. |
| `tests/test_claude_usage_monitor.py` | Create | Pytest tests for pure helper functions. |
| `docs/superpowers/specs/2026-04-15-claude-usage-monitor-rotate-now-design.md` | Read-only | Design spec, source of truth. |
| `C:\Users\Christophoros\.claude\projects\F--DevCrow-Python-Automations\memory\tool_claude_usage_monitor.md` | Modify | Memory note — updated last to reflect new features. |

**Naming conventions used throughout:** snake_case for all new functions/variables. Module-level constants `UPPER_SNAKE`.

---

## Prerequisites

- [ ] **Step 0a: Verify pytest is installed in the project venv**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pytest --version`
If it reports a version, skip step 0b. If it reports "No module named pytest", continue.

- [ ] **Step 0b: Install pytest into the venv if missing**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pip install pytest`
Expected: pytest installed successfully. Re-verify with `pytest --version`.

- [ ] **Step 0c: Pin pytest if a requirements.txt exists**

Check for `F:/DevCrow/Python/Automations/requirements.txt`. If present, add a line `pytest>=8.0` (only if not already pinned). If absent, skip — the project does not currently track dev dependencies.

---

## Task 1: Extend `turn_costs` tuple and update all consumers

**Rationale:** All downstream features (cold-turn detection, Rotate score, cache trend) need per-turn input/output/cache_read/cache_write split. Must land as one atomic change to avoid a broken intermediate state.

**Files:**
- Modify: `tools/claude_usage_monitor.py` — parser (lines ~131–223) + all 5 consumers.

**Existing tuple shape:** `(timestamp, cost, total_tokens)` — index 0 = ts, 1 = cost, 2 = total_tokens.

**New tuple shape:** `(timestamp, cost, input_tokens, output_tokens, cache_read, cache_write, model)`

- [ ] **Step 1.1: Update the append in `_parse_session_file`**

Locate this block near line 217:
```python
total_tok = inp + out + cr + cw
session["turn_costs"].append((ts_str, cost, total_tok))
```

Replace with:
```python
session["turn_costs"].append((ts_str, cost, inp, out, cr, cw, model))
```

- [ ] **Step 1.2: Update `_waste_factor` to derive total tokens from the new tuple**

Locate at line ~267:
```python
def _waste_factor(turn_costs: list) -> float | None:
    """Waste factor: average tokens/turn in last 5 turns vs first 5 turns."""
    if len(turn_costs) < 6:
        return None
    first5 = [tc[2] for tc in turn_costs[:5]]
    last5 = [tc[2] for tc in turn_costs[-5:]]
```

Replace the list-comprehension lines with:
```python
    first5 = [tc[2] + tc[3] + tc[4] + tc[5] for tc in turn_costs[:5]]
    last5 = [tc[2] + tc[3] + tc[4] + tc[5] for tc in turn_costs[-5:]]
```

- [ ] **Step 1.3: Update `_render_sessions` init_tokens extraction**

Locate at line ~953:
```python
init_tokens = s["turn_costs"][0][2] if s["turn_costs"] else 0
```

Replace with (first-turn total = in + out + cr + cw):
```python
init_tokens = (
    s["turn_costs"][0][2] + s["turn_costs"][0][3]
    + s["turn_costs"][0][4] + s["turn_costs"][0][5]
) if s["turn_costs"] else 0
```

- [ ] **Step 1.4: Update `_show_session_detail` per-turn table loop**

Locate at line ~1091:
```python
for i, (ts_str, cost, tokens) in enumerate(s["turn_costs"]):
```

Replace with:
```python
for i, (ts_str, cost, inp, out, cr, cw, _model) in enumerate(s["turn_costs"]):
    tokens = inp + out + cr + cw
```

- [ ] **Step 1.5: Update `_draw_chart` loop**

Locate at line ~1114:
```python
for _, _, tokens in turn_costs:
    total += tokens
```

Replace with:
```python
for tc in turn_costs:
    tokens = tc[2] + tc[3] + tc[4] + tc[5]
    total += tokens
```

- [ ] **Step 1.6: Update `_render_peak_hours` loop**

Locate at line ~854:
```python
for ts_str, cost, _ in s["turn_costs"]:
```

Replace with:
```python
for tc in s["turn_costs"]:
    ts_str, cost = tc[0], tc[1]
```

- [ ] **Step 1.7: Smoke test — launch tool, open a session with >5 turns**

Launch the toolbox (`Launch.pyw` or equivalent) and open the Claude Usage Monitor. Expected: Dashboard loads, Sessions tab lists sessions with correct token/cost columns, double-clicking a session opens Session Detail with the chart and per-turn table populated. The `Waste` column and `Init Tok` column should still show sensible values.

Close the window after verifying.

- [ ] **Step 1.8: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "refactor: extend turn_costs tuple with per-turn token split

Stores input/output/cache_read/cache_write separately instead of a
single total_tokens sum. Required for upcoming cold-turn detection,
cache trend, and Rotate Now features. All five consumers updated
together to avoid a broken intermediate state."
```

---

## Task 2: Add pure helper functions (cold turn, cache efficiency, cache trend)

**Files:**
- Modify: `tools/claude_usage_monitor.py` — add helpers in the "Data layer" section (after `_waste_factor`, around line 278).
- Create: `tests/__init__.py`
- Create: `tests/test_claude_usage_monitor.py`

- [ ] **Step 2.1: Add module-level constants at the top of `tools/claude_usage_monitor.py`**

After the `_DEFAULT_PRICING` line (around line 51), add:

```python
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
```

- [ ] **Step 2.2: Add helper functions after `_waste_factor`**

After the `_waste_factor` function (around line 278), insert:

```python
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
```

- [ ] **Step 2.3: Create `tests/__init__.py`**

Create an empty file at `tests/__init__.py` with a single newline.

- [ ] **Step 2.4: Create `tests/test_claude_usage_monitor.py` with the failing tests**

```python
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
```

- [ ] **Step 2.5: Run tests — expect all to PASS (helpers already exist from Step 2.2)**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pytest tests/test_claude_usage_monitor.py -v`

Expected: all 11 tests PASS.

If any fail, the helpers in Step 2.2 have a bug — fix the helper, not the test (the test codifies the spec).

- [ ] **Step 2.6: Commit**

```bash
git add tools/claude_usage_monitor.py tests/__init__.py tests/test_claude_usage_monitor.py
git commit -m "feat: add cold-turn and cache-trend helpers with tests

Pure functions for cold-turn detection, cache efficiency, cache
trend, cold-turn counting, and cluster-end flag. Used by the
upcoming Rotate Now score. Includes module constants for thresholds
and the cold-turn rule (ratio < 0.5 AND input >= 2000)."
```

---

## Task 3: Add cold-turn session fields + cache trend to session parsing

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_parse_session_file` return structure.

- [ ] **Step 3.1: Add new fields to the session dict in `_parse_session_file`**

In the `session = { ... }` initialization block (around line 133), add after the `"models_used"` line:

```python
        "tool_stats": {},            # {name: {"calls": int, "est_tokens": int, "est_cost": float}}
        "cold_turn_count": 0,
        "cold_turns_cluster_end": False,
        "cache_trend": None,         # None until >= 10 turns
```

- [ ] **Step 3.2: Populate the cold / trend fields at the end of `_parse_session_file`**

Just before `session["models_used"] = list(session["models_used"])` (around line 222), insert:

```python
    session["cold_turn_count"] = _cold_turn_count(session["turn_costs"])
    session["cold_turns_cluster_end"] = _cold_turns_cluster_end(session["turn_costs"])
    session["cache_trend"] = _cache_trend(session["turn_costs"])
```

- [ ] **Step 3.3: Smoke test — launch and confirm no regressions**

Launch the toolbox (`Launch.pyw` or equivalent), open the Claude Usage Monitor. Verify the existing Sessions tab still loads and no tracebacks appear in the terminal.

- [ ] **Step 3.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: compute cold-turn stats and cache trend during session parse

Adds cold_turn_count, cold_turns_cluster_end, cache_trend, and an
empty tool_stats dict to each parsed session. Values are computed
once at parse time to keep UI rendering cheap."
```

---

## Task 4: Add tool-use scan + cost estimation helper with tests

**Files:**
- Modify: `tools/claude_usage_monitor.py` — new helper + parser changes.
- Modify: `tests/test_claude_usage_monitor.py` — add tool-estimation tests.

- [ ] **Step 4.1: Add `_estimate_tool_cost` helper after `_cold_turns_cluster_end`**

```python
def _estimate_tool_tokens(payload: dict | list | str | None) -> int:
    """Approximate token count from a JSON-serializable payload.

    Uses the standard ~4 chars-per-token heuristic. Returns 0 for None / empty.
    """
    if payload is None:
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
```

- [ ] **Step 4.2: Scan tool_use blocks during parsing**

This requires two changes to `_parse_session_file`:

**(a)** Track the most recent assistant record's pending tool_use calls so we can match them against the next user record's tool_results. Add a new local variable near the top of the `for line in f:` loop's initialization (just before the `for line in f:` at line 157):

```python
        pending_tools: dict[str, tuple[str, int, dict]] = {}
        # maps tool_use_id -> (tool_name, out_tokens_estimate, pricing)
```

**(b)** Inside the `elif rec_type == "assistant":` block, after the `usage = msg.get("usage", {})` handling (after line 217's append), add:

```python
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
```

**(c)** Inside the `if rec_type == "user":` block (around line 176), scan the user message for `tool_result` blocks and attribute their size to the matching tool:

```python
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
```

This block goes inside the `if rec_type == "user":` handler, immediately after the existing `session["user_turns"] += 1` line is executed — keep the existing prompt-extraction logic untouched.

- [ ] **Step 4.3: Add tests for tool estimation**

Append to `tests/test_claude_usage_monitor.py`:

```python
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
```

- [ ] **Step 4.4: Run tests**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pytest tests/test_claude_usage_monitor.py -v`

Expected: all 15 tests PASS (11 prior + 4 new).

- [ ] **Step 4.5: Smoke test — open a session and check tool_stats populates**

Quick manual check in a Python REPL:
```python
from tools.claude_usage_monitor import load_all_sessions
sessions = load_all_sessions()
s = [s for s in sessions if s["tool_stats"]][0]
print(s["tool_stats"])
```
Expected: a non-empty dict with at least one tool name, `calls > 0`, and sensible `est_tokens`/`est_cost` values.

- [ ] **Step 4.6: Commit**

```bash
git add tools/claude_usage_monitor.py tests/test_claude_usage_monitor.py
git commit -m "feat: scan tool_use blocks and aggregate per-tool stats

Adds tool invocation tracking: counts calls per tool name, estimates
token spend via the chars/4 heuristic over both tool_use input and
matching tool_result output, and converts to dollars with the same
model pricing used for the turn. Marked 'est.' in downstream UI."
```

---

## Task 5: Rotate Now score computation with tests

**Files:**
- Modify: `tools/claude_usage_monitor.py` — add `_compute_rotate_score` + dominant-factor helper.
- Modify: `tests/test_claude_usage_monitor.py` — add score tests.

- [ ] **Step 5.1: Add score computation after `_estimate_tool_cost`**

```python
def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, value))


def _rotate_subscores(session: dict) -> dict | None:
    """Compute the five weighted sub-scores for a session.

    Returns None when the session has fewer than 5 turns. Shape:
        {
            "cont_cost": float,
            "fresh_proj": float,
            "savings": float,
            "waste": float,
            "cache_trend": float,
            "turn_count": float,
            "cold_cluster": float,
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
```

- [ ] **Step 5.2: Add tests for the score function**

Append to `tests/test_claude_usage_monitor.py`:

```python
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
```

- [ ] **Step 5.3: Run tests — all must pass**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pytest tests/test_claude_usage_monitor.py -v`

Expected: 20 tests PASS (15 prior + 5 new).

- [ ] **Step 5.4: Commit**

```bash
git add tools/claude_usage_monitor.py tests/test_claude_usage_monitor.py
git commit -m "feat: compute Rotate Now score with weighted sub-scores

Adds _rotate_subscores (returns raw + weighted + total), pill
state/color mapping, and a dominant-factor explanation generator.
Weights match the design spec: 0.50/0.20/0.15/0.10/0.05 across
savings/waste/cache_trend/turn_count/cold_cluster."
```

---

## Task 6: Session Detail UI — Rotate Now pill

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_build_detail_tab` (add widgets) + `_show_session_detail` (populate).

- [ ] **Step 6.1: Add pill widgets to `_build_detail_tab`**

After the `self._detail_info.pack(pady=(0, 8))` line (around line 624), before the `# Summary cards` block, insert:

```python
        # Rotate Now pill
        self._rotate_frame = ctk.CTkFrame(parent, corner_radius=12, fg_color="#2b2b2b")
        self._rotate_frame.pack(fill="x", padx=8, pady=(0, 8))

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
```

- [ ] **Step 6.2: Populate pill in `_show_session_detail`**

Immediately after the existing `self._detail_info.configure(...)` line (around line 1066), add:

```python
        # Rotate Now pill (LIVE sessions only)
        if is_active:
            self._rotate_frame.pack(fill="x", padx=8, pady=(0, 8))
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
```

- [ ] **Step 6.3: Smoke test the pill**

Launch the tool. Open a LIVE session (green tag). Verify the pill appears with a score, color, and explanation. Open an archived session — pill should be hidden.

- [ ] **Step 6.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: show Rotate Now pill on Session Detail for LIVE sessions

Big color-coded pill (red/amber/green) appears above the stat cards
for LIVE sessions with >= 5 turns. Shows the score, label, and a
one-line dominant-factor explanation. Hidden for archived sessions;
'Too early to tell' for LIVE sessions with fewer than 5 turns."
```

---

## Task 7: Session Detail UI — second cards row (Cache Eff / Cold Turns / Cache Trend)

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_build_detail_tab` + `_show_session_detail`.

- [ ] **Step 7.1: Add the second row of cards in `_build_detail_tab`**

After the loop that builds the existing `self._detail_card_widgets` row (just after the closing `self._detail_card_widgets[key] = v` on line 645), insert a new block:

```python
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
```

- [ ] **Step 7.2: Populate the new cards in `_show_session_detail`**

After the existing `wf = _waste_factor(s["turn_costs"])` block that configures `d_waste` (ends around line 1081), add:

```python
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
```

- [ ] **Step 7.3: Smoke test the second row**

Open a session with plenty of turns. Confirm Cache Eff, Cold Turns, and Cache Trend cards show sensible values in the new row. Values should match the equivalent column in the Sessions table where applicable.

- [ ] **Step 7.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: second cards row on Session Detail (Cache Eff / Cold Turns / Cache Trend)"
```

---

## Task 8: Session Detail UI — Top Tools panel

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_build_detail_tab` + `_show_session_detail`.

- [ ] **Step 8.1: Add the Top Tools panel in `_build_detail_tab`**

After the Token Growth chart section (after the `self._chart_canvas.pack(...)` call around line 659), insert:

```python
        # Top Tools panel
        tools_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        tools_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            tools_frame, text="Top Tools Used (est.)",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self._tools_body_frame = ctk.CTkFrame(tools_frame, fg_color="transparent")
        self._tools_body_frame.pack(fill="x", padx=12, pady=(0, 10))
```

- [ ] **Step 8.2: Render top-8 tools in `_show_session_detail`**

After the `self._draw_chart(s["turn_costs"])` line, before the per-turn table loop, add:

```python
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
```

- [ ] **Step 8.3: Smoke test**

Open a session with tool usage. Confirm the panel shows up to 8 tools with bar, call count, estimated tokens, and estimated cost. A session with no tool usage should show the "No tool usage recorded." message.

- [ ] **Step 8.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: Top Tools panel on Session Detail view

Shows up to 8 tools ranked by estimated cost. Uses the same bar-row
pattern as Cost by Model, with a brown bar color to distinguish
from the model/project panels."
```

---

## Task 9: Per-turn table — add Cold/Warm indicator column

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_build_detail_tab` + `_show_session_detail`.

- [ ] **Step 9.1: Add `cw` column to the turn tree definition**

Locate the `turn_cols = (...)` line near line 662. Replace:

```python
        turn_cols = ("turn", "timestamp", "cost", "tokens", "cumulative")
```

With:

```python
        turn_cols = ("turn", "cw", "timestamp", "cost", "tokens", "cumulative")
```

And update the column setup loop below it. Replace the current `for col, text, w in [...]:` block with:

```python
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
```

Add tag colors right after the column setup (still inside `_build_detail_tab`):

```python
        self._turn_tree.tag_configure("cold", foreground="#ff6666")
        self._turn_tree.tag_configure("warm", foreground="#888888")
```

- [ ] **Step 9.2: Populate the new column in `_show_session_detail`**

Replace the per-turn loop near line 1091:

```python
        cum_cost = 0.0
        for i, (ts_str, cost, inp, out, cr, cw, _model) in enumerate(s["turn_costs"]):
            cum_cost += cost
            tokens = inp + out + cr + cw
            ts = _parse_timestamp(ts_str)
            time_str = ts.astimezone().strftime("%H:%M:%S") if ts else "—"
            cold = _is_cold_turn(inp, cr)
            marker = "●"
            tag = "cold" if cold else "warm"
            self._turn_tree.insert("", "end", values=(
                i + 1, marker, time_str, _format_cost(cost),
                _format_tokens(tokens), _format_cost(cum_cost),
            ), tags=(tag,))
```

(Note: this replaces the Task 1.4 version with the final loop shape. The Step 1.4 loop was a temporary compatibility shim.)

- [ ] **Step 9.3: Smoke test**

Open a session. Verify the per-turn table now has a "C/W" column with red dots on cold turns and gray dots on warm turns. The first turn of the session should always show a red dot.

- [ ] **Step 9.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: add C/W indicator column to per-turn table

Red dot for cold turns (big fresh input, low cache hit), gray for
warm. Makes cache invalidation patterns visible at a glance."
```

---

## Task 10: Dashboard — Cost by Tool panel

**Files:**
- Modify: `tools/claude_usage_monitor.py` — `_build_dashboard` + `_render_dashboard`.

- [ ] **Step 10.1: Add the panel widget in `_build_dashboard`**

Between the "Model breakdown" block and the "Top projects" block (around line 518), insert:

```python
        # Tool breakdown
        tool_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        tool_frame.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            tool_frame, text="Cost by Tool (est.)",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self._tool_breakdown_frame = ctk.CTkFrame(tool_frame, fg_color="transparent")
        self._tool_breakdown_frame.pack(fill="x", padx=12, pady=(0, 10))
```

- [ ] **Step 10.2: Render the panel in `_render_dashboard`**

After the model breakdown loop ends (after the `ctk.CTkLabel(row, text=_format_cost(cost), ...)` for models, around line 817), insert:

```python
        # Tool breakdown (aggregate across all sessions)
        for w in self._tool_breakdown_frame.winfo_children():
            w.destroy()

        tool_costs: dict[str, float] = {}
        tool_calls: dict[str, int] = {}
        for s in self._sessions:
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
```

- [ ] **Step 10.3: Smoke test**

Launch the tool. The Dashboard should now show a "Cost by Tool (est.)" panel between "Cost by Model" and "Cost by Project". Top 10 tools ranked by estimated cost with a call count.

- [ ] **Step 10.4: Commit**

```bash
git add tools/claude_usage_monitor.py
git commit -m "feat: Cost by Tool panel on Dashboard

Parallels Cost by Model and Cost by Project. Top 10 tools ranked
by estimated dollar cost across all sessions, with a brown bar
color distinct from model (blue) and project (orange)."
```

---

## Task 11: Full smoke test + verify all tests still pass

- [ ] **Step 11.1: Run the full test suite**

Run: `F:/DevCrow/Python/Automations/venv/Scripts/python.exe -m pytest tests/ -v`

Expected: all 20 tests PASS.

- [ ] **Step 11.2: End-to-end smoke test**

Launch the tool. Verify:
- Dashboard: summary cards, peak hours chart, Cost by Model, **Cost by Tool (NEW)**, Cost by Project.
- Sessions tab: table loads, all existing columns (including `Cache %`) still populated. Sortable.
- Session Detail (archived session): no Rotate pill, all other sections populated.
- Session Detail (LIVE session with ≥5 turns): Rotate pill shows score + color + explanation; second cards row (Cache Eff / Cold Turns / Cache Trend); Top Tools panel; per-turn table with C/W dots.
- Session Detail (LIVE session with <5 turns): pill reads "— Too early to tell".

- [ ] **Step 11.3: Commit nothing (if all checks pass, no changes needed)**

If any bug surfaced, fix it with a focused commit: `fix: <bug>`.

---

## Task 12: Update memory note

**Files:**
- Modify: `C:\Users\Christophoros\.claude\projects\F--DevCrow-Python-Automations\memory\tool_claude_usage_monitor.md`

- [ ] **Step 12.1: Append a new bullet list section to the memory note**

Open the file and add, at the end of the existing content, these new bullets inside the "Key features" list (or as a new section "Added 2026-04-15" if that's cleaner):

```markdown
- Cache Efficiency card (Session Detail) — `cache_read / (input + cache_read + cache_write)`, color-coded
- Cold-turn detection — rule: `cache_read / (input + cache_read) < 0.5 AND input >= 2000`; first turn always cold
- Cold Turns card shows `N / M (X%)`; per-turn table has C/W red/gray dot column
- Cache Trend card — delta between late-5 vs first-5 cache efficiency; arrow + % + color
- Tool-usage scan — parses `tool_use` blocks, matches `tool_result` by `tool_use_id`, estimates tokens via chars/4 heuristic
- Top Tools panel on Session Detail (top 8); Cost by Tool panel on Dashboard (top 10) — brown bars, label "est."
- Rotate Now pill on Session Detail for LIVE sessions with ≥5 turns
  - Score 0..100: `0.50*savings + 0.20*waste + 0.15*cache_trend + 0.10*turn_count + 0.05*cold_cluster`
  - Thresholds: ≥60 red ROTATE NOW, 30–59 amber CONSIDER ROTATING, <30 green KEEP GOING
  - Dominant-factor explanation line underneath
- Score weights + thresholds are module constants (`_ROTATE_W_*`, `_ROTATE_RED`, `_ROTATE_AMBER`) for easy tuning
- Pytest tests cover pure helpers in `tests/test_claude_usage_monitor.py` (GUI not tested)
```

- [ ] **Step 12.2: Commit the memory-note update in git if the file is tracked**

Memory files live under `~/.claude/` (outside the project repo) so no project git commit is needed.

---

## Self-review checklist

This section is for the executor to run before marking the plan complete.

- [ ] All 12 tasks executed and their commits landed.
- [ ] `pytest tests/` reports 20 passing tests.
- [ ] Manual smoke test of Dashboard, Sessions, Session Detail (archived), Session Detail (LIVE, <5 turns), Session Detail (LIVE, ≥5 turns) — all pass the acceptance criteria in the spec.
- [ ] No changes to existing Sessions table columns (same names, same order).
- [ ] `docs/superpowers/specs/2026-04-15-claude-usage-monitor-rotate-now-design.md` remains the source of truth — any deviation from the spec must be noted in a commit message.
