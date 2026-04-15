# Claude Usage Monitor — Cache Efficiency, Tool Usage, and Rotate Now Indicator

**Date:** 2026-04-15
**Target file:** `tools/claude_usage_monitor.py`
**Status:** Approved design, pending implementation plan.

---

## Goal

Extend the existing Claude Usage Monitor with deeper cost intelligence focused on a single practical question: **"Should I start a fresh session right now, or keep going?"**

Four features, in order of novelty:

1. **Cache efficiency score** — already surfaced in the Sessions table as `Cache %`. Add the same value to the Session Detail cards.
2. **Cold-vs-warm turn detection** — count per-session, flag sessions where cold turns cluster near the end.
3. **Tool-usage breakdown** — parse `tool_use` content blocks; aggregate call count + estimated token spend per tool name. Show top tools per session; add a "Cost by Tool" panel to the Dashboard.
4. **Rotate Now indicator** — a 0–100 score (red/amber/green pill) on the Session Detail view for LIVE sessions, with a one-line dominant-factor explanation.

Non-goals:
- No changes to existing columns, pricing logic, or the waste factor computation.
- No historical-session calibration for the fresh-session projection (see Caveat 2).
- No per-tool breakdown in the Sessions table (kept on Session Detail + Dashboard only).

---

## Data model changes

### 1. Extend `turn_costs` tuple

Current: `(timestamp, cost, total_tokens)`

New:
```
(timestamp, cost, input_tokens, output_tokens, cache_read, cache_write, model)
```

All consumers are internal to `claude_usage_monitor.py`, so no migration concern. Existing consumers use index 0 (ts), 1 (cost), and "sum of tokens" — the latter becomes `input + output + cache_read + cache_write`.

### 2. New session fields

```python
session["tool_stats"]: dict[str, {
    "calls": int,
    "est_tokens": int,
    "est_cost": float,
}]
session["cold_turn_count"]: int
session["cold_turns_cluster_end"]: bool   # ≥3 of last 5 turns are cold
```

### 3. Tool-use scan

Added inside the existing `_parse_session_file` loop, during assistant record handling:

- Walk `msg["content"]` for blocks with `type == "tool_use"`.
- For each block:
  - `name` = `block["name"]`
  - Estimate output-side tokens: `len(json.dumps(block.get("input", {}))) // 4`
  - Find the matching `tool_result` in the **next** user record (by `tool_use_id`); estimate input-side tokens from `len(json.dumps(result_content)) // 4`
  - Attribute dollars using the same turn's model pricing: `est_cost = (out_tok × output_rate + in_tok × input_rate) / 1_000_000`
- Accumulate into `session["tool_stats"][name]`.

---

## Cold turn definition

```python
def _is_cold_turn(input_tokens: int, cache_read: int) -> bool:
    if input_tokens < 2000:
        return False                             # noise filter: tiny tool-result-only turns
    denom = input_tokens + cache_read
    if denom == 0:
        return False
    return (cache_read / denom) < 0.5
```

Rationale: a turn is cold when fresh input exceeds cached input **and** the turn is big enough for the cost to matter. First turn of every session satisfies this (cache_read = 0, input_tokens usually ≫ 2000).

**Clustering check:**
```python
cluster_end = sum(1 for t in last_5_turns if is_cold(t)) >= 3
```

---

## Cache efficiency

Formula (unchanged from existing):
```
cache_efficiency = cache_read / (input + cache_read + cache_write)
```

Already computed per session as `cache_hit_pct`. Reuse the same value in the new Session Detail card. **Do not add a new column to the Sessions table.**

**Cache trend** (for the Rotate formula): compare cache efficiency over 5-turn windows at the start vs end of the session.
```python
trend = cache_eff(last_5_turns) - cache_eff(first_5_turns)   # negative = degrading
```

---

## Rotate Now formula

### Applicability

- Only shown for LIVE sessions with `assistant_turns >= 5`.
- Below threshold: pill shows `—` with caption "Too early to tell".

### Inputs

| Variable | Definition |
|---|---|
| `cont_cost` | Mean cost of the last 5 turns |
| `fresh_proj` | Mean cost of the first 5 turns (cold-start model) |
| `waste` | Existing waste factor (last5 tokens / first5 tokens) |
| `trend` | `cache_eff(last5) - cache_eff(first5)` |
| `turns` | `assistant_turns` |
| `cluster_end` | True if ≥3 of last 5 turns are cold |

### Sub-scores (each clamped to 0..100)

```python
savings_score       = clamp((cont_cost - fresh_proj) / cont_cost * 100)  # 0 if cont_cost <= 0
waste_score         = clamp((waste - 1) * 25)
cache_trend_score   = clamp(-trend * 200)
turn_count_score    = clamp(max(0, turns - 25) * 2)
cold_cluster_score  = 100 if cluster_end else 0
```

### Final score

```python
score = (
      0.50 * savings_score
    + 0.20 * waste_score
    + 0.15 * cache_trend_score
    + 0.10 * turn_count_score
    + 0.05 * cold_cluster_score
)
```

All five weights live as module-level constants (`_ROTATE_W_*`) so they can be retuned without logic changes.

### Pill states

| Score | State | Color |
|---|---|---|
| ≥ 60 | `ROTATE NOW` | red `#cc3333` |
| 30–59 | `CONSIDER ROTATING` | amber `#e09a1a` |
| < 30 | `KEEP GOING` | green `#2a8a2a` |

### Dominant factor explanation

Pick the factor with the largest weighted contribution to `score`. The one-liner under the pill:

| Dominant factor | Text template |
|---|---|
| savings | `Last 5 turns avg ${cont_cost:.3f} vs projected fresh ${fresh_proj:.3f}` |
| waste | `Context bloat: last-5 turns use {waste:.1f}x tokens vs first-5` |
| cache_trend | `Cache efficiency falling: {early_eff:.0%} → {late_eff:.0%}` |
| turn_count | `Long session: {turns} turns in` |
| cold_cluster | `Cold turns clustering at session end` |

### Validation cases

| Scenario | Score | Expected pill |
|---|---|---|
| savings=0.9 alone, others neutral, turns=30 | ~46 | amber |
| savings=0.5, waste=3, trend=−0.3, turns=60, cluster=true | ~56 | amber |
| savings=0.8, waste=4, trend=−0.2, turns=50, cluster=true | ~71 | red |
| Healthy long session: turns=60, savings=0, waste=1.5, trend=0 | ~9 | green |
| Fresh session: turns=5, savings=0, waste=1, trend=0 | ~0 | green |

---

## UI changes

### Session Detail view (primary home)

Order from top:

1. **Header + info line** — unchanged.
2. **NEW: Rotate Now pill** — prominent row directly under the info line.
   - `CTkLabel` with `corner_radius=12`, colored background, bold ~22pt.
   - Second label below in gray 11pt for the dominant-factor explanation.
   - Hidden for archived sessions; `—  Too early to tell` for <5 turns.
3. **Existing cards row** (Input / Output / Cache R / Cache W / Cost / Waste) — untouched.
4. **NEW: second cards row** (Cache Eff / Cold Turns / Cache Trend).
   - Same card pattern as existing row (`CTkFrame` corner_radius=8, `#2b2b2b`).
   - "Cold Turns" displays `N of M (X%)`.
   - "Cache Trend" displays arrow + delta: `↓ 12%` red, `↑ 3%` green, `—` gray for no data.
5. **Token growth chart** — unchanged.
6. **NEW: Top Tools panel** — follows the `Cost by Model` bar-row pattern.
   - Top 8 tools sorted by estimated cost descending.
   - Each row: tool name | bar (color `#9e6a3a`) | `N calls  ~XK tok  ~$0.xx`.
   - Mark `$` values with a superscript "est" or the label "est." to signal the heuristic.
7. **Per-turn table** — add a leading `C/W` column.
   - Red `●` for cold turns, gray `●` for warm turns.

### Dashboard tab

**NEW: "Cost by Tool" panel** — inserted between "Cost by Model" and "Cost by Project".
- Identical layout to the two neighbors.
- Aggregates `tool_stats` across all sessions.
- Top 10 by estimated cost, bar color `#9e6a3a`.

### Sessions tab

No changes. The existing `Cache %` column already represents cache efficiency.

---

## Module constants (added at top of file)

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

# Tool-spend heuristic
_TOOL_CHARS_PER_TOKEN = 4
```

---

## Caveats

1. **Cache TTL assumption.** The 5-minute ephemeral cache is the default. `fresh_proj` (mean of first 5 turns of this session) implicitly assumes the fresh session is started immediately. Idling >5 minutes before the first turn of the new session expires any stale cache writes — the real fresh cost is slightly cheaper than projected. Under-estimates savings marginally; not worth modeling.

2. **Fresh-session projection calibration.** Using this session's own first 5 turns fails when (a) the session resumed from a prior one rather than a true cold start, or (b) the project is brand new vs. mature (cache coverage differs). Not building historical calibration yet — candidate future enhancement: median of first-5-turn costs across the last N sessions in the same `cwd`.

3. **Tool-spend is estimated.** Char-length ÷ 4 heuristic. Expected ~±20% error. UI labels it "est." and ranks by relative size — direction is more trustworthy than absolute dollars. The call counts are exact.

4. **Score assumes homogeneous work within a session.** A run of expensive late turns (e.g., a complex task at the end of an otherwise light session) can spike `cont_cost` and tip the pill even when rotation wouldn't help. Waste factor and cache trend partially offset this.

5. **MCP tool names include their server prefix** (`mcp__server__tool`). Displayed as-is; future enhancement could shorten.

---

## Acceptance criteria

- [ ] Sessions table unchanged (same columns, same ordering).
- [ ] Session Detail shows the Rotate Now pill for LIVE sessions with ≥5 turns, "Too early" otherwise, hidden for archived.
- [ ] Pill color and text match the thresholds (≥60 red, 30–59 amber, <30 green).
- [ ] Dominant-factor explanation text matches the template table.
- [ ] Cache Eff / Cold Turns / Cache Trend cards appear in a new second row.
- [ ] Top Tools panel appears on Session Detail; Cost by Tool panel appears on Dashboard between Model and Project panels.
- [ ] Per-turn table has a `C/W` indicator column; red dot matches the cold-turn rule.
- [ ] No regressions: dashboard summary cards, peak hours chart, sortable session list, turn growth chart, and waste-factor card all behave as before.
- [ ] No new external dependencies.

---

## Out of scope (explicitly)

- Historical calibration of fresh-session projection.
- Retrospective Rotate score on archived sessions.
- Per-tool breakdown in the Sessions table.
- Configurable weights via UI (constants only).
- Rotate pill on the Sessions table rows.
- MCP tool-name shortening.
