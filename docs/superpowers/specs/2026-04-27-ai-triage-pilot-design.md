# AI Triage Pilot — Design Spec

**Date:** 2026-04-27
**Status:** Design — pending user review
**Pilot tool:** `tools/network_intrusion_detector_pro.py` (NID)
**Shared module (new):** `tools/_common/ai_triage.py`

## 1. Goal

Add an opt-in AI triage layer to NID that turns raw alerts and suspicious connections into plain-English explanations with suggested actions. Layer is purely additive — rule-based classification (SAFE / KNOWN / UNKNOWN / SUSPICIOUS / DANGEROUS) is unchanged.

Pilot proves the integration pattern. Same `_common/ai_triage.py` module is reused later by `security_audit`, `system_health_monitor`, and `account_activity_monitor`.

## 2. Non-goals (anti-scope)

- No replacement of rule-based classification.
- No autonomous block / kill / firewall actions from AI output. Suggestions only — humans click.
- No background polling that calls AI on every connection. Triage is *requested*, not *pushed*.
- No god-file split of NID this round. (B8 split happens during Tier-2 expansion.)
- No portable/ shadow-copy update this round. Pilot lands in tools/ only.
- No telemetry, analytics, or external logging beyond local SQLite cache.

## 3. Success criteria

1. User clicks "🤖 Triage" on a NID alert → receives a structured explanation in <8s (Haiku) on warm cache, <15s cold.
2. AI panel shows: severity-in-words, why-it-matters, suggested-action, false-positive-likelihood.
3. Existing rule-based classification renders unchanged when AI is OFF.
4. Daily token cap is respected — overruns gray the button with a tooltip.
5. With Claude Code logged in (Max sub), zero extra billing observed across a week of normal use.
6. Pilot ships with one before/after demo screenshot pair for portfolio README.

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ NID UI (network_intrusion_detector_pro.py)                  │
│                                                              │
│  Alerts table ──┐                                           │
│                 ├── "🤖 Triage" button (per row)            │
│  ConnectionDetailPopup ──┘                                  │
│                          │                                  │
└──────────────────────────┼──────────────────────────────────┘
                           │ alert dict + 5 recent same-IP conns
                           ▼
┌─────────────────────────────────────────────────────────────┐
│ tools/_common/ai_triage.py                                  │
│                                                              │
│  triage_alert(payload) ──► sanitizer ──► budget gate        │
│                                              │              │
│                                              ▼              │
│                                       cache lookup          │
│                                       (sqlite, 24h TTL)     │
│                                              │              │
│                                              ▼ miss         │
│                                       Claude Agent SDK      │
│                                       (Haiku 4.5 default)   │
│                                              │              │
│  TriageResult ◄──── structured JSON ◄────────┘              │
└─────────────────────────────────────────────────────────────┘
```

**Boundaries:**
- NID never imports `anthropic` or `claude_agent_sdk` directly. All AI traffic goes through `_common/ai_triage.py`.
- `ai_triage.py` is the only module that touches the SDK, sanitizer, cache, and budget. Single seam = one place to test, one place to swap models.

## 5. Data flow

### 5.1 Input — what NID hands to `triage_alert()`

```python
{
  "alert": {
    "severity": "WARN",        # INFO|WARN|HIGH
    "category": "outbound",
    "title": "Unknown outbound to RU",
    "details": { ... },         # alert details dict
  },
  "context": {
    "classification": "SUSPICIOUS",
    "ip": "<remote_ip>",
    "port": 443,
    "country": "RU",
    "org": "<asn org>",
    "process_name": "chrome.exe",  # NAME ONLY
    "geo": { "country": "RU", "city": "Moscow" },
    "reputation": { "vt_score": 12, "abuse_score": 87 },  # if cached
    "recent_same_ip": [
      { "ts": "...", "port": 443, "process_name": "chrome.exe" },
      ...  # last 5 connections from same remote IP, ordered by timestamp desc
    ],
  },
}
```

### 5.2 Sanitizer — what NEVER leaves the machine

Strip before send:
- Process command-line args (`/full/path --token=secret`).
- Any path under `os.path.expanduser("~")`.
- Wi-Fi SSID, MAC addresses, hostname.
- Strings matching credential shape: `(api[_-]?key|token|password|secret|bearer)\s*[:=]\s*\S+`.
- IPs in private ranges from `recent_same_ip` are kept (useful context, not sensitive).

Sanitizer is a single function `_sanitize(payload: dict) -> dict` with unit tests for each redaction rule.

### 5.3 Output — `TriageResult` dataclass

```python
@dataclass
class TriageResult:
    severity_human: str        # "low" | "medium" | "high" | "critical"
    why_it_matters: str        # 1-2 sentences, plain English
    suggested_action: str      # "monitor" | "block" | "kill_process" | "investigate" | "ignore"
    suggested_action_reason: str  # 1 sentence
    false_positive_likelihood: float  # 0.0 – 1.0
    evidence: list[str]        # short bullets the AI based the call on
    model: str                 # "claude-haiku-4-5-20251001"
    cached: bool
    triaged_at: str            # ISO timestamp
```

NID renders this in a side panel inside `ConnectionDetailPopup`. The rule-based classification stays exactly where it is; AI panel is a new sibling section.

## 6. Components

### 6.1 `tools/_common/ai_triage.py` (new, ~250 LOC)

Public surface:

```python
def is_available() -> tuple[bool, str]:
    """(enabled, reason) — checks env flag, SDK import, auth, daily budget."""

def triage_alert(payload: dict, *, deep: bool = False) -> TriageResult:
    """Main entry. deep=True routes to Opus 4.7."""

def remaining_budget_tokens() -> int:
    """For UI tooltip."""
```

Private:
- `_sanitize(payload) -> dict`
- `_cache_lookup(key) / _cache_store(key, result)` — SQLite at `tools/_common/ai_triage_cache.db`
- `_call_claude(sanitized, model) -> dict` — wraps `claude_agent_sdk.query()`
- `_parse_response(text) -> TriageResult`
- `_budget_check_and_decrement(tokens_estimate) -> bool`

### 6.2 NID changes (minimal — no god-file split)

Three additions:

1. **`ConnectionDetailPopup._build()`** — add "🤖 Triage" button next to "Block IP" / "Trust IP" / "Kill Process". State: enabled / greyed-with-tooltip based on `ai_triage.is_available()`.
2. **`ConnectionDetailPopup._on_triage()`** (new method) — builds payload, calls `ai_triage.triage_alert()`, renders result in a new side-panel `Frame`.
3. **Alerts table context menu** — add "🤖 Triage this alert" item (same flow, payload from alert dict).

Total NID delta: ~80 LOC. No restructuring.

### 6.3 Config (extends existing `tools/_common/config.py`)

New env vars (all optional, default OFF/safe):
- `AUTOMATIONS_AI_ENABLED` — `"1"` to opt in. Default off.
- `AUTOMATIONS_AI_DAILY_TOKENS` — daily token cap. Default `50000`.
- `AUTOMATIONS_AI_MODEL_FAST` — default `"claude-haiku-4-5-20251001"`.
- `AUTOMATIONS_AI_MODEL_DEEP` — default `"claude-opus-4-7"`.
- `AUTOMATIONS_AI_AUTH_MODE` — `"subscription"` (default, uses Claude Code OAuth) or `"api_key"` (uses `ANTHROPIC_API_KEY`).

`.env.example` updated with these and a comment block explaining subscription vs api_key billing.

### 6.4 Dependency

`requirements.txt` adds the Claude Agent SDK (Python) — exact package name and version range determined during implementation by checking PyPI for the current released name (the SDK was renamed from `claude-code-sdk` to `claude-agent-sdk` in late 2025). Pin once verified.

Implementation step 4 (§17) is the right place to lock the pin.

## 7. Error handling

| Failure | UI behavior | Code path |
|---|---|---|
| `AUTOMATIONS_AI_ENABLED != "1"` | Button hidden | `is_available()` returns `(False, "disabled")` |
| SDK not installed | Button greyed, tooltip "pip install claude-agent-sdk" | `is_available()` returns `(False, "sdk_missing")` |
| Auth missing (no Claude login + no API key) | Button greyed, tooltip "log in with `claude` CLI" | `is_available()` returns `(False, "no_auth")` |
| Daily budget exhausted | Button greyed, tooltip "AI budget exhausted — resets midnight" | `_budget_check` returns False |
| Network error during call | Toast "AI triage unavailable, see logs"; rule-based classification untouched | `_call_claude` raises → caught, logged to stderr |
| Malformed JSON from model | Same as network error; one auto-retry with stricter system prompt | `_parse_response` raises |
| Model returns partial fields | Fill missing with `"unknown"`; never crash | `_parse_response` defensive |

Logging: stderr only (matches project pattern). No PII in logs — log hashes of IPs, not IPs.

## 8. Caching

- Storage: SQLite at `tools/_common/ai_triage_cache.db` (matches `network_incidents.db` pattern).
- Key: `sha256(ip + port + process_name + alert_category + alert_title)`.
- TTL: 24 hours (configurable via `AUTOMATIONS_AI_CACHE_TTL_HOURS`).
- Eviction: simple — drop rows older than TTL on each lookup. No LRU complexity for pilot.

Cache hit → returns `TriageResult(cached=True)` — UI shows a small "cached" badge so user knows it's not a fresh assessment.

## 9. Cost & rate limiting

- **Model default**: Haiku 4.5. Triage prompt + payload ≈ 800 input tokens, response ≈ 400 output tokens. Per call: ~1200 tokens, ~$0.001 at Haiku rates.
- **50k daily cap** = ~40 fresh triages/day. Average user clicks <10. Cap is a safety net, not a normal limit.
- **Per-IP debounce**: same `(ip, alert_category)` request within 60s → return cached/in-flight result, never re-call.
- **Burst guard**: max 5 concurrent in-flight calls (`threading.Semaphore(5)`).
- **Subscription mode**: when auth is Claude Code OAuth, calls bill against Max plan (no separate spend). Token cap still enforced for predictability.

## 10. Testing

Per project convention (pytest, `test_*.py` files in `tests/`, alongside existing `test_common_config.py` etc.):

`tests/test_ai_triage.py`:
- `test_sanitize_strips_home_paths` — happy path
- `test_sanitize_strips_credential_strings` — happy path
- `test_sanitize_keeps_public_ips` — happy path
- `test_is_available_no_env_flag` — error case
- `test_is_available_no_auth` — error case
- `test_cache_hit_returns_cached_result` — happy path
- `test_cache_miss_calls_sdk` (mocked SDK) — happy path
- `test_budget_decrement_blocks_when_exhausted` — error case
- `test_parse_response_partial_fields_default_to_unknown` — error case

`tests/test_nid_triage_integration.py`:
- `test_button_hidden_when_disabled` — UI gated correctly
- `test_button_greyed_when_no_auth` — UI gated correctly
- `test_payload_shape_matches_spec` — contract test

Network calls always mocked. No live SDK calls in CI.

## 11. Privacy boundary (explicit)

| Field | Sent | Reason |
|---|---|---|
| Remote IP | yes | Core to threat assessment |
| Port | yes | Core |
| Process name (e.g. `chrome.exe`) | yes | Useful, low-risk |
| Process command line | **no** | Can leak tokens, paths, args |
| Geo (country, city, org) | yes | Already public |
| Local hostname | **no** | User identification |
| Wi-Fi SSID | **no** | Location identification |
| MAC addresses | **no** | Device fingerprint |
| File paths under home | **no** | User identification |
| Alert title + category | yes | Core |
| Alert details dict | filtered through sanitizer | Recursive scan |
| VT / AbuseIPDB scores (if cached locally) | yes | Public reputation data |

Sanitizer test suite covers each row.

## 12. Failure mode — degraded UX

If AI ever goes wrong (model error, slow network, budget exhausted), **NID continues to function exactly as it does today**. The "🤖 Triage" button is the only AI surface — disabling it removes AI entirely. No other code path depends on AI output.

## 13. Tier-2 expansion (post-pilot, out of scope this round)

Once pilot lands and `_common/ai_triage.py` is stable:
- `security_audit` adds `🤖 Triage` per finding → re-uses sanitizer + budget.
- `system_health_monitor` adds "Why is this process eating CPU?" button.
- `account_activity_monitor` adds nightly summary generation.
- Daily Briefing Agent (cross-tool) reads structured outputs from above and generates a morning report.

Each Tier-2 hook adds <100 LOC per tool. The shared module does not grow.

## 14. Portfolio deliverable

Pilot ships with:
- `docs/portfolio/ai-triage-demo.md` — short writeup, problem→solution narrative.
- 2 screenshots: raw NID alert (before) vs same alert with AI panel (after).
- Optional: 30-second screen recording showing the click-and-explain flow.
- README badge: "AI-augmented" linking to the writeup.

## 15. Open risks (carried from brainstorm)

- **R1 (medium)** — Subscription auth requires `claude` CLI logged in on same machine. SDK falls back to API key (separate billing) silently if not. Mitigation: `is_available()` reports auth mode in tooltip so user always knows which billing applies.
- **R2 (low-med)** — NID alerts can burst → cap blown. Mitigation: per-IP debounce + 5-concurrent semaphore (§9).
- **R3 (low)** — Haiku false-confidence on novel threats. Mitigation: AI panel always shown alongside rule-based classification, never replacing.

## 16. Estimate

- `_common/ai_triage.py` + tests: ~6h
- `.env.example` + config wiring: ~30min
- NID UI hook (button + side panel): ~2h
- Demo writeup + screenshots: ~1h
- Total pilot: **~10h** of focused work.

Tier-2 expansion (per tool): ~2-3h each.

## 17. Implementation order (for the writing-plans skill next)

1. `_common/ai_triage.py` skeleton + sanitizer + tests (no SDK call yet, mocked).
2. SDK integration + auth detection + budget gate.
3. SQLite cache.
4. Config additions (`config.py`, `.env.example`, `requirements.txt`).
5. NID button + side panel.
6. Integration tests.
7. Demo writeup + screenshots.
8. Commit each step as its own logical unit.
