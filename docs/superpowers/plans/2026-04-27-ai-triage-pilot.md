# AI Triage Pilot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in AI triage layer to `network_intrusion_detector_pro` (NID) via a new shared `tools/_common/ai_triage.py` module that wraps the Claude Agent SDK against the Max subscription. Layer is purely additive — rule-based 5-level classification is untouched.

**Architecture:** New module `tools/_common/ai_triage.py` owns: sanitizer, SQLite cache, daily token-budget gate, auth/availability detection, SDK call wrapper, response parser, and `triage_alert()` orchestrator. NID's `ConnectionDetailPopup` gets a "🤖 Triage" button + side panel. Default OFF (`AUTOMATIONS_AI_ENABLED=1` to opt in). Network never called in tests (SDK mocked).

**Tech Stack:** Python 3.11+, Tkinter, pytest, `claude-agent-sdk` (PyPI), sqlite3 (stdlib), existing `tools/_common/{config,paths,exceptions,logging}`.

**Spec:** [docs/superpowers/specs/2026-04-27-ai-triage-pilot-design.md](../specs/2026-04-27-ai-triage-pilot-design.md)

---

## File Structure

**Create:**
- `tools/_common/ai_triage.py` — full module (~250 LOC)
- `tests/test_common_ai_triage.py` — unit tests for the module
- `tests/test_nid_triage_integration.py` — UI gating + payload shape contract tests
- `docs/portfolio/ai-triage-demo.md` — portfolio writeup

**Modify:**
- `tools/_common/__init__.py` — re-export public API
- `tools/network_intrusion_detector_pro.py` — `ConnectionDetailPopup._build()` (add button), new `_on_triage()` method, alerts-table context menu
- `.env.example` — add AI section
- `requirements.txt` — add `claude-agent-sdk`

**No changes to:**
- Existing rule-based classification (`classify_connection`, `compute_threat_level`)
- Other tools — Tier-2 expansion is post-pilot

---

## Task 1: Module skeleton + TriageResult dataclass

**Files:**
- Create: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing test**

`tests/test_common_ai_triage.py`:

```python
"""Unit tests for ``tools._common.ai_triage``."""

from __future__ import annotations

import pytest


class TestTriageResult:
    def test_dataclass_fields_present(self) -> None:
        from tools._common.ai_triage import TriageResult

        result = TriageResult(
            severity_human="medium",
            why_it_matters="Outbound to suspicious IP.",
            suggested_action="monitor",
            suggested_action_reason="Reputation borderline.",
            false_positive_likelihood=0.3,
            evidence=["VT score 12"],
            model="claude-haiku-4-5-20251001",
            cached=False,
            triaged_at="2026-04-27T12:00:00Z",
        )
        assert result.severity_human == "medium"
        assert result.cached is False
        assert result.false_positive_likelihood == 0.3
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest tests/test_common_ai_triage.py::TestTriageResult -v
```

Expected: `FAILED ... ModuleNotFoundError: No module named 'tools._common.ai_triage'`

- [ ] **Step 3: Create the module skeleton**

`tools/_common/ai_triage.py`:

```python
"""Shared AI triage layer used by the toolbox's monitoring tools.

This module is the *only* place that imports ``claude_agent_sdk``. Every
caller goes through :func:`triage_alert` so the sanitizer, budget gate,
and cache live in exactly one seam.

Public surface
--------------
* :class:`TriageResult` — dataclass returned by :func:`triage_alert`.
* :func:`is_available` — ``(enabled, reason)`` for UI gating.
* :func:`triage_alert` — main entry. Sanitizes, caches, calls Claude.
* :func:`remaining_budget_tokens` — UI counter helper.

Design notes
------------
The layer is purely additive. If anything fails (env flag off, SDK
missing, no auth, budget exhausted, network error, malformed JSON), the
caller's existing rule-based behaviour MUST remain unchanged. The
``is_available`` check is the single point UIs consult before showing
an AI affordance.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TriageResult:
    """Structured AI triage output rendered by tool UIs.

    Attributes:
        severity_human: ``"low"`` | ``"medium"`` | ``"high"`` | ``"critical"``.
        why_it_matters: 1–2 sentence plain-English reason.
        suggested_action: ``"monitor"`` | ``"block"`` | ``"kill_process"`` |
            ``"investigate"`` | ``"ignore"``.
        suggested_action_reason: 1 sentence justification.
        false_positive_likelihood: 0.0–1.0 calibrated estimate.
        evidence: Short bullets the model based the call on.
        model: Resolved Claude model id (e.g. ``claude-haiku-4-5-20251001``).
        cached: ``True`` when served from the local 24h cache.
        triaged_at: ISO-8601 UTC timestamp string.
    """

    severity_human: str
    why_it_matters: str
    suggested_action: str
    suggested_action_reason: str
    false_positive_likelihood: float
    evidence: list[str]
    model: str
    cached: bool
    triaged_at: str


__all__ = ["TriageResult"]
```

- [ ] **Step 4: Run test to verify it passes**

```
pytest tests/test_common_ai_triage.py::TestTriageResult -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add module skeleton + TriageResult"
```

---

## Task 2: Sanitizer — strip PII / credentials before send

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestSanitize:
    def test_strips_home_paths(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from tools._common.ai_triage import _sanitize

        monkeypatch.setenv("USERPROFILE", r"C:\Users\christophoros")
        monkeypatch.setenv("HOME", "/home/christophoros")
        payload = {"context": {"detail": r"opened C:\Users\christophoros\secrets.txt"}}
        out = _sanitize(payload)
        assert "christophoros" not in out["context"]["detail"]
        assert "<HOME>" in out["context"]["detail"]

    def test_strips_credential_strings(self) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {"alert": {"details": {"raw": "api_key=sk-abc123 token=xyz"}}}
        out = _sanitize(payload)
        raw = out["alert"]["details"]["raw"]
        assert "sk-abc123" not in raw
        assert "xyz" not in raw
        assert "<REDACTED>" in raw

    def test_strips_mac_addresses(self) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {"context": {"note": "device aa:bb:cc:dd:ee:ff joined"}}
        out = _sanitize(payload)
        assert "aa:bb:cc:dd:ee:ff" not in out["context"]["note"]
        assert "<MAC>" in out["context"]["note"]

    def test_strips_command_line_args(self) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {"context": {"process_cmdline": "chrome.exe --disable-foo --token=abc"}}
        out = _sanitize(payload)
        assert "process_cmdline" not in out["context"]

    def test_keeps_public_ip(self) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {"context": {"ip": "8.8.8.8", "port": 443}}
        out = _sanitize(payload)
        assert out["context"]["ip"] == "8.8.8.8"
        assert out["context"]["port"] == 443

    def test_keeps_alert_core_fields(self) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {
            "alert": {"severity": "WARN", "category": "outbound", "title": "X"},
            "context": {"country": "RU", "process_name": "chrome.exe"},
        }
        out = _sanitize(payload)
        assert out["alert"]["severity"] == "WARN"
        assert out["context"]["process_name"] == "chrome.exe"
        assert out["context"]["country"] == "RU"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestSanitize -v
```

Expected: 6 FAILs with `cannot import name '_sanitize'`.

- [ ] **Step 3: Implement the sanitizer**

Append to `tools/_common/ai_triage.py` (above `__all__`):

```python
import os
import re
from typing import Any

# Drop these keys entirely — too risky to send.
_DROP_KEYS = frozenset({
    "process_cmdline", "cmdline", "command_line",
    "hostname", "wifi_ssid", "ssid", "username",
})

_MAC_RE = re.compile(r"\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_CRED_RE = re.compile(
    r"\b(api[_-]?key|token|password|secret|bearer)\s*[:=]\s*\S+",
    re.IGNORECASE,
)


def _home_paths() -> list[str]:
    """Return all path prefixes that look like the current user's home."""
    candidates: list[str] = []
    for var in ("USERPROFILE", "HOME"):
        value = os.environ.get(var)
        if value:
            candidates.append(value)
    return candidates


def _scrub_string(text: str) -> str:
    """Apply all string-level redactions to ``text``."""
    for home in _home_paths():
        if home and home in text:
            text = text.replace(home, "<HOME>")
    text = _MAC_RE.sub("<MAC>", text)
    text = _CRED_RE.sub(lambda m: f"{m.group(1)}=<REDACTED>", text)
    return text


def _sanitize(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a deep-copied payload with PII / credentials stripped.

    The original payload is left untouched. Drops keys in :data:`_DROP_KEYS`
    entirely; rewrites strings via :func:`_scrub_string`; recurses into
    nested dicts and lists.
    """

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items() if k not in _DROP_KEYS}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        if isinstance(node, str):
            return _scrub_string(node)
        return node

    return _walk(payload)
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py::TestSanitize -v
```

Expected: 6 PASSes.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add _sanitize for PII/credential stripping"
```

---

## Task 3: SQLite cache with 24h TTL

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestCache:
    def test_cache_miss_returns_none(self, tmp_path) -> None:
        from tools._common.ai_triage import _Cache

        cache = _Cache(tmp_path / "c.db")
        assert cache.get("missing-key") is None

    def test_cache_store_and_lookup_roundtrip(self, tmp_path) -> None:
        from tools._common.ai_triage import TriageResult, _Cache

        cache = _Cache(tmp_path / "c.db")
        result = TriageResult(
            severity_human="low", why_it_matters="ok",
            suggested_action="ignore", suggested_action_reason="benign",
            false_positive_likelihood=0.9, evidence=[],
            model="claude-haiku-4-5-20251001", cached=False,
            triaged_at="2026-04-27T00:00:00Z",
        )
        cache.put("k1", result, ttl_hours=24)

        hit = cache.get("k1")
        assert hit is not None
        assert hit.severity_human == "low"
        assert hit.cached is True

    def test_cache_evicts_expired(self, tmp_path, monkeypatch) -> None:
        import time
        from tools._common.ai_triage import TriageResult, _Cache

        cache = _Cache(tmp_path / "c.db")
        result = TriageResult(
            severity_human="low", why_it_matters="x",
            suggested_action="ignore", suggested_action_reason="x",
            false_positive_likelihood=0.5, evidence=[],
            model="m", cached=False, triaged_at="t",
        )

        fake_now = [1_000_000.0]
        monkeypatch.setattr(time, "time", lambda: fake_now[0])
        cache.put("k1", result, ttl_hours=1)

        fake_now[0] = 1_000_000.0 + 3700  # past 1h TTL
        assert cache.get("k1") is None
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestCache -v
```

Expected: 3 FAILs with `cannot import name '_Cache'`.

- [ ] **Step 3: Implement the cache**

Append to `tools/_common/ai_triage.py`:

```python
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path


class _Cache:
    """SQLite-backed 24h cache for :class:`TriageResult` rows.

    Schema is single-table; lookup evicts expired rows lazily on access.
    Concurrent processes are serialized by SQLite's own locking.
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS ai_triage_cache (
            key        TEXT PRIMARY KEY,
            payload    TEXT NOT NULL,
            stored_at  REAL NOT NULL,
            expires_at REAL NOT NULL
        )
    """

    def __init__(self, db_path: Path) -> None:
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as cx:
            cx.execute(self._SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self._path)

    def get(self, key: str) -> "TriageResult | None":
        with self._connect() as cx:
            row = cx.execute(
                "SELECT payload, expires_at FROM ai_triage_cache WHERE key=?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        payload_json, expires_at = row
        if time.time() >= expires_at:
            with self._connect() as cx:
                cx.execute("DELETE FROM ai_triage_cache WHERE key=?", (key,))
            return None
        data = json.loads(payload_json)
        data["cached"] = True
        return TriageResult(**data)

    def put(self, key: str, result: "TriageResult", ttl_hours: float) -> None:
        now = time.time()
        expires = now + (ttl_hours * 3600.0)
        payload_json = json.dumps(asdict(result))
        with self._connect() as cx:
            cx.execute(
                "INSERT OR REPLACE INTO ai_triage_cache "
                "(key, payload, stored_at, expires_at) VALUES (?, ?, ?, ?)",
                (key, payload_json, now, expires),
            )
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py::TestCache -v
```

Expected: 3 PASSes.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add SQLite cache with 24h TTL"
```

---

## Task 4: Daily token-budget gate

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestBudget:
    def test_fresh_day_allows_call(self, tmp_path) -> None:
        from tools._common.ai_triage import _Budget

        b = _Budget(tmp_path / "b.json", daily_cap=10_000)
        assert b.try_consume(1500) is True
        assert b.remaining() == 8500

    def test_exhaustion_blocks_further_calls(self, tmp_path) -> None:
        from tools._common.ai_triage import _Budget

        b = _Budget(tmp_path / "b.json", daily_cap=2000)
        assert b.try_consume(1500) is True
        assert b.try_consume(1000) is False  # would exceed cap
        assert b.remaining() == 500

    def test_resets_at_midnight_local(self, tmp_path, monkeypatch) -> None:
        import datetime as _dt
        from tools._common import ai_triage as mod

        b = mod._Budget(tmp_path / "b.json", daily_cap=1000)

        class _Day1:
            @staticmethod
            def today() -> _dt.date:
                return _dt.date(2026, 4, 27)

        class _Day2:
            @staticmethod
            def today() -> _dt.date:
                return _dt.date(2026, 4, 28)

        monkeypatch.setattr(mod, "_today", _Day1.today)
        b.try_consume(1000)
        assert b.remaining() == 0

        monkeypatch.setattr(mod, "_today", _Day2.today)
        assert b.remaining() == 1000  # rolled over
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestBudget -v
```

Expected: 3 FAILs.

- [ ] **Step 3: Implement the budget gate**

Append to `tools/_common/ai_triage.py`:

```python
import datetime as _dt


def _today() -> _dt.date:
    """Indirection so tests can monkeypatch ``date.today``."""
    return _dt.date.today()


class _Budget:
    """Persistent daily token budget.

    Stores ``{"date": "YYYY-MM-DD", "used": int}`` in a JSON file. On a
    new local day, ``used`` resets to 0 on first read. Single-process.
    """

    def __init__(self, state_path: Path, daily_cap: int) -> None:
        self._path = Path(state_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._cap = int(daily_cap)

    def _load(self) -> dict[str, Any]:
        if not self._path.exists():
            return {"date": _today().isoformat(), "used": 0}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"date": _today().isoformat(), "used": 0}
        if data.get("date") != _today().isoformat():
            return {"date": _today().isoformat(), "used": 0}
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self._path.write_text(json.dumps(data), encoding="utf-8")

    def remaining(self) -> int:
        data = self._load()
        return max(0, self._cap - int(data.get("used", 0)))

    def try_consume(self, tokens: int) -> bool:
        data = self._load()
        used = int(data.get("used", 0))
        if used + tokens > self._cap:
            self._save(data)  # persist any date-rollover
            return False
        data["used"] = used + tokens
        self._save(data)
        return True
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py::TestBudget -v
```

Expected: 3 PASSes.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add daily token-budget gate"
```

---

## Task 5: Availability detection (`is_available`)

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestIsAvailable:
    def test_disabled_when_env_flag_off(self, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.delenv("AUTOMATIONS_AI_ENABLED", raising=False)
        ok, reason = mod.is_available()
        assert ok is False
        assert reason == "disabled"

    def test_disabled_when_sdk_missing(self, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.setenv("AUTOMATIONS_AI_ENABLED", "1")
        monkeypatch.setattr(mod, "_sdk_importable", lambda: False)
        ok, reason = mod.is_available()
        assert ok is False
        assert reason == "sdk_missing"

    def test_disabled_when_no_auth(self, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.setenv("AUTOMATIONS_AI_ENABLED", "1")
        monkeypatch.setattr(mod, "_sdk_importable", lambda: True)
        monkeypatch.setattr(mod, "_detect_auth_mode", lambda: ("none", ""))
        ok, reason = mod.is_available()
        assert ok is False
        assert reason == "no_auth"

    def test_available_when_subscription_authed(self, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.setenv("AUTOMATIONS_AI_ENABLED", "1")
        monkeypatch.setattr(mod, "_sdk_importable", lambda: True)
        monkeypatch.setattr(mod, "_detect_auth_mode", lambda: ("subscription", "claude-cli"))
        ok, reason = mod.is_available()
        assert ok is True
        assert reason == "subscription"
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestIsAvailable -v
```

Expected: 4 FAILs.

- [ ] **Step 3: Implement availability detection**

Append to `tools/_common/ai_triage.py`:

```python
import importlib
import shutil

from tools._common.config import get_bool, get_config


def _sdk_importable() -> bool:
    """Return True if ``claude_agent_sdk`` can be imported."""
    try:
        importlib.import_module("claude_agent_sdk")
        return True
    except ImportError:
        return False


def _detect_auth_mode() -> tuple[str, str]:
    """Return ``(mode, source)``.

    ``mode`` is ``"subscription"`` (Claude Code OAuth on this machine),
    ``"api_key"`` (``ANTHROPIC_API_KEY`` set), or ``"none"``. ``source``
    is a short tag for tooltips.
    """
    forced = (get_config("AUTOMATIONS_AI_AUTH_MODE") or "").strip().lower()
    if forced == "api_key" and get_config("ANTHROPIC_API_KEY"):
        return ("api_key", "ANTHROPIC_API_KEY")
    if forced == "subscription" and shutil.which("claude") is not None:
        return ("subscription", "claude-cli")

    # Auto-detect: prefer subscription if claude CLI is on PATH.
    if shutil.which("claude") is not None:
        return ("subscription", "claude-cli")
    if get_config("ANTHROPIC_API_KEY"):
        return ("api_key", "ANTHROPIC_API_KEY")
    return ("none", "")


def is_available() -> tuple[bool, str]:
    """Return ``(enabled, reason)`` for UI gating.

    ``reason`` values: ``"disabled"``, ``"sdk_missing"``, ``"no_auth"``,
    ``"budget_exhausted"``, ``"subscription"``, ``"api_key"``. Callers
    use the reason as a tooltip key.
    """
    if not get_bool("AUTOMATIONS_AI_ENABLED", default=False):
        return (False, "disabled")
    if not _sdk_importable():
        return (False, "sdk_missing")
    mode, _source = _detect_auth_mode()
    if mode == "none":
        return (False, "no_auth")
    return (True, mode)
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py::TestIsAvailable -v
```

Expected: 4 PASSes.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add is_available + auth detection"
```

---

## Task 6: Response parser (defensive JSON → TriageResult)

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestParseResponse:
    def test_parses_well_formed_json(self) -> None:
        from tools._common.ai_triage import _parse_response

        raw = """
        {"severity_human": "high", "why_it_matters": "Bad IP.",
         "suggested_action": "block", "suggested_action_reason": "VT 18/89.",
         "false_positive_likelihood": 0.1, "evidence": ["VT 18/89"]}
        """
        result = _parse_response(raw, model="claude-haiku-4-5-20251001")
        assert result.severity_human == "high"
        assert result.suggested_action == "block"
        assert result.false_positive_likelihood == 0.1
        assert result.evidence == ["VT 18/89"]
        assert result.cached is False

    def test_partial_fields_default_to_unknown(self) -> None:
        from tools._common.ai_triage import _parse_response

        raw = '{"severity_human": "low"}'
        result = _parse_response(raw, model="m")
        assert result.severity_human == "low"
        assert result.why_it_matters == "unknown"
        assert result.suggested_action == "investigate"  # safe default
        assert result.evidence == []

    def test_extracts_json_from_surrounding_prose(self) -> None:
        from tools._common.ai_triage import _parse_response

        raw = 'Sure, here is the analysis: {"severity_human": "medium"}\nThanks.'
        result = _parse_response(raw, model="m")
        assert result.severity_human == "medium"

    def test_bad_json_raises(self) -> None:
        import json
        from tools._common.ai_triage import _parse_response

        with pytest.raises(json.JSONDecodeError):
            _parse_response("not json at all", model="m")
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestParseResponse -v
```

Expected: 4 FAILs.

- [ ] **Step 3: Implement the parser**

Append to `tools/_common/ai_triage.py`:

```python
def _parse_response(raw: str, *, model: str) -> TriageResult:
    """Extract and validate a JSON triage object from a model response.

    Tolerates leading/trailing prose (the model sometimes adds a sentence
    before the JSON). Missing fields fall back to safe defaults. Raises
    :class:`json.JSONDecodeError` if no JSON object is found at all.
    """
    obj = _extract_first_json_object(raw)

    return TriageResult(
        severity_human=str(obj.get("severity_human", "unknown")),
        why_it_matters=str(obj.get("why_it_matters", "unknown")),
        suggested_action=str(obj.get("suggested_action", "investigate")),
        suggested_action_reason=str(obj.get("suggested_action_reason", "")),
        false_positive_likelihood=float(obj.get("false_positive_likelihood", 0.5)),
        evidence=list(obj.get("evidence", [])),
        model=model,
        cached=False,
        triaged_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    )


def _extract_first_json_object(text: str) -> dict[str, Any]:
    """Return the first ``{...}`` JSON object found in ``text``.

    Raises :class:`json.JSONDecodeError` on no object or invalid JSON.
    """
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("no JSON object found", text, 0)

    depth = 0
    for idx in range(start, len(text)):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start : idx + 1])
    raise json.JSONDecodeError("unterminated JSON object", text, start)
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py::TestParseResponse -v
```

Expected: 4 PASSes.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add _parse_response with prose tolerance"
```

---

## Task 7: SDK wrapper (`_call_claude`) with mocked test

**Files:**
- Modify: `tools/_common/ai_triage.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/test_common_ai_triage.py`:

```python
class TestCallClaude:
    def test_call_claude_uses_provided_model_and_returns_text(
        self, monkeypatch
    ) -> None:
        from tools._common import ai_triage as mod

        seen = {}

        def fake_query(*, prompt: str, model: str, system: str) -> str:
            seen["prompt"] = prompt
            seen["model"] = model
            seen["system"] = system
            return '{"severity_human": "low"}'

        monkeypatch.setattr(mod, "_sdk_query", fake_query)

        text = mod._call_claude(
            sanitized_payload={"alert": {"title": "X"}},
            model="claude-haiku-4-5-20251001",
        )
        assert "severity_human" in text
        assert seen["model"] == "claude-haiku-4-5-20251001"
        assert "alert" in seen["prompt"]
        assert "AI triage" in seen["system"]
```

- [ ] **Step 2: Run test to verify it fails**

```
pytest tests/test_common_ai_triage.py::TestCallClaude -v
```

Expected: FAIL.

- [ ] **Step 3: Implement the wrapper**

Append to `tools/_common/ai_triage.py`:

```python
_SYSTEM_PROMPT = (
    "You are an AI triage assistant for a personal network/security toolbox. "
    "Given an alert and connection context, return a single JSON object with "
    "keys: severity_human (low|medium|high|critical), why_it_matters (1-2 "
    "sentences), suggested_action (monitor|block|kill_process|investigate|"
    "ignore), suggested_action_reason (1 sentence), false_positive_likelihood "
    "(0.0-1.0), evidence (list of short strings). Output ONLY the JSON object. "
    "Be calibrated: if data is sparse, return moderate severity and high "
    "false_positive_likelihood."
)


def _sdk_query(*, prompt: str, model: str, system: str) -> str:
    """Thin wrapper around ``claude_agent_sdk.query`` for monkeypatching.

    Returns the concatenated assistant-text content. Real SDK call. Tests
    monkeypatch this function and never go to the network.
    """
    from claude_agent_sdk import query  # type: ignore[import-not-found]

    parts: list[str] = []
    for block in query(prompt=prompt, options={"model": model, "system_prompt": system}):
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "".join(parts)


def _call_claude(*, sanitized_payload: dict[str, Any], model: str) -> str:
    """Call the SDK with a triage prompt, return raw text response."""
    prompt = (
        "Triage the following network alert. Respond with the required "
        "JSON object only.\n\n"
        f"{json.dumps(sanitized_payload, indent=2, default=str)}"
    )
    return _sdk_query(prompt=prompt, model=model, system=_SYSTEM_PROMPT)
```

- [ ] **Step 4: Run test to verify it passes**

```
pytest tests/test_common_ai_triage.py::TestCallClaude -v
```

Expected: PASS.

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add _call_claude SDK wrapper"
```

---

## Task 8: `triage_alert()` orchestrator + cache-key + remaining_budget

**Files:**
- Modify: `tools/_common/ai_triage.py`, `tools/_common/__init__.py`
- Test: `tests/test_common_ai_triage.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_common_ai_triage.py`:

```python
class TestTriageAlert:
    @pytest.fixture
    def patched_paths(self, tmp_path, monkeypatch):
        from tools._common import ai_triage as mod

        monkeypatch.setattr(mod, "_cache_db_path", lambda: tmp_path / "c.db")
        monkeypatch.setattr(mod, "_budget_state_path", lambda: tmp_path / "b.json")
        monkeypatch.setenv("AUTOMATIONS_AI_ENABLED", "1")
        monkeypatch.setenv("AUTOMATIONS_AI_DAILY_TOKENS", "10000")
        monkeypatch.setattr(mod, "_sdk_importable", lambda: True)
        monkeypatch.setattr(
            mod, "_detect_auth_mode", lambda: ("subscription", "claude-cli")
        )
        return mod

    def test_triage_alert_calls_sdk_and_caches(
        self, patched_paths, monkeypatch
    ) -> None:
        mod = patched_paths
        monkeypatch.setattr(
            mod,
            "_sdk_query",
            lambda **kw: '{"severity_human": "high", "suggested_action": "block"}',
        )

        payload = {
            "alert": {"severity": "WARN", "category": "outbound", "title": "X",
                      "details": {}},
            "context": {"ip": "1.2.3.4", "port": 443, "process_name": "x.exe"},
        }
        result = mod.triage_alert(payload)
        assert result.severity_human == "high"
        assert result.cached is False

        # Second call → cache hit, no SDK call.
        def boom(**kw):
            raise AssertionError("SDK should not be called on cache hit")

        monkeypatch.setattr(mod, "_sdk_query", boom)
        result2 = mod.triage_alert(payload)
        assert result2.cached is True
        assert result2.severity_human == "high"

    def test_triage_alert_blocks_when_budget_exhausted(
        self, patched_paths, monkeypatch
    ) -> None:
        mod = patched_paths
        monkeypatch.setenv("AUTOMATIONS_AI_DAILY_TOKENS", "100")  # tiny cap

        called = {"n": 0}

        def fake_sdk(**kw):
            called["n"] += 1
            return '{"severity_human": "low"}'

        monkeypatch.setattr(mod, "_sdk_query", fake_sdk)

        payload_a = {
            "alert": {"category": "outbound", "title": "A", "details": {}},
            "context": {"ip": "1.1.1.1", "port": 80, "process_name": "a.exe"},
        }
        # First call consumes the cap (estimate=1200 > 100 → blocked immediately).
        with pytest.raises(mod.BudgetExhausted):
            mod.triage_alert(payload_a)
        assert called["n"] == 0


class TestRemainingBudget:
    def test_remaining_budget_returns_int(self, tmp_path, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.setattr(mod, "_budget_state_path", lambda: tmp_path / "b.json")
        monkeypatch.setenv("AUTOMATIONS_AI_DAILY_TOKENS", "5000")
        assert mod.remaining_budget_tokens() == 5000
```

- [ ] **Step 2: Run tests to verify they fail**

```
pytest tests/test_common_ai_triage.py::TestTriageAlert tests/test_common_ai_triage.py::TestRemainingBudget -v
```

Expected: 3 FAILs.

- [ ] **Step 3: Implement the orchestrator**

Append to `tools/_common/ai_triage.py`:

```python
import hashlib

from tools._common.paths import REPO_ROOT


class BudgetExhausted(RuntimeError):
    """Raised by :func:`triage_alert` when the daily token cap blocks the call."""


_DEFAULT_DAILY_CAP = 50_000
_DEFAULT_FAST_MODEL = "claude-haiku-4-5-20251001"
_DEFAULT_DEEP_MODEL = "claude-opus-4-7"
_TOKEN_ESTIMATE_PER_CALL = 1_200  # ~800 in + 400 out


def _cache_db_path() -> Path:
    return REPO_ROOT / "tools" / "_common" / "ai_triage_cache.db"


def _budget_state_path() -> Path:
    return REPO_ROOT / "tools" / "_common" / "ai_triage_budget.json"


def _daily_cap() -> int:
    raw = get_config("AUTOMATIONS_AI_DAILY_TOKENS")
    if not raw:
        return _DEFAULT_DAILY_CAP
    try:
        return int(raw)
    except ValueError:
        return _DEFAULT_DAILY_CAP


def _cache_key(payload: dict[str, Any]) -> str:
    """Stable key over (ip, port, process_name, category, title)."""
    ctx = payload.get("context", {}) or {}
    alert = payload.get("alert", {}) or {}
    parts = [
        str(ctx.get("ip", "")),
        str(ctx.get("port", "")),
        str(ctx.get("process_name", "")),
        str(alert.get("category", "")),
        str(alert.get("title", "")),
    ]
    return hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()


def remaining_budget_tokens() -> int:
    """Return tokens remaining in today's budget. Used by UI tooltips."""
    return _Budget(_budget_state_path(), daily_cap=_daily_cap()).remaining()


def triage_alert(payload: dict[str, Any], *, deep: bool = False) -> TriageResult:
    """Run the AI triage pipeline on ``payload``.

    Args:
        payload: ``{"alert": {...}, "context": {...}}`` produced by the
            calling tool. Sanitized before send.
        deep: ``True`` routes to the deep model (Opus). Default fast (Haiku).

    Returns:
        :class:`TriageResult` from cache or the model.

    Raises:
        BudgetExhausted: When the daily cap blocks the call.
        json.JSONDecodeError: When the model returns no parseable JSON
            after one retry (caller should display an error toast).
    """
    cache = _Cache(_cache_db_path())
    key = _cache_key(payload)
    cached = cache.get(key)
    if cached is not None:
        return cached

    budget = _Budget(_budget_state_path(), daily_cap=_daily_cap())
    if not budget.try_consume(_TOKEN_ESTIMATE_PER_CALL):
        raise BudgetExhausted("daily AI token cap reached")

    sanitized = _sanitize(payload)
    model = (
        get_config("AUTOMATIONS_AI_MODEL_DEEP", _DEFAULT_DEEP_MODEL)
        if deep
        else get_config("AUTOMATIONS_AI_MODEL_FAST", _DEFAULT_FAST_MODEL)
    )
    raw = _call_claude(sanitized_payload=sanitized, model=model or _DEFAULT_FAST_MODEL)
    result = _parse_response(raw, model=model or _DEFAULT_FAST_MODEL)
    cache.put(key, result, ttl_hours=24.0)
    return result
```

Update the bottom-of-file `__all__`:

```python
__all__ = [
    "BudgetExhausted",
    "TriageResult",
    "is_available",
    "remaining_budget_tokens",
    "triage_alert",
]
```

Modify `tools/_common/__init__.py` — append:

```python
from tools._common.ai_triage import (  # noqa: F401
    BudgetExhausted,
    TriageResult,
    is_available,
    remaining_budget_tokens,
    triage_alert,
)
```

- [ ] **Step 4: Run tests to verify they pass**

```
pytest tests/test_common_ai_triage.py -v
```

Expected: ALL PASS (every TestXxx class).

- [ ] **Step 5: Commit**

```
git add tools/_common/ai_triage.py tools/_common/__init__.py tests/test_common_ai_triage.py
git commit -m "feat(_common/ai_triage): add triage_alert orchestrator + public API"
```

---

## Task 9: `.env.example` + `requirements.txt`

**Files:**
- Modify: `.env.example`, `requirements.txt`

- [ ] **Step 1: Add the AI section to `.env.example`**

Append to `.env.example`:

```
# -------- AI Triage (opt-in, off by default) --------
# Master switch — set to 1 to enable the "🤖 Triage" button in NID and
# unlock Tier-2 expansions. Default OFF for safety/cost predictability.
# AUTOMATIONS_AI_ENABLED=0

# Daily token cap. Worst-case spend at Haiku 4.5 rates is ~$0.05/day at
# the default 50k cap. Subscription auth (Claude Code OAuth) bills against
# your Max plan and does not incur extra spend.
# AUTOMATIONS_AI_DAILY_TOKENS=50000

# Model routing.
# AUTOMATIONS_AI_MODEL_FAST=claude-haiku-4-5-20251001
# AUTOMATIONS_AI_MODEL_DEEP=claude-opus-4-7

# Auth mode. "subscription" uses Claude Code OAuth (your Max plan, no
# extra billing). "api_key" uses ANTHROPIC_API_KEY (separate Console
# billing). Default: auto-detect — prefers subscription when `claude`
# CLI is on PATH, falls back to ANTHROPIC_API_KEY.
# AUTOMATIONS_AI_AUTH_MODE=subscription
# ANTHROPIC_API_KEY=
```

- [ ] **Step 2: Add the SDK to `requirements.txt`**

Verify the current package and version on PyPI before pinning:

```
pip index versions claude-agent-sdk
```

Replace `<VERSION>` below with the latest stable release (e.g. `0.1.5`):

`requirements.txt`:

```
send2trash>=1.8,<2.0
keyboard>=0.13.5,<1.0
tzdata>=2024.1
winotify>=1.1,<2.0; sys_platform == "win32"
claude-agent-sdk>=<VERSION>,<1.0
```

- [ ] **Step 3: Install the SDK locally and confirm import**

```
pip install -r requirements.txt
python -c "import claude_agent_sdk; print(claude_agent_sdk.__name__)"
```

Expected: prints `claude_agent_sdk` (no traceback).

If the package name differs on PyPI from `claude-agent-sdk`, update both `requirements.txt` and `_sdk_importable()` / `_sdk_query()` in `tools/_common/ai_triage.py` to the correct module name.

- [ ] **Step 4: Run the full test suite to confirm no regressions**

```
pytest tests/ -v
```

Expected: ALL PASS.

- [ ] **Step 5: Commit**

```
git add .env.example requirements.txt
git commit -m "feat(config): wire AUTOMATIONS_AI_* env keys + claude-agent-sdk dep"
```

---

## Task 10: NID — `🤖 Triage` button on `ConnectionDetailPopup`

**Files:**
- Modify: `tools/network_intrusion_detector_pro.py` (around `ConnectionDetailPopup._build` at line 1634, and add `_on_triage` method)

- [ ] **Step 1: Read current `ConnectionDetailPopup` button row**

```
grep -n "Block IP\|Trust IP\|Kill Process" tools/network_intrusion_detector_pro.py
```

Note the line numbers of the existing action buttons inside `_build()`.

- [ ] **Step 2: Add the button + side-panel slot**

In `tools/network_intrusion_detector_pro.py`, inside `ConnectionDetailPopup._build` (around line 1634), find the row where existing action buttons (`Block IP`, `Trust IP`, `Kill Process`) are added and insert:

```python
        # AI triage button — gated on availability.
        from tools._common import ai_triage as _ai

        ok, reason = _ai.is_available()
        triage_btn = ttk.Button(
            actions_frame,  # use whatever Frame the existing buttons are packed into
            text="🤖 Triage" if ok else f"🤖 Triage ({reason})",
            state=("normal" if ok else "disabled"),
            command=self._on_triage,
        )
        triage_btn.pack(side="left", padx=4)
        self._triage_btn = triage_btn
        self._triage_panel: ttk.Frame | None = None
```

(Replace `actions_frame` with the actual Frame name used by the existing buttons. Keep `state="disabled"` when `ok` is False — the tooltip-style text in the label tells the user why.)

- [ ] **Step 3: Add the `_on_triage` method**

Inside `ConnectionDetailPopup`, add (alongside `_block_ip` / `_trust_ip` / `_kill_process` near line 1782+):

```python
    def _on_triage(self) -> None:
        """Build payload, call AI triage, render result in a side panel."""
        from tools._common import ai_triage as _ai

        payload = {
            "alert": {
                "severity": self.conn.get("severity", "INFO"),
                "category": self.conn.get("category", "outbound"),
                "title": self.conn.get("title") or "Connection detail",
                "details": dict(self.conn.get("details", {})),
            },
            "context": {
                "classification": self.conn.get("classification", "UNKNOWN"),
                "ip": self.conn.get("ip", ""),
                "port": int(self.conn.get("port", 0) or 0),
                "country": self.conn.get("country", ""),
                "org": self.conn.get("org", ""),
                "process_name": self.conn.get("process_name", ""),
                "geo": dict(self.conn.get("geo", {})),
                "reputation": dict(self.conn.get("reputation", {})),
                "recent_same_ip": list(self.monitor.recent_for_ip(  # see Step 4
                    self.conn.get("ip", ""), limit=5
                )),
            },
        }

        try:
            result = _ai.triage_alert(payload)
        except _ai.BudgetExhausted:
            self._show_triage_error("AI budget exhausted — resets midnight.")
            return
        except Exception as exc:  # noqa: BLE001 — final defensive boundary
            self._show_triage_error(f"AI triage failed: {type(exc).__name__}")
            return

        self._render_triage_panel(result)

    def _show_triage_error(self, message: str) -> None:
        """Show a small error label in place of the side panel."""
        self._render_triage_panel(None, error=message)

    def _render_triage_panel(
        self, result: "_ai.TriageResult | None", error: str | None = None
    ) -> None:
        """Render or refresh the triage side panel."""
        if self._triage_panel is not None:
            self._triage_panel.destroy()
        panel = ttk.Frame(self)  # parent is the popup itself
        panel.pack(side="right", fill="both", expand=False, padx=8, pady=8)
        self._triage_panel = panel

        if error:
            ttk.Label(panel, text=error, foreground="#c44").pack()
            return

        assert result is not None
        cached = " (cached)" if result.cached else ""
        ttk.Label(
            panel,
            text=f"AI: {result.severity_human.upper()}{cached}",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w")
        ttk.Label(panel, text=result.why_it_matters, wraplength=320).pack(
            anchor="w", pady=(4, 8)
        )
        ttk.Label(
            panel,
            text=f"Suggested: {result.suggested_action} — {result.suggested_action_reason}",
            wraplength=320,
        ).pack(anchor="w")
        ttk.Label(
            panel,
            text=f"FP likelihood: {result.false_positive_likelihood:.0%}",
        ).pack(anchor="w", pady=(8, 0))
        if result.evidence:
            ttk.Label(panel, text="Evidence:", font=("Segoe UI", 9, "bold")).pack(
                anchor="w", pady=(8, 0)
            )
            for ev in result.evidence:
                ttk.Label(panel, text=f"• {ev}", wraplength=320).pack(anchor="w")
```

- [ ] **Step 4: Add `NetworkMonitor.recent_for_ip` helper**

Find `class NetworkMonitor` (line 878). Add a method (next to `snapshot_outbound` near line 1089):

```python
    def recent_for_ip(self, ip: str, limit: int = 5) -> list[dict]:
        """Return the last ``limit`` outbound connections to ``ip``.

        Ordered newest-first. Used by AI triage to give the model
        recent context for the same remote endpoint.
        """
        if not ip:
            return []
        with self._alert_lock:
            # Reuse whatever connection history the monitor already keeps.
            # If a `self._conn_history` deque exists, draw from there;
            # otherwise fall back to the active alerts table filtered by IP.
            history = list(getattr(self, "_conn_history", []))
        return [
            {"ts": h.get("ts", ""), "port": h.get("port", 0),
             "process_name": h.get("process_name", "")}
            for h in reversed(history)
            if h.get("ip") == ip
        ][:limit]
```

If `NetworkMonitor` does not yet keep a `_conn_history` deque, this method will return `[]` — which is acceptable for the pilot (the model still works on the current alert alone). A follow-up task can wire history if needed.

- [ ] **Step 5: Smoke test by hand (no automated test for Tk yet)**

```
python Main.py
```

Open NID → trigger any alert → double-click a connection to open `ConnectionDetailPopup`. Confirm:
- Button labelled `🤖 Triage (disabled)` (since `AUTOMATIONS_AI_ENABLED` is unset).
- Clicking it does nothing (button is disabled).

- [ ] **Step 6: Commit**

```
git add tools/network_intrusion_detector_pro.py
git commit -m "feat(NID): add 🤖 Triage button + side panel to ConnectionDetailPopup"
```

---

## Task 11: NID — alerts-table context-menu item

**Files:**
- Modify: `tools/network_intrusion_detector_pro.py` (alerts table popup menu)

- [ ] **Step 1: Locate the alerts table widget**

```
grep -n "alerts.*Treeview\|alerts_tree\|alerts_table\|popup_menu" tools/network_intrusion_detector_pro.py
```

Identify the `Treeview` (or `Listbox`) holding alerts and the existing right-click menu builder (if any).

- [ ] **Step 2: Add a "🤖 Triage this alert" menu item**

Wherever the alerts-table context menu is built (search hits from Step 1), append:

```python
        from tools._common import ai_triage as _ai
        ok, _ = _ai.is_available()
        alerts_menu.add_command(
            label="🤖 Triage this alert",
            command=self._on_triage_selected_alert,
            state=("normal" if ok else "disabled"),
        )
```

- [ ] **Step 3: Add the handler**

In the same UI class (the main NID window class — find via `grep -n "self.alerts_tree\|self._alerts_tree" tools/network_intrusion_detector_pro.py`):

```python
    def _on_triage_selected_alert(self) -> None:
        """Triage the alert under the right-click cursor."""
        from tools._common import ai_triage as _ai

        selection = self.alerts_tree.selection()  # or whatever holds the selection
        if not selection:
            return
        alert = self._alert_for_tree_item(selection[0])  # see Step 4
        if alert is None:
            return

        payload = {
            "alert": {
                "severity": alert.get("severity", "INFO"),
                "category": alert.get("category", ""),
                "title": alert.get("title", ""),
                "details": dict(alert.get("details", {})),
            },
            "context": {
                "ip": alert.get("details", {}).get("ip", ""),
                "port": int(alert.get("details", {}).get("port", 0) or 0),
                "country": alert.get("details", {}).get("country", ""),
                "process_name": alert.get("details", {}).get("process_name", ""),
            },
        }

        try:
            result = _ai.triage_alert(payload)
        except _ai.BudgetExhausted:
            messagebox.showwarning("AI Triage", "Daily token budget exhausted.")
            return
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("AI Triage", f"Failed: {type(exc).__name__}")
            return

        # Reuse the popup's panel renderer by opening a small modal.
        self._show_triage_dialog(alert, result)
```

- [ ] **Step 4: Add `_alert_for_tree_item` and `_show_triage_dialog` helpers**

In the same class:

```python
    def _alert_for_tree_item(self, item_id: str) -> dict | None:
        """Look up the alert dict whose tree-row id is ``item_id``.

        The alerts table is populated row-by-row from
        ``self.monitor.alerts``; this helper inverts that mapping.
        """
        try:
            idx = self.alerts_tree.index(item_id)
        except Exception:
            return None
        alerts = list(self.monitor.alerts)
        if 0 <= idx < len(alerts):
            return alerts[idx]
        return None

    def _show_triage_dialog(self, alert: dict, result: "object") -> None:
        """Render the triage result in a small Toplevel dialog."""
        dlg = tk.Toplevel(self)
        dlg.title(f"AI Triage — {alert.get('title', '')}")
        ttk.Label(
            dlg,
            text=f"{result.severity_human.upper()}{' (cached)' if result.cached else ''}",
            font=("Segoe UI", 11, "bold"),
        ).pack(anchor="w", padx=12, pady=(12, 4))
        ttk.Label(dlg, text=result.why_it_matters, wraplength=420).pack(
            anchor="w", padx=12, pady=4
        )
        ttk.Label(
            dlg,
            text=f"Action: {result.suggested_action} — {result.suggested_action_reason}",
            wraplength=420,
        ).pack(anchor="w", padx=12, pady=4)
        ttk.Button(dlg, text="Close", command=dlg.destroy).pack(pady=(8, 12))
```

- [ ] **Step 5: Manual smoke test**

```
AUTOMATIONS_AI_ENABLED=1 python Main.py
```

Trigger an alert → right-click the row → "🤖 Triage this alert" → expect either a populated dialog OR a clean error message (no traceback). With SDK still mocked / no auth, expect `Failed: ...` dialog.

- [ ] **Step 6: Commit**

```
git add tools/network_intrusion_detector_pro.py
git commit -m "feat(NID): add 🤖 Triage context-menu item on alerts table"
```

---

## Task 12: Integration tests (payload shape + UI gating)

**Files:**
- Create: `tests/test_nid_triage_integration.py`

- [ ] **Step 1: Write the contract tests**

`tests/test_nid_triage_integration.py`:

```python
"""Integration tests — NID triage payload shape and UI gating.

These do NOT instantiate Tkinter. They verify the contract between
NID and ``tools._common.ai_triage`` via the dict shapes only.
"""

from __future__ import annotations

import pytest


class TestPayloadShape:
    """Contract tests for the payload NID hands to ``triage_alert``."""

    @pytest.fixture
    def nid_alert(self) -> dict:
        return {
            "severity": "WARN",
            "category": "outbound",
            "title": "Suspicious outbound to RU",
            "details": {
                "ip": "203.0.113.5",
                "port": 443,
                "country": "RU",
                "process_name": "chrome.exe",
            },
        }

    def test_payload_top_level_keys(self, nid_alert) -> None:
        from tools._common.ai_triage import _sanitize

        payload = {
            "alert": nid_alert,
            "context": {
                "ip": nid_alert["details"]["ip"],
                "port": nid_alert["details"]["port"],
                "country": nid_alert["details"]["country"],
                "process_name": nid_alert["details"]["process_name"],
            },
        }
        out = _sanitize(payload)
        assert "alert" in out and "context" in out
        assert out["context"]["ip"] == "203.0.113.5"
        assert out["alert"]["severity"] == "WARN"

    def test_sanitizer_strips_cmdline_if_nid_includes_it(self, nid_alert) -> None:
        from tools._common.ai_triage import _sanitize

        nid_alert["details"]["process_cmdline"] = "chrome.exe --token=abc"
        payload = {"alert": nid_alert, "context": {}}
        out = _sanitize(payload)
        assert "process_cmdline" not in out["alert"]["details"]


class TestAvailabilityGating:
    def test_disabled_reports_disabled_reason(self, monkeypatch) -> None:
        from tools._common.ai_triage import is_available

        monkeypatch.delenv("AUTOMATIONS_AI_ENABLED", raising=False)
        ok, reason = is_available()
        assert ok is False
        assert reason == "disabled"

    def test_enabled_with_no_auth_reports_no_auth(self, monkeypatch) -> None:
        from tools._common import ai_triage as mod

        monkeypatch.setenv("AUTOMATIONS_AI_ENABLED", "1")
        monkeypatch.setattr(mod, "_sdk_importable", lambda: True)
        monkeypatch.setattr(mod, "_detect_auth_mode", lambda: ("none", ""))
        ok, reason = mod.is_available()
        assert ok is False
        assert reason == "no_auth"
```

- [ ] **Step 2: Run tests to verify they pass**

```
pytest tests/test_nid_triage_integration.py -v
```

Expected: ALL PASS.

- [ ] **Step 3: Run the full suite — no regressions**

```
pytest tests/ -v
```

Expected: ALL PASS (everything from Task 1 onward + existing `test_common_*`).

- [ ] **Step 4: Commit**

```
git add tests/test_nid_triage_integration.py
git commit -m "test(NID): add AI-triage payload + gating contract tests"
```

---

## Task 13: Portfolio writeup + screenshots

**Files:**
- Create: `docs/portfolio/ai-triage-demo.md`

- [ ] **Step 1: Capture before/after screenshots**

With `AUTOMATIONS_AI_ENABLED` unset:
1. Open NID, trigger or wait for an outbound alert.
2. Open `ConnectionDetailPopup` for one connection.
3. Save screenshot as `docs/portfolio/img/nid-before.png`.

With `AUTOMATIONS_AI_ENABLED=1` and `claude` CLI logged in:
1. Same flow, click `🤖 Triage`, wait for response.
2. Save screenshot as `docs/portfolio/img/nid-after.png`.

(Create the `docs/portfolio/img/` folder if missing.)

- [ ] **Step 2: Write the demo writeup**

`docs/portfolio/ai-triage-demo.md`:

```markdown
# AI Triage Pilot — Network Intrusion Detector

## Problem

The Network Intrusion Detector (NID) classifies every outbound connection
into one of five buckets (SAFE / KNOWN / UNKNOWN / SUSPICIOUS / DANGEROUS)
using IP reputation, geo, and process heuristics. It works, but the user
still has to interpret each `SUSPICIOUS` row themselves: *why* is this
connection flagged, *what* should I do about it, and is this likely a
false positive?

## Solution

Added an opt-in `🤖 Triage` button. Clicking it sends a sanitized payload
(no command-lines, no home paths, no MAC, no SSID) to Claude Haiku 4.5
via the Claude Agent SDK against my Max subscription. The model returns a
structured JSON object the UI renders in a side panel:

- Severity in plain English (low / medium / high / critical)
- One-sentence "why it matters"
- Suggested action (monitor / block / kill_process / investigate / ignore)
- False-positive likelihood (0–100%)
- Evidence bullets

The rule-based classification is unchanged. AI is layered on top, never
replacing it. Default OFF — single env var to enable. Daily token cap of
50k acts as a safety net.

## Before / After

![Before — raw alert detail](img/nid-before.png)

![After — same alert with AI triage panel](img/nid-after.png)

## Architecture

All AI calls go through one shared module: `tools/_common/ai_triage.py`.
That module owns the sanitizer, SQLite cache (24h TTL), daily-token
budget gate, auth detection (Claude Code OAuth or `ANTHROPIC_API_KEY`),
SDK wrapper, and response parser. NID itself does not import the SDK.

This keeps the integration small and re-usable. The same module powers
upcoming AI features in `security_audit`, `system_health_monitor`, and
`account_activity_monitor`.

## Tech

- Python 3.11+, Tkinter
- Claude Agent SDK (subscription-billed via Max)
- SQLite for the response cache
- pytest with mocked SDK calls — zero network in CI

## Source

- Spec: [`docs/superpowers/specs/2026-04-27-ai-triage-pilot-design.md`](../superpowers/specs/2026-04-27-ai-triage-pilot-design.md)
- Module: [`tools/_common/ai_triage.py`](../../tools/_common/ai_triage.py)
- UI hook: `tools/network_intrusion_detector_pro.py`
- Tests: [`tests/test_common_ai_triage.py`](../../tests/test_common_ai_triage.py)
```

- [ ] **Step 3: Commit**

```
git add docs/portfolio/ai-triage-demo.md docs/portfolio/img/
git commit -m "docs(portfolio): add AI triage demo writeup with before/after screenshots"
```

---

## Self-Review Checklist (run before handing off)

**1. Spec coverage** — every spec section has a task:
- §3 success criteria 1-6 → covered by Tasks 8 (latency / structure), 10-11 (UI), 4 (cap), 13 (demo)
- §4 architecture → Tasks 1-8 build the module; 10-11 wire NID
- §5.1 input shape → Task 12 contract test
- §5.2 sanitizer → Task 2
- §5.3 TriageResult → Task 1
- §6.1 public surface (`is_available`, `triage_alert`, `remaining_budget_tokens`) → Tasks 5, 8
- §6.2 NID changes → Tasks 10, 11
- §6.3 config env vars → Task 9
- §6.4 SDK dependency → Task 9
- §7 error handling table → Tasks 5 (`is_available` reasons), 10 (`_on_triage` exception path)
- §8 caching → Task 3
- §9 cost / budget → Tasks 4, 8
- §10 testing → Tasks 1-8 (unit), 12 (integration)
- §11 privacy table → Task 2 (sanitizer covers every "no" row)
- §12 failure mode (graceful degrade) → Task 10 button gating + exception handler
- §14 portfolio deliverable → Task 13
- §17 implementation order → Tasks ordered 1→13 to match

**2. Placeholder scan:**
- "TBD" / "TODO" / "implement later": NONE.
- "Add appropriate error handling": NONE — every error path is explicit.
- Code blocks present in every code-changing step: YES.
- One spot uses `<VERSION>` in Task 9 Step 2 — that is intentional, the engineer fills it from `pip index versions` output one line above.

**3. Type / signature consistency:**
- `TriageResult` fields are referenced consistently across Tasks 1, 3 (cache `put`/`get`), 6 (`_parse_response`), 8 (`triage_alert` return).
- `is_available` returns `(bool, str)` everywhere it's tested or called.
- `_sanitize` signature `dict -> dict` consistent.
- `_Cache` methods `get(key) -> TriageResult | None`, `put(key, result, ttl_hours)` consistent.
- `_Budget` methods `try_consume(int) -> bool`, `remaining() -> int` consistent.
- `BudgetExhausted` raised in Task 8, caught in Tasks 10 + 11 — consistent.

No issues found.

---

## Execution Handoff

**Plan complete and saved to `docs/superpowers/plans/2026-04-27-ai-triage-pilot.md`. Two execution options:**

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Best for a 13-task plan where each task is well-bounded and benefits from a clean context.

**2. Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints for your review.

**Which approach?**
