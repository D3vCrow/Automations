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

import asyncio
import datetime as _dt
import importlib
import json
import os
import re
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from tools._common.config import get_bool, get_config


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
    ``"subscription"``, ``"api_key"``. Callers use the reason as a
    tooltip key. Budget exhaustion is surfaced at call time via
    :class:`BudgetExhausted` from :func:`triage_alert`, not here.
    """
    if not get_bool("AUTOMATIONS_AI_ENABLED", default=False):
        return (False, "disabled")
    if not _sdk_importable():
        return (False, "sdk_missing")
    mode, _source = _detect_auth_mode()
    if mode == "none":
        return (False, "no_auth")
    return (True, mode)


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
        """Return tokens remaining in today's budget."""
        data = self._load()
        return max(0, self._cap - int(data.get("used", 0)))

    def try_consume(self, tokens: int) -> bool:
        """Attempt to consume ``tokens`` from today's budget.

        Args:
            tokens: Number of tokens to consume.

        Returns:
            ``True`` if tokens were consumed; ``False`` if the cap would
            be exceeded (no tokens are consumed in that case).
        """
        data = self._load()
        used = int(data.get("used", 0))
        if used + tokens > self._cap:
            self._save(data)  # persist any date-rollover
            return False
        data["used"] = used + tokens
        self._save(data)
        return True


def _extract_first_json_object(text: str) -> dict[str, Any]:
    """Return the first ``{...}`` JSON object found in ``text``.

    Uses :class:`json.JSONDecoder` so that braces inside string values
    are handled correctly. Raises :class:`json.JSONDecodeError` if no
    object is found, the JSON is malformed, or the parsed value is not
    a dict.
    """
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("no JSON object found", text, 0)
    decoder = json.JSONDecoder()
    obj, _end = decoder.raw_decode(text, start)
    if not isinstance(obj, dict):
        raise json.JSONDecodeError("expected a JSON object", text, start)
    return obj


def _safe_float(value: Any, *, default: float) -> float:
    """Coerce ``value`` to ``float`` defensively.

    Returns ``default`` when ``value`` is ``None`` or cannot be coerced.
    """
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_evidence(value: Any) -> list[str]:
    """Coerce a model-supplied ``evidence`` field to ``list[str]``.

    A list passes through (each element ``str()``-coerced). A bare string
    becomes a single-element list. Anything else returns an empty list.
    """
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        return [value]
    return []


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

    ``claude_agent_sdk.query`` is an async generator, so we drive it with
    ``asyncio.run``.  Each yielded ``Message`` may be an ``AssistantMessage``
    whose ``.content`` is a list of ``ContentBlock``; we extract only the
    ``TextBlock`` items (which carry a ``.text`` attribute).

    Constraint: must NOT be called from inside a running event loop —
    ``asyncio.run`` would raise ``RuntimeError``. Today's callers
    (NID's ``_on_triage`` button cmd, ``_on_triage_selected_alert``
    menu cmd) run synchronously on the Tkinter UI thread, which does
    not own an asyncio loop, so ``asyncio.run`` works. Caveat: cache
    misses block the UI for the full SDK round-trip (~2-5s on Haiku).
    Future work should wrap NID call sites in ``threading.Thread`` to
    keep the UI responsive. Async callers must dispatch off-loop.
    """
    from claude_agent_sdk import AssistantMessage, ClaudeAgentOptions, query  # type: ignore[import-not-found]

    async def _collect() -> str:
        opts = ClaudeAgentOptions(model=model, system_prompt=system)
        parts: list[str] = []
        async for message in query(prompt=prompt, options=opts):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    text = getattr(block, "text", None)
                    if text:
                        parts.append(text)
        return "".join(parts)

    return asyncio.run(_collect())


def _call_claude(*, sanitized_payload: dict[str, Any], model: str) -> str:
    """Call the SDK with a triage prompt, return raw text response."""
    prompt = (
        "Triage the following network alert. Respond with the required "
        "JSON object only.\n\n"
        f"{json.dumps(sanitized_payload, indent=2, default=str)}"
    )
    return _sdk_query(prompt=prompt, model=model, system=_SYSTEM_PROMPT)


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
        false_positive_likelihood=_safe_float(
            obj.get("false_positive_likelihood"), default=0.5
        ),
        evidence=_coerce_evidence(obj.get("evidence", [])),
        model=model,
        cached=False,
        triaged_at=_dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
    )


# ---------------------------------------------------------------------------
# Task 8: triage_alert() orchestrator + helpers + public API
# ---------------------------------------------------------------------------

import hashlib
import warnings

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
            (caller should display an error toast).
    """
    key = _cache_key(payload)
    cache: _Cache | None = None
    try:
        cache = _Cache(_cache_db_path())
        cached = cache.get(key)
    except sqlite3.OperationalError:
        cached = None
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
    if cache is not None:
        try:
            cache.put(key, result, ttl_hours=24.0)
        except sqlite3.OperationalError as exc:
            warnings.warn(f"ai_triage cache write failed: {exc}")
    return result


__all__ = [
    "BudgetExhausted",
    "TriageResult",
    "is_available",
    "remaining_budget_tokens",
    "triage_alert",
]
