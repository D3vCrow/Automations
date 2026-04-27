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


__all__ = ["TriageResult"]


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
