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

import os
import re
from dataclasses import dataclass
from typing import Any


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
