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
