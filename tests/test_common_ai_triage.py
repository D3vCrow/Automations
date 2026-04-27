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
