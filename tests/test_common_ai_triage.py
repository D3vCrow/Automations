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
