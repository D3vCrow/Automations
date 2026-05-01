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
