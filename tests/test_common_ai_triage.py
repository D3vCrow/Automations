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
