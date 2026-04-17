"""Unit tests for ``tools._common.config``."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tools._common import config as cfg


@pytest.fixture(autouse=True)
def _skip_dotenv_load(monkeypatch: pytest.MonkeyPatch) -> None:
    """Skip real ``.env`` loading unless a test opts in."""
    monkeypatch.setattr(cfg, "_DOTENV_LOADED", True)


class TestGetConfig:
    def test_env_var_returned_when_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_TEST_KEY", "hello")
        assert cfg.get_config("AUTOMATIONS_TEST_KEY") == "hello"

    def test_default_returned_when_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTOMATIONS_TEST_KEY", raising=False)
        assert cfg.get_config("AUTOMATIONS_TEST_KEY", "fallback") == "fallback"

    def test_none_returned_when_unset_and_no_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTOMATIONS_MISSING", raising=False)
        assert cfg.get_config("AUTOMATIONS_MISSING") is None

    def test_empty_env_value_is_returned_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_EMPTY", "")
        assert cfg.get_config("AUTOMATIONS_EMPTY", "fallback") == ""


class TestGetBool:
    @pytest.mark.parametrize("raw", ["1", "true", "TRUE", "yes", "on", "y", "t"])
    def test_truthy_tokens(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_FLAG", raw)
        assert cfg.get_bool("AUTOMATIONS_FLAG") is True

    @pytest.mark.parametrize("raw", ["0", "false", "no", "off", "", "F"])
    def test_falsy_tokens(
        self, monkeypatch: pytest.MonkeyPatch, raw: str
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_FLAG", raw)
        assert cfg.get_bool("AUTOMATIONS_FLAG", default=True) is False

    def test_unset_returns_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTOMATIONS_FLAG", raising=False)
        assert cfg.get_bool("AUTOMATIONS_FLAG", default=True) is True
        assert cfg.get_bool("AUTOMATIONS_FLAG", default=False) is False

    def test_unknown_value_falls_back_to_default(
        self,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_FLAG", "maybe")
        with caplog.at_level("WARNING", logger=cfg.__name__):
            assert cfg.get_bool("AUTOMATIONS_FLAG", default=True) is True
        assert any("not a recognized bool" in r.message for r in caplog.records)


class TestGetPath:
    def test_env_value_expands_tilde(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("AUTOMATIONS_DIR", "~/custom")
        result = cfg.get_path("AUTOMATIONS_DIR", default="/unused")
        assert result == Path("~/custom").expanduser()

    def test_default_as_string_expands(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("AUTOMATIONS_DIR", raising=False)
        result = cfg.get_path("AUTOMATIONS_DIR", default="~/videos")
        assert result == Path("~/videos").expanduser()

    def test_default_as_path_returned_unchanged(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.delenv("AUTOMATIONS_DIR", raising=False)
        result = cfg.get_path("AUTOMATIONS_DIR", default=tmp_path)
        assert result == tmp_path


class TestDotenvLoading:
    """Exercise the one-shot ``.env`` loader in isolation."""

    def test_dotenv_file_loaded_when_present(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        pytest.importorskip("dotenv")

        env_file = tmp_path / ".env"
        env_file.write_text("AUTOMATIONS_FROM_DOTENV=via_file\n", encoding="utf-8")

        monkeypatch.setattr(cfg, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)
        monkeypatch.delenv("AUTOMATIONS_FROM_DOTENV", raising=False)

        assert cfg.get_config("AUTOMATIONS_FROM_DOTENV") == "via_file"

    def test_real_env_beats_dotenv(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        pytest.importorskip("dotenv")

        env_file = tmp_path / ".env"
        env_file.write_text("AUTOMATIONS_WINS=from_dotenv\n", encoding="utf-8")

        monkeypatch.setattr(cfg, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)
        monkeypatch.setenv("AUTOMATIONS_WINS", "from_env")

        assert cfg.get_config("AUTOMATIONS_WINS") == "from_env"

    def test_missing_dotenv_file_is_noop(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr(cfg, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)
        monkeypatch.delenv("AUTOMATIONS_NONE", raising=False)

        assert cfg.get_config("AUTOMATIONS_NONE", "fallback") == "fallback"

    def test_load_is_idempotent(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        call_count = {"n": 0}

        def fake_loader(*args: object, **kwargs: object) -> bool:
            call_count["n"] += 1
            return True

        fake_dotenv = importlib.util.module_from_spec(
            importlib.util.spec_from_loader("dotenv", loader=None)  # type: ignore[arg-type]
        )
        fake_dotenv.load_dotenv = fake_loader  # type: ignore[attr-defined]

        monkeypatch.setitem(__import__("sys").modules, "dotenv", fake_dotenv)
        monkeypatch.setattr(cfg, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(cfg, "_DOTENV_LOADED", False)
        (tmp_path / ".env").write_text("X=1", encoding="utf-8")

        cfg.get_config("X")
        cfg.get_config("X")
        cfg.get_config("X")
        assert call_count["n"] == 1
