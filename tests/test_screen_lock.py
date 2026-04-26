"""Tests for tools.screen_lock pure helpers.

Covers the three classes of logic that are safe to exercise in a headless
pytest run:

* config I/O (``load_config`` / ``save_config``)
* crash-flag detection (``write_lock_flag`` / ``is_stale_lock_flag``)
* triple-click timing (``TripleClickDetector``)

GUI/keyboard-hook/multi-monitor behavior is deliberately out of scope for
these tests — see the manual verification list in PLAN_A_critical.md.

All filesystem access is redirected to ``tmp_path`` via an ``APPDATA``
monkeypatch so the real user profile is never touched.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools import screen_lock  # noqa: E402


@pytest.fixture
def appdata(tmp_path, monkeypatch):
    """Redirect APPDATA to a tmp location; return the screen_lock subdir path.

    The helpers lazily create the ``screen_lock`` folder on first access.
    """
    monkeypatch.setenv("APPDATA", str(tmp_path))
    return tmp_path / "screen_lock"


# ─────────────────────────────────────────────
#  Config I/O
# ─────────────────────────────────────────────


class TestConfigIO:
    def test_get_config_dir_creates_folder(self, appdata):
        d = screen_lock.get_config_dir()
        assert d == appdata
        assert d.is_dir()

    def test_load_missing_config_returns_defaults(self, appdata):
        cfg = screen_lock.load_config()
        assert cfg == screen_lock.DEFAULT_CONFIG
        # Must be a COPY — mutating the return must not affect defaults.
        cfg["esc_unlock"] = True
        assert screen_lock.DEFAULT_CONFIG["esc_unlock"] is False

    def test_save_then_reload_roundtrip(self, appdata):
        screen_lock.save_config({
            "esc_unlock": True,
            "panic_corner": "bottom-right",
            "panic_target_px": 60,
            "panic_window_s": 2.0,
        })
        cfg = screen_lock.load_config()
        assert cfg["esc_unlock"] is True
        assert cfg["panic_corner"] == "bottom-right"
        assert cfg["panic_target_px"] == 60
        assert cfg["panic_window_s"] == 2.0

    def test_save_ignores_unknown_keys(self, appdata):
        screen_lock.save_config({"esc_unlock": True, "rogue_key": "x"})
        raw = (appdata / "config.json").read_text(encoding="utf-8")
        parsed = json.loads(raw)
        assert "rogue_key" not in parsed
        assert parsed["esc_unlock"] is True

    def test_load_malformed_json_returns_defaults(self, appdata):
        appdata.mkdir(parents=True, exist_ok=True)
        (appdata / "config.json").write_text("{ not valid json", encoding="utf-8")
        cfg = screen_lock.load_config()
        # Defaults, no exception.
        assert cfg == screen_lock.DEFAULT_CONFIG

    def test_load_partial_config_fills_defaults(self, appdata):
        appdata.mkdir(parents=True, exist_ok=True)
        (appdata / "config.json").write_text(
            json.dumps({"esc_unlock": True}),
            encoding="utf-8",
        )
        cfg = screen_lock.load_config()
        assert cfg["esc_unlock"] is True
        # Missing keys filled from defaults.
        assert cfg["panic_corner"] == screen_lock.DEFAULT_CONFIG["panic_corner"]
        assert cfg["panic_window_s"] == screen_lock.DEFAULT_CONFIG["panic_window_s"]


# ─────────────────────────────────────────────
#  Crash-flag detection
# ─────────────────────────────────────────────


class TestCrashFlag:
    def test_no_flag_is_not_stale(self, appdata):
        assert screen_lock.is_stale_lock_flag() is False

    def test_live_pid_is_not_stale(self, appdata):
        # Our own PID is guaranteed alive for the duration of the test.
        screen_lock.write_lock_flag(os.getpid())
        assert (appdata / "locked.flag").exists()
        assert screen_lock.is_stale_lock_flag() is False

    def test_dead_pid_is_stale(self, appdata, monkeypatch):
        # Mock _pid_alive to force "dead" so we don't have to spawn and kill
        # a real process (platform-dependent and flaky in CI).
        monkeypatch.setattr(screen_lock, "_pid_alive", lambda pid: False)
        screen_lock.write_lock_flag(999_999_999)
        assert screen_lock.is_stale_lock_flag() is True

    def test_clear_removes_flag(self, appdata):
        screen_lock.write_lock_flag(os.getpid())
        assert (appdata / "locked.flag").exists()
        screen_lock.clear_lock_flag()
        assert not (appdata / "locked.flag").exists()

    def test_clear_missing_flag_is_noop(self, appdata):
        # Must not raise when the file doesn't exist.
        screen_lock.clear_lock_flag()
        assert not (appdata / "locked.flag").exists()

    def test_malformed_flag_is_stale(self, appdata):
        appdata.mkdir(parents=True, exist_ok=True)
        (appdata / "locked.flag").write_text("not-a-pid", encoding="utf-8")
        # A garbage flag cannot be validated → treat as stale so the user is
        # prompted to clean up.
        assert screen_lock.is_stale_lock_flag() is True

    def test_write_flag_uses_current_pid_by_default(self, appdata):
        screen_lock.write_lock_flag()
        raw = (appdata / "locked.flag").read_text(encoding="utf-8").strip()
        assert raw == str(os.getpid())


# ─────────────────────────────────────────────
#  Triple-click detector
# ─────────────────────────────────────────────


class TestTripleClickDetector:
    def test_three_clicks_in_window_fires(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        assert d.register(now=10.0) is False
        assert d.register(now=10.5) is False
        assert d.register(now=11.0) is True

    def test_two_clicks_do_not_fire(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        assert d.register(now=0.0) is False
        assert d.register(now=0.5) is False

    def test_three_clicks_outside_window_do_not_fire(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        assert d.register(now=0.0) is False
        assert d.register(now=1.0) is False
        # Span = 2.0 s, above the 1.5 s window.
        assert d.register(now=2.0) is False

    def test_fire_resets_state(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        d.register(now=0.0)
        d.register(now=0.2)
        assert d.register(now=0.4) is True
        # After firing, one more click must NOT immediately re-fire.
        assert d.register(now=0.5) is False

    def test_sliding_window(self):
        """Old clicks drop out as new ones arrive; a late third click inside
        the window of the second click should still fire."""
        d = screen_lock.TripleClickDetector(window_s=1.5)
        d.register(now=0.0)  # click 1
        d.register(now=2.0)  # click 2 (far from click 1)
        # Third click: deque holds clicks 1, 2, 3 → span 3-1 = 3.0 > 1.5 → no.
        assert d.register(now=3.0) is False
        # But a FOURTH click inside the window of 2 and 3 should fire,
        # because deque now holds 2, 3, 4 (maxlen=3).
        assert d.register(now=3.4) is True

    def test_exact_window_boundary_fires(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        d.register(now=0.0)
        d.register(now=0.75)
        # Span exactly 1.5 s — inclusive.
        assert d.register(now=1.5) is True

    def test_reset_clears_pending_clicks(self):
        d = screen_lock.TripleClickDetector(window_s=1.5)
        d.register(now=0.0)
        d.register(now=0.1)
        d.reset()
        # After reset, need three fresh clicks again.
        assert d.register(now=0.2) is False
        assert d.register(now=0.3) is False
        assert d.register(now=0.4) is True

    def test_custom_required_count(self):
        # Double-click variant: should fire on 2 clicks.
        d = screen_lock.TripleClickDetector(window_s=1.0, required=2)
        assert d.register(now=0.0) is False
        assert d.register(now=0.5) is True


# ─────────────────────────────────────────────
#  Misc module helpers
# ─────────────────────────────────────────────


class TestInstallHook:
    def test_install_hook_fails_fast_if_critical_combo_unsupported(self, monkeypatch, appdata):
        """Verify _install_hook returns False and rolls back if a critical combo fails."""
        import importlib
        import tkinter as tk

        # Create a mock keyboard module where hook() succeeds but block_key("left windows") fails.
        # "left windows" is the first entry in the new _CRITICAL_COMBOS tuple.
        mock_hook = object()
        blocked_id_counter = [0]
        unhook_called = []

        def mock_block_key(combo):
            if combo == "left windows":
                raise ValueError(f"Unsupported key name: {combo}")
            blocked_id_counter[0] += 1
            return blocked_id_counter[0]

        def mock_unhook(hook):
            unhook_called.append(hook)

        class MockKeyboard:
            @staticmethod
            def hook(handler, suppress=False):
                return mock_hook

            @staticmethod
            def block_key(combo):
                return mock_block_key(combo)

            @staticmethod
            def unhook(hook):
                mock_unhook(hook)

        # Patch the module's keyboard reference
        import sys
        original_kb = sys.modules.get("keyboard")
        sys.modules["keyboard"] = MockKeyboard()
        try:
            # Reload screen_lock to pick up the mocked keyboard
            importlib.reload(screen_lock)

            # Now mock the messagebox
            showerror_calls = []

            def mock_showerror(title, message):
                showerror_calls.append((title, message))

            monkeypatch.setattr(screen_lock.messagebox, "showerror", mock_showerror)

            # Create a minimal root window for ScreenLockApp
            root = tk.Tk()
            root.withdraw()
            try:
                # Create app and attempt to install hook
                app = screen_lock.ScreenLockApp(root)
                result = app._install_hook()

                # Verify it failed
                assert result is False

                # Verify unhook was called to rollback
                assert len(unhook_called) == 1
                assert unhook_called[0] is mock_hook

                # Verify error messagebox was shown
                assert len(showerror_calls) == 1
                assert showerror_calls[0][0] == "Screen Lock"
                assert "left windows" in showerror_calls[0][1]
            finally:
                root.destroy()
        finally:
            # Restore original keyboard module
            if original_kb is not None:
                sys.modules["keyboard"] = original_kb
            elif "keyboard" in sys.modules:
                del sys.modules["keyboard"]
            importlib.reload(screen_lock)

    def test_install_hook_rollback_unblocks_on_critical_failure(self, monkeypatch, appdata):
        """Verify _install_hook unblocks all previously blocked combos on critical failure."""
        import importlib
        import tkinter as tk

        # Track calls to keyboard functions
        mock_hook = object()
        blocked_counter = [0]
        unblock_calls = []
        unhook_calls = []

        def mock_block_key(combo):
            # 1st critical combo (left windows) succeeds, 2nd (right windows) fails.
            # Tests the rollback path: previously-blocked IDs must be unblocked.
            blocked_counter[0] += 1
            if blocked_counter[0] == 1:
                return blocked_counter[0]  # return unique block ID
            raise ValueError(f"Unsupported key name: {combo}")

        def mock_unblock_key(bid):
            unblock_calls.append(bid)

        def mock_unhook(hook):
            unhook_calls.append(hook)

        class MockKeyboard:
            @staticmethod
            def hook(handler, suppress=False):
                return mock_hook

            @staticmethod
            def block_key(combo):
                return mock_block_key(combo)

            @staticmethod
            def unblock_key(bid):
                mock_unblock_key(bid)

            @staticmethod
            def unhook(hook):
                mock_unhook(hook)

        # Patch the module's keyboard reference
        import sys
        original_kb = sys.modules.get("keyboard")
        sys.modules["keyboard"] = MockKeyboard()
        try:
            # Reload screen_lock to pick up the mocked keyboard
            importlib.reload(screen_lock)

            # Now mock the messagebox
            showerror_calls = []

            def mock_showerror(title, message):
                showerror_calls.append((title, message))

            monkeypatch.setattr(screen_lock.messagebox, "showerror", mock_showerror)

            # Create a minimal root window for ScreenLockApp
            root = tk.Tk()
            root.withdraw()
            try:
                # Create app and attempt to install hook
                app = screen_lock.ScreenLockApp(root)
                result = app._install_hook()

                # Verify it failed
                assert result is False

                # Verify unblock_key was called for the 1 successful block (left windows)
                assert len(unblock_calls) == 1
                assert set(unblock_calls) == {1}

                # Verify unhook was called once
                assert len(unhook_calls) == 1
                assert unhook_calls[0] is mock_hook

                # Verify error messagebox was shown for the failing 2nd critical combo
                assert len(showerror_calls) == 1
                assert showerror_calls[0][0] == "Screen Lock"
                assert "right windows" in showerror_calls[0][1]
            finally:
                root.destroy()
        finally:
            # Restore original keyboard module
            if original_kb is not None:
                sys.modules["keyboard"] = original_kb
            elif "keyboard" in sys.modules:
                del sys.modules["keyboard"]
            importlib.reload(screen_lock)


class TestVirtualScreenFallback:
    def test_fallback_used_when_metrics_fail(self, monkeypatch):
        # Force the helper down the fallback path regardless of platform.
        monkeypatch.setattr(screen_lock.sys, "platform", "linux")
        rect = screen_lock.get_virtual_screen_rect(fallback=(800, 600))
        assert rect == (0, 0, 800, 600)
