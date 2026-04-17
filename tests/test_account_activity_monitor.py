"""Tests for account_activity_monitor filter-snapshot thread safety.

Covers A4: _active_categories / _active_severities are now read via
_snapshot_filters() under an RLock so UI toggle writes cannot race with
after()-callback or worker-thread reads.
"""

import sys
import threading
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.account_activity_monitor import App


def _make_bare_app() -> App:
    """Instantiate App without running __init__ (no Tk root required).

    Wires up only the attributes _snapshot_filters touches.
    """
    app = App.__new__(App)
    app._active_categories = {f"CAT_{i}" for i in range(20)}
    app._active_severities = {"CRITICAL", "WARNING", "INFO"}
    app._filter_lock = threading.RLock()
    return app


def test_snapshot_filters_returns_frozensets():
    app = _make_bare_app()
    cats, sevs = app._snapshot_filters()
    assert isinstance(cats, frozenset)
    assert isinstance(sevs, frozenset)
    assert cats == app._active_categories
    assert sevs == app._active_severities


def test_snapshot_is_isolated_from_later_mutation():
    app = _make_bare_app()
    cats, sevs = app._snapshot_filters()
    with app._filter_lock:
        app._active_categories.add("NEW_CAT")
        app._active_severities.discard("INFO")
    assert "NEW_CAT" not in cats
    assert "INFO" in sevs


def test_snapshot_survives_concurrent_mutation():
    """Reader snapshots while writer mutates — no RuntimeError, no partial reads."""
    app = _make_bare_app()
    stop = threading.Event()
    errors: list = []

    def writer():
        toggle = True
        while not stop.is_set():
            with app._filter_lock:
                if toggle:
                    app._active_categories.add("RACE_CAT")
                    app._active_severities.discard("INFO")
                else:
                    app._active_categories.discard("RACE_CAT")
                    app._active_severities.add("INFO")
            toggle = not toggle

    def reader():
        try:
            for _ in range(5000):
                cats, sevs = app._snapshot_filters()
                # Force iteration to surface any copy-mid-mutation corruption.
                _ = sum(1 for _ in cats) + sum(1 for _ in sevs)
        except Exception as e:  # pragma: no cover — only fires on regression
            errors.append(e)

    w = threading.Thread(target=writer, daemon=True)
    r = threading.Thread(target=reader)
    w.start()
    r.start()
    r.join(timeout=10)
    stop.set()
    w.join(timeout=2)
    assert not errors, f"Concurrent snapshot raised: {errors}"


def test_snapshot_result_is_immutable():
    """Returned frozensets must reject mutation — no accidental shared state."""
    app = _make_bare_app()
    cats, sevs = app._snapshot_filters()
    import pytest
    with pytest.raises(AttributeError):
        cats.add("x")  # type: ignore[attr-defined]
    with pytest.raises(AttributeError):
        sevs.discard("INFO")  # type: ignore[attr-defined]
