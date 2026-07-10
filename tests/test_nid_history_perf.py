"""NID connection-history persistence: debounce, cap, and compact on-disk form.

The scan worker used to rewrite the whole (up to ~1.5 MB) nid_conn_history.json
every scan. These tests cover the three fixes on App's history methods:
debounce (write at most once per interval), cap (keep the 5000 most-recently
seen), and compact JSON (no pretty-print newlines). The methods only touch plain
attributes, so we build a bare App via object.__new__ (no Tk).
"""

import json
import threading

from tools.network_intrusion_detector_pro import App


def _make_app(tmp_path, **over):
    app = object.__new__(App)
    app._history_path = str(tmp_path / "nid_conn_history.json")
    app._history_lock = threading.Lock()
    app._conn_history = {}
    app._history_dirty = False
    app._history_last_write = 0.0
    app._HISTORY_WRITE_INTERVAL = 30.0
    app._HISTORY_MAX_ENTRIES = 5000
    for key, value in over.items():
        setattr(app, key, value)
    return app


def test_save_history_caps_to_most_recent(tmp_path):
    app = _make_app(tmp_path)
    # 6000 entries; last_seen is a zero-padded index so higher index = newer.
    app._conn_history = {
        f"ip-{i}": {"remote_ip": f"ip-{i}", "trust": "unknown", "last_seen": f"{i:06d}"}
        for i in range(6000)
    }
    app._save_history()
    assert len(app._conn_history) == 5000
    # The 5000 newest (indices 1000..5999) survive; older ones are dropped.
    assert "ip-5999" in app._conn_history
    assert "ip-1000" in app._conn_history
    assert "ip-999" not in app._conn_history
    assert "ip-0" not in app._conn_history
    # File matches the pruned in-memory dict.
    on_disk = json.loads((tmp_path / "nid_conn_history.json").read_text(encoding="utf-8"))
    assert len(on_disk) == 5000


def test_save_history_writes_compact_json(tmp_path):
    app = _make_app(tmp_path)
    app._conn_history = {
        "ip-1": {"remote_ip": "ip-1", "trust": "unknown", "last_seen": "000001"},
        "ip-2": {"remote_ip": "ip-2", "trust": "suspicious", "last_seen": "000002"},
    }
    app._save_history()
    text = (tmp_path / "nid_conn_history.json").read_text(encoding="utf-8")
    # Compact form: single line, no pretty-print newlines, still valid JSON.
    assert "\n" not in text
    assert json.loads(text) == app._conn_history


def test_debounce_skips_write_inside_window(tmp_path):
    import time as _time

    app = _make_app(tmp_path, _history_last_write=_time.time())  # just "wrote"
    app._conn_history = {"ip-1": {"remote_ip": "ip-1", "last_seen": "000001"}}
    app._save_history_debounced()
    # Inside the window: nothing written, change marked dirty for later.
    assert app._history_dirty is True
    assert not (tmp_path / "nid_conn_history.json").exists()


def test_debounce_writes_after_window(tmp_path):
    app = _make_app(tmp_path, _history_last_write=0.0)  # last write long ago
    app._conn_history = {"ip-1": {"remote_ip": "ip-1", "last_seen": "000001"}}
    app._save_history_debounced()
    assert app._history_dirty is False
    assert (tmp_path / "nid_conn_history.json").exists()


def test_flush_writes_pending_then_clears_dirty(tmp_path):
    app = _make_app(tmp_path, _history_dirty=True, _history_last_write=__import__("time").time())
    app._conn_history = {"ip-1": {"remote_ip": "ip-1", "last_seen": "000001"}}
    app._flush_history()
    assert (tmp_path / "nid_conn_history.json").exists()
    assert app._history_dirty is False


def test_flush_is_noop_when_clean(tmp_path):
    app = _make_app(tmp_path, _history_dirty=False)
    app._conn_history = {"ip-1": {"remote_ip": "ip-1", "last_seen": "000001"}}
    app._flush_history()
    assert not (tmp_path / "nid_conn_history.json").exists()


def test_update_history_defers_write_when_recent(tmp_path):
    import time as _time

    # A fresh write timestamp means _update_history should defer (debounce),
    # not rewrite the file on this scan.
    app = _make_app(tmp_path, _history_last_write=_time.time())
    conns = [{"remote_ip": "5.6.7.8", "trust": "suspicious", "process": "x.exe"}]
    app._update_history(conns)
    assert "5.6.7.8" in app._conn_history  # in-memory update happened
    assert app._history_dirty is True       # but disk write was deferred
    assert not (tmp_path / "nid_conn_history.json").exists()
