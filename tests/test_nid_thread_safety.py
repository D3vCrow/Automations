"""NID alert list is safe to read while the worker thread appends.

Before the fix, UI readers iterated NetworkMonitor.alerts directly while the
scan worker appended under _alert_lock, raising
``RuntimeError: list changed size during iteration`` on busy hosts. The readers
now go through snapshot_alerts()/clear_alerts(), which copy/clear under the lock.
"""

import threading

from tools.network_intrusion_detector_pro import NetworkMonitor


class _NoOpStore:
    """Stub AlertStore so these list-threading tests don't pay per-insert DB cost.

    Durable persistence is covered separately by test_nid_alert_persistence.
    """

    def insert(self, *_args, **_kwargs):
        return 1

    def update_seen(self, *_args, **_kwargs):
        return None


def test_snapshot_alerts_is_isolated_copy(tmp_path):
    mon = NetworkMonitor(str(tmp_path / "nid_state.json"))
    mon.log("WARN", "SCAN", "probe", {"src": "1"})
    snap = mon.snapshot_alerts()
    snap.append({"junk": True})  # mutating the copy must not touch the live list
    assert len(mon.snapshot_alerts()) == 1


def test_clear_alerts_resets_dedup_maps(tmp_path):
    mon = NetworkMonitor(str(tmp_path / "nid_state.json"))
    mon.log("WARN", "SCAN", "probe", {"src": "1"})
    assert len(mon.snapshot_alerts()) == 1
    mon.clear_alerts()
    assert mon.snapshot_alerts() == []
    # The index/last-seen maps are cleared together with the list.
    assert mon._alert_index == {}
    assert mon._alert_last_seen == {}


def test_concurrent_log_and_read_never_raises(tmp_path):
    # The regression guard: hammer log() (worker) while reading (UI). Distinct
    # titles force real appends, and N > 1500 also exercises the locked
    # trim/rebind path. Any raised exception (RuntimeError from a racing
    # iteration, most of all) fails the test.
    mon = NetworkMonitor(str(tmp_path / "nid_state.json"))
    mon.alert_store = _NoOpStore()  # isolate list threading from DB I/O
    errors = []
    n = 2000

    def writer():
        try:
            for i in range(n):
                mon.log("WARN", "SCAN", f"probe {i}", {"src": str(i)})
        except Exception as exc:  # noqa: BLE001 - test records any failure
            errors.append(exc)

    t = threading.Thread(target=writer)
    t.start()
    try:
        reads = 0
        while t.is_alive():
            mon.snapshot_alerts()
            mon.compute_threat_level()
            mon.get_active_threats()
            reads += 1
        assert reads > 0  # reader actually ran alongside the writer
    except Exception as exc:  # noqa: BLE001 - the crash we are guarding against
        errors.append(exc)
    finally:
        t.join()

    assert not errors, f"concurrent access raised: {errors[0]!r}"
    # Trim keeps the live list bounded at its 1200 floor after crossing 1500.
    assert len(mon.snapshot_alerts()) <= 1500
