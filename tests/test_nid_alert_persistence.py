"""NID threat history survives an app close (alert_store wiring)."""

import os

from tools.network_intrusion_detector_pro import NetworkMonitor
from tools._common.alert_store import AlertStore


def test_logged_alert_persists_to_db(tmp_path):
    state = str(tmp_path / "nid_state.json")
    mon = NetworkMonitor(state)
    mon.log("HIGH", "MITM", "Gateway MAC changed", {"gateway_ip": "192.168.1.1"})
    # Persisted the instant it fires.
    assert mon.alert_store.count() == 1
    # Survives "close": a fresh store on the same DB file still sees it.
    reopened = AlertStore(os.path.join(str(tmp_path), "nid_incidents.db"))
    rows = reopened.load()
    assert len(rows) == 1
    assert rows[0]["title"] == "Gateway MAC changed"
    assert rows[0]["severity"] == "HIGH"


def test_dedup_updates_count_in_db(tmp_path):
    state = str(tmp_path / "nid_state.json")
    mon = NetworkMonitor(state)
    # Same alert twice inside the 45s dedup window -> one row, count 2.
    mon.log("WARN", "SCAN", "Port scan", {"src_ip": "10.0.0.5"})
    mon.log("WARN", "SCAN", "Port scan", {"src_ip": "10.0.0.5"})
    assert mon.alert_store.count() == 1
    assert mon.alert_store.load()[0]["details"]["_count"] == 2
