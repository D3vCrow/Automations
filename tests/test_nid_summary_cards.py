"""NID Summary card classification helpers (direction-A redesign parity).

The App builds a Tk root, so it can't be instantiated headless; the pure
classification helpers are exercised on a bare object via ``object.__new__(App)``
(they read only their arguments or a stubbed ``self.mon``). This mirrors
``test_nsm_overview_cards`` so both dashboards derive card colour from the one
shared verdict palette.
"""
from pathlib import Path
import sys
import types

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.network_intrusion_detector_pro import App
from tools._common.threadsafe import BoundedDeque
from tools._common.verdict import VerdictState


# ---------- threat level ----------

def test_threat_status_mapping():
    assert App._threat_status("LOW") is VerdictState.GREEN
    assert App._threat_status("MEDIUM") is VerdictState.AMBER
    assert App._threat_status("HIGH") is VerdictState.RED
    assert App._threat_status("CRITICAL") is VerdictState.RED


def test_threat_status_unknown_is_grey():
    # An unexpected level must not masquerade as GREEN ("all clear").
    assert App._threat_status("") is VerdictState.GRAY
    assert App._threat_status("WHATEVER") is VerdictState.GRAY


# ---------- flagged connections ----------

def test_flagged_status_prioritises_dangerous():
    assert App._flagged_status(0, 0) is VerdictState.GREEN
    assert App._flagged_status(3, 0) is VerdictState.AMBER   # suspicious only
    assert App._flagged_status(0, 1) is VerdictState.RED     # a dangerous one wins
    assert App._flagged_status(5, 1) is VerdictState.RED     # dangerous outranks suspicious


# ---------- new (untrusted) devices ----------

def test_new_devices_status():
    assert App._new_devices_status(0) is VerdictState.GREEN
    assert App._new_devices_status(1) is VerdictState.AMBER
    assert App._new_devices_status(9) is VerdictState.AMBER


# ---------- gateway identity (MITM guard) ----------

def _app_with_gateway(baseline, arp, gw_ip="192.168.0.1"):
    a = object.__new__(App)
    a.mon = types.SimpleNamespace(baseline_gateway_mac=baseline, last_arp=arp)
    a.gateway = types.SimpleNamespace(get=lambda: gw_ip)
    return a


def test_gateway_status_no_baseline_is_grey():
    state, word = _app_with_gateway("", {})._gateway_status()
    assert state is VerdictState.GRAY
    assert word == "Not set"


def test_gateway_status_matches_baseline_is_green():
    state, word = _app_with_gateway("aa:bb", {"192.168.0.1": "aa:bb"})._gateway_status()
    assert state is VerdictState.GREEN
    assert word == "OK"


def test_gateway_status_changed_mac_is_red():
    state, word = _app_with_gateway("aa:bb", {"192.168.0.1": "de:ad"})._gateway_status()
    assert state is VerdictState.RED
    assert word == "Changed"


def test_gateway_status_missing_live_mac_never_fabricates_change():
    # No passive capture yet -> no live MAC. Must stay GREEN "OK", not "Changed".
    state, word = _app_with_gateway("aa:bb", {})._gateway_status()
    assert state is VerdictState.GREEN
    assert word == "OK"


# ---------- activity sampling ----------

def test_sample_activity_counts_active_and_flagged():
    a = object.__new__(App)
    a._last_conns = [
        {"trust": "safe"}, {"trust": "known"},
        {"trust": "suspicious"}, {"trust": "dangerous"},
    ]
    a._activity_history = BoundedDeque(maxlen=10)
    a._sample_activity()
    snap = a._activity_history.snapshot()
    assert len(snap) == 1
    _ts, active, flagged = snap[0]
    assert active == 4
    assert flagged == 2   # suspicious + dangerous only
