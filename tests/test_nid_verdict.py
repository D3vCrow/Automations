"""Tests for the Network Intrusion Detector plain-language verdict adapter.

The load-bearing rule (audit plan §6): attack-vs-noise comes from the alert
CATEGORY, not a raw HIGH count. These tests pin that a burst of benign
"new device" alerts stays AMBER (where compute_threat_level would cry
CRITICAL), that a single attack-shaped alert is RED, and that a possible attack
outranks benign noise. All headless — no Tk.
"""

from __future__ import annotations

import time
from typing import Dict

from tools._common.verdict import VerdictState
from tools.network_intrusion_detector_pro import (
    build_nid_verdict,
    summarize_nid_alerts,
)

# Fixed "now" so the 1-hour window is deterministic (2023-11-14, no DST edge).
NOW = 1_700_000_000.0


def _alert(category: str, severity: str, *, ago_s: float = 60.0) -> Dict:
    """Build an alert dict `ago_s` seconds before NOW (local-time timestamp)."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(NOW - ago_s))
    return {"timestamp": ts, "severity": severity, "category": category,
            "title": "t", "details": {}}


# --- Quiet / non-threat inputs -> GREEN --------------------------------------

def test_no_alerts_is_green() -> None:
    v = build_nid_verdict([], NOW)
    assert v.state is VerdictState.GREEN
    assert "clean" in v.headline.lower()


def test_info_alerts_are_ignored() -> None:
    v = build_nid_verdict([_alert("MITM", "INFO"), _alert("DEVICE", "INFO")], NOW)
    assert v.state is VerdictState.GREEN


def test_system_category_is_ignored_even_at_high() -> None:
    # SYSTEM = tool/status noise, never a threat verdict.
    v = build_nid_verdict([_alert("SYSTEM", "HIGH")], NOW)
    assert v.state is VerdictState.GREEN


def test_alerts_outside_window_are_ignored() -> None:
    old = _alert("MITM", "HIGH", ago_s=7200)  # 2 hours ago, window is 1 hour
    assert build_nid_verdict([old], NOW).state is VerdictState.GREEN


def test_unparseable_timestamp_is_skipped() -> None:
    bad = {"timestamp": "not-a-date", "severity": "HIGH", "category": "MITM"}
    assert build_nid_verdict([bad], NOW).state is VerdictState.GREEN


# --- Attack-shaped categories -> RED -----------------------------------------

def test_high_mitm_is_red() -> None:
    v = build_nid_verdict([_alert("MITM", "HIGH")], NOW)
    assert v.state is VerdictState.RED
    assert "attack" in v.headline.lower()
    assert "impersonat" in v.headline.lower()


def test_high_scan_is_red_with_scan_wording() -> None:
    v = build_nid_verdict([_alert("SCAN", "HIGH")], NOW)
    assert v.state is VerdictState.RED
    assert "scan" in v.headline.lower()


def test_high_dns_is_red() -> None:
    v = build_nid_verdict([_alert("DNS", "HIGH")], NOW)
    assert v.state is VerdictState.RED


def test_warn_attack_is_amber_not_red() -> None:
    v = build_nid_verdict([_alert("MITM", "WARN")], NOW)
    assert v.state is VerdictState.AMBER
    assert "suspicious" in v.headline.lower()


# --- Benign categories: AMBER at most, never RED (the plan's core rule) -------

def test_high_new_device_is_amber_not_red() -> None:
    # compute_threat_level would call this HIGH/CRITICAL on severity alone;
    # the banner must not — a new device is benign-shaped.
    v = build_nid_verdict([_alert("DEVICE", "HIGH")], NOW)
    assert v.state is VerdictState.AMBER
    assert "device" in v.headline.lower()


def test_burst_of_new_devices_stays_amber() -> None:
    alerts = [_alert("DEVICE", "HIGH") for _ in range(5)]
    v = build_nid_verdict(alerts, NOW)
    assert v.state is VerdictState.AMBER  # not CRITICAL/RED despite 5 HIGHs


def test_warn_outbound_is_amber() -> None:
    v = build_nid_verdict([_alert("OUTBOUND", "WARN")], NOW)
    assert v.state is VerdictState.AMBER
    assert "traffic" in v.headline.lower()


# --- Arbitration: a possible attack outranks benign noise --------------------

def test_attack_outranks_benign() -> None:
    alerts = [_alert("DEVICE", "HIGH"), _alert("MITM", "HIGH")]
    v = build_nid_verdict(alerts, NOW)
    assert v.state is VerdictState.RED


def test_attack_warn_outranks_benign_warn_but_stays_amber() -> None:
    alerts = [_alert("DEVICE", "WARN"), _alert("SCAN", "WARN")]
    v = build_nid_verdict(alerts, NOW)
    assert v.state is VerdictState.AMBER


# --- Dominant category drives the wording ------------------------------------

def test_dominant_attack_category_picks_wording() -> None:
    alerts = [_alert("SCAN", "HIGH"), _alert("SCAN", "HIGH"), _alert("DNS", "HIGH")]
    v = build_nid_verdict(alerts, NOW)
    assert v.state is VerdictState.RED
    assert "scan" in v.headline.lower()  # SCAN dominates 2:1


# --- Capability note ----------------------------------------------------------

def test_capability_note_propagates_to_winner() -> None:
    v = build_nid_verdict(
        [_alert("MITM", "HIGH")], NOW,
        capability_note="Limited visibility — not running as Administrator.",
    )
    assert v.state is VerdictState.RED
    assert "Administrator" in v.capability_note


def test_capability_note_on_green() -> None:
    v = build_nid_verdict([], NOW, capability_note="passive capture off")
    assert v.state is VerdictState.GREEN
    assert v.capability_note == "passive capture off"


# --- summarize_nid_alerts directly -------------------------------------------

def test_summary_counts_and_dominant() -> None:
    alerts = [
        _alert("MITM", "HIGH"), _alert("SCAN", "WARN"),
        _alert("DEVICE", "HIGH"), _alert("SYSTEM", "HIGH"),  # SYSTEM ignored
        _alert("DNS", "INFO"),  # INFO ignored
    ]
    s = summarize_nid_alerts(alerts, NOW)
    assert s["attack_high"] == 1
    assert s["attack_warn"] == 1
    assert s["benign_high"] == 1
    assert s["benign_warn"] == 0
    assert s["dominant_attack"] in ("MITM", "SCAN")
    assert s["dominant_benign"] == "DEVICE"
