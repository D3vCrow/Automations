"""Tests for the Network Stability Monitor plain-language verdict adapter.

The adapter maps the NSM classifier (status + category) plus the intelligence
engine's suspicion signals onto the shared five-state Verdict vocabulary. These
tests pin the mapping table, the two safety-critical rules (a possible attack
outranks a reassuring outage; a low-confidence BLUE degrades to AMBER), and the
plain-English wording contract — all headless, no Tk.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tools._common.verdict import VerdictState
from tools.network_stability_monitor import (
    build_nsm_verdict,
    verdict_from_sample,
)


# --- Base connectivity mapping ------------------------------------------------

def test_ok_is_green() -> None:
    v = build_nsm_verdict("OK", "DEGRADED")
    assert v.state is VerdictState.GREEN
    assert "healthy" in v.headline.lower()


def test_down_isp_high_confidence_is_blue() -> None:
    v = build_nsm_verdict("DOWN", "ISP", isp_confidence=0.9)
    assert v.state is VerdictState.BLUE
    assert "not your fault" in v.headline.lower()


def test_down_isp_low_confidence_degrades_to_amber() -> None:
    # Below the 0.7 confidence floor, the reassuring BLUE must not stand.
    v = build_nsm_verdict("DOWN", "ISP", isp_confidence=0.5)
    assert v.state is VerdictState.AMBER


def test_down_isp_without_intelligence_degrades_to_amber() -> None:
    # No probability available -> below-floor default -> AMBER, never a bare BLUE.
    v = build_nsm_verdict("DOWN", "ISP", isp_confidence=None)
    assert v.state is VerdictState.AMBER


def test_down_link_is_amber() -> None:
    v = build_nsm_verdict("DOWN", "LINK")
    assert v.state is VerdictState.AMBER
    assert "router" in v.headline.lower() or "wi-fi" in v.headline.lower()


def test_down_gateway_is_amber() -> None:
    v = build_nsm_verdict("DOWN", "GATEWAY")
    assert v.state is VerdictState.AMBER
    assert "router" in v.headline.lower()


def test_down_unknown_category_is_amber() -> None:
    v = build_nsm_verdict("DOWN", "MYSTERY")
    assert v.state is VerdictState.AMBER


@pytest.mark.parametrize("category", ["DNS", "DEGRADED", ""])
def test_degraded_is_amber(category: str) -> None:
    v = build_nsm_verdict("DEGRADED", category)
    assert v.state is VerdictState.AMBER


def test_blank_status_is_gray() -> None:
    v = build_nsm_verdict("", "")
    assert v.state is VerdictState.GRAY


def test_case_insensitive_inputs() -> None:
    assert build_nsm_verdict("down", "isp", isp_confidence=0.9).state is VerdictState.BLUE
    assert build_nsm_verdict("ok", "dns").state is VerdictState.GREEN


# --- Security signal ----------------------------------------------------------

def test_high_suspicion_is_red() -> None:
    v = build_nsm_verdict("OK", "DEGRADED", suspicion_level="HIGH")
    assert v.state is VerdictState.RED
    assert "attack" in v.headline.lower()


def test_strong_malicious_probability_is_red() -> None:
    v = build_nsm_verdict("OK", "DEGRADED", malicious_prob=0.6)
    assert v.state is VerdictState.RED


def test_medium_suspicion_bumps_green_to_amber() -> None:
    v = build_nsm_verdict("OK", "DEGRADED", suspicion_level="MEDIUM")
    assert v.state is VerdictState.AMBER
    assert "worth a look" in v.headline.lower()


def test_low_suspicion_leaves_base_untouched() -> None:
    v = build_nsm_verdict("OK", "DEGRADED", suspicion_level="LOW")
    assert v.state is VerdictState.GREEN


# --- Arbitration: the load-bearing safety rule --------------------------------

def test_attack_outranks_isp_outage() -> None:
    # ISP outage (would be a confident BLUE) + a HIGH suspicion signal must
    # surface as RED — an attack often presents as an outage.
    v = build_nsm_verdict("DOWN", "ISP", isp_confidence=0.95, suspicion_level="HIGH")
    assert v.state is VerdictState.RED


def test_attack_outranks_isp_outage_via_probability() -> None:
    v = build_nsm_verdict("DOWN", "ISP", isp_confidence=0.95, malicious_prob=0.7)
    assert v.state is VerdictState.RED


def test_red_detail_reports_the_signal() -> None:
    v = build_nsm_verdict("DOWN", "GATEWAY", suspicion_level="HIGH", malicious_prob=0.4)
    assert v.state is VerdictState.RED
    assert "HIGH" in v.detail


# --- Capability note ----------------------------------------------------------

def test_capability_note_propagates_to_winner() -> None:
    v = build_nsm_verdict(
        "OK", "DEGRADED", suspicion_level="HIGH",
        capability_note="Only this PC is checked",
    )
    assert v.state is VerdictState.RED  # note rides the arbitrated winner
    assert v.capability_note == "Only this PC is checked"


# --- verdict_from_sample: pulls signals off a live sample ---------------------

def _sample(**kw) -> SimpleNamespace:
    base = dict(
        status="OK", category="DEGRADED", severity="INFO",
        suspicion_level="NONE", root_cause=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_from_sample_ok_no_intelligence_is_green() -> None:
    assert verdict_from_sample(_sample()).state is VerdictState.GREEN


def test_from_sample_isp_uses_root_cause_confidence() -> None:
    rc = SimpleNamespace(isp_issue=0.92, possible_malicious_activity=0.0)
    v = verdict_from_sample(_sample(status="DOWN", category="ISP", root_cause=rc))
    assert v.state is VerdictState.BLUE


def test_from_sample_weak_isp_confidence_degrades() -> None:
    rc = SimpleNamespace(isp_issue=0.4, possible_malicious_activity=0.0)
    v = verdict_from_sample(_sample(status="DOWN", category="ISP", root_cause=rc))
    assert v.state is VerdictState.AMBER


def test_from_sample_malicious_root_cause_is_red() -> None:
    rc = SimpleNamespace(isp_issue=0.8, possible_malicious_activity=0.6)
    v = verdict_from_sample(_sample(status="DOWN", category="ISP", root_cause=rc))
    assert v.state is VerdictState.RED


def test_from_sample_isp_without_intelligence_degrades_to_amber() -> None:
    # root_cause is None -> no confidence -> BLUE can't stand.
    v = verdict_from_sample(_sample(status="DOWN", category="ISP"))
    assert v.state is VerdictState.AMBER
