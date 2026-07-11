"""Wi-Fi channel-map label de-duplication.

When several networks share a 2.4 GHz channel (e.g. three on channel 6), the
channel map must label only the strongest so their SSIDs don't stack on top of
each other. That pick is a pure helper, tested here.
"""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.network_stability_monitor import _strongest_by_channel


def test_strongest_by_channel_picks_highest_signal():
    nets = [
        {"channel": 6, "signal_pct": 50, "ssid": "Tenda"},
        {"channel": 6, "signal_pct": 94, "ssid": "FamilyPapa"},
        {"channel": 6, "signal_pct": 46, "ssid": "The7"},
        {"channel": 1, "signal_pct": 89, "ssid": "Fridge"},
    ]
    best = _strongest_by_channel(nets)
    assert set(best.keys()) == {1, 6}
    assert best[6]["ssid"] == "FamilyPapa"   # the 94% one, not 50/46
    assert best[1]["ssid"] == "Fridge"


def test_strongest_by_channel_ignores_out_of_range_channels():
    nets = [{"channel": 0, "signal_pct": 99, "ssid": "X"},
            {"channel": 14, "signal_pct": 99, "ssid": "Y"}]
    assert _strongest_by_channel(nets) == {}


def test_strongest_by_channel_empty():
    assert _strongest_by_channel([]) == {}


def test_strongest_by_channel_identity_is_stable():
    # The drawing code compares `strongest.get(ch) is net`, so the returned
    # value must be the SAME dict object from the input list.
    a = {"channel": 11, "signal_pct": 80, "ssid": "DIGI"}
    best = _strongest_by_channel([a])
    assert best[11] is a
