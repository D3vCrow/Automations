"""Tests for network_stability_monitor IPv4 extraction and string shortening."""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from tools.network_stability_monitor import parse_ipv4, short


# ---------- parse_ipv4 ----------

def test_parse_ipv4_single():
    assert parse_ipv4("gateway 192.168.1.1") == ["192.168.1.1"]


def test_parse_ipv4_multiple():
    assert parse_ipv4("from 8.8.8.8 to 1.1.1.1") == ["8.8.8.8", "1.1.1.1"]


def test_parse_ipv4_embedded_range():
    assert parse_ipv4("From 10.0.0.1 to 10.0.0.255") == ["10.0.0.1", "10.0.0.255"]


def test_parse_ipv4_no_match():
    assert parse_ipv4("no ips here") == []


def test_parse_ipv4_empty_string():
    assert parse_ipv4("") == []


def test_parse_ipv4_incomplete_three_octets():
    assert parse_ipv4("192.168.1") == []


def test_parse_ipv4_regex_does_not_validate_range():
    """Regex only checks shape (\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}); 999.999.999.999 still matches."""
    assert parse_ipv4("999.999.999.999") == ["999.999.999.999"]


# ---------- short ----------

def test_short_below_limit():
    assert short("hello", 10) == "hello"


def test_short_at_exact_limit():
    s = "a" * 220
    assert short(s, 220) == s


def test_short_over_limit_appends_ellipsis():
    s = "a" * 221
    assert short(s, 220) == ("a" * 220) + "..."


def test_short_strips_carriage_returns():
    assert short("line1\r\nline2", 100) == "line1\nline2"


def test_short_empty_string():
    assert short("", 10) == ""


def test_short_default_length_truncates():
    """Default n=220; longer input gets truncated with ellipsis."""
    s = "a" * 250
    out = short(s)
    assert out == ("a" * 220) + "..."
    assert len(out) == 223
