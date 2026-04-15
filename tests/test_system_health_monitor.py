"""Tests for system_health_monitor thermal conversion and CPU normalization."""
from pathlib import Path
import re
import sys

# Make 'tools' importable when running pytest from project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

# Import the real thermal conversion function
from tools.system_health_monitor import convert_wmi_temp


# ---------- Thermal Conversion Tests ----------

def test_thermal_normal_room_temp():
    """3000 tenths of Kelvin -> 26.85°C (room temperature)."""
    result = convert_wmi_temp(3000)
    assert result == 26.9, f"Expected 26.9, got {result}"


def test_thermal_normal_warm_cpu():
    """3500 tenths of Kelvin -> 76.85°C (warm CPU)."""
    result = convert_wmi_temp(3500)
    assert result == 76.9, f"Expected 76.9, got {result}"


def test_thermal_high_but_valid():
    """3800 tenths of Kelvin -> 106.85°C (high but valid CPU)."""
    result = convert_wmi_temp(3800)
    assert result == 106.9, f"Expected 106.9, got {result}"


def test_thermal_out_of_range_too_low():
    """10 tenths of Kelvin -> -272.15°C (below 0, reject as unavailable)."""
    result = convert_wmi_temp(10)
    assert result is None, f"Expected None, got {result}"


def test_thermal_out_of_range_too_high():
    """99999 tenths of Kelvin -> 9996.85°C (far above 110, reject as unavailable)."""
    result = convert_wmi_temp(99999)
    assert result is None, f"Expected None, got {result}"


def test_thermal_boundary_zero_celsius():
    """2731.5 tenths of Kelvin -> 0.0°C (lower boundary)."""
    result = convert_wmi_temp(2731.5)
    assert result == 0.0, f"Expected 0.0, got {result}"


def test_thermal_boundary_110_celsius():
    """3831.5 tenths of Kelvin -> 110.0°C (upper boundary, should accept)."""
    result = convert_wmi_temp(3831.5)
    assert result == 110.0, f"Expected 110.0, got {result}"


def test_thermal_just_above_110():
    """3832 tenths of Kelvin -> 110.05°C (just above 110, should reject)."""
    result = convert_wmi_temp(3832)
    assert result is None, f"Expected None, got {result}"


def test_thermal_out_of_range_logs_warning(capsys):
    """Out-of-range values should emit WARNING to stderr."""
    result = convert_wmi_temp(99999)
    assert result is None
    captured = capsys.readouterr()
    assert re.search(r"WARNING: CPU temp out of range.*raw=99999", captured.err), \
        f"Expected 'WARNING: CPU temp out of range' and 'raw=99999' in stderr, got: {captured.err}"
