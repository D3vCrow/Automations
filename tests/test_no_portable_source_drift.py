"""Drift guard for portable/ — prevents re-introduction of shadow copies.

Post-A7, portable/ must contain only *_Portable.py launchers + support
files (.bat, dist/, build/). Any bare `.py` source in portable/ other
than the launchers is a duplicate of a tools/* module and will silently
diverge — exactly the failure mode A7 fixed.
"""

from pathlib import Path

PORTABLE_DIR = Path(__file__).resolve().parents[1] / "portable"


def test_no_duplicate_tool_sources_in_portable():
    """No flat .py in portable/ other than the _Portable.py launchers."""
    assert PORTABLE_DIR.is_dir(), f"portable/ missing: {PORTABLE_DIR}"
    bad = [
        p.name for p in PORTABLE_DIR.glob("*.py")
        if not p.name.endswith("_Portable.py")
    ]
    assert not bad, (
        f"portable/ must not contain tool source duplicates: {bad}. "
        "Launchers import from tools.* — do not copy tool sources here."
    )
