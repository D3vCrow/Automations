"""
PoC: L2 — Path traversal in FFmpeg Studio screenshot capture output.

What this demonstrates
----------------------
`tools/ffmpeg_studio.py` lines 1285/1294/1329 read the screenshot output
folder from a tkinter Entry (`cap_out_var`) and feed it straight into
`subprocess.run(["ffmpeg", ..., out_file])` with no validation. A user who
types `../../Windows/Temp` (or any traversal string) into the "Output
Folder" field for screenshot capture lands files outside the intended
`~/Pictures` sandbox. Same root cause as L1 but on the Screenshot tab.

This PoC simulates the vulnerable code path *without* touching the real
GUI or real FFmpeg. It re-implements the 3 vulnerable lines
(`cap_out_var.get().strip()` → `os.path.join` → `subprocess.run`) and
drives them with an attacker-controlled traversal string. If the traversal
lands a file outside the intended sandbox, the exploit is considered
successful.

Safety
------
- Loopback/local only — no network, no external sockets.
- Sandbox is a fresh dir under `%TEMP%`; "outside" target is also under
  `%TEMP%` (sibling dir). No writes to `C:\\Windows\\Temp` or anywhere
  privileged.
- Uses a stub "ffmpeg" call (`cmd /c echo` on Windows, `true` elsewhere)
  so no real encoder runs. We then manually touch the output path to
  prove `os.path.join` resolved outside the sandbox.
- Idempotent: cleans up its own temp dirs on exit.

Expected output
---------------
- Unpatched: "EXPLOIT SUCCEEDED — wrote file outside sandbox: <path>"
- Patched:   "EXPLOIT BLOCKED — validator rejected traversal input"

Exit codes
----------
- 0  = exploit succeeded (vulnerability present)
- 1  = exploit blocked (patch working)
- 2  = harness error (unexpected state, not a security result)
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def _try_import_validator():
    """Return the fix's validator if it exists, else None (unpatched)."""
    try:
        # The fix in Sub-task B adds `_validate_output_dir` to ffmpeg_studio.
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        from tools.ffmpeg_studio import _validate_output_dir  # type: ignore
        return _validate_output_dir
    except Exception:
        return None


def _simulate_vulnerable_capture(cap_out_var_value: str, sandbox: Path) -> Path:
    """Mirror the 3 vulnerable lines from ffmpeg_studio.py:1285/1294/1329.

    Returns the resolved output path the vulnerable code would have
    handed to subprocess.run.
    """
    out_d = cap_out_var_value.strip()                       # line 1285
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    ext = "png"
    out_file = os.path.join(out_d, f"capture_{timestamp}.{ext}")  # line 1294

    # Stub "ffmpeg" — proves the arg flows into subprocess without
    # actually encoding. On Windows: cmd /c echo; elsewhere: true.
    if os.name == "nt":
        stub = ["cmd", "/c", "echo", out_file]
    else:
        stub = ["true", out_file]

    # line 1329 — the args list contains out_file, unvalidated.
    subprocess.run(stub, capture_output=True)

    # Real ffmpeg would have written to out_file. We touch it manually
    # so the harness can observe the path resolution outcome.
    resolved = Path(out_file).resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_bytes(b"PoC artifact - L2 path traversal simulation")
    return resolved


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="l2_poc_"))
    sandbox = base / "sandbox_pictures"        # mimics ~/Pictures
    outside = base / "outside_victim"          # mimics ../../Windows/Temp
    sandbox.mkdir()
    outside.mkdir()

    # Attacker payload — traversal from sandbox into sibling dir.
    malicious = f"{sandbox}{os.sep}..{os.sep}outside_victim"

    validator = _try_import_validator()
    try:
        if validator is not None:
            try:
                validator(malicious, allowed_bases=[Path(sandbox)])
            except (ValueError, PermissionError) as e:
                print(f"EXPLOIT BLOCKED — validator rejected traversal input: {e}")
                return 1

        written = _simulate_vulnerable_capture(malicious, sandbox)
        try:
            written.relative_to(sandbox.resolve())
            print(f"EXPLOIT BLOCKED — file stayed inside sandbox: {written}")
            return 1
        except ValueError:
            print(f"EXPLOIT SUCCEEDED — wrote file outside sandbox: {written}")
            return 0
    finally:
        shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
