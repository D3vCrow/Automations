"""
L1 — Path traversal in FFmpeg Studio output folder (PoC)
========================================================

Vulnerability
-------------
`tools/ffmpeg_studio.py:502,542,552` reads `output_dir_var` (a tkinter
`StringVar` bound to a free-text Entry widget) with no path validation,
then `os.path.join`s a filename onto it and hands the result to
`subprocess.Popen` as an FFmpeg output argument. An attacker who can
reach the UI (local user, RDP, shared session, shoulder-surf-and-paste)
can supply a traversal string like `..\\..\\..\\Windows\\System32` and
cause FFmpeg to drop a `.mp4` in that directory.

What this PoC does
------------------
We do NOT touch real system directories. Instead:

  1. Create a sandbox root  %TEMP%\\security_probe_L1\\legit
  2. Create a "victim" dir  %TEMP%\\security_probe_L1\\victim
  3. Simulate the buggy code path: reproduce the exact
     `os.path.join(out_dir, f"gameplay_{ts}.mp4")` idiom from
     `ffmpeg_studio.py:542` using the attacker-supplied traversal
     string as `out_dir`. No FFmpeg / subprocess is spawned — we
     replace Popen with a tiny `open(out_file, "wb").write(...)`
     because that is sufficient to demonstrate the write-primitive.
  4. Check whether the resulting file landed inside `victim/`. If so:
     the traversal worked end-to-end — exploit succeeded.

Expected output on success
--------------------------
  [+] Sandbox legit dir:  <%TEMP%>\\security_probe_L1\\legit
  [+] Sandbox victim dir: <%TEMP%>\\security_probe_L1\\victim
  [+] Attacker-supplied out_dir string: ..\\victim
  [+] os.path.join gave: <...>\\security_probe_L1\\legit\\..\\victim\\gameplay_<ts>.mp4
  [+] Resolved actual path: <...>\\security_probe_L1\\victim\\gameplay_<ts>.mp4
  [+] File landed in victim/ — traversal was NOT blocked
  EXPLOIT SUCCEEDED

After the fix is applied, re-running this PoC should print
`EXPLOIT BLOCKED` (the validator raises / rejects before the write).

Safety caveats
--------------
- No network calls. No real system dirs written. Runs entirely under
  %TEMP%. Cleans up its sandbox at the end.
- Uses plain `open()`, NOT subprocess or FFmpeg — we are modelling the
  vector, not actually executing the recorder.
- Exits with code 0 on success (prints EXPLOIT SUCCEEDED) and code 1
  on failure (prints EXPLOIT BLOCKED), so CI can just run it and
  check the exit status once the fix is in.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

SANDBOX_ROOT = Path(tempfile.gettempdir()) / "security_probe_L1"


def _setup_sandbox() -> tuple[Path, Path]:
    """Fresh legit/ and victim/ dirs under %TEMP%."""
    if SANDBOX_ROOT.exists():
        shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)
    legit = SANDBOX_ROOT / "legit"
    victim = SANDBOX_ROOT / "victim"
    legit.mkdir(parents=True, exist_ok=True)
    victim.mkdir(parents=True, exist_ok=True)
    return legit, victim


def _try_validator(candidate: Path, allowed_base: Path) -> bool:
    """Mirror of the proposed fix. Returns True if path is inside base.

    We import the real validator if it's available; otherwise this PoC
    still runs and prints EXPLOIT SUCCEEDED (pre-fix behaviour)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    try:
        from tools.ffmpeg_studio import _validate_output_dir  # type: ignore
    except ImportError:
        return True  # validator not yet installed → vulnerable path

    try:
        _validate_output_dir(str(candidate), allowed_bases=[allowed_base])
        return True
    except Exception:
        return False


def main() -> int:
    legit, victim = _setup_sandbox()
    print(f"[+] Sandbox legit dir:  {legit}")
    print(f"[+] Sandbox victim dir: {victim}")

    # Attacker pastes this into the Output Folder Entry. The UI code's
    # `output_dir_var.get().strip()` returns it unchanged.
    attacker_input = "..\\victim"
    # Simulate: Chris had just browsed to `legit/` via the file picker,
    # then the attacker overwrote the entry. Real code reads the Entry
    # once, so effectively `out_dir = legit / attacker_input`.
    tainted_out_dir = str(legit / attacker_input)
    print(f"[+] Attacker-supplied out_dir string: {attacker_input}")

    # Gate with the (yet-to-exist) validator. If the fix is applied,
    # this returns False and we bail out before writing anything.
    if not _try_validator(Path(tainted_out_dir), legit):
        print("[+] Validator rejected the path — no write attempted")
        print("EXPLOIT BLOCKED")
        shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)
        return 1

    # ── This is the exact pattern from ffmpeg_studio.py:542 ─────────
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_file = os.path.join(tainted_out_dir, f"gameplay_{timestamp}.mp4")
    print(f"[+] os.path.join gave: {out_file}")

    # Stand-in for subprocess.Popen(["ffmpeg", ..., out_file]). FFmpeg
    # would open this path for writing; we do the same with plain open.
    try:
        with open(out_file, "wb") as fh:
            fh.write(b"FAKE_MP4_PAYLOAD")
    except OSError as e:
        print(f"[-] Write failed ({e}) — exploit did not land")
        shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)
        return 1

    resolved = Path(out_file).resolve()
    print(f"[+] Resolved actual path: {resolved}")

    victim_resolved = victim.resolve()
    try:
        resolved.relative_to(victim_resolved)
        print("[+] File landed in victim/ — traversal was NOT blocked")
        print("EXPLOIT SUCCEEDED")
        rc = 0
    except ValueError:
        print("[+] File stayed in legit/ — traversal did not escape")
        print("EXPLOIT BLOCKED")
        rc = 1

    shutil.rmtree(SANDBOX_ROOT, ignore_errors=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
