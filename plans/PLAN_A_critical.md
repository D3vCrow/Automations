# Plan A — Critical Fixes (Tier A: user-visible bugs, data-loss risk, security)

Derived from `REVIEW.md §3 Tier A`. These are the issues that can **corrupt user state, display wrong numbers, or be actively bypassed**. Fix before any convention sweep.

## Goal

Eliminate data-loss paths, visible correctness bugs, and exploitable bypasses across the toolbox.

## Success criteria (verifiable)

1. `system_cleaner.py` never permanently deletes without explicit user consent + a reversible trash path + symlink check.
2. `system_health_monitor.py` CPU temp is within [0, 110] °C on a machine where WMI thermal support returns a value.
3. `screen_lock.py` overlay cannot be bypassed with Alt+Tab, Alt+F4, Win key, or Task Manager, and the unlock shortcut is not printed on screen.
4. `Main.py` launches each tool in a subprocess; a `sys.exit(1)` inside a tool does not close the launcher.
5. Thread-safety races are closed: running each affected tool for 10 minutes under load produces zero dropped samples, zero iteration-during-mutation exceptions, zero phantom UI states.
6. `claude_usage_monitor.py` peak-hours pill reflects the user's local clock correctly in at least one non-UTC timezone.

## Scope notes

- One task = one branch = one commit (or small series). Each task lists its verification step.
- Prefer `pathlib`/type hints/logging **in the same PR** where it's touched, but **don't expand** into unrelated files (that's Plan B).
- No new dependencies without a note in the task. Allowed: `send2thread` (pure-python, pinned), stdlib only otherwise.

---

## Tasks

### A1 — System Cleaner: safe-delete refactor  [L]

**Problem**  
`tools/system_cleaner.py:98,100,118` calls `shutil.rmtree(..., ignore_errors=True)` and `os.remove()` with no dry-run, no trash, no symlink check. `_clean_selected` (L755–796) fires after one generic "Continue?" dialog (L762–765) that shows category *names* but not *sizes*. Zero undo.

**Files**  
`tools/system_cleaner.py`, `tools/system_cleaner_test.py` (new), `requirements.txt`.

**Approach**
1. Add `send2trash>=1.8,<2.0` to `requirements.txt`. (Pure-python, no C deps.)
2. Introduce a `DeleteMode` enum at module scope: `DRY_RUN`, `TRASH`, `PERMANENT`. Default = `TRASH`.
3. Rewrite `_delete_dir_contents()` (L85–108) and `_delete_glob_files()` (L111–123) to:
   - Skip entries where `os.path.islink(entry)` is true — log and continue.
   - Branch on `DeleteMode`:
     - `DRY_RUN` → accumulate size, do not touch disk.
     - `TRASH` → `send2trash.send2trash(entry)`; on failure, log and increment `skipped`.
     - `PERMANENT` → current behavior, but wrap each deletion in a narrow `try/except (OSError, PermissionError)` with structured logging (path, errno).
4. Expand the confirmation dialog body to show, per selected category: size in human units (reuse `format_size()` from tools/system_cleaner.py), full target path, and a boolean "will go to Recycle Bin" badge.
5. Add a "Cancel" button that flips `self._cancel_flag = threading.Event()`; check it between every category in `_run_category_clean()` and return early with a summary of "cleaned / remaining".
6. Add a "Preview (dry-run)" button to the main UI that runs with `DeleteMode.DRY_RUN` and renders a per-category deletion list in the existing log box.
7. CLI: add `argparse` entry point supporting `--scan`, `--dry-run`, `--permanent`, `--categories "Temp,Chrome Cache"`. Default is GUI (preserves current Launch.pyw flow).

**Verification**
- Manual: select one category, click Preview → log shows files and sizes, nothing deleted.
- Manual: select one category with `TRASH` mode → files appear in Windows Recycle Bin.
- Automated: new tests in `tests/test_system_cleaner.py` covering (a) dry-run does not touch disk, (b) symlink is skipped not followed, (c) `%TEMP%` unset fallback returns empty without crash.

**Effort** L (~1 day including tests).

---

### A2 — System Health Monitor: fix WMI CPU-temperature formula  [S]

**Problem**  
`tools/system_health_monitor.py:339` — comment claims "tenths of Kelvin" but the formula `(raw / 10.0) - 273.15` applied to the raw value produces ~2708 °C on machines where WMI actually returns a value. The rest of the pipeline silently accepts it and renders garbage.

**Files**  
`tools/system_health_monitor.py`, `tests/test_system_health_monitor.py` (new).

**Approach**
1. Read the real `MSAcpi_ThermalZoneTemperature` contract: value is absolute temp in **tenths of Kelvin**. Correct formula: `celsius = raw / 10.0 - 273.15` **but only when `raw` is in the expected range** (roughly 2700–4000 → 0–130 °C).
2. Add a sanity clamp: reject values outside `[0, 110]` as "unavailable" and log at WARNING to stderr. Return `None` so the UI falls through to the "N/A" path.
3. Fix the double `psutil.cpu_percent()` call at L193–194 — keep only the `percpu=True` call; compute aggregate from it.
4. Fix the broken normalization at L418–419: drop the unnecessary `* 100`; raw `psutil.cpu_percent()` is already in percent. Use `min(raw_cpu, 100.0)`.
5. Add `cpu_count = cpu_count or 1` guard at the L419 use-site too (mirror L406).

**Verification**
- Unit test in `tests/test_system_health_monitor.py`: feed known raws (e.g., `3000 → 26.85°C`, `99999 → None`, `10 → None`) into the converter.
- Manual smoke on the host machine: open Overview tab, verify CPU temp is plausible (20–90 °C) or "N/A".

**Effort** S (~45 min).

---

### A3 — Screen Lock: close bypass vectors + remove self-defeating UI  [L]

**Problem**  
`tools/screen_lock.py` does not intercept Alt+Tab (L447–448), Alt+F4 (L427–434), Win key (L610 explicitly skips), or Ctrl+Shift+Esc. If the `keyboard` hook fails to install, L575–576 silently accepts unlock attempts. The unlock shortcut is visibly printed on the overlay (L455–457) and the ESC-unlock toggle is an exposed checkbox (L380–382). Single-monitor only (L429 hardcodes `+0+0`). If the parent process dies, the overlay orphans.

**Files**  
`tools/screen_lock.py`, optionally `tools/_common/win_hooks.py` (new if we factor keyboard hook).

**Approach**
1. **Keyboard hook hardening** (L574–630):
   - Hook `keyboard.block_key("alt+tab")`, `"alt+f4"`, `"win"`, `"left windows"`, `"right windows"`, `"ctrl+shift+esc"`.
   - If `keyboard.hook(...)` raises (non-admin on some Windows), surface a `messagebox.showerror` BEFORE entering locked state. Do not pretend the lock is active.
   - Log install/uninstall to stderr (success or failure + errno).
2. **Unlock UI hygiene**:
   - Remove the on-screen label at L455–457. The shortcut is documented in the unlocked control panel only.
   - Replace the ESC-unlock checkbox with a hidden config persisted at `%APPDATA%\screen_lock\config.json` (see A5 for config plumbing).
3. **Multi-monitor**:
   - Replace L428–429 with a loop over all monitors: use `ctypes.windll.user32.GetSystemMetrics(78)` (SM_CXVIRTUALSCREEN) and `(79)` (SM_CYVIRTUALSCREEN) and `(76)/(77)` for origin. Create one Toplevel per monitor OR one overlay that spans the virtual screen. Choose the latter to avoid focus-routing issues.
4. **Panic unlock**:
   - Add an invisible 40×40 px hit target in a configurable corner (default top-left). Triple-click within 1.5 s triggers unlock even if the keyboard hook is dead.
5. **Crash orphan recovery**:
   - On lock, write `%APPDATA%\screen_lock\locked.flag` containing the launcher PID. On `cleanup()`, delete it. On next launcher startup, if flag exists and PID is dead, offer "Previous lock session crashed — clear overlay?".
6. **Fix `run_tool` NameError at L674**: initialize `root = None` before the `try`.

**Verification**
- Manual: lock, then try Alt+Tab, Alt+F4, Win, Ctrl+Shift+Esc — all blocked. Screen shortcut no longer printed.
- Manual: on a dual-monitor machine, confirm both screens are covered.
- Manual: kill Python from Task Manager while locked; relaunch — recovery prompt appears.
- Manual: intentionally run without admin on a version where `keyboard.hook` fails; error dialog shown, overlay not displayed.

**Effort** L (~1 day).

---

### A4 — Main.py: subprocess-isolate tool launches  [L]

**Problem**  
`Main.py:283–296` imports every tool via `importlib.util.spec_from_file_location` and runs `module.run_tool()` in the launcher process. A crashing tool kills the launcher; module-level state leaks across reloads. `Launch.pyw:24` opens `toolbox_crash.log` as a file handle and never closes it.

**Files**  
`Main.py`, `Launch.pyw`, `tools/__init__.py`, `tools/_runner.py` (new), `tools/_common/logging.py` (new — shared; also used by Plan B).

**Approach**
1. Add a `tools/_runner.py` with `if __name__ == "__main__": import importlib, sys; mod = importlib.import_module(sys.argv[1]); mod.run_tool()`. This is the subprocess entrypoint.
2. In `Main.py`, replace `module.run_tool()` (L438) with:
   ```
   proc = subprocess.Popen([sys.executable, "-m", "tools._runner", "tools." + tool_module_name],
                           cwd=BASE_DIR, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                           creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
   self._tool_procs[tool_id] = proc
   ```
3. Replace the window-tracking machinery (L395, L449–476) with process tracking. Single-instance = `if tool_id in self._tool_procs and self._tool_procs[tool_id].poll() is None: focus window via OS-level (optional) else proc.terminate()`.
4. Spawn a reader thread per running tool that drains stderr into `%APPDATA%\toolbox\logs\<tool>-<pid>.log`. If tool exits with non-zero, surface a toast "<Tool> exited unexpectedly — view log" that opens the log file.
5. Migrate `Launch.pyw`:
   - Replace `sys.stderr = open(log_path, "w")` with `logging.basicConfig(handlers=[RotatingFileHandler(log_path, maxBytes=2_000_000, backupCount=3)])`.
   - Wrap launch in a `try/finally` that calls `logging.shutdown()`.
6. Scan `tools/` still runs in-process (cheap — reads `TOOL_NAME` + docstring only). Extract this to a pure `discover_tools()` function that does NOT `exec_module`; use `ast.parse` to read the `TOOL_NAME` constant and module docstring. No arbitrary code runs during discovery.

**Verification**
- Manual: launch any tool, kill it from Task Manager → launcher stays alive, toast appears.
- Manual: `raise RuntimeError` on entry of a test tool, launch it → launcher stays alive, log shows traceback.
- Manual: edit a tool's source, relaunch the same tool → new subprocess picks up the change without restarting the launcher (no module caching).

**Effort** L (~1 day).

---

### A5 — Thread-safety locks on shared mutable state  [M]

**Problem**  
Multiple tools share mutable lists between a worker thread and the Tk main loop with no synchronization:
- `tools/network_intrusion_detector_pro.py:125` — `_ip_geo_cache` (dict).
- `tools/account_activity_monitor.py:2262–2288` — `_live_events` (list, worker extends while UI iterates).
- `tools/system_health_monitor.py:254,398,1255,1376–1395` — `engine.samples`, `engine.alerts`, thresholds.
- `tools/folder_size_analyzer.py:354–373,405` — `self.folders` rebuilt on worker while `_refresh_tree` reads it.
- `tools/NETWORK STABILITY MONITOR.py:627–628,622–623` — sample/event lists (append + slice while UI refresh reads).

**Files**  
The five tools above, plus a new `tools/_common/threadsafe.py` (also used by Plan B).

**Approach**
1. Create `tools/_common/threadsafe.py` with:
   - `BoundedDeque(maxlen: int)` — thin wrapper around `collections.deque(maxlen=maxlen)` with `append_safe()` and `snapshot() -> tuple` under an internal `threading.Lock`.
   - `SnapshotDict` — `dict` behind a lock with `get_snapshot() -> MappingProxyType`.
2. For each affected tool:
   - Replace the raw list/dict with the wrapper.
   - In every UI refresh path, call `snapshot()` once and iterate the tuple, not the live object.
   - Remove manual slice-cap code (deprecated by `maxlen`).
3. `system_health_monitor.py` has the most state — wrap `engine.samples`, `engine.alerts`, and the thresholds dict separately.

**Verification**
- Unit test: spawn two threads, one appending 10k items, one calling `snapshot()` in a tight loop. No exceptions, snapshot length monotonic.
- Manual: run each tool for 10 minutes with aggressive refresh; no `list changed size during iteration` / `RuntimeError` in logs.

**Effort** M (~4 h once `_common/threadsafe.py` exists).

---

### A6 — Claude Usage Monitor: fix peak-hours timezone mix-up  [S]

**Problem**  
`tools/claude_usage_monitor.py:1233–1240` compares `datetime.now().hour` (naive local) against a `peak_hours` set computed from timestamps that were `.astimezone()`-converted. Users in non-UTC timezones see OFF-PEAK when they're actually in peak, and vice versa. `_months_spanned()` (L1074–1083) has the same underlying "which clock?" confusion.

**Files**  
`tools/claude_usage_monitor.py`, `tests/test_claude_usage_monitor.py` (new).

**Approach**
1. Parse every timestamp once at load time (`_parse_timestamp`, L292) into a tz-aware `datetime` in UTC. Do **not** re-call `.astimezone()` downstream.
2. Build `peak_hours` by computing `.astimezone(LOCAL_TZ).hour` where `LOCAL_TZ = datetime.now().astimezone().tzinfo` (captured once).
3. Compare against `datetime.now().astimezone(LOCAL_TZ).hour`. Both sides now in the same local wall clock.
4. In `_months_spanned()`, use `(last_utc - first_utc).days` (tz-aware subtraction) rather than `.days` on whatever mix you started with.
5. While here: fix model prefix matching at L87–89 to use explicit version parsing instead of `rsplit("-", 1)[0]` (prevents `claude-opus-5` silently mapping to `claude-opus-4` pricing). Use a sorted-by-length-descending match.

**Verification**
- Unit tests covering the UTC→local roundtrip for UTC-5, UTC+0, UTC+5, and DST boundaries.
- Manual: on a non-UTC host, confirm peak-hours pill state matches the user's clock.

**Effort** S (~90 min).

---

## Ordering / dependencies

```
A5 (locks, depends on _common/threadsafe.py)  ──┐
A4 (subprocess, depends on _common/logging.py) ─┤
A1 (cleaner)                                    ├── independent, can parallelize
A2 (cpu temp)                                   ├── independent
A3 (screen lock)                                ├── independent
A6 (tz)                                         ──┘
```

Recommended single-threaded order if working alone:
1. **A2** — smallest, immediate user-visible win, builds confidence in the review process.
2. **A6** — also small, also immediate win.
3. **A5** — lands `_common/threadsafe.py` that Plan B reuses.
4. **A1** — biggest safety impact.
5. **A4** — largest architectural change; do after the above so fallout is contained.
6. **A3** — polish the safety/security feature last because it also touches `_common/` via config paths.

## Out of scope (→ Plan B)

- Type hint / docstring sweeps that aren't adjacent to a fix.
- `os.path` → `pathlib.Path` in files not touched here.
- UX polish beyond what each Tier-A fix demands.
- Refactoring monolithic App classes (FFmpeg `run_tool`, others).
- Test suites for tools not touched here.

## Definition of done

- All 6 tasks have merged commits on their respective branches.
- Each has its verification step executed and recorded in the PR body.
- `REVIEW.md §3 Tier A` items 1–6 check off.
