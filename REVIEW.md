# Automation Toolbox — Deep Multi-Lens Review

Date: 2026-04-15
Scope: 13 Python files in `tools/` + `Main.py` + `Launch.pyw` (~19,500 LOC of app code).
Lenses: brainstorming, code review, optimize, design-critique, design-review, tech-debt, simplify.

---

## 1. Executive Summary

The toolbox is **feature-rich and visually polished** but shares a consistent set of convention violations and latent correctness bugs across nearly every tool. Four issues stand out as *actually dangerous* and should be fixed before anything cosmetic:

1. **System Cleaner permanently deletes files** with no `--dry-run`, no recycle bin, no undo, and without symlink checks. One admin run in the wrong place = data loss.
2. **System Health Monitor CPU-temp formula is wrong** — users who actually have WMI thermal support will see values like 2708 °C and assume the whole tool is broken.
3. **Screen Lock has multiple bypass vectors** (Alt+Tab, Win key, Task Manager, external process kill) and *prints the unlock shortcut on screen*, defeating its own purpose as a kid-safe tool.
4. **Main.py launches tools via `importlib` in-process** — any `.py` file dropped in `tools/` runs with full interpreter privileges; a single crashing tool takes the whole launcher with it.

The rest of the findings are the usual suspects — type hints, docstrings, `os.path`, `except Exception: pass`, god-object App classes, missing `pathlib`, and no tests. They're worth a coordinated sweep rather than per-tool piecemeal fixes.

---

## 2. Cross-Cutting Patterns

| # | Pattern | Severity | Tools affected |
|---|---------|----------|----------------|
| 1 | Missing type hints on public functions | CLAUDE.md violation | **All 13** |
| 2 | Missing Google-style docstrings | CLAUDE.md violation | **All 13** |
| 3 | `os.path` used instead of `pathlib.Path` | CLAUDE.md violation | 12/13 |
| 4 | Bare `except Exception: pass` swallowing errors | High (debuggability) | **All 13** |
| 5 | No stderr logging; uses `print()` or silent except | CLAUDE.md violation | **All 13** |
| 6 | No pytest tests anywhere | CLAUDE.md violation | **All 13** |
| 7 | Hardcoded paths/config, no env vars | CLAUDE.md violation | **All 13** |
| 8 | God-object `App` class > 1000 lines | Maintainability | 7/13 (FFmpeg, Account, NetStability, NetIntrusion, SysHealth, SysCleaner, ClaudeUsage) |
| 9 | Shared mutable state across threads without locks | Correctness (races) | Account Activity, Network Intrusion, System Health, Folder Size, Network Stability |
| 10 | Rolling buffers implemented as list slices instead of `deque(maxlen=N)` | Perf (O(n) → O(1)) | NetStability, Account Activity, NetIntrusion |
| 11 | Hardcoded hex colors duplicated inline | Tech debt | Every GUI tool |
| 12 | Emoji-in-labels parsed back via regex | Fragile | FFmpeg Studio, others |
| 13 | No cancellation on long operations | UX | Folder Size, System Cleaner, System Health (large scans), Account Activity (log queries) |
| 14 | No config persistence between sessions | UX | FFmpeg Studio, Decision Dice, Folder Size, System Cleaner, Screen Lock |

---

## 3. Suite-Wide Priority Actions (Top 10)

Ordered by impact-to-effort. Tags: **[CRIT]** = data-loss/safety, **[BUG]** = user-visible bug, **[CONV]** = convention, **[DEBT]** = maintainability, **[PERF]** = performance.

### Tier A — fix now (user-visible or dangerous)

1. **[CRIT] Make System Cleaner safe** — add `--dry-run`, route deletions through `send2trash`, pre-check `os.path.islink()` before `shutil.rmtree()`, show category sizes in confirmation dialog, add Cancel button mid-scan. Lines: `system_cleaner.py:98, 100, 118, 762–765`. Effort: L.

2. **[BUG] Fix WMI CPU-temperature formula in System Health Monitor** — current code returns `(raw / 10.0) - 273.15` on values that are already in that scale, producing ~2708 °C. Validate against a known value and clamp to a sane range (0–110 °C). Lines: `system_health_monitor.py:339`. Effort: S.

3. **[BUG] Close Screen Lock bypass vectors + hide unlock hint** — intercept Alt+Tab / Alt+F4 / Win-key via low-level keyboard hook, loop overlays across all monitors (not just `+0+0`), remove the visible "Ctrl+Alt+U to unlock" label, add a panic-unlock fallback that works even if `keyboard` hook install failed silently. Lines: `screen_lock.py:427–468, 575–576, 455–457, 610`. Effort: L.

4. **[CRIT] Sandbox Main.py tool launches** — replace `importlib.util.spec_from_file_location` + `module.run_tool()` with `subprocess.Popen([sys.executable, "-m", "tools.<name>"])`. Add per-tool timeout, capture stderr to launcher log window, kill-on-close. Prevents one crashing tool from killing the launcher and isolates state leaks. Lines: `Main.py:283–296, 389–448`. Effort: L.

5. **[BUG] Fix thread-safety races on shared state** — wrap with `threading.Lock()`:
   - `network_intrusion_detector_pro.py:125` (`_ip_geo_cache`)
   - `account_activity_monitor.py:2262–2288` (`_live_events`)
   - `system_health_monitor.py:254, 398, 1255, 1376–1395` (engine samples / alerts / thresholds)
   - `folder_size_analyzer.py:354–373, 405` (`self.folders` iterated during rewrite)
   Or pass immutable snapshots via `queue.Queue`. Effort: M each, do together.

6. **[BUG] Fix Claude Usage Monitor peak-hours timezone mix-up** — `datetime.now().hour` (local) is being compared against a set derived from `astimezone()`-converted timestamps; can show OFF-PEAK when user is in PEAK. Normalize both sides to the same reference. Lines: `claude_usage_monitor.py:1074–1083, 1233–1240`. Effort: S.

### Tier B — convention sweep (should be one coordinated refactor)

7. **[CONV] Create `tools/_common/` module** with shared utilities instead of patching each tool:
   - `logger.py` — stderr logger + optional file handler
   - `paths.py` — pathlib-based path helpers, env-driven config dir
   - `admin.py` — cached `is_admin()`, privilege helpers
   - `subproc.py` — `safe_run()` with `CREATE_NO_WINDOW` + timeout
   - `threadsafe.py` — `BoundedDeque`, snapshot pattern
   - `ui/theme.py` — centralized color constants (`SEVERITY_COLORS`, `STATUS_COLORS`)
   - `ui/confirm.py` — destructive-op confirmation dialog with size summary
   Then rewrite each tool to use these instead of reinventing. Effort: M (one-time) + S per tool call-site. Pays back immediately.

8. **[CONV] Sweep: `os.path` → `pathlib.Path`, add type hints, add Google docstrings** — all tools, one PR per tool or a single scripted refactor. Effort: L aggregate, S per tool. Do this after #7 so the shared helpers land first.

9. **[CONV] Replace `except Exception: pass` with logged exceptions everywhere** — use the new `_common/logger.py`, keep exception types narrow (`FileNotFoundError`, `PermissionError`, `OSError`, `json.JSONDecodeError`, `subprocess.TimeoutExpired`, etc.). Effort: M aggregate.

### Tier C — performance / UX polish

10. **[PERF] Replace manual list slicing with `collections.deque(maxlen=N)`** for rolling buffers in Network Stability Monitor (`627–628, 622–623, 766`), Account Activity Monitor (`_live_events`), Network Intrusion Detector. Makes append O(1) and removes risk of accidental OOM on long-running monitoring sessions. Effort: S.

---

## 4. Per-Tool Deep Reviews

Each report below is the deep multi-lens analysis (code review / perf / UX / tech debt / simplify / ideas / top 5 actions).

---

## Main (Toolbox Launcher) + Launch.pyw

### What it does
700-line customtkinter launcher that discovers tools from `tools/` by dynamic `importlib`, renders a grid of cards with search/favorites, tracks single-instance tool windows, and shows system stats. `Launch.pyw` is the 35-line console-free entrypoint that redirects stderr to `toolbox_crash.log`.

### Code review (bugs, security, correctness, convention compliance)
- **Zero type hints** across all 30+ methods (`Main.py:46–700`). Convention violation.
- **Zero docstrings** except `load_tools` at `Main.py:267`. Convention violation.
- **`os.path` throughout** (`Main.py:16–18, 232, 274, 282, 651`). Should be `pathlib.Path`.
- **Hardcoded config**: `BASE_DIR`, `TOOL_FOLDER`, `FAVORITES_PATH` are module-level constants (`Main.py:16–18`), not env-driven.
- **`print()` to stdout for errors** (`Main.py:290`). Should be stderr via `logging`.
- **Launch.pyw leaks the crash-log file handle** — `sys.stderr = open(log_path, "w")` at `Launch.pyw:24` is never closed; no rotation.
- **Window-tracking race** (`Main.py:449–476`): `_track_new_window()` compares `self.winfo_children()` before/after launch, but a tool creating an independent `CTk()` root won't appear there. Line `466–468` calls `self.tk.call('winfo', 'children', '.')` and throws the result away. Tools can escape single-instance tracking.
- **Module reload leak** (`Main.py:283–296`): `exec_module` repeatedly executes modules without `sys.modules` cleanup; module-level state from prior loads persists as zombies.
- **Arbitrary code execution by design** (`Main.py:283–296`): any `.py` file in `tools/` runs in-process with no sandbox, no signing, no warning.
- **Path-traversal via tools dir** (`Main.py:277`): `os.listdir(TOOL_FOLDER)` doesn't filter symlinks; a symlink pointing outside the tools dir gets imported.
- **Favorite IDs are filenames** (`Main.py:310`). Rename a tool file → favorites break.
- **Tool-window refs never cleared** (`Main.py:395`): `_open_tools[filename]` accumulates until user reclicks the tool; closed windows leak.

### Performance
- **Stats loop runs forever** (`Main.py:612–622`) even post-close.
- **Recursive hover binds** (`Main.py:604–610`): `<Enter>/<Leave>` bound on every descendant of every card — hundreds of handlers. Bind on card frame only.
- **Full re-render on every search keystroke** (`Main.py:479–480`). Use hide/show, not destroy/recreate.

### UX / UI critique
- **Failed tools hidden behind troubleshooting button** — most users won't click it.
- **Single-instance focus is silent** — no feedback the click was intentional.
- **Tool windows don't inherit tool names** — taskbar can't disambiguate 10 open tools.
- **"No tools match your filters"** in gray 9pt is easy to miss.
- **Favorite star ☆/★ has no tooltip** explaining the filter.

### Tech debt
- 700 lines of intermixed concerns (discovery, loading, UI, window tracking, stats, favorites) in one class.
- Hardcoded colors scattered across `76, 94, 97, 100, 112, 537, 605, ...`.
- Three separate window-finding methods (`_find_tool_windows`, `_focus_tool_window`, `_track_new_window`) with duplicated logic.
- Raw `print()` for errors; no log rotation; `toolbox_crash.log` can grow unbounded.

### Simplify
- Dead no-op at `Main.py:466–468`.
- `_tool_window_titles` loop dedup (`343–350`) → `dict.fromkeys()`.
- `before_toplevels` captured at `430, 441` but unused downstream.
- Magic debounce numbers `200ms/300ms/100ms` at `225, 263, 573` — consolidate.

### Ideas
- **Subprocess isolation** (see Tier A #4).
- **`tools.yaml` manifest** instead of scanning `.py` files: metadata, icon, safety level, deps.
- **Lifecycle hooks** (`on_close`, `on_unload`) so tools clean up.
- **Crash recovery**: reopen previously-open tools on launch.
- **Dependencies preflight** before launching a tool (show "pip install ..." if missing).

### Top 5 prioritized actions
1. **Subprocess-isolate tool launches** — L. Covers safety + stability.
2. **Add type hints + Google docstrings across `Main.py`** — S.
3. **Replace `sys.stderr = open(...)` with `logging.FileHandler` + rotation** — M.
4. **Fix window-tracking + bind `<Destroy>` cleanup on tracked windows** — M.
5. **Split `load_tools()` into `discover_tools()` + `import_tool_module()`; move paths to env-driven `pathlib.Path`** — M.

---

## Network Stability Monitor

### What it does
Real-time Tkinter tool that pings gateway + two internet targets + DNS servers, classifies incidents by category/severity, exports data, and optionally runs WMI Wi-Fi analysis and an AI root-cause engine.

### Code review
- `os.path` throughout (L507, L534, L1219) — should be `pathlib.Path`.
- Broad `except Exception` + `print()` to stdout in `_do_sample` (L2290), intelligence analysis (L2425), DB ops (L574–576, L594–595). Silent failures.
- Daemon threads at L1285, L1776 — no shutdown join; `force_stop()` (L2014) just flips a flag.
- `queue.put_nowait()` at L2237 wrapped in bare except — dropped samples go unlogged.
- `_last_sample` (L1256) never cleared when monitoring stops → stale UI state.

### Performance
- Sample list (L627–628), event list (L622–623), signal history (L766): manual slice-cap → O(n) per append. Replace with `deque(maxlen=N)`.
- `ThreadPoolExecutor` rebuilt per sample (L2324) — reuse at module level.
- `refresh_incidents` iterates-then-reverses (L2641) — iterate `reversed()` directly.
- Intelligence root-cause probabilities recomputed on every refresh (L2520–2539) — cache on sample.

### UX / UI critique
- Top bar (L1299–1304) has 6 fields + 3 buttons → wraps on narrow window (min 800×500 at L1214).
- Treeview sort (L1518–1519) has no up/down arrow on the active column.
- "Initializing" status (L2463) never updates if first sample fails.
- Event/incident text widgets (L1594, L1603) use `state="disabled"` → users can't copy text.
- No empty-state message on incidents/events tabs.
- No input validation on ping targets (L1301) — garbage silently fails.

### Tech debt
- `App` is 2000+ lines (L1208+): UI, logic, data all mixed.
- Reason normalization (L854–857) hardcoded string matching → should normalize at classification time.
- Intelligence coupling: `Sample` has optional `root_cause`/`explanation`/`suspicion_level`; two parallel code paths through `enhance_sample_with_intelligence()` (L1097–1148).
- `generate_ai_export()` (L1150–1201) has two code paths based on whether intelligence is present.

### Simplify
- `wifi_bssid`, `wifi_channel`, `wifi_radio`, `wifi_signal_pct` (L403) duplicate `wifi_signal`/`wifi_state`/`wifi_ssid` — consolidate.
- Reason-normalization if/elif cascade (L843–857) → dict mapping or regex.
- Explanation dicts (L2700–2743) repeat identical structure — move to JSON/enum.
- `_wifi_auto_refresh()` (L2008) schedules itself via `self.after()` with no cancel on close → infinite chain if app doesn't stop cleanly.

### Ideas
- Multiple baseline profiles (home / office) auto-detected on network change.
- Bayesian confidence breakdown for root cause ("78% Router, 15% ISP, 7% other").
- Predictive alerting from latency trend curves.
- Multi-gateway / dual-WAN support.
- Wi-Fi roaming detection (distinguish legitimate BSSID change from evil twin).
- Jitter (RTT stddev) metric.

### Top 5 prioritized actions
1. **Replace `os.path` with `pathlib.Path`** (L507, L534, L1219) — S.
2. **Split `App` into UI panels + engine; cap at ~600 lines each** — M.
3. **Use `collections.deque(maxlen=N)`** for sample / event / signal buffers (L627–628, L622–623, L766) — S.
4. **Add stderr logging; remove silent excepts in worker loop** (L1170, L2290, L2425) — M.
5. **Fix UI polish: sort arrows, empty-state messages, ping target validation** (L1518, L1301) — M.

---

## Network Intrusion Detector

### What it does
Tkinter/customtkinter tool for Windows that ARP-scans the LAN, passively sniffs packets (scapy), classifies outbound connections on a 5-level scale, detects Tor/Flipper/BadUSB, and pulls reputation data from VirusTotal + AbuseIPDB. Tabs: Devices, Connections, Alerts, Threats, History, Trust List.

### Code review
- Missing Google docstrings on public methods: `classify_connection` (L329), `check_ip` (L493), `snapshot_outbound` (L1087), `discover_devices` (L1019).
- `os.path` 10× (L367, L1413–1414, L1986–1988) — should be `pathlib.Path`.
- Bare `except Exception: pass` at L410, L462, L488, etc. Silent.
- **Global `_ip_geo_cache` (L125) is NOT locked** — concurrent `get_ip_geolocation()` races (L245–274). Cache cleared entirely at 2000 entries (L251) — no LRU.
- Firewall `netsh` call (L576–587) interpolates IP without quoting. Safe today (list subprocess) but fragile.
- `ABUSE_MAX_PER_DAY` (L391) resets per session (L435–437), not persisted.
- API keys in plaintext JSON (L367). No env-var config.
- `_ui_tick()` (L2790) calls `scan_now()` every 1–3.5 s on UI thread — heavy scans (ARP, process enum, geo lookups).

### Performance
- `snapshot_outbound()` (L1087) calls `psutil.Process()` per connection (L1103), no cache.
- `requests.get()` with 3 s timeout per IP in geolocation (L254) → 500 IPs × 3 s worst case = 25 min blocking.
- Reputation check at 3 IPs per cycle (L1185) is correctly rate-limited but synchronous.
- Threat-level timestamp parsing every UI tick (L1522, L1527–1529) via `time.mktime(time.strptime(...))` — slow.

### UX / UI critique
- Admin banner silent if not admin + sniff enabled → user assumes it works (L1451).
- Scapy missing → "Passive sniff" checkbox shown but does nothing (L1441). Disable the checkbox instead.
- Tab name detection via string equality `"Devices"` (L2860) — fragile to label changes.
- Double-click on Connection uses unstable index `int(iid.split("-")[1])` (L2214, L2225) → opens wrong row after filter.

### Tech debt
- No tests.
- `wmic` calls (L1224, L1278) are slow and deprecated — use `psutil` or `winreg`.
- File watcher (`file_observer`) not always stopped on exit (L1430).
- `sniff_thread` stopped but never `.join()`-ed (L2447–2448).
- Duplicate trust logic: MAC (L994–1008) vs IP (L621–629).

### Simplify
- `extract_remote_ip()` (L315) never used.
- `analyze_device_behavior()` (L802) computes `ip_history` that isn't used.
- `REP_*` constants (L370–382) → `StrEnum`.

### Ideas
- Async (asyncio) replace `time.sleep` loops.
- Persistent reputation cache (SQLite).
- Probabilistic threat score (0–100), not 5 buckets.
- MaxMind GeoIP2 offline fallback.
- CLI mode (`--scan-once`, `--check-ip`).
- Webhook alerting (Slack/Discord/HTTP).

### Top 5 prioritized actions
1. **Stderr logging in all excepts** — S.
2. **Lock `_ip_geo_cache`** (L125) — M.
3. **`os.path` → `pathlib.Path`** (L367, L1413–1414, L1986–1988, L596) — M.
4. **Google docstrings on public functions** — M.
5. **Move `scan_now()` off UI tick to longer interval (10–60 s), or manual-only** — L.

---

## Account Activity Monitor

### What it does
Tracks Windows event logs (accounts, logons, devices, system changes, security policy, software installs) via historical (24h) query + live stream. Includes "spy check" for camera/mic history, RDP/remote tools, suspicious tasks, log tampering.

### Code review
- Missing type hints on `_worker_loop` (L2211), `_process_queue` (L2241), `_populate_tree` (L1801).
- Missing `-> None` on `_toggle_category` (L1369), `_toggle_severity` (L1382).
- Bare `except Exception: pass` at L404–405, L460–461, L2238–2239, L2289–2290. Silent.
- **Race condition in live monitor** (L2262): `_live_events = new_events + _live_events` from worker thread while UI iterates `_populate_tree` (L1807–1823). Needs a lock.
- Live event list capped at 5000 (L2264–2288) — but only when a queue result arrives. Paused polling = unbounded growth.
- Timestamp aggregation (L330–341) loses microsecond precision and is timezone-naive.
- Admin check not cached: called at L287, L1306, L1581, L2298 (despite `__init__` cache at L229).
- Event XML namespace hardcoded twice (L397, L664). If MS changes namespace, parser silently returns nothing.
- Hardcoded user whitelist `"christophoros", "chrpa"` (L995). Make env var.
- `wevtutil` query cap `/c:500` (L382) hardcoded.

### Performance
- **O(n²) event aggregation** (L312–365): every event pair within 5 min. Sort by ID+time then scan.
- Full tree redraw on every filter toggle (L2256 → L1805). Use tree tags to hide/show.
- Spy check not debounced (L762) — 3 rapid clicks = 3 sequential runs.
- `+=` string concat in detail builder (L1106–1111) — use list + `"".join()`.
- `ET.tostring(event_elem)` on every event (L438) — 50k strings held in memory after 24h.

### UX / UI critique
- Admin banner (L1309–1311) is 130+ chars, wraps on 900px min width. Orange on dark bg → WCAG AA contrast risk.
- No loading indicator during long event-log query (L1782–1792).
- Treeview columns not resizable; event text truncated at 200 chars (L1819) with no "…".
- Detail popup hardcoded `"700x550"` (L1867); wraplength 600 (L1892, L1938) wastes space on 4K.
- Zero keyboard shortcuts (no Ctrl+F, Ctrl+E).

### Tech debt
- Dual `customtkinter`-or-Tkinter fallback (L23–27, L1246) doubles widget code paths.
- `EVENT_DEFS` (L80–143) hardcoded — move to JSON config.
- Color constants (L49–64, L152–158, L543–548, L1355–1365) scattered.
- Filter logic duplicated in `_populate_tree` (L1808–1815) vs `_process_queue` (L2272–2279). Extract `_match_filters()`.

### Simplify
- `ParsedEvent` stores both `timestamp` and `timestamp_raw` (L206–217). Keep one.
- 50+ findings dicts across spy check — convert to `@dataclass Finding`.
- Event-data extraction via `.split("\\")[-1]`, `.split(":")[-1]` (L532, L541, L589, L1179) — use `pathlib.PureWindowsPath`.

### Ideas
- CSV export (current is JSON only).
- Alert rules engine: "3+ failed logons from same IP in 10 min → webhook/sound".
- Auto-refresh interval slider (currently 5 s hardcoded at L2266).
- Dark/light mode tied to Windows setting.
- Inline notes on events (SQLite sidecar).
- Hourly event-rate heatmap.

### Top 5 prioritized actions
1. **Lock `_live_events` access** — M.
2. **Cache admin check; narrow excepts; log to stderr** — S.
3. **Extract `_match_filters()` shared function** — S.
4. **Fix timestamp aggregation with tz-aware `datetime` + microseconds** — S.
5. **Load `EVENT_DEFS` + user whitelist from config file / env vars** — M.

---

## FFmpeg Studio

### What it does
customtkinter Record / Capture / Convert GUI. Detects GPU (NVENC/AMF/QSV) with real micro-encodes (not just parser-based), handles color-range correction, offers preset bundles for streaming/archival.

### Code review
- **Zero type hints** across L140–332, L369–1711. Convention violation.
- **Only `_probe_hardware()` has a docstring** (L189–195). Others missing.
- **No `pathlib.Path`** — all I/O via `os.path.*` (L350, L372, L542, L593, L900, L1294, L1437, L1541, L1548, L1549, L1570).
- Audio device names (L268, L431) interpolated into FFmpeg args without validation — safe via list-style Popen but could break on exotic device names.
- `_verify_startup()` has no Popen timeout (L550–572, L579) — infinite hang if FFmpeg wedges.
- Temp screenshot files (L1041) relied on OS purge; not explicitly cleaned.
- **GPU detection via actual 0.1 s test encode is excellent** (L175–187) — catches broken drivers.
- **Color-range handling is right** (L434–446): declares `in_range=full` for gdigrab; comment explains why crushed blacks would happen otherwise.
- **Fatal-conflict auto-fix is correct** (L105–128, L516) — prevents 0-byte recordings.

### Performance
- GPU probe ≈1–2 s on startup — acceptable.
- No frame buffering in Python; FFmpeg does the work. ~10 MB RSS.

### UX / UI critique
- Optional (non-fatal) conflict warnings (L535–539) can still lead to 0-byte files if user clicks through. Auto-fix like the fatal path.
- GPU labels (L214, L227, L243) are human strings regex-parsed back (L276). Fragile. Use tuples.
- No recording-startup progress (L577) — feels frozen 2.5 s during `_verify_startup()` sleep.

### Tech debt
- **Monolithic `run_tool()` — 1350+ lines, 10 nested closures each capturing 20+ outer variables** (L335–1717). Testability: 0. Must become a class.
- Capture command building (L424–467) and conversion command building (L1478–1523) duplicate color/scale logic — extract `_build_scale_and_color_args()`.
- No config persistence — settings reset every session.
- `messagebox` shows raw exception strings (L564, L1575); full traceback should go to stderr.

### Simplify
- `SPEED_OPTIONS` (L75–80) and `ENCODER_MAP` (L82–87) partially duplicate each other.
- `_chroma_depth_keys` (L288–293) parses UI labels via `"4:2:2" in label` — store tuples directly.
- `TOOL_NAME` / `TOOL_DESC` (L20–21) unused after init.
- `CRF_LABELS` / `CROP_PRESETS` / `CONV_RESOLUTIONS` scattered → one `CONFIG` dict.

### Ideas
- Auto-fix all unsupported combos with a toast (drop the user prompts for non-fatal cases).
- Config persistence at `~/.ffmpeg_studio_config.json`.
- Live bitrate/ETA via `-progress pipe:1`.
- Drag-and-drop batch conversion queue.
- In-app screenshot preview before save.
- GPU VRAM check for 4K60 recording (warn if < 2 GB).
- Keyboard shortcuts (Ctrl+R, Ctrl+S, Ctrl+C).

### Top 5 prioritized actions
1. **Type hints on all functions (75 fixes)** — S.
2. **`os.path` → `pathlib.Path`** — S.
3. **Extract shared color/scale arg builder** (L441–446 vs L1483–1488) — M.
4. **Google docstrings on `_probe_hardware`, `_detect_audio_devices`, `_build_cmd`, `_build_conv_cmd`, `run_tool`** — M.
5. **Refactor `run_tool()` into `FFmpegStudio(ctk.CTkToplevel)` class** — L.

---

## Claude Usage Monitor

### What it does
Live Tkinter dashboard tracking Claude Code session cost / tokens / waste. Parses JSONL session logs under `~/.claude/projects/`, applies Apr-2026 pricing, computes a "Rotate Now" score, renders peak-hours + model/tool breakdowns, auto-refreshes every 30 s.

### Code review
- **Bare `except Exception: pass`** at L282 swallows JSONL file-I/O errors (permission, encoding, disk). No log.
- `errors="replace"` on read (L179) silently corrupts JSON at bad bytes.
- Tool-result matching (L226–232) assumes ordering; no file lock.
- `run_tool()` (L1610) has no `-> None`; `_get_pricing()` returns bare `dict`.
- `load_all_sessions()`, `_get_active_session_ids()` — semi-public, no Google docstrings.
- **Timezone mix-up in peak hours** (L1233–1240): `datetime.now().hour` (local) compared against peak set derived from `astimezone()`-converted timestamps. User in UTC+5 sees OFF-PEAK when actually in PEAK.
- `_months_spanned()` (L1074–1083) uses `(last - first).days` assuming both tz-aware — no DST-safety.
- Model-pricing prefix match (L87–89) via `startswith(key.rsplit("-", 1)[0])`: a future `claude-opus-5` silently matches `claude-opus-4` key.
- Glob over `*.jsonl` (L584) can hit an actively-written file mid-turn.
- `_sessions` + `turn_costs` never pruned (L624–625, L170) — memory growth.

### Performance
- `rows.sort()` inside `_render_sessions()` (L1368) fires on every search keystroke (via `trace_add` L827). O(n²) re-sort on 500 sessions.
- `_parse_timestamp()` called 2–3× per session (L1074–1078, L1329, L1551) — memoize.
- `_draw_chart()` redraws 100+ points on every detail re-open (L1562–1603) — memoize by session id.
- `ttk.Style` reconfigured inside `_build_sessions_tab()` — move to `__init__` (L838–846).

### UX / UI critique
- Peak-hours pill can flip OFF when it should be ON (see tz bug).
- No load-failure feedback (L578–579) — silent empty state.
- Session name truncation (L144–145) drops last word on overflow.
- Unmatched tool_result silently shows zero tool cost — add warning.

### Tech debt
- Unused imports: `time` (L11), `glob` (L9), `os` (L7).
- Magic numbers: `_COLD_INPUT_MIN = 2000` (L54), `_TOOL_CHARS_PER_TOKEN = 4` (L69), `_ROTATE_RED = 60`, `_ROTATE_AMBER = 30` (L65–66), `30_000` (L1039, L1044) — document or constify.
- Plan pricing split across UI (L660–665) + `_plan_monthly_cost()` (L1062–1067) — unify.
- `turn_costs` is a tuple accessed by positional index (L546–549) — use `TypedDict` or `dataclass`.

### Simplify
- `models_used` starts as `set`, converted to `list` at end (L171, L239, L288) — pick one.
- Duplicate window_eff function (L378–382 vs L497–501).
- `_get_pricing(model)` called twice per assistant block (L255, L264) — compute once.

### Ideas
- `watchdog` file watcher instead of 30 s poll.
- SQLite cache (`.claude/session_cache.db`) — cut startup from ~2 s to ~100 ms on 100+ sessions.
- Per-week / per-month cost graphs.
- "Why ROTATE NOW?" expanded breakdown of all 5 subscores.
- CSV export via tree-row context menu.
- Configurable refresh (env `CLAUDE_MONITOR_REFRESH_SECONDS`).
- Session diff view ("was my refactor cheaper?").

### Top 5 prioritized actions
1. **Remove bare excepts; log to stderr with file/line context** (L282, L297, L411, L608, L1051) — S.
2. **Type hints + docstrings on public funcs** — S.
3. **Fix tz handling in `_months_spanned()` + peak-hours pill** (L1074–1083, L1233–1240) — M.
4. **Skip `.tmp` files; validate `first ≤ last`; use session metadata as truth** — M.
5. **LRU/time-based prune of old sessions + lazy-load detail `turn_costs`** — L.

---

## Security Audit

### What it does
10-category Windows security scanner: startup/persistence, process analysis, ports/firewall, file system, DNS, accounts, Wi-Fi, USB/hardware, browser cert store, event logs. Baseline comparison + JSON export. ~4-worker concurrent check pool.

### Code review
- 5 public UI methods missing `-> None` (L1303–1439).
- `Finding` dataclass + all 10 `check_*` methods lack docstrings.
- `os.path` 6× (L287–292, L579, L1287, L1792) — `pathlib`.
- **Registry handle leaks on exception paths**: `winreg.OpenKey()` + `CloseKey()` not paired via context manager at L252–267 (startup), L980–1013 (USB), L1170–1185 (browser), L743–761 (DNS). If `EnumValue()` raises, the handle leaks.
- `open(filepath, "w")` at L1811 is correct (uses `with`) but `_load_state()` at L186 does not.
- No `argparse` / `--dry-run` yet — tool currently doesn't mutate, but remediation text says "Remove / Delete / Disable" → if auto-apply lands, this becomes critical.
- UAC not elevated; non-admin silently skips Security event log (L1212, L1264–1268). Acceptable but limits checks.
- Windows-only by design; graceful import fallbacks (L16–30) are good.

### Performance
- `psutil.net_connections('inet')` called twice if IPv4+IPv6 (L449–464) — minor.
- `os.walk` in file-system check bounded to depth 3 (L587–591); runs on worker thread so UI stays responsive.
- PowerShell cert dump (L1094–1099) returns 100+ entries unfiltered.
- UI renders all findings as labels (L1426–1432, L1738–1750) — could freeze at 1000+ findings (typical < 500).

### UX / UI critique
- No copy-to-clipboard on finding cards (L1669–1706).
- No search box across findings.
- Export is JSON only — add CSV / Markdown.
- "ISSUES FOUND" (L1559–1570) is vague — add 0–10 risk score.
- "Changed since last scan" filter only on Baseline tab — offer on Details too.

### Tech debt
- Regex recompiled per scan (L567, L890, L1029, L1106) — move to module level.
- Color codes repeated across L1310, L1597, L1663, L1744 — `SEVERITY_COLORS` constant.
- `SAFE_PROCESS_PATHS` (L68–71) overlaps inline lists at L531–532, L1032–1034.
- `csv.DictReader` on `schtasks` output (L327–350) fragile to malformed rows.
- Event-log counting via `<Event` / `EventID` substring match (L1227–1230) — parse `/f:xml` instead.
- Magic thresholds (L305, L405, L1202–1206) undocumented.

### Simplify
- `if not changed: pass` (L1582) — remove.
- `Finding.key()` (L95–97) re-implemented inline at L1757–1759 — call the method.
- Key-value parsers at L812–824 (accounts) and L906–908 (Wi-Fi) duplicate — extract `parse_key_value()`.
- Severity color maps redefined 3× (L1413, L1663, L1744).

### Ideas
- Severity-weighted 0–10 risk score.
- Opt-in "Auto-fix" for safe remedies (UAC + dry-run).
- Historical trend graphs over days/weeks.
- Side-by-side diff of two baselines.
- "Mark as safe" whitelist for recurring false positives.
- Scheduled scans UI.
- Merge duplicate findings across checks (RDP appears in Ports and Settings).

### Top 5 prioritized actions
1. **Fix registry handle leaks** (L252–267, L980–1013, L1170–1185, L743–761) — M.
2. **Add `-> None` + Google docstrings on UI and `check_*` methods** — M.
3. **`os.path` → `pathlib.Path`** (L287–292, L1287–1288, L1792) — S.
4. **Move regex patterns to module-level constants** — S.
5. **Consolidate color and threshold constants** — S.

---

## System Health Monitor

### What it does
6-tab Tkinter dashboard: Overview (CPU/RAM/disk/GPU live charts), Processes, Disk (I/O, large files, temp scanner), Startup (registry manager), Alerts (thresholds), Settings. Uses `psutil`, `nvidia-smi`, PowerShell (LibreHardwareMonitor) for CPU temp.

### Code review
- No `pathlib` — L476, L533, L555, L566, L589, L592, L1028–1033, L1118.
- Docstrings missing on Engine (L149–632) and all UI builders (L638–1498).
- **Thread-safety races** on shared state:
  - `engine.samples` appended by worker (L253), read by UI (`_update_chart`, L1400), truncated at L255. Needs lock.
  - `engine.alerts` appended by worker (`check_alerts`, L398), cleared by UI (`_clear_alerts`, L1203).
  - Thresholds read in `_update_active_alerts` while written by `_apply_thresholds` (L1197).
- `scan_large_files` + large OS walks run on worker thread but block sample collection.
- **Broken CPU% normalization** (L418–419): `min(raw_cpu / cpu_count * 100, 100)` — on an 8-core with raw=150%, yields 1875% → capped to 100. Wrong algebra; either `min(raw_cpu / cpu_count, 100) * 100` or cap raw directly.
- Double `psutil.cpu_percent()` call (L193–194) — first result discarded. Wasted syscall.
- **WMI CPU temp formula wrong** (L339): comment says "tenths of Kelvin" but `raw / 10 - 273.15` on a value that's already in that range gives ~2708 °C. Validate against a known temp.
- `cpu_count` division at L419 has no `or 1` guard (only L406 does).
- Process list capped silently at 500 (L888) — no UI indicator.
- GPU nvidia-smi timeout 3 s (L263–266); if GPU is absent, worker blocks every 2 s. Add exponential backoff.
- PowerShell filter strings hardcoded now (L311–319); if user-supplied later, injection risk.
- Disabled-startup JSON written to source dir (L538–545) — should be `%APPDATA%`.
- `ctk` + raw `tk.Spinbox` mixed (L807, L1163–1166) — theming mismatch.
- Bare excepts: L109, L216, L226, L236, L249, L276, L324, L342, L629, L1283, L1296, L1317, L1496. Worst at L1283 (worker loop): job lost silently.

### Performance
- Wasted `cpu_percent()` at L193 — drop.
- `disk_partitions()` every 2 s (L204–215) — cache with TTL on slow network mounts.
- GPU polling with 3 s timeout in the worker tick — exponential backoff after repeated failure.
- `scan_large_files` full walk on worker blocks samples (L549–578).
- `get_temp_sizes` iterates 100k+ files in %TEMP% with no timeout (L580–613).
- `get_processes()` every 6 s when tab visible — acceptable.
- Good: sample cap 1800 (L152), alert cooldown 60 s (L170), process cap 500 (L888).

### UX / UI critique
- "N/A" / "--" for GPU/CPU temp (L329–330, L1344) has no reason — show "no nvidia-smi".
- Drive-letter case hack (L1338) via dual check — normalize with `.upper()`.
- Startup command truncated to 200 chars (L1090) with no tooltip.
- `cmd.split('"')[0]` (L1117) breaks on unquoted paths with spaces — use `shlex.split`.
- Thresholds: user can set warn > crit. Validate.
- Chart title "Last 5 Minutes" (L756) doesn't update when window changes (L1243–1245).

### Tech debt
- 1534 lines, App class 860 of them. Split `app.py` / `engine.py` / `ui.py` / `models.py`.
- Three temp-probe strategies (Ohm / WMI / none) scattered — consolidate `TemperatureProbe`.
- Magic thresholds scattered L173–181.
- Hardcoded disabled-startup path in source tree.

### Simplify
- `color_pct` (L78–83) duplicated inline at L1341–1342.
- Alert-refresh logic at L404–431 + L1292–1295 coupled via tab-visibility check — prefer tab-change callback.
- Chart legend redrawn per frame (L1456–1463) — cache.
- Alert-level tag names ("CRITICAL"/"WARNING") as strings — no typo validation before `tree.insert(..., tags=(level,))`.
- Manual clipboard: `clipboard_clear()` + `clipboard_append()` (L929–930) — use `clipboard_append(..., clear=True)` or helper.

### Ideas
- Thread-safe state via dataclass snapshots on queue.
- Config file / env for thresholds, refresh, startup blacklist.
- Log temp-probe success/fail to `%TEMP%\system_health_monitor.log`.
- Async temp/GPU probes via `ThreadPoolExecutor` with timeouts.
- Battery health via `psutil.sensors_battery()`.
- CSV export of samples/alerts.
- Custom alert actions ("if GPU > X for Y s, run Z").

### Top 5 prioritized actions
1. **Fix WMI CPU temp formula** (L339) — **S, but user-visible**.
2. **Lock engine state (samples, alerts, thresholds)** — M.
3. **`os.path` → `pathlib.Path`** — M.
4. **Narrow excepts + stderr logging** — M.
5. **Google docstrings on Engine + App methods** — M.

---

## System Cleaner

### What it does
Tkinter GUI that frees disk (temp, caches, browser, Recycle Bin), optimizes RAM (working-set trim + standby purge), and offers an Explorer restart to unlock caches. Admin-gated operations.

### Code review
- No type hints on L377–1162 (all App methods).
- No docstrings on `App` (L375) or `run_tool()` (L1167) — convention violation.
- `os.path` + raw strings (L241, L268, L278) — `pathlib` would be cleaner; `expandvars("%TEMP%")` (L232) is the right pattern.
- **Critical: permanent deletion with one confirm dialog**. `shutil.rmtree(full, ignore_errors=True)` (L98) swallows ALL errors — can't distinguish locked vs denied vs "oops wrong path". No Recycle Bin routing; `send2trash` would make operations reversible.
- **No `--dry-run`** despite CLAUDE.md rule for destructive ops.
- **No symlink check** before `shutil.rmtree` (L98). On admin runs, a link could lead deletion to its target outside the intended dir.
- Race between scan + delete (L694–729 → L755): user checks boxes based on stale size; `_clean_selected()` doesn't rescan.
- `skipped += 1` (L102) with no per-file detail — you learn a number, not which files.
- Recycle Bin size (L809) queried then immediately wiped (L811) — bin could change between check and empty.
- Windows-only, will crash on import on other OSes (no guard at L18).
- `%TEMP%` unset corner case (L232) → empty path → `os.walk` returns 0 silently.
- No timeout on `os.walk` of `%TEMP%` (L74–79) — slow network share locks the UI-adjacent scan loop.

### Performance
- `_scan_worker()` (L694) single-threads per-dir — parallelize with `ThreadPoolExecutor`.
- `_run_category_clean()` ignores cached sizes from scan (L736); recalculates in `_delete_dir_contents()` (L96–97).
- `psutil.process_iter()` at L969 loops 500+ processes to trim working sets — OK for manual but no progress feedback.

### UX / UI critique
- **Confirm dialog shows category names only, not sizes or paths** (L762–765). Users don't know they're about to wipe 10 GB vs 10 MB.
- **No undo, no trash, no rollback**.
- **No Cancel during cleaning** (L770 disables button but provides no abort).
- "Admin: NO (some items disabled)" label (L425) implies everything is blocked.
- RAM optimization label empty if freed exactly 0 (L998–1001).
- No progress bar during cleaning.

### Tech debt
- 800-line App class. Split `Scanner` / `Cleaner` / `UI` / `RAMOptimizer`.
- `CATEGORIES` list (L227–367) hardcoded — move to config.
- Windows-specific `ctypes` for privileges (L180–221) not abstracted for reuse.
- `_SHQUERYRBINFO` struct (L43–48) shared-worthy.
- No stderr logging.
- No `argparse` — tool can't be scripted.

### Simplify
- Size-label coloring duplicated (L734, L746) — extract `_format_size_label(size) -> (text, color)`.
- GPU-vendor detection inline (L835–837) — helper `_detect_gpu_vendor(path)`.
- Uptime label recomputed every 30 s (L640–655) even when text is unchanged — update on-demand.
- `_enable_privilege()` return (L1028) ignored — should log failure.
- `os.path.isdir(path)` checked twice (L87 + L723).

### Ideas
- `send2trash` integration with 30-day rollback folder.
- `--dry-run` preview button.
- Scheduled cleanup (daily/weekly subprocess with log).
- Config file for categories + custom paths.
- Error log (skipped file details) at `%TEMP%\cleaner_errors.log`.
- Parallel scan via `ThreadPoolExecutor` (cut scan time ~3× on typical systems).

### Top 5 prioritized actions
1. **[CRIT] `--dry-run` + `send2trash` + symlink check** (L98, L100, L118) — L.
2. **Symlink traversal block** (add `os.path.islink` guard in `_delete_dir_contents`) — S.
3. **Type hints + Google docstrings across the file** — M.
4. **`logging` module + `--debug` flag** — M.
5. **Parallel directory scanning** in `_scan_worker` (L695) — L.

---

## Decision Dice

### What it does
Weighted RNG decision-maker with 4-outcome custom profiles (0–100% weights), persistent JSON journal, 3D animated cube (specular + particles), streak detection, sound effects.

### Code review
- **`build_pool()` is O(total_weight) and silently falls back on all-zero weights** (L103–106, L821–822). Use `random.choices()` with `weights=` (O(1), proper error surface).
- `os.path` for state (L30–32, L111–144) — `pathlib`.
- Type hints missing on helpers `hex_to_rgb` (L91), `rgb_to_hex` (L95), `lerp_color` (L98), `build_pool` (L103), `App.__init__` (L443), `Particle.__init__` (L344), all `spawn_*` (L358–437).
- Bare excepts at L116, L124, L136, L144, L1108 — silent load/save failures.
- No docstrings on any public helper; no class docstring on `App` (L443).
- Default-dict lookup pattern duplicated across `_open_journal` (L769–774) and `_check_streak` (L1001–1003).
- `json.load` with no schema/version (L114–115, L133–134).
- Journal save slice `[-500:]` (L142) — should be constant / env.
- Particle list mutation during animate loop (L1067–1068) — fragile (single-threaded Tk saves it today).

### Performance
- 16 ms frame tick (L874) + 20 ms particle tick (L1068) — fine.
- `build_pool` duplicates outcome dicts `weight` times → memory O(total_weight). Not a bottleneck at 400 entries but unnecessary.
- Glow ring redraws 5 concentric ovals per frame (L199–213) — cache as image.
- `_check_streak` reverses whole journal every roll (L992–997) — store `last_outcome`.
- History chip widgets destroyed/recreated every roll (L1072–1087) — rotate in place.

### UX / UI critique
- Profile editor slider label "Total must be 100!" (L712–729) doesn't explain normalization. Let users leave gaps, auto-normalize.
- Streak label math is correct but confusing: "🔥 3x YES streak! (9.1% chance)" — is that chance-of-next-YES or rarity-of-streak?
- No counts-per-profile or date filter in journal (L765–790).
- Question text truncated by char count (`q[:50]` L785) instead of measured width.
- Sound toggle button has icon only, no label.

### Tech debt
- `Particle` + `Dice3D` should be `@dataclass(slots=True)` (L341–356, L150–170).
- Magic numbers scattered (perspective `d = 600` at L184, specular exponent 32 at L276, `1 - (1 - t) ** 3` easing at L842, `roll_duration = 2.0` at L453).
- `DEFAULT_OUTCOMES` / `DEFAULT_PROFILES` hardcoded (L69–86).
- No tests.
- `requirements.txt` pin missing for `customtkinter` (noted only in docstring L12).

### Simplify
- Duplicate outcome-lookup (L755–774 vs L1001–1003) → `get_outcome_by_label`.
- `shake_offset_x/y` declared (L457–458) but never used — dead.
- `current_outcome` (L454) stored but only used immediately in `_finish_roll` (L880–890) — pass as param.

### Ideas
- `random.choices()` migration.
- Outcomes from JSON config (custom outcomes, rename, recolor).
- CSV/PDF export of journal.
- Undo/redo last decision.
- Pie-chart profile preview instead of bar.
- Keyboard shortcuts (Ctrl+R = roll, Ctrl+J = journal).
- Personal-record streaks per outcome.
- "Chaos Mode" randomized weights summing to 100%.

### Top 5 prioritized actions
1. **Replace `build_pool` + `random.choice` with `random.choices(..., weights=...)`** (L103–106, L821–822) — S.
2. **`pathlib.Path` + logged I/O failures** (L30–32, L111–144) — M.
3. **Type hints across helpers + App + spawns** — M.
4. **Extract `get_outcome_by_label` helper + add docstrings** — M.
5. **Add pytest tests** (`test_build_pool_distribution`, `test_save_load_journal`, `test_streak_detection`, `test_hex_rgb_roundtrip`) — L.

---

## Screen Lock

### What it does
Full-screen transparent overlay that blocks keyboard/mouse for kid-safe use. Educational popup cards per keypress (emoji, letter, word) with physics. Opacity slider, optional ESC unlock, mandatory Ctrl+Alt+U unlock.

### Code review
- Most methods lack type hints (`_on_alpha_change`, `lock`, `unlock`, `_show_overlay`, `_raise_hud`, `_tick_clock`, `_hide_overlay`, `_spawn_card`, `_on_click`, `_install_hook`, `_remove_hook`, `cleanup`, `run_tool`).
- No docstrings on `run_tool` (L651), `lock`, `unlock`, `cleanup`.
- **Critical bypass vectors**:
  - Alt+Tab not blocked (L447–448) — child can switch away.
  - Alt+F4 not blocked (L427–434).
  - Win key not blocked; L610 explicitly skips it.
  - Task Manager (Ctrl+Shift+Esc) not blocked; overlay `grab_set_global()` doesn't stop `taskkill`.
  - If process is killed, overlay orphans (no persistent lock state).
- **`keyboard` hook needs admin on some Windows versions**; if `hook()` fails silently at L575–576, user thinks they're locked but aren't.
- **Unlock shortcut printed on screen** (L455–457) — defeats the kid-safe goal.
- **ESC unlock opt-in checkbox visible in UI** (L380–382) — kid tests it.
- **Multi-monitor unsupported** — `+0+0` geometry (L429) covers primary only.
- Circular refs in `_peers` list (L108, L548) — each card references all siblings; an exception in `_tick` prevents pruning.
- No validation on `_find_spawn` (L300) — negative `sw/sh` crashes `random.randint`.
- `run_tool` exception handler (L674) calls `root.destroy()` but `root` may not be bound if init raised.

### Performance
- 62 FPS cap (L76 `FPS_MS = 16`) — fine.
- Card cap 10 (L89 `MAX_CARDS = 10`) — fine.
- Repulsion O(n²) (L152–161) — fine at 10 cards.
- Full `Canvas.delete()` + `create_*()` per frame (L196, L211–216, L225–240) — could use `coords()` to move shapes.

### UX / UI critique
- Opacity slider good (L371–375).
- Shortcut label visible → remove or hide behind parent-only panel.
- ESC-unlock checkbox exposed → remove or gate.
- Clock overlay is a nice touch (L490–494).
- **No panic unlock fallback** — if hook fails or shortcut gets eaten, parent must task-kill.

### Tech debt
- No logging (hook install/remove, unlock triggered, canvas destroyed).
- Hardcoded fonts ("Segoe UI Emoji", "Arial Rounded MT Bold") at L227, L232, L239 — no fallback.
- Unlock shortcut hardcoded at L600 — make configurable.
- No config persistence (opacity, ESC-unlock toggle, shortcut).
- No tests.
- `_norm()` and `_handler()` defined inside `_install_hook()` (L582–620) — hard to unit-test; extract to module level.
- Magic easing math `1 - (1 - t) ** 3` (L125), `(1 - (2*t - 1) ** 2)` (L274) with no comment.

### Simplify
- Canvas-existence try/except pattern repeated at L137–142, L265–271, L486–489, L516–520, L558–562 → `_canvas_alive()` helper.
- Peer-pruning logic duplicated at L523 and L565 → `_maintain_peers()`.
- Exception suppression at L500–508, L626–630, L671–673 → context manager.
- `REPULSE_R = CARD_W * 0.95` (L86) redundant — compute on first use.

### Ideas
- Panic unlock button revealed on long-press of Ctrl+Alt+U.
- Multi-monitor: loop `Tk.wm_attributes("-fullscreen", True)` across all screens.
- Persist lock state to JSON for crash recovery.
- Configurable unlock shortcut.
- Block Alt+Tab / Alt+F4 / Win via `win32api` hook re-grab on focus lost.
- Activity journal (encrypted) — parent reviews attempted keys / unlocks.
- Gesture unlock (draw a pattern) instead of keyboard shortcut.
- Disable PrintScreen.

### Top 5 prioritized actions
1. **Close critical bypass vectors (Alt+Tab, Alt+F4, Win key, Task Manager) + multi-monitor + panic unlock** — L.
2. **Remove on-screen unlock-shortcut label + ESC checkbox** — S.
3. **Type hints + Google docstrings** on public/internal methods — S.
4. **Canvas-alive + maintain-peers helpers; move `_norm`/`_handler` to module scope** — M.
5. **Fix `root.destroy()` NameError risk** (L674) + add stderr logging of hook install/remove success/failure — S.

---

## Folder Size Analyzer

### What it does
Tkinter GUI for recursive folder size analysis. Threaded scan, real-time progress, search/filter, sort, CSV/JSON export, double-click navigation, drive capacity display.

### Code review
- Type hints missing on `get_folder_size` (L61), `get_drive_info` (L98), `FolderSizeAnalyzerApp.__init__` params (L134–150), callback lambdas (L354–355).
- Google docstrings missing on utility functions (L37–40, L55–59, L98–108) and all public methods.
- `pathlib` imported but never used (L24). Everything uses `os.path.join`, `os.listdir`, `os.stat` (incl L475).
- **Symlink loop risk**: `os.walk` with no explicit `followlinks=False` (L72); manual navigation into circular symlinks crashes recursion (L327–330).
- **Permission/IO errors silently skipped** (L90–91, L331–333) — no stderr log, no UI warning about incomplete results.
- **Race condition**: `self.folders` mutated on worker thread (L354–355, L373) while `_refresh_tree()` iterates it (L405). No lock.
- **Sparse file / hardlink / junction correctness**: `stat.st_size` used (L79–80); NTFS sparse/hardlink/junction inflate totals (L385 sum).
- Progress callback every 100 files *within one folder* (L87–88) — big folder feels stuck.
- No cancel mid-scan (L305–306) — 500k-file dir locks UI for minutes.
- Home dir hardcoded (L142), colors hardcoded (L164–166, L177–181, L426–431).
- CSV "Full Path" column may surprise users when they're inside a subfolder (L529–540).
- `FolderInfo.__lt__` returns hardcoded `True` and is never called (L125–127) — dead.
- Bare `except:` at L107–108, L514–515 catches `KeyboardInterrupt`.

### Performance
- Serial `os.walk` per top-level folder (L72, L339–358); parallelize with `ThreadPoolExecutor`.
- Memory grows with all `FolderInfo` in list (L341–348); at 10k folders × 50 KB ≈ 500 MB. Consider pagination.
- Progress `.after()` every 100 files produces 10k UI queue hits per 1M files. Throttle to 1–2 s.
- No folder-size cache; auto-scan on load + startup = 2× work.
- Treeview rebuilt on every search keystroke (L280–281, L405–451). Debounce and cache filter list.

### UX / UI critique
- No breadcrumb, no Up button — must edit path manually (L475 double-click forward only).
- Scan progress: no elapsed time, no ETA.
- Live search has no result count.
- Color thresholds 1 GB / 100 MB / 10 MB (L426–431) arbitrary and hardcoded.
- Double-click reconstructs path from tree column text (L475) — fragile for names with special chars.
- No keyboard shortcuts.

### Tech debt
- No stderr logging.
- No pinned `requirements.txt`.
- No pytest tests.
- Bare `except:` clauses.
- Hardcoded colors scattered.

### Simplify
- Delete dead `FolderInfo.__lt__` (L125–127).
- Move treeview tag-color reconfig out of `_refresh_tree` hot path (L449–451).
- Consolidate duplicate progress updates (L352–355).
- Unused `from pathlib import Path` (L24).
- Add 300 ms debounce on search trace (L171) — avoid rebuilding on every keystroke.

### Ideas
- Incremental re-scan using mtimes.
- Parallel scanning with 4–8 workers.
- Cancel mid-scan via `threading.Event`.
- Sparse file detection (`st_blocks * 512 < st_size`) with apparent vs actual size.
- Symlink loop detection (track visited inodes).
- Configurable thresholds and skip patterns (`node_modules`).
- Breadcrumb + Up button + history.
- Regex filter.
- Live pie chart.

### Top 5 prioritized actions
1. **Type hints + Google docstrings** across functions — S.
2. **`os.path` → `pathlib.Path`** — M.
3. **`threading.Lock` on `self.folders` + throttle progress `.after()`** — M.
4. **Symlink-loop and sparse-file handling + user warning on permission errors** — M.
5. **Cancel button + parallel folder scanning** — L.

---

## Network Pattern Analyzer

### What it does
customtkinter tool that loads Network Stability Monitor's JSON exports and does offline post-hoc analysis (time distribution, category frequency, correlation detection). JSON export of results.

### Code review
- `_parse_timestamp()` (L383) typed as `datetime` but returns `None` on failure — should be `Optional[datetime]`.
- `_calculate_duration_seconds()` (L390) same issue.
- `__init__` (L28) missing `-> None`.
- `"exports"` path hardcoded (L85) — env-driven `Path(os.getenv("EXPORT_DIR", "exports"))`.
- `os.path.join` (L85), `os.path.basename` (L118) — `pathlib`.
- Bare excepts at L105, L124, L161, L379, L387, L429 — `print()` at L106 goes to stdout (violates stderr rule).
- Callers rely on truthiness (`if start_time:` at L179, L218, L245) rather than explicit `Optional` handling.
- Correlation detection (L249) hard-codes 10-minute window on `start_time`-sorted incidents; ignores duration → overlapping incidents logged out of order are missed.
- Memory: `export_data` + `analysis_results` (L33–34) accumulate without limit. 1000 large files → OOM.
- Missing docstrings on `__init__` (L28), `_build_ui` (L38), `_display_results` (L270).

### Performance
- Quadratic correlation loop (L241) — 10k incidents ≈ 100M comparisons.
- Whole-file JSON load (L100–104) — no streaming.
- 50+ `.insert(tk.END, ...)` calls in display loop (L279–338) — batch.
- No result caching on re-analyze.

### UX / UI critique
- Loading requires separate button click (L131–132) — could auto-prompt file picker.
- Hardcoded top-N limits (L319 top 5, L332 top 10) with no UI to adjust.
- Placeholder disabled text box (L78–79) before load — no guidance.
- Export default name `network_pattern_analysis.json` (L349–354) lacks timestamp.

### Tech debt
- Tight coupling to export schema (`'incidents'`, `'events'` keys) with no validation (L103–104, L140–141).
- No config / persistence — window geometry hardcoded (L31).
- `print()` for errors (L106).
- No logging module.
- Monolithic 425-line class.

### Simplify
- Hour extraction duplicated at L179–182, L218–220 → `_extract_hour(ts)`.
- ASCII bar chart `"█" * min(count, 20)` (L292) could be a real widget (progressbar or canvas rect) in customtkinter.

### Ideas
- Streaming / incremental load with partial results.
- Pluggable loaders (CSV, Parquet, SQLite) beyond JSON.
- Correlation by IP→IP, not just category→category.
- Z-score / isolation-forest anomaly detection.
- Date range + category filter dropdowns.
- Markdown/HTML report export.
- SQLite backend for scalability.

### Redundancy check
Not redundant with Network Intrusion Detector or Network Stability Monitor — complementary (offline consumer of their exports). Could be consolidated into the Monitor as an "Analysis" tab, or refactored into a library supporting CLI + GUI.

### Top 5 prioritized actions
1. **Fix `Optional` type hints** (L383, L390, L28) — S.
2. **Env-driven exports dir** (L85) — S.
3. **`os.path` → `pathlib.Path`** (L85, L118) — S.
4. **Memory cap + streaming for large datasets** (L33–34, L141) — M.
5. **Extract `_extract_hour` + migrate `print()` to `logging.error()` / stderr** (L106, L179, L218) — M.

---

## 5. Appendix — Convention Compliance Matrix

`✔` = compliant, `✘` = violation, `⚠` = partial.

| Tool | Type hints | Docstrings | `pathlib` | Narrow except + stderr log | env-var config | argparse + dry-run | tests |
|---|---|---|---|---|---|---|---|
| Main.py + Launch.pyw | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ |
| Network Stability Monitor | ⚠ | ⚠ | ✘ | ✘ | ✘ | n/a | ✘ |
| Network Intrusion Detector | ⚠ | ✘ | ✘ | ✘ | ✘ | ✘ | ✘ |
| Account Activity Monitor | ⚠ | ⚠ | ⚠ | ✘ | ✘ | n/a | ✘ |
| FFmpeg Studio | ✘ | ✘ | ✘ | ⚠ | ✘ | n/a | ✘ |
| Claude Usage Monitor | ⚠ | ⚠ | ✔ | ✘ | ✘ | n/a | ✘ |
| Security Audit | ⚠ | ⚠ | ✘ | ⚠ | ✘ | ⚠ (non-destructive today) | ✘ |
| System Health Monitor | ✘ | ✘ | ✘ | ✘ | ✘ | n/a | ✘ |
| System Cleaner | ✘ | ✘ | ⚠ | ✘ | ✘ | **✘ (destructive!)** | ✘ |
| Decision Dice | ⚠ | ✘ | ✘ | ✘ | ⚠ | n/a | ✘ |
| Screen Lock | ⚠ | ⚠ | n/a | ✘ | ✘ | n/a | ✘ |
| Folder Size Analyzer | ⚠ | ✘ | ✘ | ✘ | ✘ | n/a | ✘ |
| Network Pattern Analyzer | ⚠ | ⚠ | ✘ | ✘ | ✘ | n/a | ✘ |

---

## 6. Recommended Order of Attack

1. **Tier A safety fixes** (items 1–6 in §3) — one branch each, landed independently.
2. **Stand up `tools/_common/`** (item 7). This is the single highest-leverage change in the suite.
3. **Sweep-migrate the 13 tools** onto `_common/`: one PR per tool, touching only the files needed. Include type hints + docstrings + `pathlib` + narrow excepts + stderr logging in the same PR.
4. **Tier C polish** (item 10 and the per-tool "Top 5" lists).
5. **Kick off a tests directory** (`tests/`) with pytest. Start with the pure-logic pieces (Decision Dice weighted choice, Claude Usage Monitor pricing map, Network Pattern Analyzer correlation window, `_common/` helpers).

The tools are already doing useful work. The payoff of the shared-helpers sweep is that every future tool starts compliant and every existing tool gets cheaper to maintain in the same PR that fixes its most pressing bug.
