# Plan B — Convention & Tech-Debt Sweep (Tier B + C)

Derived from `REVIEW.md §2–3 Tier B/C`. These are the *small* issues — convention violations, silent excepts, `os.path`, missing hints/docstrings, UX polish, perf nits. Individually trivial, collectively enormous. The trick is to **stop reinventing shared helpers** and do the sweep once.

Run this **after Plan A** lands, so the shared modules created there (`tools/_common/threadsafe.py`, `tools/_common/logging.py`) are already in place.

## Goal

Bring every tool in `tools/` + `Main.py` into compliance with `CLAUDE.md` conventions, remove silent failure modes, and polish the obvious UX rough edges — without rewriting any tool from scratch.

## Success criteria

1. `tools/_common/` exists with logger, paths, admin, subproc, threadsafe (from A5), theme, confirm helpers.
2. Every file in `tools/` uses:
   - Type hints on public function signatures.
   - Google-style docstrings on public functions & classes.
   - `pathlib.Path` (not `os.path`) for all filesystem work.
   - `tools._common.logging.get_logger(__name__)` (not `print()`, not bare `except Exception: pass`).
3. `tests/` directory exists with pytest smoke tests covering pure-logic helpers in each tool.
4. `requirements.txt` pins every third-party dep (customtkinter, psutil, keyboard, scapy, send2trash, etc.).
5. The convention compliance matrix in `REVIEW.md §5` shows ✔ across all rows.

## Scope notes

- Each task is self-contained; can be parallelized across branches.
- Prefer **surgical** diffs — don't rewrite a file because you touched it.
- Zero behavioral changes except where a task explicitly says so.

---

## Tasks

### B0 — Stand up `tools/_common/` (foundation)  [M]

**Problem**  
Every tool reinvents: admin check, subprocess helper, color palette, error handler, confirm dialog, rolling buffer, config loader. ~1500 LOC of duplicated utility code across the suite.

**Files**  
`tools/_common/__init__.py`, `tools/_common/logging.py`, `tools/_common/paths.py`, `tools/_common/admin.py`, `tools/_common/subproc.py`, `tools/_common/ui_theme.py`, `tools/_common/ui_confirm.py`, `tools/_common/config.py`.
(`tools/_common/threadsafe.py` already shipped in Plan A5.)

**Approach**

Keep each helper small (≤ 80 LOC). Type-hinted and docstringed from the start so they're the template.

- `logging.py` — `get_logger(name: str) -> logging.Logger` with stderr handler at INFO, optional file handler at DEBUG via env `TOOLBOX_LOG_DIR`. One-time init guarded by a module flag.
- `paths.py`
   - `CONFIG_DIR = Path(os.getenv("TOOLBOX_CONFIG_HOME", Path.home() / ".toolbox"))`
   - `LOG_DIR`, `STATE_DIR`, `CACHE_DIR` derived similarly.
   - `ensure_dir(p: Path) -> Path` (mkdir parents=True, exist_ok=True).
- `admin.py`
   - `@functools.lru_cache(maxsize=1) def is_admin() -> bool` — single cached Windows check via `ctypes.windll.shell32.IsUserAnAdmin`.
- `subproc.py`
   - `safe_run(cmd: list[str], timeout: float = 30.0) -> tuple[int, str, str]` using `CREATE_NO_WINDOW` on Windows, logging command + exit code at DEBUG.
- `ui_theme.py`
   - Constants: `SEVERITY_COLORS`, `STATUS_COLORS`, `CATEGORY_COLORS`, `ACCENT`, `BG`, `FG_MUTED`. Single source of truth.
- `ui_confirm.py`
   - `confirm_destructive(parent, title: str, summary_rows: list[tuple[str, str]], total_size_bytes: int) -> bool` — renders a dialog with per-row labels + human-readable sizes, returns True only if user types the word "DELETE" (or clicks a checkbox for non-destructive cases).
- `config.py`
   - `load_json(path: Path, schema: dict | None = None) -> dict`, `save_json(path: Path, data: dict) -> None` with atomic write (`tempfile` + `replace`).

**Verification**

- `tests/test_common_logging.py`, `test_common_paths.py`, `test_common_admin.py`, `test_common_subproc.py`. Each ≥2 tests (happy path + one error).
- Each module imported once in `tests/test_common_imports.py` just to catch syntax errors cheaply.

**Effort** M (~4 h).

---

### B1 — Convention migration: one sub-task per tool  [S each × 13]

Pick the least-touched tool first (Network Pattern Analyzer, 433 LOC) to validate the template, then run the same recipe through the rest.

**Recipe (apply per tool)**
1. Add `from tools._common.logging import get_logger`; `logger = get_logger(__name__)` at top.
2. Replace every `os.path.*` with `pathlib.Path`. Common patterns:
   - `os.path.join(a, b)` → `Path(a) / b`
   - `os.path.exists(p)` → `Path(p).exists()`
   - `os.path.dirname(os.path.abspath(__file__))` → `Path(__file__).resolve().parent`
3. Replace every `print(..., file=sys.stderr)` and `print()` for errors with `logger.info/warning/error(...)`.
4. Replace every `except Exception: pass` with:
   - Narrow exception class(es) — list them explicitly.
   - `logger.warning("...", exc_info=True)` (or error, for the rare unexpected).
5. Add type hints on every public function signature (Python 3.10+ syntax: `list[int]`, `X | None`).
6. Add Google-style docstrings on public functions and classes. Three sections: one-line summary, `Args:`, `Returns:` (+ `Raises:` if relevant).
7. Replace hardcoded config paths with `tools._common.paths.CONFIG_DIR / "<tool>_state.json"`; read with `tools._common.config.load_json`.
8. Replace hardcoded hex colors with `tools._common.ui_theme.*` where they appear.
9. Replace hand-rolled subprocess calls with `tools._common.subproc.safe_run`.
10. Replace hand-rolled `is_admin()` with `tools._common.admin.is_admin`.

**Tools in order (cheapest first)**

| # | Tool | File | LOC | Notes |
|---|------|------|-----|-------|
| B1a | Network Pattern Analyzer | `tools/network_pattern_analyzer.py` | 433 | Smallest; use as template. |
| B1b | Folder Size Analyzer | `tools/folder_size_analyzer.py` | 606 | Already mostly clean. |
| B1c | Screen Lock | `tools/screen_lock.py` | 683 | Shares config with Plan A3. |
| B1d | Decision Dice | `tools/decision_dice.py` | 1121 | Also do B3 perf items in same PR. |
| B1e | System Cleaner | `tools/system_cleaner.py` | 1197 | Post-A1, revisit for convention. |
| B1f | System Health Monitor | `tools/system_health_monitor.py` | 1534 | Post-A2 + A5. |
| B1g | Claude Usage Monitor | `tools/claude_usage_monitor.py` | 1558 | Post-A6. |
| B1h | FFmpeg Studio | `tools/ffmpeg_studio.py` | 1716 | Do convention + B2 (class refactor) together. |
| B1i | Security Audit | `tools/security_audit.py` | 1836 | Includes registry-handle leak fix. |
| B1j | Account Activity Monitor | `tools/account_activity_monitor.py` | 2362 | Post-A5 locks. |
| B1k | Network Intrusion Detector | `tools/network_intrusion_detector_pro.py` | 3064 | Post-A5. |
| B1l | Network Stability Monitor | `tools/NETWORK STABILITY MONITOR.py` | 3206 | Rename file → `network_stability_monitor.py` in same PR. |
| B1m | Main.py | `Main.py` | 700 | Post-A4. |

**Verification (per tool)**
- `ruff check tools/<file>` (or similar) passes.
- `mypy --ignore-missing-imports tools/<file>` — no errors from the file itself (ignore third-party noise).
- Tool still launches and performs its core action smoke-test.
- PR diff shows no behavior change except where called out.

**Effort** S per tool (~1–2 h each = ~20 h total across 13 files).

---

### B2 — Architecture: break up the god-objects  [L × 3]

**Problem**  
Six tools have a single `App` class > 1000 LOC mixing UI, data, background threads. REVIEW calls these out: FFmpeg Studio (1350-line `run_tool`), Network Stability Monitor, Network Intrusion Detector, Account Activity Monitor, System Health Monitor, System Cleaner.

Do **not** refactor all six. Pick the three most likely to keep growing:

**B2a — FFmpeg Studio**: extract `class FFmpegStudio(ctk.CTkToplevel)` from the 1350-line `run_tool`. Methods for each UI panel. Shared data via instance attributes instead of 10-closure variable capture. Extract `_build_color_args()` helper used by both recording (`tools/ffmpeg_studio.py:441–446`) and conversion (`tools/ffmpeg_studio.py:1483–1488`).

**B2b — Network Stability Monitor**: split into `engine.py` (Sampler, IncidentDetector, Intelligence), `ui_panels.py` (Tab classes), keep `App` as a thin orchestrator < 500 LOC.

**B2c — System Health Monitor**: split `Engine` (lines 149–632) into its own `engine.py` with locked state (piggyback on B0 + A5). UI stays in `app.py`. Extract `TemperatureProbe` class consolidating the three temp strategies (Ohm / WMI / none).

**Verification (per tool)**
- No file > 900 LOC after refactor.
- Each extracted module has at least one pytest covering a pure-logic function in it.
- Smoke test: tool launches and all tabs render.

**Effort** L each (~1 day per tool = 3 days). Do only if time permits; Plan B is valuable even without this.

---

### B3 — Performance nits (low-hanging)  [S each]

Collected from the per-tool reviews. Each is a 10–60 min fix.

| ID | Tool | File:line | Fix |
|----|------|-----------|-----|
| B3a | Network Stability Monitor | `tools/NETWORK STABILITY MONITOR.py:627–628, 622–623, 766` | Replace `list` + `[:N]` slice cap with `collections.deque(maxlen=N)`. |
| B3b | Network Stability Monitor | `tools/NETWORK STABILITY MONITOR.py:2324` | Module-level `ThreadPoolExecutor` instead of rebuilding per sample. |
| B3c | Network Stability Monitor | `tools/NETWORK STABILITY MONITOR.py:2641` | Iterate `reversed(incidents)` directly instead of build-then-reverse. |
| B3d | Account Activity Monitor | `tools/account_activity_monitor.py:312–365` | Replace O(n²) aggregation loop with sort-then-scan. |
| B3e | Account Activity Monitor | `tools/account_activity_monitor.py:1106–1111` | List + `"".join()` instead of `+=` in detail builder. |
| B3f | Claude Usage Monitor | `tools/claude_usage_monitor.py:1368` | Move `rows.sort()` out of per-keystroke render; re-sort only on column change. |
| B3g | Claude Usage Monitor | `tools/claude_usage_monitor.py:838–846` | Move `ttk.Style` config from `_build_sessions_tab` to `__init__`. |
| B3h | Network Intrusion Detector | `tools/network_intrusion_detector_pro.py:251–252` | LRU eviction on `_ip_geo_cache` instead of full clear at 2000. |
| B3i | Network Intrusion Detector | `tools/network_intrusion_detector_pro.py:2830–2839, 2832` | Decouple `scan_now()` from UI tick; put behind a longer-period timer. |
| B3j | Decision Dice | `tools/decision_dice.py:103–106, 821–822` | Replace `build_pool` + `random.choice` with `random.choices(..., weights=...)`. |
| B3k | Decision Dice | `tools/decision_dice.py:992–997` | Track `last_outcome` field; kill the reverse-journal lookup. |
| B3l | Decision Dice | `tools/decision_dice.py:1072–1087` | Update history chips in place instead of destroy + recreate. |
| B3m | Folder Size Analyzer | `tools/folder_size_analyzer.py:87–88` | Throttle progress callback to every ~1 s instead of every 100 files. |
| B3n | Folder Size Analyzer | `tools/folder_size_analyzer.py:171` | Add 300 ms debounce on search `trace_add`. |
| B3o | System Health Monitor | `tools/system_health_monitor.py:193–194` | Drop the redundant first `cpu_percent()` call. |
| B3p | System Health Monitor | `tools/system_health_monitor.py:204–215` | Cache `disk_partitions()` with TTL (e.g., 30 s). |
| B3q | System Health Monitor | `tools/system_health_monitor.py:259–281` | Exponential-backoff GPU polling when nvidia-smi fails repeatedly. |
| B3r | System Cleaner | `tools/system_cleaner.py:694` | Parallel `ThreadPoolExecutor` across categories in `_scan_worker`. |
| B3s | Security Audit | `tools/security_audit.py:567, 890, 1029, 1106` | Move `re.compile()` calls to module-level constants. |
| B3t | Main.py | `Main.py:604–610` | Bind hover on card frame only; stop recursive descendant bind. |
| B3u | Main.py | `Main.py:479–480` | Hide/show existing cards on filter change instead of destroy + recreate. |

**Verification**: micro-benchmark before/after for B3a, B3d, B3j, B3r (where perf is the point); others just need the behavior not to change.

**Effort** S each.

---

### B4 — UX polish pass (cross-tool)  [S each]

Small-but-noticeable improvements. Each ≤ 1 h.

| ID | Tool | Improvement |
|----|------|-------------|
| B4a | Network Stability Monitor | Sort-direction arrow on active column; empty-state text on tabs; input validation on ping targets (L1518–1519, L1301). |
| B4b | Account Activity Monitor | Resizable Treeview columns; tooltip/expand for truncated 200-char detail; keyboard shortcuts (Ctrl+F, Ctrl+E). |
| B4c | Claude Usage Monitor | Session-name truncation by measured pixel width, not char count (L144–145). Warning banner if `~/.claude/projects/` unreadable. |
| B4d | System Health Monitor | Show why GPU/CPU temp is "N/A" (e.g., "no nvidia-smi"). "500+ processes" indicator when capped. Use `shlex.split` for startup commands (L1117). Validate warn ≤ crit on threshold spinboxes. |
| B4e | System Cleaner | Confirm dialog shows per-category sizes (already in A1). Admin badge rephrased from "some items disabled" to "Limited mode". RAM-freed label shows "0 B freed" rather than going blank. Progress bar during cleaning. |
| B4f | Decision Dice | Profile editor: allow non-100% totals, auto-normalize. Streak label wording: "🔥 3× YES (1-in-11 rarity)". Date and outcome-count filters on journal. |
| B4g | Screen Lock | Already handled in A3. |
| B4h | Folder Size Analyzer | Breadcrumb + Up button; elapsed-time label during scan; result count in search; keyboard shortcuts. |
| B4i | Network Intrusion Detector | Disable "Passive sniff" checkbox when scapy missing. Admin warning banner when sniff is on but no admin. Stable connection IDs (drop `int(iid.split("-")[1])`). |
| B4j | FFmpeg Studio | Auto-fix all unsupported combos with a toast (no modal prompt for non-fatal). Progress spinner during `_verify_startup`. |
| B4k | Security Audit | Copy-to-clipboard on finding cards. Search across findings. CSV + Markdown export options. 0–10 risk score pill. |

**Verification**: visual QA, one or two pytest tests for the validation logic.

**Effort** S each.

---

### B5 — Tests directory bootstrap  [M]

**Problem**  
CLAUDE.md requires pytest; zero tests exist today.

**Files**  
`tests/__init__.py`, `tests/conftest.py`, `pyproject.toml` (or `pytest.ini`), new `tests/test_<tool>.py` per tool.

**Approach**
1. Add `pytest>=7,<9` to `requirements-dev.txt` (new file).
2. `pyproject.toml` addition:
   ```toml
   [tool.pytest.ini_options]
   testpaths = ["tests"]
   filterwarnings = ["error::DeprecationWarning"]
   ```
3. `tests/conftest.py`: fixture for a temp `CONFIG_DIR` via monkeypatch of `tools._common.paths`.
4. Write smoke tests for **pure-logic** only (no Tk):
   - `test_decision_dice.py`: weight distribution statistics (`random.choices` proof), journal save/load, hex/rgb roundtrip, streak detection.
   - `test_claude_usage_monitor.py`: pricing map lookup, JSONL parser on canned fixture, timezone math for peak-hours (post A6).
   - `test_system_health_monitor.py`: CPU temp formula boundary cases (post A2), CPU% normalization.
   - `test_network_pattern_analyzer.py`: correlation window with overlapping incidents.
   - `test_folder_size_analyzer.py`: symlink-loop detector, sparse-file detection.
   - `test_system_cleaner.py`: dry-run accounting, symlink skip (post A1).
   - `test_common_*.py` (already from B0).
5. GitHub Action or local `pytest` hook in `CONTRIBUTING.md` (don't over-engineer CI if none exists).

**Verification**
- `pytest` runs all tests green locally.
- At least one test per tool in the list above.

**Effort** M (~6 h).

---

### B6 — Dependency pinning & requirements hygiene  [S]

**Problem**  
No (or partial) version pins across tools. Screen Lock docstring references `pip install keyboard` without any version. Decision Dice documents `pip install customtkinter` in a docstring, not `requirements.txt`.

**Files**  
`requirements.txt`, `requirements-dev.txt`.

**Approach**
1. Enumerate all third-party imports across `tools/` + `Main.py`:
   - `customtkinter`, `psutil`, `keyboard`, `scapy`, `requests`, `send2trash` (from A1), `Pillow` (if used), `watchdog` (if used).
2. Pin to a minor-compatible range (`customtkinter>=5.2,<6.0`).
3. `requirements-dev.txt`: `pytest`, `mypy`, `ruff`.
4. Document in `CLAUDE.md` or `README.md`: "install with `pip install -r requirements.txt`".

**Verification**: fresh venv `pip install -r requirements.txt` then launch the toolbox.

**Effort** S (~45 min).

---

### B7 — Rename the embarrassing filename  [S]

**Problem**  
`tools/NETWORK STABILITY MONITOR.py` — spaces and caps break imports, tab completion, and PEP 8.

**Approach**  
Rename to `tools/network_stability_monitor.py`. Update `Main.py` if it special-cases the file. Run the entire `Main.py` toolbox once to confirm discovery still works.

**Verification**: launcher lists the tool by its `TOOL_NAME`, the tool launches, no import error.

**Effort** S (~10 min).

---

## Ordering

```
B0 (foundation) ── must land first ──┐
                                     │
B6 (deps)       ── parallel          ├── unlock everything below
B7 (rename)     ── parallel          │
                                     │
B1 × 13 (convention sweep) ──────────┤── sequential or parallel per tool
                                     │
B3 (perf nits)  ── grouped in B1 PRs ┤
B4 (UX polish)  ── grouped in B1 PRs ┤
                                     │
B2 (god-object split) ── optional ───┤── only if time allows
                                     │
B5 (tests bootstrap) ── parallel ────┘
```

Realistic minimum viable sweep: **B0 → B6 → B7 → B1 × 13** with B3/B4 items pulled into each B1 PR where they touch the same file. That alone clears every row of the compliance matrix.

## Out of scope

- New features beyond what REVIEW called out as "Ideas".
- Platform portability (Linux/Mac) — tools remain Windows-only by design.
- Any of the Tier A safety fixes (those are Plan A).

## Definition of done

- Compliance matrix in `REVIEW.md §5` flipped to ✔ across all rows.
- `pytest` passes locally on a fresh clone + `pip install -r requirements.txt`.
- No tool's file exceeds 1500 LOC (or, if it does, has an accompanying `ARCHITECTURE.md` note explaining why — e.g., God-object intentionally not split).
- Grep for `except Exception: pass`, `print(f".*error"`, and `os.path.join` in `tools/` returns zero hits.
