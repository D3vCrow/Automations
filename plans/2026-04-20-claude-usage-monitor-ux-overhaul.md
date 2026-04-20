# Plan — Claude Usage Monitor UX overhaul (single pass)

Derived from `knowledge/research/2026-04-20-claude-usage-monitor-ux-patterns.md` + brainstorm on 2026-04-20. Bundles all 8 improvements into one branch.

## Goal

Close the four reported pain points (scroll loss on refresh, non-scrollable Session Detail, cramped Cost-by-Project panel, missing rotate notifications) and ship four supporting improvements (mtime-cache, collapsible cards, border tint, time-window filter) in a single pass through `tools/claude_usage_monitor.py`.

## Success criteria

1. Adding a new session/project during live refresh does not reset the Sessions tab scroll position.
2. Session Detail tab scrolls end-to-end; all cards + chart + tools + turn table reachable on a 900×550 window.
3. Dashboard Cost-by-Project shows 10+ projects without forcing window scroll; "Show all" toggle reveals remainder.
4. Any LIVE session crossing the AMBER or RED rotate threshold fires exactly one toast + in-app banner per threshold crossing (dedup across refreshes).
5. Unchanged JSONL files are not re-parsed on refresh (mtime-cache hit).
6. Time-window filter (`Today` / `Week` / `Month` / `All`) updates both Dashboard totals and Sessions list.
7. Existing 22 pytest tests still pass; new tests added for mtime-cache, time-window bucketing, and notification dedup.
8. Single-file structure preserved (per project convention).

## Hard blockers (decide before starting)

- **B1 — winotify dep approval.** Zero runtime deps, pure-Python, maintained. If rejected: in-app banner only, skip OS toast.
- **B2 — ORDER_FILE schema extension.** Add `collapsed: [project_name, ...]` and `notif_state: {session_id: last_level}` keys, or use two new sibling JSON files. Recommend single file for atomicity.

## Scope notes

- One branch: `ui/claude-usage-monitor-overhaul`.
- No changes to pricing, rotate-score formula, or cold-turn detection — behavior preserved.
- Dark palette unchanged (`#1e1e1e`, `#2b2b2b`, `#3a7ebf`, `#9e6a3a`, `#bf6a3a`, `#ffd479`).
- Keep helpers on top / GUI class below; no multi-file split.

## Tasks

### T1 — mtime-cache on JSONL parse [Effort: S, Risk: LOW]

**Problem:** `load_all_sessions()` re-parses every `*.jsonl` file every 30s. On machines with 50+ projects this is wasted I/O.

**Files:** `tools/claude_usage_monitor.py`, `tests/test_claude_usage_monitor.py`.

**Approach:**
1. Module-scope cache: `_SESSION_CACHE: dict[str, tuple[float, dict]]` mapping filepath → (mtime, parsed_session).
2. In `load_all_sessions`, `stat` each file; reuse cached dict if `st_mtime` matches.
3. Evict entries for files that no longer exist.
4. Test: same file parsed twice returns the same object; modifying file invalidates cache.

### T2 — Scrollable Session Detail tab [Effort: S, Risk: LOW, ║ parallel with T1/T3/T4]

**Problem:** Cards, chart, tools panel, and turn table overflow on small windows; no scrollbar.

**Approach:**
1. Wrap the pack-layout body of `_build_detail_tab` in `ctk.CTkScrollableFrame`.
2. Bind mousewheel passthrough so the inner `ttk.Treeview` (turn table) doesn't swallow scroll events when cursor outside it.
3. Verify minsize 900×550 renders full detail without clipping.

### T3 — Cost-by-Project 2-col grid + Show all toggle [Effort: S, Risk: LOW, ║]

**Problem:** Dashboard Cost-by-Project list is a single tall column; many projects force window scroll.

**Approach:**
1. Replace the `pack(fill="x")` rows with a 2-column grid inside `_project_breakdown_frame`.
2. Default: top 10 projects; add "Show all (N)" / "Show top 10" toggle button on panel header.
3. Preserve existing bar widths + colors.

### T4 — Time-window filter control [Effort: S, Risk: LOW, ║]

**Problem:** All-time totals drown out today/this-week signal.

**Approach:**
1. Add `ctk.CTkSegmentedButton` to top bar: `Today | Week | Month | All` (default: All).
2. Store selection in `self._window`; expose `_session_in_window(s) -> bool` helper that compares `last_timestamp` to cutoff.
3. No rendering change yet — landed fully in T9.

### T5 — Project-card widget map extraction [Effort: M, Risk: MED]

**Problem:** Current `_build_project_card` creates and returns widgets implicitly; no way to update them later without destroy+rebuild.

**Approach:**
1. Refactor `_build_project_card` to return a dict of widget handles: `{card, header_label, meta_label, live_label, tree, collapse_btn}`.
2. Store in `self._project_cards[proj]` (already exists; expand shape).
3. Add `_update_project_card(proj, items)` that configures existing widgets in place (no destroy).
4. Tree rows: save iids on insert; `tree.delete(*get_children())` then re-insert is fine — scroll position of the outer CTkScrollableFrame is what matters, not per-Treeview.

### T6 — Reconcile-by-key refactor of `_render_sessions` [Effort: M, Risk: HIGH]

**Problem:** `_render_sessions` destroys all children every 30s → scroll reset + flicker.

**Approach:**
1. Compute new ordered project list (saved order + remaining by cost).
2. Diff vs `self._project_cards.keys()`:
   - `removed = old - new` → destroy those cards.
   - `added = new - old` → build via `_build_project_card`.
   - `kept = old & new` → call `_update_project_card`.
3. Re-pack in new order via `card.pack_forget()` then `card.pack(fill="x", pady=6, padx=4)` in loop order.
4. Persist the saved order as before.
5. Belt-and-braces: save `self._sess_scroll._parent_canvas.yview()` at top, restore after `update_idletasks()` (T7 covers this as its own concern).

**Risk mitigation:** if reconcile misbehaves, fall back to current destroy-rebuild behind a `_USE_RECONCILE = True` module flag for quick rollback.

### T7 — Scroll preservation safety net [Effort: S, Risk: LOW]

**Problem:** Belt-and-braces for T6 in case reconcile ever degrades.

**Approach:**
1. Wrapper on `_render_sessions`: save `self._sess_scroll._parent_canvas.yview()` pre-reconcile, restore post-`update_idletasks()`.
2. Same pattern for any future scroll-bearing rebuild.
3. Pin `customtkinter` version in `requirements.txt` since `_parent_canvas` is internal.

### T8 — Collapsible project cards [Effort: M, Risk: MED]

**Problem:** Users with many projects still can't see overview without scrolling.

**Approach:**
1. Add `▼/▶` toggle button to card header (left of the project name).
2. Clicking toggles `tree.pack_forget()` / `tree.pack(...)`.
3. Persist `collapsed: [proj_name, ...]` in ORDER_FILE (pending B2).
4. On load, restore collapsed state before first render.
5. `Ctrl+click` the toggle = collapse/expand all (small UX bonus).

### T9 — Plumb window filter through renderers [Effort: M, Risk: MED]

**Problem:** T4 adds the control; now wire it.

**Approach:**
1. Dashboard: filter `self._sessions` by `_session_in_window` before computing totals, peak hours, model/tool/project breakdowns.
2. Sessions: same filter before bucketing into projects.
3. "Plan Cost" card: scale to months-in-window (e.g. Week = 0.25 month) for accurate ratio.
4. Status label shows window context: `"42 sessions in Week | Last refresh: 14:32"`.

### T10 — Notification dedup state [Effort: S, Risk: LOW]

**Problem:** Without dedup, every 30s refresh would re-fire the same alert.

**Approach:**
1. State structure: `{session_id: {"level": "amber"|"red", "fired_at": iso_ts}}`.
2. Persisted in ORDER_FILE under `notif_state` (pending B2).
3. Helper `_should_notify(session_id, new_level) -> bool`: fires only when `new_level` is a *higher* tier than last recorded, or when no record exists.
4. Evict entries whose sessions are no longer LIVE.
5. Test: amber → amber no fire; amber → red fires once; red → amber no fire (downgrade silent).

### T11 — winotify integration with in-app banner fallback [Effort: M, Risk: MED]

**Problem:** Need OS toast *and* an in-app signal the user can click to jump to the session.

**Approach:**
1. `try: import winotify` at top; set `_HAS_TOAST` flag.
2. If available, `winotify.Notification(app_id="Claude Usage Monitor", title=..., msg=..., launch=deep_link)`.
3. In-app banner: a `ctk.CTkFrame` slot in the top bar, initially `pack_forget`'d. Shown when any unsatisfied notification exists. Single "Jump to session" button calls `_show_session_detail(s)`.
4. Banner color: amber `#e09a1a`, red `#cc3333` to match pill palette.
5. Banner persists until user clicks "Jump" or session drops below threshold.
6. If `winotify` rejected (B1), steps 2 is skipped — banner alone covers the need.

### T12 — Rotate-threshold scan in `_on_loaded` [Effort: M, Risk: MED]

**Problem:** Need to detect crossings after every refresh.

**Approach:**
1. After `_on_loaded` finishes populating `self._sessions` + `self._active_ids`:
2. For each LIVE session with ≥5 turns, compute `_rotate_subscores`.
3. Map total score → level (`red` ≥60, `amber` ≥30, else `none`).
4. Consult `_should_notify`; if fire: toast + banner update.
5. Record to dedup state file.

### T13 — Ambient rotation border on project cards [Effort: S, Risk: LOW]

**Problem:** Users want at-a-glance signal of which projects have a burning session.

**Approach:**
1. In `_update_project_card` (T5), compute max rotate score across its LIVE sessions.
2. Set `card.configure(border_color=...)`:
   - red ≥60 → `#cc3333`
   - amber ≥30 → `#e09a1a`
   - else → `#333` (default).
3. Border is already 1px; no width change.

### T14 — Tests [Effort: S, Risk: LOW]

**Files:** `tests/test_claude_usage_monitor.py`.

**Approach:**
- mtime-cache: same file → cached; mtime bump → re-parse.
- Window filter: `_session_in_window` bucketing at day/week/month boundaries (build fixture with fixed `now`).
- Dedup state: amber→amber no fire; amber→red fires; red→amber no fire; session removed → state evicted.
- All existing 22 tests pass unchanged.

## Sequencing

Parallel lane (land first, any order): **T1, T2, T3, T4**.
Then refactor lane (sequential): **T5 → T6 → T7 → T8 → T13**.
Then feature lane: **T9** (needs T4).
Then notifications lane (sequential): **T10 → T11 → T12**.
Finally: **T14** (can incrementally grow alongside each task).

## Verification

- Manual: open monitor, trigger a live claude session in another cwd, wait 30s — Sessions tab does not scroll-jump; banner appears when score goes amber.
- Manual: resize window to 900×550 — Session Detail scrolls cleanly.
- Automated: `pytest tests/test_claude_usage_monitor.py -v` all green (22 existing + ~6 new).

## Rollback plan

Each task is a separate commit. If T6 (reconcile refactor) regresses, flip `_USE_RECONCILE = False` and revert only that commit. T11 (winotify) can be toggled via import-guard.

## Out of scope

- Rotate-score formula changes.
- New metrics beyond time-window filter.
- CSV export (defer to a follow-up plan).
- System-tray icon (too heavy — would need pystray).
- Splitting the single-file tool (project convention to keep tools as single files).
