"""
Claude Usage Monitor — Live session cost tracker for Claude Code.
Reads JSONL session logs from ~/.claude/projects/ and calculates
token usage, costs, waste factor, and per-session breakdowns.
"""

import os
import json
import glob
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
import customtkinter as ctk
from tkinter import ttk

TOOL_NAME = "Claude Usage Monitor"
TOOL_DESC = "Live monitor for Claude Code session costs, tokens & waste"

# ---------------------------------------------------------------------------
# Anthropic official pricing (USD per million tokens) — April 2026
# ---------------------------------------------------------------------------
MODEL_PRICING = {
    "claude-opus-4-6": {
        "input": 5.0, "output": 25.0,
        "cache_read": 0.50, "cache_write_5m": 6.25, "cache_write_1h": 10.0,
    },
    "claude-opus-4-5": {
        "input": 5.0, "output": 25.0,
        "cache_read": 0.50, "cache_write_5m": 6.25, "cache_write_1h": 10.0,
    },
    "claude-sonnet-4-6": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-sonnet-4-5": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-sonnet-4": {
        "input": 3.0, "output": 15.0,
        "cache_read": 0.30, "cache_write_5m": 3.75, "cache_write_1h": 6.0,
    },
    "claude-haiku-4-5": {
        "input": 1.0, "output": 5.0,
        "cache_read": 0.10, "cache_write_5m": 1.25, "cache_write_1h": 2.0,
    },
}

# Fallback pricing (use Sonnet rates as conservative default)
_DEFAULT_PRICING = MODEL_PRICING["claude-sonnet-4-6"]

CLAUDE_DIR = Path.home() / ".claude"
PROJECTS_DIR = CLAUDE_DIR / "projects"
SESSIONS_DIR = CLAUDE_DIR / "sessions"


# ---------------------------------------------------------------------------
# Data layer
# ---------------------------------------------------------------------------

def _get_pricing(model_name: str) -> dict:
    """Return pricing dict for a model, falling back to defaults."""
    if not model_name:
        return _DEFAULT_PRICING
    # Try exact match first, then prefix match
    if model_name in MODEL_PRICING:
        return MODEL_PRICING[model_name]
    for key in MODEL_PRICING:
        if model_name.startswith(key.rsplit("-", 1)[0]):
            return MODEL_PRICING[key]
    return _DEFAULT_PRICING


def _calc_turn_cost(usage: dict, pricing: dict) -> float:
    """Calculate dollar cost for a single API turn."""
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cache_read = usage.get("cache_read_input_tokens", 0)

    # Determine cache write breakdown
    cache_creation = usage.get("cache_creation", {})
    cache_5m = cache_creation.get("ephemeral_5m_input_tokens", 0)
    cache_1h = cache_creation.get("ephemeral_1h_input_tokens", 0)
    total_cache_write = usage.get("cache_creation_input_tokens", 0)

    # If no breakdown available, assume all cache writes are 5m.
    # Claude Code defaults to the 5-minute cache; defaulting to 1h was
    # inflating estimates by ~1.60x vs the API-billed cost.
    if total_cache_write > 0 and (cache_5m + cache_1h) == 0:
        cache_5m = total_cache_write

    cost = (
        (inp / 1_000_000) * pricing["input"]
        + (out / 1_000_000) * pricing["output"]
        + (cache_read / 1_000_000) * pricing["cache_read"]
        + (cache_5m / 1_000_000) * pricing["cache_write_5m"]
        + (cache_1h / 1_000_000) * pricing["cache_write_1h"]
    )
    return cost


def _extract_prompt_text(user_record: dict, max_len: int = 80) -> str | None:
    """Pull human-readable text from a user message record.

    Returns None if the record has no real user text (e.g. tool_result only).
    Skips blocks that start with '<' (system-reminder XML tags).
    """
    msg = user_record.get("message", {})
    content = msg.get("content", "")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text", "").strip()
                # Skip system/XML injected content
                if text and not text.startswith("<"):
                    content = text
                    break
        else:
            return None
    if not isinstance(content, str):
        content = str(content)
    text = " ".join(content.split()).strip()
    if not text or text.startswith("<"):
        return None
    if len(text) > max_len:
        text = text[:max_len].rsplit(" ", 1)[0] + "..."
    return text


def _parse_session_file(filepath: str) -> dict:
    """Parse a single JSONL session file and return aggregated stats."""
    session = {
        "file": filepath,
        "session_id": Path(filepath).stem,
        "project": Path(filepath).parent.name,
        "session_name": None,   # derived from first user prompt
        "model": None,
        "entrypoint": None,
        "version": None,
        "cwd": None,
        "git_branch": None,
        "first_timestamp": None,
        "last_timestamp": None,
        "user_turns": 0,
        "assistant_turns": 0,
        "total_input": 0,
        "total_output": 0,
        "total_cache_read": 0,
        "total_cache_write": 0,
        "total_cost": 0.0,
        "turn_costs": [],       # (timestamp, cost, input, output, cache_read, cache_write, model)
        "models_used": set(),
    }

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                rec_type = obj.get("type")
                ts_str = obj.get("timestamp")

                # Track timestamps
                if ts_str:
                    if session["first_timestamp"] is None:
                        session["first_timestamp"] = ts_str
                    session["last_timestamp"] = ts_str

                if rec_type == "user":
                    session["user_turns"] += 1
                    if not session["entrypoint"]:
                        session["entrypoint"] = obj.get("entrypoint")
                    if not session["version"]:
                        session["version"] = obj.get("version")
                    if not session["cwd"]:
                        session["cwd"] = obj.get("cwd")
                    if not session["git_branch"]:
                        session["git_branch"] = obj.get("gitBranch")
                    # Keep the last real user prompt as session name
                    prompt = _extract_prompt_text(obj)
                    if prompt:
                        session["session_name"] = prompt

                elif rec_type == "assistant":
                    session["assistant_turns"] += 1
                    msg = obj.get("message", {})
                    model = msg.get("model")
                    if model:
                        session["models_used"].add(model)
                        if not session["model"]:
                            session["model"] = model

                    usage = msg.get("usage", {})
                    if usage:
                        inp = usage.get("input_tokens", 0)
                        out = usage.get("output_tokens", 0)
                        cr = usage.get("cache_read_input_tokens", 0)
                        cw = usage.get("cache_creation_input_tokens", 0)

                        session["total_input"] += inp
                        session["total_output"] += out
                        session["total_cache_read"] += cr
                        session["total_cache_write"] += cw

                        pricing = _get_pricing(model)
                        cost = _calc_turn_cost(usage, pricing)
                        session["total_cost"] += cost

                        session["turn_costs"].append((ts_str, cost, inp, out, cr, cw, model))

    except Exception:
        pass

    session["models_used"] = list(session["models_used"])
    return session


def _parse_timestamp(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except Exception:
        return None


def _format_tokens(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def _format_cost(c: float) -> str:
    if c >= 1.0:
        return f"${c:.2f}"
    if c >= 0.01:
        return f"${c:.3f}"
    return f"${c:.4f}"


def _duration_str(first_ts: str, last_ts: str) -> str:
    t1 = _parse_timestamp(first_ts)
    t2 = _parse_timestamp(last_ts)
    if not t1 or not t2:
        return "—"
    delta = t2 - t1
    secs = int(delta.total_seconds())
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    hours = secs // 3600
    mins = (secs % 3600) // 60
    return f"{hours}h {mins}m"


def _waste_factor(turn_costs: list) -> float | None:
    """Waste factor: average tokens/turn in last 5 turns vs first 5 turns."""
    if len(turn_costs) < 6:
        return None
    first5 = [tc[2] + tc[3] + tc[4] + tc[5] for tc in turn_costs[:5]]
    last5 = [tc[2] + tc[3] + tc[4] + tc[5] for tc in turn_costs[-5:]]
    base = sum(first5) / len(first5)
    current = sum(last5) / len(last5)
    if base <= 0:
        return None
    return current / base


def _friendly_project(dirname: str, cwd: str | None = None) -> str:
    """Convert directory name or cwd path into a readable project name.

    Prefers the real cwd path (e.g. 'F:\\DevCrow\\Python\\Automations')
    over the encoded dirname ('F--DevCrow-Python-Automations').
    """
    if cwd:
        parts = Path(cwd).parts
        # Drop drive root like 'F:\\'
        if len(parts) > 1 and len(parts[0]) <= 3:
            parts = parts[1:]
        # Show last 3 segments max
        parts = parts[-3:] if len(parts) > 3 else parts
        return "/".join(parts)

    # Fallback: decode the dirname encoding
    segments = dirname.split("--")
    if len(segments) > 1 and len(segments[0]) <= 2:
        segments = segments[1:]
    return "/".join(segments)


def load_all_sessions() -> list[dict]:
    """Scan all projects and return parsed session data, newest first."""
    sessions = []
    if not PROJECTS_DIR.exists():
        return sessions

    for proj_dir in PROJECTS_DIR.iterdir():
        if not proj_dir.is_dir():
            continue
        for jsonl_file in proj_dir.glob("*.jsonl"):
            sess = _parse_session_file(str(jsonl_file))
            if sess["assistant_turns"] > 0:
                sessions.append(sess)

    # Sort by last timestamp descending
    sessions.sort(
        key=lambda s: s.get("last_timestamp") or "",
        reverse=True,
    )
    return sessions


def _get_active_session_ids() -> set:
    """Read ~/.claude/sessions/*.json to find currently active sessions."""
    active = set()
    if not SESSIONS_DIR.exists():
        return active
    for f in SESSIONS_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            sid = data.get("sessionId")
            if sid:
                active.add(sid)
        except Exception:
            pass
    return active


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class ClaudeUsageMonitor(ctk.CTkToplevel):
    def __init__(self):
        super().__init__()
        self.title("Claude Usage Monitor")
        self.geometry("1100x720")
        self.minsize(900, 550)

        self._sessions: list[dict] = []
        self._active_ids: set = set()
        self._loading = False
        self._auto_refresh = True
        self._sort_col = "date"       # default sort column
        self._sort_reverse = True     # newest first
        self._plan = "Max 5x ($100/mo)"  # default plan

        self._build_ui()
        self._start_load()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        # Top bar
        top = ctk.CTkFrame(self, height=50, corner_radius=0)
        top.pack(fill="x")

        ctk.CTkLabel(
            top, text="Claude Usage Monitor",
            font=ctk.CTkFont(size=18, weight="bold"),
        ).pack(side="left", padx=16, pady=10)

        self._status_label = ctk.CTkLabel(
            top, text="Loading...", text_color="gray",
            font=ctk.CTkFont(size=12),
        )
        self._status_label.pack(side="left", padx=10)

        btn_frame = ctk.CTkFrame(top, fg_color="transparent")
        btn_frame.pack(side="right", padx=12)

        # Plan selector
        self._plan_var = ctk.StringVar(value=self._plan)
        ctk.CTkLabel(btn_frame, text="Plan:", font=ctk.CTkFont(size=11)).pack(side="left", padx=(0, 4))
        plan_menu = ctk.CTkOptionMenu(
            btn_frame, variable=self._plan_var,
            values=[
                "Max 5x ($100/mo)",
                "Max 20x ($200/mo)",
                "Pro ($20/mo)",
                "API (pay-per-token)",
            ],
            width=160, height=28,
            command=self._on_plan_change,
            font=ctk.CTkFont(size=11),
        )
        plan_menu.pack(side="left", padx=(0, 12))

        self._auto_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            btn_frame, text="Auto-refresh (30s)",
            variable=self._auto_var,
            command=self._toggle_auto_refresh,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_frame, text="Refresh Now", width=100,
            command=self._start_load,
            fg_color="#3a7ebf", hover_color="#2b6194",
        ).pack(side="left")

        # Tabs
        self._tabs = ctk.CTkTabview(self, corner_radius=10)
        self._tabs.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        self._tab_dash = self._tabs.add("Dashboard")
        self._tab_sessions = self._tabs.add("Sessions")
        self._tab_detail = self._tabs.add("Session Detail")

        self._build_dashboard()
        self._build_sessions_tab()
        self._build_detail_tab()

    # ------ Dashboard tab
    def _build_dashboard(self):
        parent = self._tab_dash

        # Summary cards row
        self._cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._cards_frame.pack(fill="x", pady=(8, 4))

        self._card_widgets = {}
        cards_def = [
            ("api_value", "API-Equivalent Value", "$0.00"),
            ("plan_cost", "Your Plan Cost", "$0.00"),
            ("savings", "You Saved", "$0.00"),
            ("value_ratio", "Value Ratio", "0x"),
        ]
        for i, (key, label, default) in enumerate(cards_def):
            card = ctk.CTkFrame(self._cards_frame, corner_radius=10, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=8, pady=4, sticky="nsew")
            self._cards_frame.grid_columnconfigure(i, weight=1)

            ctk.CTkLabel(
                card, text=label,
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(pady=(10, 2), padx=12, anchor="w")

            val_lbl = ctk.CTkLabel(
                card, text=default,
                font=ctk.CTkFont(size=22, weight="bold"),
            )
            val_lbl.pack(pady=(0, 10), padx=12, anchor="w")
            self._card_widgets[key] = val_lbl

        # Second row: usage stats
        self._stats_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._stats_frame.pack(fill="x", pady=(0, 4))

        stats_def = [
            ("total_sessions", "Sessions", "0"),
            ("total_turns", "Total Turns", "0"),
            ("total_tokens", "Total Tokens", "0"),
        ]
        for i, (key, label, default) in enumerate(stats_def):
            card = ctk.CTkFrame(self._stats_frame, corner_radius=10, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=8, pady=4, sticky="nsew")
            self._stats_frame.grid_columnconfigure(i, weight=1)

            ctk.CTkLabel(
                card, text=label,
                font=ctk.CTkFont(size=11), text_color="gray",
            ).pack(pady=(8, 1), padx=12, anchor="w")

            val_lbl = ctk.CTkLabel(
                card, text=default,
                font=ctk.CTkFont(size=16, weight="bold"),
            )
            val_lbl.pack(pady=(0, 8), padx=12, anchor="w")
            self._card_widgets[key] = val_lbl

        # Peak hours panel
        peak_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        peak_frame.pack(fill="x", padx=8, pady=8)

        peak_header = ctk.CTkFrame(peak_frame, fg_color="transparent")
        peak_header.pack(fill="x", padx=12, pady=(10, 2))
        ctk.CTkLabel(
            peak_header, text="Usage by Hour of Day",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(side="left")
        self._peak_pill = ctk.CTkLabel(
            peak_header, text="—", corner_radius=10,
            fg_color="#444444", text_color="#ffffff",
            font=ctk.CTkFont(size=10, weight="bold"),
            width=90, height=20,
        )
        self._peak_pill.pack(side="right")

        self._peak_canvas = ctk.CTkCanvas(
            peak_frame, height=110, bg="#1e1e1e",
            highlightthickness=0,
        )
        self._peak_canvas.pack(fill="x", padx=12, pady=(4, 10))

        # Model breakdown
        breakdown_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        breakdown_frame.pack(fill="x", padx=8, pady=8)
        ctk.CTkLabel(
            breakdown_frame, text="Cost by Model",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self._model_breakdown_frame = ctk.CTkFrame(breakdown_frame, fg_color="transparent")
        self._model_breakdown_frame.pack(fill="x", padx=12, pady=(0, 10))

        # Top projects
        proj_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        proj_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        ctk.CTkLabel(
            proj_frame, text="Cost by Project",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(10, 4))

        self._project_breakdown_frame = ctk.CTkFrame(proj_frame, fg_color="transparent")
        self._project_breakdown_frame.pack(fill="both", expand=True, padx=12, pady=(0, 10))

    # ------ Sessions tab
    def _build_sessions_tab(self):
        parent = self._tab_sessions

        # Filter row
        filt = ctk.CTkFrame(parent, fg_color="transparent")
        filt.pack(fill="x", pady=(4, 8))

        self._sess_search_var = ctk.StringVar()
        ctk.CTkEntry(
            filt, textvariable=self._sess_search_var,
            placeholder_text="Filter by project, model, or session...",
            width=300, height=34,
        ).pack(side="left", padx=(0, 8))
        self._sess_search_var.trace_add("write", lambda *_: self._render_sessions())

        self._hide_archived_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            filt, text="Active only",
            variable=self._hide_archived_var,
            command=self._render_sessions,
            font=ctk.CTkFont(size=11),
        ).pack(side="left", padx=(8, 0))

        # Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.Treeview",
                        background="#1e1e1e", foreground="#e0e0e0",
                        fieldbackground="#1e1e1e", borderwidth=0,
                        font=("Segoe UI", 10))
        style.configure("Dark.Treeview.Heading",
                        background="#2b2b2b", foreground="#ffffff",
                        font=("Segoe UI", 10, "bold"))
        style.map("Dark.Treeview",
                   background=[("selected", "#3a7ebf")],
                   foreground=[("selected", "#ffffff")])

        cols = ("status", "project", "session_name", "model", "turns",
                "tok_in", "tok_cache_r", "tok_cache_w", "tok_out",
                "cache_hit", "init", "cost", "waste", "duration", "date")
        self._sess_tree = ttk.Treeview(
            parent, columns=cols, show="headings",
            style="Dark.Treeview", height=20,
        )

        headings = {
            "status": ("", 30),
            "project": ("Project", 140),
            "session_name": ("Session", 200),
            "model": ("Model", 110),
            "turns": ("Turns", 50),
            "tok_in": ("in", 55),
            "tok_cache_r": ("cache_r", 65),
            "tok_cache_w": ("cache_w", 65),
            "tok_out": ("out", 55),
            "cache_hit": ("Cache %", 60),
            "init": ("Init Tok", 65),
            "cost": ("Est. Cost", 75),
            "waste": ("Waste", 55),
            "duration": ("Duration", 70),
            "date": ("Date", 110),
        }
        numeric_cols = ("turns", "tok_in", "tok_cache_r", "tok_cache_w",
                        "tok_out", "cache_hit", "init", "cost", "waste")
        for col, (text, width) in headings.items():
            self._sess_tree.heading(
                col, text=text,
                command=lambda c=col: self._on_heading_click(c),
            )
            anchor = "e" if col in numeric_cols else "w"
            self._sess_tree.column(col, width=width, anchor=anchor, minwidth=40)

        self._sess_tree.pack(fill="both", expand=True)
        self._sess_tree.bind("<Double-1>", self._on_session_double_click)

        hint = ctk.CTkLabel(
            parent, text="Double-click a session to see per-turn detail",
            font=ctk.CTkFont(size=10), text_color="gray",
        )
        hint.pack(pady=(2, 4))

    # ------ Detail tab
    def _build_detail_tab(self):
        parent = self._tab_detail

        self._detail_header = ctk.CTkLabel(
            parent, text="Select a session from the Sessions tab",
            font=ctk.CTkFont(size=14, weight="bold"),
        )
        self._detail_header.pack(pady=(10, 4))

        self._detail_info = ctk.CTkLabel(
            parent, text="", font=ctk.CTkFont(size=11), text_color="gray",
        )
        self._detail_info.pack(pady=(0, 8))

        # Summary cards for selected session
        self._detail_cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        self._detail_cards_frame.pack(fill="x", padx=8, pady=(0, 4))

        self._detail_card_widgets = {}
        for i, (key, label) in enumerate([
            ("d_input", "Input Tokens"),
            ("d_output", "Output Tokens"),
            ("d_cache_read", "Cache Read"),
            ("d_cache_write", "Cache Write"),
            ("d_cost", "Total Cost"),
            ("d_waste", "Waste Factor"),
        ]):
            card = ctk.CTkFrame(self._detail_cards_frame, corner_radius=8, fg_color="#2b2b2b")
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            self._detail_cards_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=10), text_color="gray").pack(pady=(6, 1), padx=6)
            v = ctk.CTkLabel(card, text="—", font=ctk.CTkFont(size=15, weight="bold"))
            v.pack(pady=(0, 6), padx=6)
            self._detail_card_widgets[key] = v

        # Cost growth chart (text-based sparkline)
        chart_frame = ctk.CTkFrame(parent, corner_radius=10, fg_color="#2b2b2b")
        chart_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(
            chart_frame, text="Token Growth per Turn (cumulative)",
            font=ctk.CTkFont(size=12, weight="bold"),
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self._chart_canvas = ctk.CTkCanvas(
            chart_frame, height=120, bg="#1e1e1e",
            highlightthickness=0,
        )
        self._chart_canvas.pack(fill="x", padx=12, pady=(0, 10))

        # Turn-by-turn table
        turn_cols = ("turn", "timestamp", "cost", "tokens", "cumulative")
        self._turn_tree = ttk.Treeview(
            parent, columns=turn_cols, show="headings",
            style="Dark.Treeview", height=10,
        )
        for col, text, w in [
            ("turn", "#", 50), ("timestamp", "Time", 180),
            ("cost", "Cost", 90), ("tokens", "Tokens", 100),
            ("cumulative", "Cumulative $", 100),
        ]:
            self._turn_tree.heading(col, text=text)
            anchor = "e" if col in ("cost", "tokens", "cumulative") else "w"
            self._turn_tree.column(col, width=w, anchor=anchor)
        self._turn_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    # ------------------------------------------------------------------ Data loading
    def _start_load(self):
        if self._loading:
            return
        self._loading = True
        self._status_label.configure(text="Scanning sessions...")
        threading.Thread(target=self._bg_load, daemon=True).start()

    def _bg_load(self):
        sessions = load_all_sessions()
        active = _get_active_session_ids()
        self.after(0, lambda: self._on_loaded(sessions, active))

    def _on_loaded(self, sessions, active):
        self._sessions = sessions
        self._active_ids = active
        self._loading = False

        total = len(sessions)
        self._status_label.configure(
            text=f"{total} sessions loaded  |  Last refresh: {datetime.now().strftime('%H:%M:%S')}"
        )

        self._render_dashboard()
        self._render_sessions()

        # Schedule next auto-refresh
        if self._auto_refresh:
            self.after(30_000, self._auto_refresh_tick)

    def _toggle_auto_refresh(self):
        self._auto_refresh = self._auto_var.get()
        if self._auto_refresh:
            self.after(30_000, self._auto_refresh_tick)

    def _auto_refresh_tick(self):
        if not self._auto_refresh:
            return
        try:
            self.winfo_exists()
        except Exception:
            return
        self._start_load()

    def _on_plan_change(self, _val=None):
        self._plan = self._plan_var.get()
        self._render_dashboard()

    @staticmethod
    def _plan_monthly_cost(plan: str) -> float | None:
        """Return monthly $ cost for a plan, or None for API."""
        if "5x" in plan:
            return 100.0
        if "20x" in plan:
            return 200.0
        if "Pro" in plan:
            return 20.0
        return None  # API = pay-per-token

    def _months_spanned(self) -> float:
        """How many months the session data spans (min 1)."""
        first_ts, last_ts = None, None
        for s in self._sessions:
            t = _parse_timestamp(s.get("first_timestamp"))
            if t and (first_ts is None or t < first_ts):
                first_ts = t
            t = _parse_timestamp(s.get("last_timestamp"))
            if t and (last_ts is None or t > last_ts):
                last_ts = t
        if not first_ts or not last_ts:
            return 1.0
        days = max((last_ts - first_ts).days, 1)
        return max(days / 30.0, 1.0)

    # ------------------------------------------------------------------ Renderers
    def _render_dashboard(self):
        api_value = sum(s["total_cost"] for s in self._sessions)
        total_turns = sum(s["assistant_turns"] for s in self._sessions)
        total_tokens = sum(
            s["total_input"] + s["total_output"] + s["total_cache_read"] + s["total_cache_write"]
            for s in self._sessions
        )

        # Plan calculations
        monthly = self._plan_monthly_cost(self._plan)
        months = self._months_spanned()

        if monthly is not None:
            plan_total = monthly * months
            savings = api_value - plan_total
            ratio = api_value / plan_total if plan_total > 0 else 0

            self._card_widgets["api_value"].configure(text=_format_cost(api_value))
            self._card_widgets["plan_cost"].configure(
                text=f"${plan_total:.0f}",
            )
            self._card_widgets["savings"].configure(
                text=_format_cost(savings) if savings >= 0 else f"-{_format_cost(abs(savings))}",
                text_color="#44cc44" if savings >= 0 else "#ff4444",
            )
            self._card_widgets["value_ratio"].configure(
                text=f"{ratio:.1f}x",
                text_color="#44cc44" if ratio >= 1 else "#ff9500",
            )
        else:
            # API mode: just show total cost
            self._card_widgets["api_value"].configure(text=_format_cost(api_value))
            self._card_widgets["plan_cost"].configure(text="Pay-per-token")
            self._card_widgets["savings"].configure(text="N/A", text_color="gray")
            self._card_widgets["value_ratio"].configure(text="N/A", text_color="gray")

        self._card_widgets["total_sessions"].configure(text=str(len(self._sessions)))
        self._card_widgets["total_turns"].configure(text=f"{total_turns:,}")
        self._card_widgets["total_tokens"].configure(text=_format_tokens(total_tokens))

        # Peak hours
        self._render_peak_hours()

        # Model breakdown
        for w in self._model_breakdown_frame.winfo_children():
            w.destroy()

        model_costs: dict[str, float] = {}
        for s in self._sessions:
            for m in s["models_used"]:
                model_costs[m] = model_costs.get(m, 0) + s["total_cost"]
        if not model_costs:
            model_costs["No data"] = 0

        max_cost = max(model_costs.values()) if model_costs else 1
        for model, cost in sorted(model_costs.items(), key=lambda x: -x[1]):
            row = ctk.CTkFrame(self._model_breakdown_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=model, font=ctk.CTkFont(size=11), width=180).pack(side="left")

            bar_width = max(4, int(300 * (cost / max_cost))) if max_cost > 0 else 4
            bar = ctk.CTkFrame(row, width=bar_width, height=16, corner_radius=4, fg_color="#3a7ebf")
            bar.pack(side="left", padx=(8, 4))
            bar.pack_propagate(False)

            ctk.CTkLabel(row, text=_format_cost(cost), font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

        # Project breakdown
        for w in self._project_breakdown_frame.winfo_children():
            w.destroy()

        proj_costs: dict[str, float] = {}
        proj_sessions: dict[str, int] = {}
        proj_cwd: dict[str, str | None] = {}
        for s in self._sessions:
            p = s["project"]
            proj_costs[p] = proj_costs.get(p, 0) + s["total_cost"]
            proj_sessions[p] = proj_sessions.get(p, 0) + 1
            if p not in proj_cwd:
                proj_cwd[p] = s.get("cwd")

        max_pc = max(proj_costs.values()) if proj_costs else 1
        for proj, cost in sorted(proj_costs.items(), key=lambda x: -x[1]):
            row = ctk.CTkFrame(self._project_breakdown_frame, fg_color="transparent")
            row.pack(fill="x", pady=2)

            friendly = _friendly_project(proj, proj_cwd.get(proj))
            ctk.CTkLabel(row, text=friendly, font=ctk.CTkFont(size=11), width=220, anchor="w").pack(side="left")

            bar_width = max(4, int(250 * (cost / max_pc))) if max_pc > 0 else 4
            bar = ctk.CTkFrame(row, width=bar_width, height=16, corner_radius=4, fg_color="#bf6a3a")
            bar.pack(side="left", padx=(8, 4))
            bar.pack_propagate(False)

            info = f"{_format_cost(cost)}  ({proj_sessions[proj]} sessions)"
            ctk.CTkLabel(row, text=info, font=ctk.CTkFont(size=11)).pack(side="left", padx=4)

    def _render_peak_hours(self):
        """Draw 24-bar chart of total cost per hour-of-day and update peak pill."""
        # Aggregate cost per local hour across every turn
        hour_costs = [0.0] * 24
        for s in self._sessions:
            for tc in s["turn_costs"]:
                ts_str, cost = tc[0], tc[1]
                ts = _parse_timestamp(ts_str)
                if not ts:
                    continue
                local_hour = ts.astimezone().hour
                hour_costs[local_hour] += cost

        # Top 3 peak hours
        ranked = sorted(range(24), key=lambda h: hour_costs[h], reverse=True)
        peak_hours = {h for h in ranked[:3] if hour_costs[h] > 0}

        # Update pill based on current local hour
        now_hour = datetime.now().hour
        if not peak_hours:
            self._peak_pill.configure(text="NO DATA", fg_color="#444444")
        elif now_hour in peak_hours:
            self._peak_pill.configure(text="PEAK HOUR", fg_color="#cc3333")
        else:
            self._peak_pill.configure(text="OFF-PEAK", fg_color="#2a8a2a")

        # Draw bars
        c = self._peak_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 1000
        h = c.winfo_height() or 110

        pad_l, pad_r, pad_t, pad_b = 30, 10, 8, 18
        chart_w = w - pad_l - pad_r
        chart_h = h - pad_t - pad_b
        bar_slot = chart_w / 24
        bar_w = max(2, bar_slot * 0.7)

        max_cost = max(hour_costs) if any(hour_costs) else 1.0

        for hr in range(24):
            cost = hour_costs[hr]
            bar_h = (cost / max_cost) * chart_h if max_cost > 0 else 0
            x0 = pad_l + hr * bar_slot + (bar_slot - bar_w) / 2
            x1 = x0 + bar_w
            y0 = pad_t + chart_h - bar_h
            y1 = pad_t + chart_h

            if hr in peak_hours:
                color = "#e05a2a"  # peak highlight
            elif hr == now_hour:
                color = "#6a9ed5"  # current-hour tint
            else:
                color = "#3a6a94"

            if bar_h > 0:
                c.create_rectangle(x0, y0, x1, y1, fill=color, outline="")

            # Hour labels (every 3 hours to reduce clutter)
            if hr % 3 == 0:
                c.create_text(
                    x0 + bar_w / 2, pad_t + chart_h + 2,
                    text=f"{hr:02d}", fill="#888888",
                    anchor="n", font=("Segoe UI", 8),
                )

        # Y-axis max label
        c.create_text(
            pad_l - 4, pad_t, text=_format_cost(max_cost),
            fill="#888888", anchor="ne", font=("Segoe UI", 8),
        )
        c.create_text(
            pad_l - 4, pad_t + chart_h, text="$0",
            fill="#888888", anchor="se", font=("Segoe UI", 8),
        )

    def _render_sessions(self):
        for item in self._sess_tree.get_children():
            self._sess_tree.delete(item)

        query = self._sess_search_var.get().strip().lower()
        hide_archived = self._hide_archived_var.get()

        # Build rows with both display values and raw sortable values
        rows = []
        for s in self._sessions:
            is_active = s["session_id"] in self._active_ids

            if hide_archived and not is_active:
                continue

            proj = _friendly_project(s["project"], s.get("cwd"))
            model = s["model"] or "unknown"
            sess_name = s.get("session_name") or "Untitled"

            if query and query not in proj.lower() and query not in model.lower() and query not in sess_name.lower():
                continue
            status = "LIVE" if is_active else ""
            tok_in = s["total_input"]
            tok_out = s["total_output"]
            tok_cr = s["total_cache_read"]
            tok_cw = s["total_cache_write"]
            wf = _waste_factor(s["turn_costs"])
            waste_str = f"{wf:.1f}x" if wf is not None else "—"
            init_tokens = (
                s["turn_costs"][0][2] + s["turn_costs"][0][3]
                + s["turn_costs"][0][4] + s["turn_costs"][0][5]
            ) if s["turn_costs"] else 0
            duration = _duration_str(s["first_timestamp"], s["last_timestamp"])

            cache_denom = tok_cr + tok_cw + tok_in
            cache_hit_pct = (tok_cr / cache_denom * 100.0) if cache_denom > 0 else 0.0
            cache_hit_str = f"{cache_hit_pct:.0f}%" if cache_denom > 0 else "—"

            date_str = ""
            ts = _parse_timestamp(s["last_timestamp"])
            if ts:
                local = ts.astimezone()
                date_str = local.strftime("%Y-%m-%d %H:%M")

            tags = ("active",) if is_active else ()

            display = (status, proj, sess_name, model, s["assistant_turns"],
                       _format_tokens(tok_in), _format_tokens(tok_cr),
                       _format_tokens(tok_cw), _format_tokens(tok_out),
                       cache_hit_str,
                       _format_tokens(init_tokens),
                       _format_cost(s["total_cost"]),
                       waste_str, duration, date_str)

            # Raw values for sorting (numeric where applicable)
            sort_vals = {
                "status": (0 if is_active else 1),
                "project": proj.lower(),
                "session_name": sess_name.lower(),
                "model": model.lower(),
                "turns": s["assistant_turns"],
                "tok_in": tok_in,
                "tok_cache_r": tok_cr,
                "tok_cache_w": tok_cw,
                "tok_out": tok_out,
                "cache_hit": cache_hit_pct,
                "init": init_tokens,
                "cost": s["total_cost"],
                "waste": wf if wf is not None else 0,
                "duration": (ts.timestamp() if ts else 0) - (_parse_timestamp(s["first_timestamp"]).timestamp() if _parse_timestamp(s["first_timestamp"]) else 0),
                "date": s["last_timestamp"] or "",
            }

            rows.append((s["session_id"], display, tags, sort_vals))

        # Apply current sort
        col, reverse = self._sort_col, self._sort_reverse
        if col:
            rows.sort(key=lambda r: r[3].get(col, ""), reverse=reverse)

        for sid, display, tags, _ in rows:
            self._sess_tree.insert("", "end", iid=sid, values=display, tags=tags)

        self._sess_tree.tag_configure("active", foreground="#44ee44")

    def _on_heading_click(self, col):
        """Sort sessions table by clicked column header."""
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False

        # Update heading arrows
        cols = ("status", "project", "session_name", "model", "turns",
                "tok_in", "tok_cache_r", "tok_cache_w", "tok_out",
                "cache_hit", "init", "cost", "waste", "duration", "date")
        base_headings = {
            "status": "", "project": "Project", "session_name": "Session",
            "model": "Model", "turns": "Turns",
            "tok_in": "in", "tok_cache_r": "cache_r",
            "tok_cache_w": "cache_w", "tok_out": "out",
            "cache_hit": "Cache %",
            "init": "Init Tok",
            "cost": "Est. Cost", "waste": "Waste", "duration": "Duration", "date": "Date",
        }
        for c in cols:
            arrow = ""
            if c == self._sort_col:
                arrow = " v" if self._sort_reverse else " ^"
            self._sess_tree.heading(c, text=base_headings[c] + arrow)

        self._render_sessions()

    def _on_session_double_click(self, event):
        sel = self._sess_tree.selection()
        if not sel:
            return
        sid = sel[0]
        session = None
        for s in self._sessions:
            if s["session_id"] == sid:
                session = s
                break
        if not session:
            return

        self._show_session_detail(session)
        self._tabs.set("Session Detail")

    def _show_session_detail(self, s: dict):
        proj = _friendly_project(s["project"], s.get("cwd"))
        sess_name = s.get("session_name") or "Untitled"
        model = s["model"] or "unknown"
        is_active = s["session_id"] in self._active_ids
        status_str = "  [LIVE]" if is_active else ""
        self._detail_header.configure(text=f"{proj}{status_str}")

        info_parts = [
            f"Model: {model}",
            f"Branch: {s['git_branch'] or '—'}",
            f"Version: {s['version'] or '—'}",
            f"Duration: {_duration_str(s['first_timestamp'], s['last_timestamp'])}",
        ]
        self._detail_info.configure(text=f"\"{sess_name}\"\n{'  |  '.join(info_parts)}")

        # Cards
        self._detail_card_widgets["d_input"].configure(text=_format_tokens(s["total_input"]))
        self._detail_card_widgets["d_output"].configure(text=_format_tokens(s["total_output"]))
        self._detail_card_widgets["d_cache_read"].configure(text=_format_tokens(s["total_cache_read"]))
        self._detail_card_widgets["d_cache_write"].configure(text=_format_tokens(s["total_cache_write"]))
        self._detail_card_widgets["d_cost"].configure(text=_format_cost(s["total_cost"]))

        wf = _waste_factor(s["turn_costs"])
        if wf is not None:
            waste_text = f"{wf:.1f}x"
            color = "#44cc44" if wf < 3 else "#ff9500" if wf < 8 else "#ff4444"
            self._detail_card_widgets["d_waste"].configure(text=waste_text, text_color=color)
        else:
            self._detail_card_widgets["d_waste"].configure(text="—", text_color="gray")

        # Chart
        self._draw_chart(s["turn_costs"])

        # Turn table
        for item in self._turn_tree.get_children():
            self._turn_tree.delete(item)

        cum_cost = 0.0
        for i, (ts_str, cost, inp, out, cr, cw, _model) in enumerate(s["turn_costs"]):
            tokens = inp + out + cr + cw
            cum_cost += cost
            ts = _parse_timestamp(ts_str)
            time_str = ts.astimezone().strftime("%H:%M:%S") if ts else "—"
            self._turn_tree.insert("", "end", values=(
                i + 1, time_str, _format_cost(cost),
                _format_tokens(tokens), _format_cost(cum_cost),
            ))

    def _draw_chart(self, turn_costs: list):
        c = self._chart_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 600
        h = c.winfo_height() or 120

        if len(turn_costs) < 2:
            c.create_text(w // 2, h // 2, text="Not enough data", fill="gray", font=("Segoe UI", 10))
            return

        # Cumulative tokens
        cum = []
        total = 0
        for tc in turn_costs:
            tokens = tc[2] + tc[3] + tc[4] + tc[5]
            total += tokens
            cum.append(total)

        max_val = max(cum) if cum else 1
        pad_x, pad_y = 10, 10
        chart_w = w - 2 * pad_x
        chart_h = h - 2 * pad_y

        points = []
        for i, val in enumerate(cum):
            x = pad_x + (i / (len(cum) - 1)) * chart_w
            y = pad_y + chart_h - (val / max_val) * chart_h
            points.append((x, y))

        # Fill area
        fill_pts = [(pad_x, pad_y + chart_h)] + points + [(pad_x + chart_w, pad_y + chart_h)]
        flat = [coord for pt in fill_pts for coord in pt]
        c.create_polygon(flat, fill="#1a3a5c", outline="")

        # Line
        line_flat = [coord for pt in points for coord in pt]
        c.create_line(line_flat, fill="#3a9eef", width=2, smooth=True)

        # Labels
        c.create_text(pad_x + 4, pad_y, text=_format_tokens(max_val), fill="gray",
                       anchor="nw", font=("Segoe UI", 8))
        c.create_text(pad_x + chart_w, pad_y + chart_h, text=f"{len(cum)} turns", fill="gray",
                       anchor="se", font=("Segoe UI", 8))


# ---------------------------------------------------------------------------
# Entry point for toolbox
# ---------------------------------------------------------------------------

def run_tool():
    ClaudeUsageMonitor()
