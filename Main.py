"""
Main.py: Premium Toolbox GUI Application
Refactored for Grid Layout, Search, and Smart Icons.

Tools are launched as isolated subprocesses via ``tools._runner`` so a
crashing tool cannot bring down the launcher. Tool discovery uses
``ast.parse`` to read ``TOOL_NAME`` and the module docstring without
executing arbitrary code.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

import customtkinter as ctk
import psutil
from tkinter import messagebox

from tools._common.logging import get_log_dir, get_logger

# -------------------- Global Configuration --------------------
BASE_DIR = Path(__file__).resolve().parent
TOOL_FOLDER = BASE_DIR / "tools"
FAVORITES_PATH = BASE_DIR / "favorites.json"

log = get_logger("launcher")

# -------------------- Smart Icon Mapping --------------------
ICON_MAP = {
    "network": "🌐",
    "security": "🛡️",
    "monitor": "📊",
    "todo": "📝",
    "doc": "📄",
    "code": "💻",
    "input": "🔒",
    "lock": "🔐",
    "temp": "🌡️",
    "notification": "🔔",
    "reminder": "⏰",
    "rng": "🎲",
    "decision": "🤔",
}


def get_icon(name: str) -> str:
    """Return an emoji icon for the given tool name."""
    name_lower = name.lower()
    for key, icon in ICON_MAP.items():
        if key in name_lower:
            return icon
    return "🛠️"


# -------------------- AST-based tool discovery --------------------

def _extract_string_assign(node: ast.Assign, target_name: str) -> Optional[str]:
    """Return the string value assigned to *target_name* on this node, else None."""
    if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
        return None
    for tgt in node.targets:
        if isinstance(tgt, ast.Name) and tgt.id == target_name:
            return node.value.value
    return None


def _parse_tool_metadata(path: Path) -> Optional[dict]:
    """Parse *path* with ``ast`` and extract TOOL_NAME, TOOL_DESC/description, docstring.

    Args:
        path: Path to a ``.py`` file under the tools folder.

    Returns:
        A dict with keys ``name``, ``description``, ``filename``, ``path``,
        or None if the file is not a valid tool (parse error, no ``TOOL_NAME``,
        no ``run_tool`` defined).
    """
    try:
        source = path.read_text(encoding="utf-8")
    except Exception as exc:
        log.warning("failed to read %s: %s", path, exc)
        return None

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        log.warning("failed to parse %s: %s", path, exc)
        return None

    tool_name: Optional[str] = None
    tool_desc: Optional[str] = None
    tool_desc_alt: Optional[str] = None
    has_run_tool = False

    for node in tree.body:
        if isinstance(node, ast.Assign):
            if tool_name is None:
                tool_name = _extract_string_assign(node, "TOOL_NAME")
            if tool_desc is None:
                tool_desc = _extract_string_assign(node, "TOOL_DESC")
            if tool_desc_alt is None:
                tool_desc_alt = _extract_string_assign(node, "TOOL_DESCRIPTION")
        elif isinstance(node, ast.FunctionDef) and node.name == "run_tool":
            has_run_tool = True

    if tool_name is None or not has_run_tool:
        return None

    docstring = ast.get_docstring(tree) or ""
    description = (tool_desc or tool_desc_alt or "").strip()
    if not description and docstring:
        description = docstring.splitlines()[0].strip()

    return {
        "name": tool_name,
        "description": description,
        "filename": path.name,
        "path": str(path),
        "id": path.name,
    }


def discover_tools(tool_folder: Path) -> tuple[list[dict], list[dict]]:
    """Discover tools under *tool_folder* without executing their code.

    Args:
        tool_folder: Directory containing tool ``.py`` files.

    Returns:
        Tuple ``(tools, failures)``. ``tools`` is a list of dicts ready for
        display. ``failures`` is a list of ``{"filename", "error"}`` for
        files that looked like tools but failed to parse.
    """
    tools: list[dict] = []
    failures: list[dict] = []

    if not tool_folder.is_dir():
        return tools, failures

    for entry in sorted(tool_folder.iterdir()):
        if entry.is_dir():
            continue
        if entry.suffix != ".py":
            continue
        if entry.name.startswith("_"):
            continue

        try:
            meta = _parse_tool_metadata(entry)
        except Exception as exc:  # defensive: AST parsing should not raise
            log.warning("unexpected error discovering %s: %s", entry, exc)
            failures.append({"filename": entry.name, "error": str(exc)})
            continue

        if meta is None:
            # Could be a non-tool helper, a parse failure, or missing run_tool.
            # Differentiate by attempting a second parse to report errors clearly.
            try:
                ast.parse(entry.read_text(encoding="utf-8"), filename=str(entry))
            except SyntaxError as exc:
                failures.append({"filename": entry.name, "error": f"SyntaxError: {exc}"})
            continue

        tools.append(meta)

    return tools, failures


# -------------------- Tool Loading Logic --------------------
class ToolboxApp(ctk.CTk):
    """Main launcher window."""

    def __init__(self) -> None:
        super().__init__()

        self.title("Automations Toolbox Pro")
        self.geometry("900x700")

        self.all_tools: list[dict] = []
        self.failed_tools: list[dict] = []
        self.filtered_tools: list[dict] = []
        self.favorites: set[str] = self._load_favorites()
        # Process tracking: tool_id -> Popen (single-instance enforcement)
        self._tool_procs: dict[str, subprocess.Popen] = {}
        # Reader threads that drain each subprocess's stderr into a file
        self._reader_threads: dict[str, threading.Thread] = {}

        self._build_sidebar()
        self._build_main_content()

        # Initialize
        self._last_columns: Optional[int] = None
        self._resize_job: Optional[str] = None
        self.refresh_tools()
        self._start_stats_loop()
        self._start_proc_reaper()

        # Re-render grid on resize for a responsive layout (column-count based)
        self.bind("<Configure>", self._on_resize)

        # Keyboard shortcuts
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.bind("<Control-F>", lambda _e: self.search_entry.focus_set())
        self.bind("<Return>", self._launch_first_tool_shortcut)

        # Terminate child tools on window close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="TOOLBOX\nPRO", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.pack(pady=(30, 20))

        # Stats Section
        self.stats_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.stats_frame.pack(pady=20, padx=10, fill="x")

        ctk.CTkLabel(self.stats_frame, text="SYSTEM STATS", font=ctk.CTkFont(size=12, weight="bold"), text_color="gray").pack(anchor="w")

        self.cpu_label = ctk.CTkLabel(self.stats_frame, text="CPU: 0%", font=ctk.CTkFont(size=13))
        self.cpu_label.pack(anchor="w", pady=2)

        self.ram_label = ctk.CTkLabel(self.stats_frame, text="RAM: 0%", font=ctk.CTkFont(size=13))
        self.ram_label.pack(anchor="w", pady=2)

        self.sidebar_sep = ctk.CTkFrame(self.sidebar, height=2, fg_color="#333333")
        self.sidebar_sep.pack(fill="x", pady=20, padx=20)

        self.refresh_btn = ctk.CTkButton(self.sidebar, text="Refresh Tools", command=self.refresh_tools, fg_color="#3a7ebf", hover_color="#2b6194")
        self.refresh_btn.pack(pady=10, padx=20)

        self.troubleshoot_btn = ctk.CTkButton(self.sidebar, text="Troubleshoot", command=self.show_troubleshooting, fg_color="#ff9500", hover_color="#cc7700")
        self.troubleshoot_btn.pack(pady=5, padx=20)

        self.fav_only_var = ctk.BooleanVar(value=False)
        self.fav_only_chk = ctk.CTkCheckBox(
            self.sidebar,
            text="Show favorites only",
            variable=self.fav_only_var,
            command=lambda: self._render_tools(self.search_var.get() if hasattr(self, "search_var") else ""),
        )
        self.fav_only_chk.pack(pady=(0, 10), padx=20, anchor="w")

        self.quit_btn = ctk.CTkButton(self.sidebar, text="Exit App", command=self._on_close, fg_color="#bf3a3a", hover_color="#942b2b")
        self.quit_btn.pack(side="bottom", pady=20, padx=20)

    def _build_main_content(self) -> None:
        self.content_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.content_frame.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        # Title / description
        self.title_block = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.title_block.pack(fill="x", pady=(0, 10))

        title_font = ctk.CTkFont(size=22, weight="bold")
        subtitle_font = ctk.CTkFont(size=13)

        self.main_title = ctk.CTkLabel(
            self.title_block,
            text="Automations Toolbox Pro",
            font=title_font,
        )
        self.main_title.pack(anchor="w")

        self.main_subtitle = ctk.CTkLabel(
            self.title_block,
            text="Browse, search and launch your desktop tools from one place.",
            font=subtitle_font,
            text_color="gray",
        )
        self.main_subtitle.pack(anchor="w", pady=(4, 0))

        # Header with Search + stats
        self.header = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.header.pack(fill="x", pady=(0, 20))

        self.search_var = ctk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)

        self.search_entry = ctk.CTkEntry(
            self.header,
            placeholder_text="Search tools by name, description, or filename...",
            width=420,
            height=45,
            textvariable=self.search_var,
        )
        self.search_entry.pack(side="left")

        self.clear_search_btn = ctk.CTkButton(
            self.header,
            text="Clear",
            width=70,
            height=32,
            command=lambda: self.search_var.set(""),
            fg_color="#444444",
            hover_color="#555555",
        )
        self.clear_search_btn.pack(side="left", padx=(10, 0))

        # Tool count label on the right
        self.tool_count_label = ctk.CTkLabel(
            self.header,
            text="",
            font=ctk.CTkFont(size=13),
            text_color="gray",
        )
        self.tool_count_label.pack(side="right", padx=(10, 0))

        # Tool Scroll Area
        self.scroll_canvas = ctk.CTkScrollableFrame(self.content_frame, corner_radius=15, fg_color="#1a1a1a")
        self.scroll_canvas.pack(fill="both", expand=True)

        # Inner grid frame
        self.grid_frame = ctk.CTkFrame(self.scroll_canvas, fg_color="transparent")
        self.grid_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # -------------------- Layout helpers --------------------
    def _get_column_count(self) -> int:
        try:
            width = self.scroll_canvas.winfo_width() or self.content_frame.winfo_width()
        except Exception:
            width = 0

        if width <= 0:
            return 3

        approx_card_plus_margin = 240
        cols = max(1, min(4, width // approx_card_plus_margin))
        return cols or 1

    def _on_resize(self, _event=None) -> None:
        try:
            new_cols = self._get_column_count()
        except Exception:
            return

        if new_cols == self._last_columns:
            return

        self._last_columns = new_cols

        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
        self._resize_job = self.after(
            200,
            lambda: self._render_tools(self.search_var.get() if hasattr(self, "search_var") else ""),
        )

    # -------------------- Favorites persistence --------------------
    def _load_favorites(self) -> set[str]:
        try:
            if not FAVORITES_PATH.exists():
                return set()
            with FAVORITES_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return {str(x) for x in data}
        except Exception:
            pass
        return set()

    def _save_favorites(self) -> None:
        try:
            data = sorted(self.favorites)
            with FAVORITES_PATH.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _launch_first_tool_shortcut(self, _event=None) -> None:
        if self.filtered_tools:
            self._launch_tool(self.filtered_tools[0])

    def _on_search_change(self, *args) -> None:
        if hasattr(self, "_search_job") and self._search_job is not None:
            try:
                self.after_cancel(self._search_job)
            except Exception:
                pass

        self._search_job = self.after(
            300,
            lambda: self._render_tools(self.search_var.get()),
        )

    def load_tools(self) -> list[dict]:
        """Discover tools and the list of parse failures.

        Returns:
            A list of tool descriptor dicts.
        """
        tools, failures = discover_tools(TOOL_FOLDER)
        self.failed_tools = failures
        for t in tools:
            t["favorite"] = t["id"] in self.favorites
        return tools

    def refresh_tools(self) -> None:
        self.all_tools = self.load_tools()
        self._render_tools()

    # -------------------- Subprocess plumbing --------------------
    def _log_path_for(self, tool_id: str, pid: int) -> Path:
        """Return the stderr log path for ``<tool>-<pid>.log``."""
        safe = tool_id.replace(os.sep, "_").replace(" ", "_")
        if safe.endswith(".py"):
            safe = safe[:-3]
        return get_log_dir() / f"{safe}-{pid}.log"

    def _stderr_reader(self, proc: subprocess.Popen, log_file: Path) -> None:
        """Drain a subprocess's stderr into ``log_file`` (runs in a thread)."""
        try:
            with log_file.open("w", encoding="utf-8") as f:
                assert proc.stderr is not None
                for line in iter(proc.stderr.readline, b""):
                    try:
                        f.write(line.decode("utf-8", errors="replace"))
                        f.flush()
                    except Exception:
                        break
        except Exception as exc:
            log.warning("stderr reader crashed for %s: %s", log_file.name, exc)

    def _launch_tool(self, tool_dict: dict) -> None:
        """Spawn the tool as a subprocess. Single-instance: focus existing run instead."""
        name = tool_dict.get("name", "Tool")
        tool_id = tool_dict.get("id") or tool_dict.get("filename") or ""
        path = tool_dict.get("path")

        if not tool_id or not path:
            messagebox.showerror("Tool launch failed", f"Missing path for '{name}'.")
            return

        # Single-instance: if the previous process is still alive, do nothing
        # (cannot reliably focus a child window owned by another OS process
        # from pure Python on Windows without platform APIs — keep it simple).
        existing = self._tool_procs.get(tool_id)
        if existing is not None and existing.poll() is None:
            messagebox.showinfo(
                "Already running",
                f"'{name}' is already running (pid {existing.pid}).",
            )
            return

        # Purge any stale entry before spawning a new process.
        self._tool_procs.pop(tool_id, None)

        try:
            creation_flags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            proc = subprocess.Popen(
                [sys.executable, "-m", "tools._runner", str(path)],
                cwd=str(BASE_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=creation_flags,
            )
        except Exception as exc:
            log.exception("failed to spawn %s", tool_id)
            messagebox.showerror(
                "Tool launch failed",
                f"An error occurred while launching '{name}':\n\n{exc}",
            )
            return

        self._tool_procs[tool_id] = proc
        log_file = self._log_path_for(tool_id, proc.pid)

        reader = threading.Thread(
            target=self._stderr_reader,
            args=(proc, log_file),
            daemon=True,
            name=f"stderr-{tool_id}",
        )
        reader.start()
        self._reader_threads[tool_id] = reader

        log.info("spawned %s pid=%d log=%s", tool_id, proc.pid, log_file)

    def _start_proc_reaper(self) -> None:
        """Poll every 500ms for exited children so we can surface crash toasts."""
        self._reap_dead_procs()
        try:
            self.after(500, self._start_proc_reaper)
        except Exception:
            # The app is being torn down; stop polling.
            pass

    def _reap_dead_procs(self) -> None:
        for tool_id, proc in list(self._tool_procs.items()):
            rc = proc.poll()
            if rc is None:
                continue
            self._tool_procs.pop(tool_id, None)
            if rc != 0:
                self._notify_crash(tool_id, proc.pid, rc)
            else:
                log.info("tool %s exited cleanly pid=%d", tool_id, proc.pid)

    def _notify_crash(self, tool_id: str, pid: int, rc: int) -> None:
        """Surface a crash to the user and point at the log file."""
        log_file = self._log_path_for(tool_id, pid)
        display_name = tool_id
        for t in self.all_tools:
            if t.get("id") == tool_id:
                display_name = t.get("name") or tool_id
                break
        log.warning("tool %s exited rc=%d pid=%d", tool_id, rc, pid)

        message = (
            f"'{display_name}' exited unexpectedly (code {rc}).\n\n"
            f"Log: {log_file}\n\n"
            f"Open log folder?"
        )
        try:
            open_folder = messagebox.askyesno(
                f"{display_name} exited unexpectedly",
                message,
            )
        except Exception:
            return

        if open_folder:
            self._open_path(log_file.parent)

    @staticmethod
    def _open_path(path: Path) -> None:
        """Open *path* in the platform's file explorer."""
        try:
            if sys.platform == "win32":
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            log.warning("could not open %s: %s", path, exc)

    def _on_close(self) -> None:
        """Terminate running tools (best effort) and exit cleanly."""
        for tool_id, proc in list(self._tool_procs.items()):
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        try:
            self.destroy()
        except Exception:
            pass
        self.quit()

    def _render_tools(self, filter_query: str = "") -> None:
        # Clear current grid
        for child in self.grid_frame.winfo_children():
            child.destroy()

        # Build filtered list
        fq = (filter_query or "").strip().lower()
        base: list[dict] = []
        if fq:
            for t in self.all_tools:
                name = t["name"].lower()
                desc = (t.get("description") or "").lower()
                fname = (t.get("filename") or "").lower()
                if fq in name or fq in desc or fq in fname:
                    base.append(t)
        else:
            base = list(self.all_tools)

        # Apply favorites-only filter if enabled
        if getattr(self, "fav_only_var", None) is not None and self.fav_only_var.get():
            filtered = [t for t in base if t.get("favorite")]
        else:
            filtered = base

        # Sort: favorites first, then name
        filtered.sort(key=lambda t: (not t.get("favorite"), t["name"].lower()))

        # Keep for keyboard shortcut launch
        self.filtered_tools = filtered

        # Update header stats
        total = len(self.all_tools)
        shown = len(filtered)
        if total == 0:
            self.tool_count_label.configure(text="No tools found in /tools folder")
        else:
            if fq:
                self.tool_count_label.configure(text=f"Showing {shown} of {total} tools")
            else:
                self.tool_count_label.configure(text=f"{total} tools")

        if not filtered:
            empty_lbl = ctk.CTkLabel(
                self.grid_frame,
                text="No tools match your filters.",
                font=ctk.CTkFont(size=16, weight="bold"),
                text_color="gray",
            )
            empty_lbl.pack(pady=40)
            return

        columns = self._get_column_count()
        for c in range(columns):
            self.grid_frame.grid_columnconfigure(c, weight=1)

        for i, tool in enumerate(filtered):
            row = i // columns
            col = i % columns

            card = ctk.CTkFrame(self.grid_frame, width=210, height=160, corner_radius=12, fg_color="#2b2b2b")
            card.grid(row=row, column=col, padx=15, pady=15, sticky="nsew")
            card.grid_propagate(False)

            top_row = ctk.CTkFrame(card, fg_color="transparent")
            top_row.pack(fill="x", pady=(8, 0), padx=8)

            icon = get_icon(tool["name"])
            ctk.CTkLabel(top_row, text=icon, font=ctk.CTkFont(size=30)).pack(side="left")

            fav_icon = "★" if tool.get("favorite") else "☆"
            fav_btn = ctk.CTkButton(
                top_row,
                text=fav_icon,
                width=30,
                height=26,
                fg_color="transparent",
                border_width=0,
                hover_color="#444444",
            )
            fav_btn.pack(side="right")

            def toggle_fav(t=tool, btn=fav_btn):
                tid = t.get("id")
                if not tid:
                    return
                if tid in self.favorites:
                    self.favorites.remove(tid)
                    t["favorite"] = False
                    btn.configure(text="☆")
                else:
                    self.favorites.add(tid)
                    t["favorite"] = True
                    btn.configure(text="★")
                self._save_favorites()
                self.after(100, lambda: self._render_tools(self.search_var.get()))

            fav_btn.configure(command=toggle_fav)

            name_lbl = ctk.CTkLabel(
                card,
                text=tool["name"],
                font=ctk.CTkFont(size=13, weight="bold"),
                wraplength=180,
            )
            name_lbl.pack(pady=(2, 0), padx=10)

            desc_text = tool.get("description") or tool.get("filename") or ""
            if desc_text:
                desc_lbl = ctk.CTkLabel(
                    card,
                    text=desc_text,
                    font=ctk.CTkFont(size=10),
                    text_color="gray",
                    wraplength=180,
                    justify="center",
                )
                desc_lbl.pack(pady=(0, 4), padx=10)

            run_btn = ctk.CTkButton(card, text="Launch", width=120, height=32, corner_radius=16,
                                    command=lambda t=tool: self._launch_tool(t),
                                    fg_color="transparent", border_width=2,
                                    hover_color="#3a7ebf")
            run_btn.pack(side="bottom", pady=(4, 8))

            # Hover effects — bind on the card and all its children to avoid flicker
            def _bind_hover(widget, card_ref):
                widget.bind("<Enter>", lambda e, c=card_ref: c.configure(fg_color="#333333"))
                widget.bind("<Leave>", lambda e, c=card_ref: c.configure(fg_color="#2b2b2b"))
                for child_widget in widget.winfo_children():
                    _bind_hover(child_widget, card_ref)

            _bind_hover(card, card)

    def _start_stats_loop(self) -> None:
        def poll():
            try:
                cpu = psutil.cpu_percent()
                ram = psutil.virtual_memory().percent
                self.cpu_label.configure(text=f"CPU: {cpu}%")
                self.ram_label.configure(text=f"RAM: {ram}%")
            except Exception:
                pass
            self.after(2000, poll)
        poll()

    def show_troubleshooting(self) -> None:
        """Show troubleshooting information for failed tools."""
        troubleshoot_window = ctk.CTkToplevel(self)
        troubleshoot_window.title("Tool Troubleshooting")
        troubleshoot_window.geometry("600x400")

        main_frame = ctk.CTkFrame(troubleshoot_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        title = ctk.CTkLabel(main_frame, text="🔧 Tool Troubleshooting", font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(pady=(0, 20))

        scroll_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        scroll_frame.pack(fill="both", expand=True)

        info_frame = ctk.CTkFrame(scroll_frame)
        info_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(info_frame, text="📊 System Information", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))

        system_info = [
            f"Python Version: {sys.version}",
            f"Platform: {sys.platform}",
            f"Tools Folder: {TOOL_FOLDER}",
            f"Tools Folder Exists: {TOOL_FOLDER.exists()}",
            f"Log Folder: {get_log_dir()}",
        ]

        for info in system_info:
            ctk.CTkLabel(info_frame, text=f"• {info}", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=2)

        if self.failed_tools:
            failed_frame = ctk.CTkFrame(scroll_frame)
            failed_frame.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(failed_frame, text="❌ Failed Tools", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))

            for tool in self.failed_tools:
                tool_info = ctk.CTkFrame(failed_frame)
                tool_info.pack(fill="x", padx=20, pady=5)

                ctk.CTkLabel(tool_info, text=f"📁 {tool['filename']}", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(5, 2))
                ctk.CTkLabel(tool_info, text=f"⚠️ Error: {tool['error']}", font=ctk.CTkFont(size=10), text_color="red").pack(anchor="w", padx=20, pady=(2, 5))
        else:
            success_frame = ctk.CTkFrame(scroll_frame)
            success_frame.pack(fill="x", pady=(0, 10))

            ctk.CTkLabel(success_frame, text="✅ All Tools Loaded Successfully", font=ctk.CTkFont(size=14, weight="bold"), text_color="green").pack(anchor="w", padx=10, pady=10)
            ctk.CTkLabel(success_frame, text="No tool loading errors detected.", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=(0, 10))

        success_count = len(self.all_tools)
        total_files = 0
        if TOOL_FOLDER.exists():
            total_files = len([f for f in TOOL_FOLDER.iterdir() if f.suffix == ".py" and not f.name.startswith("_")])

        stats_frame = ctk.CTkFrame(scroll_frame)
        stats_frame.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(stats_frame, text="📈 Loading Statistics", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        ctk.CTkLabel(stats_frame, text=f"• Total Python files: {total_files}", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(stats_frame, text=f"• Successfully loaded: {success_count}", font=ctk.CTkFont(size=11), text_color="green").pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(stats_frame, text=f"• Failed to load: {len(self.failed_tools)}", font=ctk.CTkFont(size=11), text_color="red").pack(anchor="w", padx=20, pady=(2, 10))

        close_btn = ctk.CTkButton(main_frame, text="Close", command=troubleshoot_window.destroy, fg_color="#3a7ebf", hover_color="#2b6194")
        close_btn.pack(pady=(20, 0))


if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = ToolboxApp()
    app.mainloop()
