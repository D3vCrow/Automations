"""
Main.py: Premium Toolbox GUI Application
Refactored for Grid Layout, Search, and Smart Icons.
"""

import os
import sys
import json
import importlib.util
import traceback
import customtkinter as ctk
from tkinter import messagebox
import psutil

# -------------------- Global Configuration --------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOL_FOLDER = os.path.join(BASE_DIR, "tools")
FAVORITES_PATH = os.path.join(BASE_DIR, "favorites.json")

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

def get_icon(name):
    name_lower = name.lower()
    for key, icon in ICON_MAP.items():
        if key in name_lower:
            return icon
    return "🛠️"

# -------------------- Tool Loading Logic --------------------
class ToolboxApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Automations Toolbox Pro")
        self.geometry("900x700")

        self.all_tools = []  # list of dicts: {"module", "name", "description", "filename", "favorite"}
        self.failed_tools = []
        self.filtered_tools = []
        self.favorites = self._load_favorites()

        self._build_sidebar()
        self._build_main_content()
        
        # Initialize
        self._last_columns = None
        self._resize_job = None
        self.refresh_tools()
        self._start_stats_loop()

        # Re-render grid on resize for a responsive layout (column-count based)
        self.bind("<Configure>", self._on_resize)

        # Keyboard shortcuts
        self.bind("<Control-f>", lambda _e: self.search_entry.focus_set())
        self.bind("<Control-F>", lambda _e: self.search_entry.focus_set())
        self.bind("<Return>", self._launch_first_tool_shortcut)

    def _build_sidebar(self):
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

        self.quit_btn = ctk.CTkButton(self.sidebar, text="Exit App", command=self.quit, fg_color="#bf3a3a", hover_color="#942b2b")
        self.quit_btn.pack(side="bottom", pady=20, padx=20)

    def _build_main_content(self):
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
    def _get_column_count(self):
        """
        Decide how many columns to use based on available width.
        """
        try:
            width = self.scroll_canvas.winfo_width() or self.content_frame.winfo_width()
        except Exception:
            width = 0

        if width <= 0:
            return 3

        # Each card is about 210px wide + padding; cap between 1 and 4 columns
        approx_card_plus_margin = 240
        cols = max(1, min(4, width // approx_card_plus_margin))
        return cols or 1

    def _on_resize(self, _event=None):
        """
        Only re-render when the effective column count would change,
        to avoid constant blinking while dragging the window.
        """
        try:
            new_cols = self._get_column_count()
        except Exception:
            return

        if new_cols == self._last_columns:
            return

        self._last_columns = new_cols

        # Longer debounce for smoother resizing
        if self._resize_job is not None:
            try:
                self.after_cancel(self._resize_job)
            except Exception:
                pass
        self._resize_job = self.after(
            200,  # Increased from 80ms to 200ms for smoother experience
            lambda: self._render_tools(self.search_var.get() if hasattr(self, "search_var") else ""),
        )

    # -------------------- Favorites persistence --------------------
    def _load_favorites(self):
        try:
            if not os.path.exists(FAVORITES_PATH):
                return set()
            with open(FAVORITES_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return set(str(x) for x in data)
        except Exception:
            pass
        return set()

    def _save_favorites(self):
        try:
            data = sorted(self.favorites)
            with open(FAVORITES_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def _launch_first_tool_shortcut(self, _event=None):
        if self.filtered_tools:
            self._launch_tool(self.filtered_tools[0])

    def _on_search_change(self, *args):
        # Debounce search to reduce constant re-rendering
        if hasattr(self, '_search_job') and self._search_job is not None:
            try:
                self.after_cancel(self._search_job)
            except Exception:
                pass
        
        self._search_job = self.after(
            300,  # 300ms debounce for search
            lambda: self._render_tools(self.search_var.get())
        )

    def load_tools(self):
        """
        Load toolbox-compatible modules from TOOL_FOLDER.
        Each tool is represented as a dict: {"module", "name", "description", "filename", "favorite"}.
        """
        self.failed_tools = []
        tools = []
        if not os.path.exists(TOOL_FOLDER):
            return tools

        for filename in sorted(os.listdir(TOOL_FOLDER)):
            if not (filename.endswith(".py") and not filename.startswith("__")):
                continue

            module_name = filename[:-3]
            module_path = os.path.join(TOOL_FOLDER, filename)
            spec = importlib.util.spec_from_file_location(module_name, module_path)
            module = importlib.util.module_from_spec(spec)

            try:
                spec.loader.exec_module(module)
            except Exception as e:
                # Skip broken tools but keep the launcher responsive
                print(f"❌ Tool {filename} failed to load: {str(e)}")
                self.failed_tools.append({
                    'filename': filename,
                    'error': str(e),
                    'traceback': traceback.format_exc()
                })
                continue

            if not (hasattr(module, "TOOL_NAME") and hasattr(module, "run_tool")):
                continue

            name = getattr(module, "TOOL_NAME", module_name)

            # Prefer an explicit TOOL_DESC; fall back to first docstring line if present
            desc = getattr(module, "TOOL_DESC", "").strip()
            if not desc:
                doc = (module.__doc__ or "").strip()
                if doc:
                    desc = doc.splitlines()[0].strip()

            tool_id = filename  # unique per tool folder

            tools.append(
                {
                    "module": module,
                    "name": name,
                    "description": desc,
                    "filename": filename,
                    "id": tool_id,
                    "favorite": tool_id in self.favorites,
                }
            )

        return tools

    def refresh_tools(self):
        self.all_tools = self.load_tools()
        self._render_tools()

    # -------------------- Tool window helpers --------------------
    def _tool_window_titles(self, tool_dict):
        titles = []
        module = tool_dict.get("module")
        if module is not None:
            explicit = getattr(module, "TOOL_WINDOW_TITLE", None)
            if explicit:
                titles.append(str(explicit))
            tn = getattr(module, "TOOL_NAME", None)
            if tn:
                titles.append(str(tn))
        name = tool_dict.get("name")
        if name:
            titles.append(str(name))
        # De-duplicate while preserving order
        seen = set()
        out = []
        for t in titles:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    def _find_tool_windows(self, tool_dict):
        titles = self._tool_window_titles(tool_dict)
        if not titles:
            return []
        windows = []
        for child in self.winfo_children():
            try:
                if isinstance(child, ctk.CTkToplevel):
                    t = child.title()
                    if any(t.startswith(tt) for tt in titles):
                        windows.append(child)
            except Exception:
                continue
        return windows

    def _focus_tool_window(self, tool_dict):
        wins = self._find_tool_windows(tool_dict)
        if not wins:
            return False
        win = wins[0]
        try:
            # Bring window to front with multiple techniques
            win.lift()                    # Raise to top
            win.focus_force()             # Force focus
            win.attributes("-topmost", True)  # Temporarily make topmost
            win.after(150, lambda w=win: w.attributes("-topmost", False))  # Remove topmost after brief period
            
            # Also try to activate the window
            try:
                win.state("normal")
            except Exception:
                pass
                
            return True
        except Exception:
            return False

    def _launch_tool(self, tool_dict):
        module = tool_dict.get("module")
        name = tool_dict.get("name", "Tool")

        # If an instance already exists, just focus it instead of launching another
        if self._focus_tool_window(tool_dict):
            return

        if module is None:
            messagebox.showerror("Tool launch failed", f"Module for '{name}' is not available.")
            return

        try:
            # Launch the tool
            module.run_tool()
            
            # After launch, try to focus the newly created window and bring it to front
            self.after(500, lambda: self._focus_tool_window(tool_dict))
            
        except Exception as e:
            messagebox.showerror(
                "Tool launch failed",
                f"An error occurred while launching '{name}':\n\n{e}",
            )

    def _render_tools(self, filter_query=""):
        # Clear current grid
        for child in self.grid_frame.winfo_children():
            child.destroy()

        # Build filtered list
        fq = (filter_query or "").strip().lower()
        base = []
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
        # Ensure grid columns expand evenly
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
                # Delayed re-render to avoid immediate visual disruption
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

    def _start_stats_loop(self):
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

    def show_troubleshooting(self):
        """Show troubleshooting information for failed tools"""
        troubleshoot_window = ctk.CTkToplevel(self)
        troubleshoot_window.title("Tool Troubleshooting")
        troubleshoot_window.geometry("600x400")
        
        # Main frame
        main_frame = ctk.CTkFrame(troubleshoot_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title = ctk.CTkLabel(main_frame, text="🔧 Tool Troubleshooting", font=ctk.CTkFont(size=18, weight="bold"))
        title.pack(pady=(0, 20))
        
        # Create scrollable frame
        scroll_frame = ctk.CTkScrollableFrame(main_frame, height=300)
        scroll_frame.pack(fill="both", expand=True)
        
        # System info
        info_frame = ctk.CTkFrame(scroll_frame)
        info_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(info_frame, text="📊 System Information", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        
        system_info = [
            f"Python Version: {sys.version}",
            f"Platform: {sys.platform}",
            f"Tools Folder: {TOOL_FOLDER}",
            f"Tools Folder Exists: {os.path.exists(TOOL_FOLDER)}",
        ]
        
        for info in system_info:
            ctk.CTkLabel(info_frame, text=f"• {info}", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=2)
        
        # Failed tools
        if self.failed_tools:
            failed_frame = ctk.CTkFrame(scroll_frame)
            failed_frame.pack(fill="x", pady=(0, 10))
            
            ctk.CTkLabel(failed_frame, text="❌ Failed Tools", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
            
            for tool in self.failed_tools:
                tool_info = ctk.CTkFrame(failed_frame)
                tool_info.pack(fill="x", padx=20, pady=5)
                
                ctk.CTkLabel(tool_info, text=f"📁 {tool['filename']}", font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w", padx=10, pady=(5, 2))
                ctk.CTkLabel(tool_info, text=f"⚠️ Error: {tool['error']}", font=ctk.CTkFont(size=10), text_color="red").pack(anchor="w", padx=20, pady=2)
                tb_label = ctk.CTkLabel(tool_info, text=tool['traceback'], font=ctk.CTkFont(size=9, family="Consolas"), text_color="orange", justify="left", wraplength=500)
                tb_label.pack(anchor="w", padx=20, pady=(2, 5))
        else:
            success_frame = ctk.CTkFrame(scroll_frame)
            success_frame.pack(fill="x", pady=(0, 10))
            
            ctk.CTkLabel(success_frame, text="✅ All Tools Loaded Successfully", font=ctk.CTkFont(size=14, weight="bold"), text_color="green").pack(anchor="w", padx=10, pady=10)
            ctk.CTkLabel(success_frame, text="No tool loading errors detected.", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=(0, 10))
        
        # Successful tools
        success_count = len(self.all_tools)
        total_files = len([f for f in os.listdir(TOOL_FOLDER) if f.endswith('.py') and not f.startswith('__')]) if os.path.exists(TOOL_FOLDER) else 0
        
        stats_frame = ctk.CTkFrame(scroll_frame)
        stats_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(stats_frame, text="📈 Loading Statistics", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=10, pady=(10, 5))
        ctk.CTkLabel(stats_frame, text=f"• Total Python files: {total_files}", font=ctk.CTkFont(size=11)).pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(stats_frame, text=f"• Successfully loaded: {success_count}", font=ctk.CTkFont(size=11), text_color="green").pack(anchor="w", padx=20, pady=2)
        ctk.CTkLabel(stats_frame, text=f"• Failed to load: {len(self.failed_tools)}", font=ctk.CTkFont(size=11), text_color="red").pack(anchor="w", padx=20, pady=(2, 10))
        
        # Close button
        close_btn = ctk.CTkButton(main_frame, text="Close", command=troubleshoot_window.destroy, fg_color="#3a7ebf", hover_color="#2b6194")
        close_btn.pack(pady=(20, 0))

if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = ToolboxApp()
    app.mainloop()
