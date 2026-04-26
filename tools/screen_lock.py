"""
screen_lock.py

SCREEN LOCK (Kid-Safe)
- Transparent overlay covers every monitor (virtual screen span)
- Adjustable opacity slider
- Unlock: Ctrl + Alt + U  (always) / optional ESC toggle (hidden config)
- Triple-click panic unlock in a configurable corner (1.5s window)
- Blocks Alt+Tab, Alt+F4, Win keys and Ctrl+Shift+Esc when keyboard hook is live
- Crash-orphan recovery via PID flag at %APPDATA%\\screen_lock\\locked.flag
- Educational animated cards for every keypress (letters, numbers, specials)
- Physics: gravity, bounce, soft peer repulsion
- Mouse-click emoji bursts
- Cards never overlap at spawn; drift apart naturally

Dependencies:
  pip install keyboard
"""

from __future__ import annotations

import ctypes
import json
import math
import os
import random
import sys
import time
import tkinter as tk
from collections import deque
from datetime import datetime
from pathlib import Path
from tkinter import messagebox
from typing import Optional

import customtkinter as ctk

try:
    import keyboard as _kb
    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False

TOOL_NAME = "Screen Lock (Kid-Safe)"
TOOL_DESCRIPTION = "Transparent overlay blocks keyboard input - stops kids from messing with your work"

# ─────────────────────────────────────────────
#  Config / crash-flag / panic-unlock helpers
# ─────────────────────────────────────────────

DEFAULT_CONFIG = {
    "esc_unlock": False,
    "panic_corner": "top-left",   # one of: top-left, top-right, bottom-left, bottom-right
    "panic_target_px": 40,
    "panic_window_s": 1.5,
}


def get_config_dir() -> Path:
    """Return the ``%APPDATA%/screen_lock`` directory, creating it if needed.

    On non-Windows systems falls back to ``~/.config/screen_lock``. The
    ``APPDATA`` environment variable is always consulted first so tests can
    redirect the config location.

    Returns:
        Path to the config directory (guaranteed to exist).
    """
    appdata = os.environ.get("APPDATA")
    if appdata:
        base = Path(appdata) / "screen_lock"
    elif sys.platform == "win32":
        base = Path.home() / "AppData" / "Roaming" / "screen_lock"
    else:
        base = Path.home() / ".config" / "screen_lock"
    base.mkdir(parents=True, exist_ok=True)
    return base


def get_config_path() -> Path:
    """Return the path to ``config.json`` inside the config dir."""
    return get_config_dir() / "config.json"


def get_flag_path() -> Path:
    """Return the path to ``locked.flag`` inside the config dir."""
    return get_config_dir() / "locked.flag"


def load_config() -> dict:
    """Read ``config.json`` and merge with :data:`DEFAULT_CONFIG`.

    A missing or malformed file yields the defaults without raising.

    Returns:
        Dict with every default key present.
    """
    cfg = dict(DEFAULT_CONFIG)
    path = get_config_path()
    try:
        raw = path.read_text(encoding="utf-8")
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            cfg.update({k: v for k, v in parsed.items() if k in DEFAULT_CONFIG})
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        print(f"[screen_lock] could not read config: {exc}", file=sys.stderr)
    return cfg


def save_config(cfg: dict) -> None:
    """Persist ``cfg`` (only known keys) to ``config.json``.

    Unknown keys are ignored. I/O errors are logged to stderr and swallowed
    — a failed write must not break the UI.
    """
    try:
        path = get_config_path()
        clean = {k: cfg.get(k, DEFAULT_CONFIG[k]) for k in DEFAULT_CONFIG}
        path.write_text(json.dumps(clean, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"[screen_lock] could not save config: {exc}", file=sys.stderr)


def write_lock_flag(pid: Optional[int] = None) -> Path:
    """Write ``locked.flag`` containing the given PID.

    Args:
        pid: PID to record. Defaults to :func:`os.getpid`.

    Returns:
        Path to the flag file.
    """
    path = get_flag_path()
    pid = pid if pid is not None else os.getpid()
    try:
        path.write_text(str(pid), encoding="utf-8")
    except OSError as exc:
        print(f"[screen_lock] could not write lock flag: {exc}", file=sys.stderr)
    return path


def clear_lock_flag() -> None:
    """Remove the lock flag if it exists. Missing file is not an error."""
    path = get_flag_path()
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"[screen_lock] could not clear lock flag: {exc}", file=sys.stderr)


def _pid_alive(pid: int) -> bool:
    """Return True when a process with ``pid`` is currently running.

    Uses ``psutil`` when available, falls back to OS-native checks otherwise.
    """
    try:
        import psutil  # type: ignore
        return psutil.pid_exists(pid)
    except ImportError:
        pass
    if sys.platform == "win32":
        try:
            PROCESS_QUERY = 0x0400 | 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY, False, int(pid))
            if not handle:
                return False
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        except (OSError, AttributeError):
            return True  # err on the safe side — do not wrongly claim stale
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return True
    return True


def is_stale_lock_flag() -> bool:
    """Return True when ``locked.flag`` exists but its PID is no longer alive.

    No flag, unreadable flag, or a live PID all return False.
    """
    path = get_flag_path()
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return False
    except OSError:
        return False
    try:
        pid = int(raw)
    except ValueError:
        # Malformed flag — treat as stale so cleanup runs.
        return True
    return not _pid_alive(pid)


class TripleClickDetector:
    """Track recent click timestamps and fire a callback on 3 clicks in window.

    Intended for the invisible panic-unlock target. Pure logic — no Tk code —
    so it can be unit tested.

    Args:
        window_s: Window length in seconds.
        required: How many clicks must fall inside the window (default 3).
    """

    def __init__(self, window_s: float = 1.5, required: int = 3):
        self.window_s = float(window_s)
        self.required = int(required)
        self._clicks: deque[float] = deque(maxlen=self.required)

    def register(self, now: Optional[float] = None) -> bool:
        """Record a click and return True when the threshold is reached.

        Args:
            now: Timestamp in seconds. Defaults to :func:`time.monotonic`.
                 Passed in for deterministic tests.
        """
        t = time.monotonic() if now is None else float(now)
        self._clicks.append(t)
        if len(self._clicks) < self.required:
            return False
        span = self._clicks[-1] - self._clicks[0]
        if span <= self.window_s:
            self._clicks.clear()
            return True
        return False

    def reset(self) -> None:
        """Forget pending clicks."""
        self._clicks.clear()


def get_virtual_screen_rect(fallback: tuple[int, int] = (1920, 1080)) -> tuple[int, int, int, int]:
    """Return ``(x, y, width, height)`` for the Windows virtual screen.

    The virtual screen is the bounding rectangle of every monitor,
    including negatively-positioned secondary displays. When not running on
    Windows (or when the ``user32`` call fails), falls back to a primary
    monitor at the origin.

    Args:
        fallback: ``(w, h)`` used when the OS call is unavailable.

    Returns:
        Tuple ``(origin_x, origin_y, width, height)``.
    """
    if sys.platform == "win32":
        try:
            gsm = ctypes.windll.user32.GetSystemMetrics
            x = int(gsm(76))   # SM_XVIRTUALSCREEN
            y = int(gsm(77))   # SM_YVIRTUALSCREEN
            w = int(gsm(78))   # SM_CXVIRTUALSCREEN
            h = int(gsm(79))   # SM_CYVIRTUALSCREEN
            if w > 0 and h > 0:
                return x, y, w, h
        except (OSError, AttributeError) as exc:
            print(f"[screen_lock] virtual-screen metrics failed: {exc!r}",
                  file=sys.stderr)
    fw, fh = fallback
    return 0, 0, int(fw), int(fh)

# ─────────────────────────────────────────────
#  Educational content
# ─────────────────────────────────────────────

_LETTERS = {
    "a": ("🍎", "Apple"),    "b": ("🐻", "Bear"),     "c": ("🐱", "Cat"),
    "d": ("🐶", "Dog"),      "e": ("🐘", "Elephant"), "f": ("🐸", "Frog"),
    "g": ("🦒", "Giraffe"),  "h": ("🐹", "Hamster"),  "i": ("🍦", "Ice Cream"),
    "j": ("🦋", "Jellyfish"),"k": ("🦘", "Kangaroo"), "l": ("🦁", "Lion"),
    "m": ("🐵", "Monkey"),   "n": ("🌙", "Night"),    "o": ("🦉", "Owl"),
    "p": ("🐧", "Penguin"),  "q": ("👑", "Queen"),    "r": ("🐰", "Rabbit"),
    "s": ("⭐", "Star"),     "t": ("🐯", "Tiger"),    "u": ("🦄", "Unicorn"),
    "v": ("🌸", "Violet"),   "w": ("🐳", "Whale"),    "x": ("🎄", "Xmas"),
    "y": ("🌻", "Sunflower"),"z": ("🦓", "Zebra"),
}
_NUMBERS = {
    "0": ("🍩", "Zero"), "1": ("☀️", "One"),   "2": ("🦢", "Two"),
    "3": ("🌈", "Three"),"4": ("🍀", "Four"),  "5": ("⭐", "Five"),
    "6": ("🐝", "Six"),  "7": ("🎨", "Seven"), "8": ("🐙", "Eight"),
    "9": ("🎈", "Nine"),
}
_SPECIAL = {
    "space":     ("🚀", "Space!"),  "enter":     ("✅", "Enter!"),
    "backspace": ("⬅️",  "Oops!"),  "tab":       ("➡️",  "Tab!"),
    "up":        ("⬆️",  "Up!"),    "down":      ("⬇️",  "Down!"),
    "left":      ("⬅️",  "Left!"),  "right":     ("➡️",  "Right!"),
}
_CARD_COLORS = [
    "#FF6B6B", "#FF9E00", "#4ECDC4", "#45B7D1",
    "#A29BFE", "#FD79A8", "#55EFC4", "#FDCB6E",
    "#E17055", "#74B9FF",
]
_CLICK_EMOJIS = [
    "❤️", "💛", "💚", "💙", "💜",
    "⭐", "🌟", "✨", "🎉", "🎊", "🌈", "🦋",
]

# ─────────────────────────────────────────────
#  Physics / animation constants
# ─────────────────────────────────────────────

CARD_W      = 230
CARD_H      = 215
CORNER_R    = 22        # rounded-rect corner radius (full scale)
FPS_MS      = 16        # ~62 fps

GROW_F      = 14        # frames to grow in
FLOAT_F     = 85        # frames to float
SHRINK_F    = 14        # frames to shrink out
TOTAL_F     = GROW_F + FLOAT_F + SHRINK_F

GRAVITY     = 0.22
BOUNCE      = 0.50      # velocity kept on bounce
FLOOR_FRIC  = 0.86      # horizontal damping on floor hit
REPULSE_R   = CARD_W * 0.95   # min centre-centre dist before repulsion
REPULSE_STR = 0.9

MAX_CARDS   = 10        # ignore spawns beyond this


# ─────────────────────────────────────────────
#  Card physics
# ─────────────────────────────────────────────

class CardPhysics:
    """Animated popup card: grows in, drifts with physics, shrinks out."""

    def __init__(self, canvas, cx, cy, sw, sh, color,
                 emoji, letter, word, peers: list):
        self.canvas = canvas
        self.cx, self.cy = float(cx), float(cy)
        self.sw, self.sh = sw, sh
        self.color  = color
        self.emoji  = emoji
        self.letter = letter
        self.word   = word
        self.peers  = peers

        self.vx = random.uniform(-2.5, 2.5)
        self.vy = random.uniform(-5.5, -2.5)   # initial upward kick

        self.frame_n = 0
        self.tag     = f"card_{id(self)}"
        self.alive   = True
        self._tick()

    # ── scale easing ────────────────────────────

    @property
    def _scale(self) -> float:
        f = self.frame_n
        if f < GROW_F:
            t = f / GROW_F
            return 1 - (1 - t) ** 3          # ease-out cubic  0→1
        if f < GROW_F + FLOAT_F:
            return 1.0
        t = (f - GROW_F - FLOAT_F) / SHRINK_F
        return (1 - t) ** 2                   # ease-in quadratic 1→0

    # ── animation loop ──────────────────────────

    def _tick(self):
        if not self.alive:
            return
        try:
            if not self.canvas.winfo_exists():
                self.alive = False
                return
        except tk.TclError:
            self.alive = False
            return

        sc = self._scale

        # Physics only while floating
        if GROW_F <= self.frame_n < GROW_F + FLOAT_F:
            # Gravity
            self.vy += GRAVITY

            # Soft repulsion from peer cards
            for other in self.peers:
                if other is self or not other.alive or not isinstance(other, CardPhysics):
                    continue
                dx = self.cx - other.cx
                dy = self.cy - other.cy
                dist = math.hypot(dx, dy) or 0.01
                if dist < REPULSE_R:
                    strength = (REPULSE_R - dist) / REPULSE_R * REPULSE_STR
                    self.vx += (dx / dist) * strength
                    self.vy += (dy / dist) * strength

            self.cx += self.vx
            self.cy += self.vy

            # Boundary bounce
            hw = CARD_W * sc / 2
            hh = CARD_H * sc / 2

            if self.cx - hw < 0:
                self.cx = hw;  self.vx = abs(self.vx) * BOUNCE
            elif self.cx + hw > self.sw:
                self.cx = self.sw - hw;  self.vx = -abs(self.vx) * BOUNCE

            if self.cy - hh < 0:
                self.cy = hh;  self.vy = abs(self.vy) * BOUNCE
            elif self.cy + hh > self.sh:
                self.cy = self.sh - hh
                self.vy = -abs(self.vy) * BOUNCE
                self.vx *= FLOOR_FRIC

        self._draw(sc)
        self.frame_n += 1

        if self.frame_n >= TOTAL_F:
            self.canvas.delete(self.tag)
            self.alive = False
            return

        self.canvas.after(FPS_MS, self._tick)

    # ── drawing ─────────────────────────────────

    def _draw(self, scale: float):
        c   = self.canvas
        c.delete(self.tag)
        if scale < 0.03:
            return

        w   = CARD_W * scale
        h   = CARD_H * scale
        x1  = self.cx - w / 2
        y1  = self.cy - h / 2
        x2  = self.cx + w / 2
        y2  = self.cy + h / 2
        r   = max(2.0, CORNER_R * scale)
        col = self.color
        tag = self.tag

        # Rounded rectangle (2 rects + 4 corner ovals)
        c.create_rectangle(x1+r, y1, x2-r, y2, fill=col, outline="", tags=tag)
        c.create_rectangle(x1, y1+r, x2, y2-r, fill=col, outline="", tags=tag)
        c.create_oval(x1,     y1,     x1+2*r, y1+2*r, fill=col, outline="", tags=tag)
        c.create_oval(x2-2*r, y1,     x2,     y1+2*r, fill=col, outline="", tags=tag)
        c.create_oval(x1,     y2-2*r, x1+2*r, y2,     fill=col, outline="", tags=tag)
        c.create_oval(x2-2*r, y2-2*r, x2,     y2,     fill=col, outline="", tags=tag)

        # Text sizes
        emo_sz = max(6, int(40 * scale))
        ltr_sz = max(6, int(52 * scale))
        wrd_sz = max(4, int(17 * scale))
        mx, my = self.cx, self.cy

        if self.emoji and emo_sz >= 8:
            c.create_text(mx, my - h * 0.20,
                          text=self.emoji,
                          font=("Segoe UI Emoji", emo_sz),
                          fill="white", tags=tag)

        if ltr_sz >= 8:
            c.create_text(mx, my + h * 0.07,
                          text=self.letter,
                          font=("Arial Rounded MT Bold", ltr_sz, "bold"),
                          fill="white", tags=tag)

        if self.word and wrd_sz >= 6:
            c.create_text(mx, my + h * 0.40,
                          text=self.word,
                          font=("Arial Rounded MT Bold", wrd_sz),
                          fill="white", tags=tag)


# ─────────────────────────────────────────────
#  Click burst
# ─────────────────────────────────────────────

class ClickBurst:
    """Emoji that pops up at the click point, scales and floats upward."""

    TOTAL = 38

    def __init__(self, canvas, x, y, emoji):
        self.canvas  = canvas
        self.x, self.y = float(x), float(y)
        self.vy      = -3.5
        self.emoji   = emoji
        self.frame_n = 0
        self.tag     = f"burst_{id(self)}"
        self.alive   = True
        self._tick()

    def _tick(self):
        if not self.alive:
            return
        try:
            if not self.canvas.winfo_exists():
                self.alive = False
                return
        except tk.TclError:
            self.alive = False
            return

        t = self.frame_n / self.TOTAL
        scale = (1 - (2*t - 1) ** 2)         # smooth bump: 0→1→0

        self.y  += self.vy
        self.vy *= 0.94

        self.canvas.delete(self.tag)
        sz = max(4, int(75 * scale))
        if sz >= 6:
            self.canvas.create_text(self.x, self.y,
                                    text=self.emoji,
                                    font=("Segoe UI Emoji", sz),
                                    tags=self.tag)

        self.frame_n += 1
        if self.frame_n >= self.TOTAL:
            self.canvas.delete(self.tag)
            self.alive = False
            return

        self.canvas.after(FPS_MS, self._tick)


# ─────────────────────────────────────────────
#  Spawn helpers
# ─────────────────────────────────────────────

def _find_spawn(peers: list, sw: int, sh: int, margin: int = 30) -> tuple[int, int]:
    """Return a centre (cx, cy) that doesn't overlap any live peer card."""
    min_dx = CARD_W + margin
    min_dy = CARD_H + margin

    for _ in range(50):
        cx = random.randint(CARD_W // 2 + margin, sw - CARD_W // 2 - margin)
        cy = random.randint(CARD_H // 2 + margin, sh - CARD_H // 2 - margin)

        ok = True
        for p in peers:
            if not p.alive or not isinstance(p, CardPhysics):
                continue
            if abs(cx - p.cx) < min_dx and abs(cy - p.cy) < min_dy:
                ok = False
                break
        if ok:
            return cx, cy

    # Fallback — random with at least edge margin
    return (
        random.randint(CARD_W // 2 + 10, sw - CARD_W // 2 - 10),
        random.randint(CARD_H // 2 + 10, sh - CARD_H // 2 - 10),
    )


# ─────────────────────────────────────────────
#  Main application
# ─────────────────────────────────────────────

class ScreenLockApp:
    def __init__(self, parent: ctk.CTkToplevel):
        self.parent = parent
        self.locked = False
        self._hook: object | None = None
        self._blocked_ids: list[object] = []
        self._overlay: tk.Toplevel | None = None
        self._canvas: tk.Canvas | None = None
        self._peers: list = []          # active CardPhysics + ClickBurst

        self._config = load_config()
        self.alpha_var = tk.DoubleVar(value=0.25)
        # ESC-unlock is a hidden config flag (no exposed checkbox).
        self._panic_detector = TripleClickDetector(
            window_s=float(self._config.get("panic_window_s", 1.5))
        )

        self._build_ui()

    # ── Control panel UI ────────────────────────

    def _build_ui(self):
        w = self.parent
        w.title("Screen Lock – Kid Safe")
        w.geometry("430x340")
        w.resizable(False, False)

        ctk.CTkLabel(w, text="🔐  Screen Lock",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(22, 2))
        ctk.CTkLabel(w, text="Keep kids from messing with your work",
                     font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 16))

        # Opacity card
        card = ctk.CTkFrame(w)
        card.pack(fill="x", padx=20, pady=6)
        row1 = ctk.CTkFrame(card, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=(10, 4))
        ctk.CTkLabel(row1, text="Overlay Opacity",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")
        self.lbl_pct = ctk.CTkLabel(row1, text=f"{int(self.alpha_var.get()*100)}%",
                                    font=ctk.CTkFont(size=13), text_color="#4fc3f7")
        self.lbl_pct.pack(side="right")
        row2 = ctk.CTkFrame(card, fg_color="transparent")
        row2.pack(fill="x", padx=14, pady=(0, 12))
        ctk.CTkLabel(row2, text="Transparent",
                     font=ctk.CTkFont(size=11), text_color="gray").pack(side="left")
        ctk.CTkSlider(row2, from_=0.05, to=0.90, variable=self.alpha_var,
                      command=self._on_alpha_change, width=200
                      ).pack(side="left", padx=10, expand=True, fill="x")
        ctk.CTkLabel(row2, text="Opaque",
                     font=ctk.CTkFont(size=11), text_color="gray").pack(side="left")

        # Lock button
        ctk.CTkButton(w, text="🔒  Lock Screen Now",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      height=50, fg_color="#c62828", hover_color="#8e0000",
                      command=self.lock).pack(padx=20, pady=10, fill="x")

        # Unlock shortcut is documented HERE (unlocked control panel) only.
        # It is deliberately NOT drawn on the overlay, where a child could
        # read it. ESC-unlock is a hidden toggle in config.json.
        ctk.CTkLabel(
            w,
            text="Unlock:  Ctrl + Alt + U",
            font=ctk.CTkFont(size=11),
            text_color="gray",
        ).pack(pady=(2, 0))
        panic_corner = self._config.get("panic_corner", "top-left")
        ctk.CTkLabel(
            w,
            text=f"Panic unlock:  triple-click {panic_corner} corner",
            font=ctk.CTkFont(size=10),
            text_color="gray",
        ).pack(pady=(0, 6))

        if not HAS_KEYBOARD:
            ctk.CTkLabel(w, text="⚠  'keyboard' library not found\n    pip install keyboard",
                         font=ctk.CTkFont(size=10), text_color="orange",
                         justify="left").pack(pady=4, padx=20, anchor="w")

    def _on_alpha_change(self, val):
        self.lbl_pct.configure(text=f"{int(float(val)*100)}%")
        if self._overlay and self._overlay.winfo_exists():
            self._overlay.attributes("-alpha", float(val))

    # ── Lock / Unlock ────────────────────────────

    def lock(self):
        if self.locked:
            return
        # Install the keyboard hook FIRST. If the install fails we must
        # surface the error and refuse to enter locked state — the old code
        # silently pretended it was locked, so any keypress slipped through.
        if not self._install_hook():
            return
        self.locked = True
        write_lock_flag()
        self._show_overlay()
        self.parent.withdraw()

    def unlock(self):
        if not self.locked:
            return
        self.locked = False
        self._remove_hook()
        clear_lock_flag()
        self._hide_overlay()
        self.parent.deiconify()
        self.parent.lift()
        self.parent.focus_force()

    # ── Overlay ──────────────────────────────────

    def _show_overlay(self):
        ov = tk.Toplevel()
        ov.overrideredirect(True)
        # Span across every monitor. Falling back to the primary monitor
        # would leave other screens uncovered and fully interactive.
        fallback_w = ov.winfo_screenwidth()
        fallback_h = ov.winfo_screenheight()
        ox, oy, sw, sh = get_virtual_screen_rect(fallback=(fallback_w, fallback_h))
        ov.geometry(f"{sw}x{sh}+{ox}+{oy}")
        ov.configure(bg="#000000")
        ov.attributes("-alpha", self.alpha_var.get())
        ov.attributes("-topmost", True)
        ov.grab_set_global()
        ov.focus_force()

        # Full-screen canvas — all animations drawn here
        canvas = tk.Canvas(ov, bg="#000000", bd=0, highlightthickness=0)
        canvas.place(x=0, y=0, width=sw, height=sh)
        canvas.bind("<Button-1>", self._on_click)
        canvas.bind("<Button-2>", self._on_click)
        canvas.bind("<Button-3>", self._on_click)

        # Invisible panic-unlock target. Triple-click within panic_window_s
        # triggers unlock even if the keyboard hook is dead. The widget is
        # a Frame (not a Canvas item) so its click handler fires even though
        # the canvas above is capturing Button-1 on the rest of the surface.
        panic = tk.Frame(ov, bg="#000000", bd=0, highlightthickness=0,
                         cursor="arrow")
        self._panic_detector.reset()
        panic.bind("<Button-1>", self._on_panic_click)
        self._place_panic_target(panic, sw, sh)

        # Re-grab on focus loss (keep canvas focusable)
        ov.bind("<FocusOut>", lambda e: (ov.focus_force(), ov.grab_set_global()))

        # Key bindings on overlay window (absorb all)
        for seq in ("<Key>", "<KeyPress>", "<KeyRelease>"):
            ov.bind(seq, lambda e: "break")

        # Lock indicator — drawn as permanent canvas text (stays on top after
        # peer cards because we'll raise it after each spawn).
        # NOTE: the unlock shortcut is deliberately NOT printed on the overlay
        # (prior versions leaked it here; a child reading the screen could
        # trivially unlock). The shortcut is only shown on the control panel.
        canvas.create_text(20, 18, text="🔒", anchor="nw",
                           font=("Segoe UI Emoji", 26),
                           fill="#ffffff", tags="hud")

        # Clock — top right
        canvas.create_text(sw - 20, 20, text="", anchor="ne",
                           font=("Segoe UI", 32, "bold"),
                           fill="#ffffff", tags="hud_clock")
        canvas.create_text(sw - 20, 60, text="", anchor="ne",
                           font=("Segoe UI", 13),
                           fill="#888888", tags="hud_date")

        # Release grab if overlay is destroyed externally
        ov.bind("<Destroy>", lambda e: self.unlock() if self.locked else None)

        self._overlay = ov
        self._canvas  = canvas
        self._peers   = []
        self._tick_clock()

    def _raise_hud(self):
        """Raise all HUD elements above card/burst layers."""
        self._canvas.tag_raise("hud")
        self._canvas.tag_raise("hud_clock")
        self._canvas.tag_raise("hud_date")

    def _tick_clock(self):
        canvas = self._canvas
        if canvas is None or not self.locked:
            return
        try:
            if not canvas.winfo_exists():
                return
        except tk.TclError:
            return
        now = datetime.now()
        canvas.itemconfigure("hud_clock", text=now.strftime("%H:%M:%S"))
        canvas.itemconfigure("hud_date",  text=now.strftime("%A, %d %B %Y"))
        self._raise_hud()
        canvas.after(1000, self._tick_clock)

    def _place_panic_target(self, frame: tk.Frame, sw: int, sh: int) -> None:
        """Place the invisible panic-unlock Frame in the configured corner."""
        size = int(self._config.get("panic_target_px", 40))
        size = max(10, min(size, 200))  # clamp sanity
        corner = str(self._config.get("panic_corner", "top-left")).lower()
        if corner == "top-right":
            x, y = sw - size, 0
        elif corner == "bottom-left":
            x, y = 0, sh - size
        elif corner == "bottom-right":
            x, y = sw - size, sh - size
        else:
            x, y = 0, 0  # top-left default
        frame.place(x=x, y=y, width=size, height=size)

    def _on_panic_click(self, _event) -> None:
        """Handle a click in the panic-unlock target."""
        if self._panic_detector.register():
            print("[screen_lock] panic unlock triggered", file=sys.stderr)
            _schedule_unlock(self)

    def _hide_overlay(self):
        self._canvas  = None
        self._peers   = []
        if self._overlay:
            try:
                self._overlay.grab_release()
            except tk.TclError:
                pass
            try:
                self._overlay.destroy()
            except tk.TclError:
                pass
            self._overlay = None

    # ── Popup spawning ───────────────────────────

    def _spawn_card(self, key_name: str):
        canvas = self._canvas
        if canvas is None:
            return
        try:
            if not canvas.winfo_exists():
                return
        except tk.TclError:
            return

        # Prune dead peers
        self._peers = [p for p in self._peers if p.alive]
        live_cards  = [p for p in self._peers if isinstance(p, CardPhysics)]
        if len(live_cards) >= MAX_CARDS:
            return

        name = key_name.lower()
        if name in _LETTERS:
            emoji, word = _LETTERS[name]
            letter = name.upper()
        elif name in _NUMBERS:
            emoji, word = _NUMBERS[name]
            letter = name
        elif name in _SPECIAL:
            emoji, word = _SPECIAL[name]
            letter = emoji
            emoji  = ""
        else:
            return

        color = random.choice(_CARD_COLORS)
        sw, sh = canvas.winfo_width() or canvas.winfo_screenwidth(), \
                 canvas.winfo_height() or canvas.winfo_screenheight()
        cx, cy = _find_spawn(self._peers, sw, sh)

        card = CardPhysics(canvas, cx, cy, sw, sh,
                           color, emoji, letter, word, self._peers)
        self._peers.append(card)

        # Keep HUD on top
        self._raise_hud()

    def _on_click(self, event):
        canvas = self._canvas
        if canvas is None:
            return
        try:
            if not canvas.winfo_exists():
                return
        except tk.TclError:
            return

        # Prune dead peers to prevent memory leak
        self._peers = [p for p in self._peers if p.alive]

        burst = ClickBurst(canvas, event.x, event.y,
                           random.choice(_CLICK_EMOJIS))
        self._peers.append(burst)
        self._raise_hud()

    # ── Keyboard hook ────────────────────────────

    # Key combos we actively swallow while the lock is up.
    # Critical combos: must all be blocked or lock is unsafe. Fail-fast on any failure.
    # NOTE: block_key() only accepts single key names, not combo strings like "alt+tab".
    # Combos are already suppressed by the suppress=True hook; only single keys go here.
    _CRITICAL_COMBOS = (
        "left windows",
        "right windows",
    )

    # Nice-to-have combos: best-effort via block_key (single keys only) or rely on suppress hook.
    # If these fail, lock still works because the suppress=True hook intercepts everything.
    _EXTRA_COMBOS = (
        "ctrl+esc",   # opens Start menu
        "alt+esc",    # cycles windows
        "win",        # redundant with left/right windows but harmless to try
    )

    def _install_hook(self) -> bool:
        """Install the global keyboard hook.

        Returns:
            True when the hook (and every block_key call) succeeded, False
            when the user should NOT be allowed to enter locked state. On
            failure a messagebox is shown and stderr logged.
        """
        if not HAS_KEYBOARD:
            messagebox.showerror(
                "Screen Lock",
                "The 'keyboard' library is not installed.\n\n"
                "Install it with:\n    pip install keyboard\n\n"
                "The screen lock cannot run safely without it because "
                "Alt+Tab, Alt+F4 and the Windows key would still work.",
            )
            print("[screen_lock] refusing to lock: keyboard module missing",
                  file=sys.stderr)
            return False

        esc_enabled = bool(self._config.get("esc_unlock", False))
        app = self
        _pressed: set[str] = set()
        blocked_ids: list[object] = []

        def _norm(raw: str) -> str:
            n = (raw or "").lower()
            if n in ("left ctrl", "right ctrl", "ctrl"):
                return "ctrl"
            if n in ("left alt",  "right alt",  "alt", "alt gr"):
                return "alt"
            return n

        def _handler(event):
            name = _norm(event.name)

            if event.event_type == _kb.KEY_DOWN:
                _pressed.add(name)
            elif event.event_type == _kb.KEY_UP:
                _pressed.discard(name)

            if event.event_type != _kb.KEY_DOWN:
                return

            # Unlock combos — silent, no popup
            if "ctrl" in _pressed and "alt" in _pressed and name == "u":
                _schedule_unlock(app)
                return
            if esc_enabled and name == "esc":
                _schedule_unlock(app)
                return

            # Skip bare modifier keys
            if name in ("ctrl", "alt", "shift", "left shift", "right shift",
                        "caps lock", "windows", "left windows", "right windows",
                        "menu", "num lock", "scroll lock", "pause"):
                return

            # Schedule popup on main thread
            canvas = app._canvas
            if canvas is not None:
                try:
                    canvas.after(0, lambda n=event.name: app._spawn_card(n))
                except tk.TclError:
                    pass

        # Attempt to install the suppressing hook. This fails if another
        # app owns a low-level hook or (rarely) on some restricted Windows
        # builds. A silent failure would leave the overlay visible while
        # every key still reached the OS — surface the error instead.
        try:
            hook = _kb.hook(_handler, suppress=True)
        except Exception as exc:  # noqa: BLE001 - boundary: surface keyboard.hook failure to user
            errno = getattr(exc, "errno", "")
            print(
                f"[screen_lock] keyboard.hook install failed: {exc!r} "
                f"(errno={errno})",
                file=sys.stderr,
            )
            messagebox.showerror(
                "Screen Lock",
                "Could not install the keyboard hook.\n\n"
                f"{exc}\n\n"
                "Try running the launcher as Administrator. Aborting lock.",
            )
            return False

        # Critical combos: must all succeed. If any fails, rollback and abort.
        for combo in self._CRITICAL_COMBOS:
            try:
                blocked_ids.append(_kb.block_key(combo))
            except (ValueError, OSError) as exc:
                # Failed to block a critical combo. Roll back: unblock every combo already
                # blocked + unhook the event handler.
                print(
                    f"[screen_lock] critical block_key({combo!r}) failed: {exc!r}",
                    file=sys.stderr,
                )
                try:
                    for bid in blocked_ids:
                        try:
                            _kb.unblock_key(bid)
                        except (OSError, ValueError) as unblock_exc:
                            print(
                                f"[screen_lock] rollback unblock_key failed: {unblock_exc!r}",
                                file=sys.stderr,
                            )
                    _kb.unhook(hook)
                except (OSError, ValueError) as unhook_exc:
                    print(
                        f"[screen_lock] unhook rollback failed: {unhook_exc!r}",
                        file=sys.stderr,
                    )
                messagebox.showerror(
                    "Screen Lock",
                    f"Could not block critical key combo '{combo}'.\n\n"
                    f"Error: {exc}\n\n"
                    "The lock is not safe without this protection. Aborting.",
                )
                return False

        # Extra combos: best-effort. If these fail, lock still works.
        for combo in self._EXTRA_COMBOS:
            try:
                blocked_ids.append(_kb.block_key(combo))
            except (ValueError, OSError) as exc:
                # Unknown key name or OS denied — log and continue.
                print(
                    f"[screen_lock] extra block_key({combo!r}) failed: {exc!r}",
                    file=sys.stderr,
                )
            except Exception as exc:  # noqa: BLE001 - boundary: best-effort fallback after narrow types
                print(
                    f"[screen_lock] extra block_key({combo!r}) unexpected: {exc!r}",
                    file=sys.stderr,
                )

        self._hook = hook
        self._blocked_ids = blocked_ids
        critical_count = min(len(blocked_ids), len(self._CRITICAL_COMBOS))
        extra_count = len(blocked_ids) - critical_count
        print(
            f"[screen_lock] keyboard hook installed "
            f"({critical_count} critical + {extra_count} extra key blocks, esc_unlock={esc_enabled})",
            file=sys.stderr,
        )
        return True

    def _remove_hook(self):
        if not HAS_KEYBOARD:
            return
        for bid in getattr(self, "_blocked_ids", []) or []:
            try:
                _kb.unblock_key(bid)
            except (OSError, ValueError) as exc:
                print(f"[screen_lock] unblock_key failed: {exc!r}", file=sys.stderr)
        self._blocked_ids = []
        if self._hook is not None:
            try:
                _kb.unhook(self._hook)
            except (OSError, ValueError) as exc:
                print(f"[screen_lock] unhook failed: {exc!r}", file=sys.stderr)
            self._hook = None
            print("[screen_lock] keyboard hook removed", file=sys.stderr)

    def cleanup(self):
        self._remove_hook()
        self._hide_overlay()
        # Clear the flag on graceful shutdown so we don't false-positive the
        # next launch into the crash-recovery prompt.
        clear_lock_flag()


def _schedule_unlock(app: ScreenLockApp):
    try:
        if app._canvas and app._canvas.winfo_exists():
            app._canvas.after(0, app.unlock)
        else:
            app.unlock()
    except tk.TclError:
        pass


# ─────────────────────────────────────────────
#  Toolbox entry point
# ─────────────────────────────────────────────

def run_tool():
    root: Optional[ctk.CTkToplevel] = None
    try:
        # Offer crash-recovery prompt BEFORE opening any window so the user
        # can clear a stale overlay flag from a previous killed session.
        _maybe_prompt_crash_recovery()

        root = ctk.CTkToplevel()
        app  = ScreenLockApp(root)

        def on_close():
            app.cleanup()
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)
        root.update_idletasks()
        w, h = 430, 380
        x = (root.winfo_screenwidth()  - w) // 2
        y = (root.winfo_screenheight() - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.lift()
        root.focus_force()
        root.attributes("-topmost", True)
        root.after(250, lambda: root.attributes("-topmost", False))

    except Exception as e:  # noqa: BLE001 - boundary: surface any startup fault to UI
        messagebox.showerror("Screen Lock", f"Startup error:\n{e}")
        if root is not None:
            try:
                root.destroy()
            except tk.TclError:
                pass


def _maybe_prompt_crash_recovery() -> None:
    """If a stale ``locked.flag`` is found, offer to clear it.

    Silent no-op when no flag exists or the flagged PID is still alive.
    """
    if not is_stale_lock_flag():
        return
    try:
        answer = messagebox.askyesno(
            "Screen Lock",
            "A previous Screen Lock session appears to have crashed.\n"
            "Clear the leftover overlay flag?",
        )
    except tk.TclError:
        answer = True
    if answer:
        clear_lock_flag()


if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    root.withdraw()
    run_tool()
    root.mainloop()
