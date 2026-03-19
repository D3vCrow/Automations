"""
screen_lock.py

SCREEN LOCK (Kid-Safe)
- Transparent overlay covers your entire screen
- Adjustable opacity slider
- Unlock: Ctrl + Alt + U  (always) / optional ESC toggle
- Educational animated cards for every keypress (letters, numbers, specials)
- Physics: gravity, bounce, soft peer repulsion
- Mouse-click emoji bursts
- Cards never overlap at spawn; drift apart naturally

Dependencies:
  pip install keyboard
"""

import tkinter as tk
import customtkinter as ctk
import random
import math
from datetime import datetime

try:
    import keyboard as _kb
    HAS_KEYBOARD = True
except ImportError:
    HAS_KEYBOARD = False

TOOL_NAME = "Screen Lock (Kid-Safe)"
TOOL_DESCRIPTION = "Transparent overlay blocks keyboard input - stops kids from messing with your work"

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
        except Exception:
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
        except Exception:
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
        self._overlay: tk.Toplevel | None = None
        self._canvas: tk.Canvas | None = None
        self._peers: list = []          # active CardPhysics + ClickBurst

        self.alpha_var     = tk.DoubleVar(value=0.25)
        self.esc_unlock_var = tk.BooleanVar(value=False)

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

        # ESC toggle
        esc_card = ctk.CTkFrame(w)
        esc_card.pack(fill="x", padx=20, pady=6)
        ctk.CTkCheckBox(esc_card, text="Also unlock with  ESC  key",
                        variable=self.esc_unlock_var,
                        font=ctk.CTkFont(size=13)).pack(padx=14, pady=14)

        # Lock button
        ctk.CTkButton(w, text="🔒  Lock Screen Now",
                      font=ctk.CTkFont(size=15, weight="bold"),
                      height=50, fg_color="#c62828", hover_color="#8e0000",
                      command=self.lock).pack(padx=20, pady=10, fill="x")

        ctk.CTkLabel(w, text="Unlock shortcut:  Ctrl + Alt + U",
                     font=ctk.CTkFont(size=11), text_color="gray").pack(pady=(0, 6))

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
        self.locked = True
        self._show_overlay()
        self._install_hook()
        self.parent.withdraw()

    def unlock(self):
        if not self.locked:
            return
        self.locked = False
        self._remove_hook()
        self._hide_overlay()
        self.parent.deiconify()
        self.parent.lift()
        self.parent.focus_force()

    # ── Overlay ──────────────────────────────────

    def _show_overlay(self):
        ov = tk.Toplevel()
        ov.overrideredirect(True)
        sw, sh = ov.winfo_screenwidth(), ov.winfo_screenheight()
        ov.geometry(f"{sw}x{sh}+0+0")
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

        # Re-grab on focus loss (keep canvas focusable)
        ov.bind("<FocusOut>", lambda e: (ov.focus_force(), ov.grab_set_global()))

        # Key bindings on overlay window (absorb all)
        for seq in ("<Key>", "<KeyPress>", "<KeyRelease>"):
            ov.bind(seq, lambda e: "break")

        # Lock indicator — drawn as permanent canvas text (stays on top after
        # peer cards because we'll raise it after each spawn)
        canvas.create_text(20, 18, text="🔒", anchor="nw",
                           font=("Segoe UI Emoji", 26),
                           fill="#ffffff", tags="hud")
        canvas.create_text(20, 56, text="Ctrl + Alt + U  to unlock", anchor="nw",
                           font=("Segoe UI", 9),
                           fill="#3a3a3a", tags="hud")

        # Clock — top right
        canvas.create_text(sw - 20, 20, text="", anchor="ne",
                           font=("Segoe UI", 32, "bold"),
                           fill="#ffffff", tags="hud_clock")
        canvas.create_text(sw - 20, 60, text="", anchor="ne",
                           font=("Segoe UI", 13),
                           fill="#888888", tags="hud_date")

        self._overlay = ov
        self._canvas  = canvas
        self._peers   = []
        self._tick_clock()

    def _tick_clock(self):
        canvas = self._canvas
        if canvas is None or not self.locked:
            return
        try:
            if not canvas.winfo_exists():
                return
        except Exception:
            return
        now = datetime.now()
        canvas.itemconfigure("hud_clock", text=now.strftime("%H:%M:%S"))
        canvas.itemconfigure("hud_date",  text=now.strftime("%A, %d %B %Y"))
        canvas.tag_raise("hud"); canvas.tag_raise("hud_clock"); canvas.tag_raise("hud_date")
        canvas.tag_raise("hud_clock")
        canvas.tag_raise("hud_date")
        canvas.after(1000, self._tick_clock)

    def _hide_overlay(self):
        self._canvas  = None
        self._peers   = []
        if self._overlay:
            try:
                self._overlay.grab_release()
            except Exception:
                pass
            try:
                self._overlay.destroy()
            except Exception:
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
        except Exception:
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
        canvas.tag_raise("hud"); canvas.tag_raise("hud_clock"); canvas.tag_raise("hud_date")

    def _on_click(self, event):
        canvas = self._canvas
        if canvas is None:
            return
        try:
            if not canvas.winfo_exists():
                return
        except Exception:
            return

        burst = ClickBurst(canvas, event.x, event.y,
                           random.choice(_CLICK_EMOJIS))
        self._peers.append(burst)
        canvas.tag_raise("hud"); canvas.tag_raise("hud_clock"); canvas.tag_raise("hud_date")

    # ── Keyboard hook ────────────────────────────

    def _install_hook(self):
        if not HAS_KEYBOARD:
            return

        esc_enabled = self.esc_unlock_var.get()
        app = self
        _pressed: set[str] = set()

        def _norm(raw: str) -> str:
            n = (raw or "").lower()
            if n in ("left ctrl", "right ctrl", "ctrl"):   return "ctrl"
            if n in ("left alt",  "right alt",  "alt", "alt gr"): return "alt"
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
                except Exception:
                    pass

        self._hook = _kb.hook(_handler, suppress=True)

    def _remove_hook(self):
        if not HAS_KEYBOARD or self._hook is None:
            return
        try:
            _kb.unhook(self._hook)
        except Exception:
            pass
        self._hook = None

    def cleanup(self):
        self._remove_hook()
        self._hide_overlay()


def _schedule_unlock(app: ScreenLockApp):
    try:
        if app._canvas and app._canvas.winfo_exists():
            app._canvas.after(0, app.unlock)
        else:
            app.unlock()
    except Exception:
        pass


# ─────────────────────────────────────────────
#  Toolbox entry point
# ─────────────────────────────────────────────

def run_tool():
    try:
        root = ctk.CTkToplevel()
        app  = ScreenLockApp(root)

        def on_close():
            app.cleanup()
            root.destroy()

        root.protocol("WM_DELETE_WINDOW", on_close)
        root.update_idletasks()
        w, h = 430, 340
        x = (root.winfo_screenwidth()  - w) // 2
        y = (root.winfo_screenheight() - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.lift()
        root.focus_force()
        root.attributes("-topmost", True)
        root.after(250, lambda: root.attributes("-topmost", False))

    except Exception as e:
        from tkinter import messagebox
        messagebox.showerror("Screen Lock", f"Startup error:\n{e}")


if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    root.withdraw()
    run_tool()
    root.mainloop()
