"""
decision_dice.py

DECISION DICE PRO — Weighted RNG Decision Maker
- Per-outcome animations (confetti, rain, fireworks, lightning)
- Custom dice profiles with adjustable weight sliders
- Sound effects (Windows Beep, no deps)
- 3D animated dice with specular highlights, beveled edges, ambient glow
- Screen shake on dramatic outcomes
- Persistent decision journal with streak detection

Dependencies:
  pip install customtkinter
"""

import json
import math
import os
import random
import threading
import time
import tkinter as tk
import customtkinter as ctk
from datetime import datetime

TOOL_NAME = "Decision Dice"
TOOL_DESCRIPTION = "Premium weighted RNG dice — custom profiles, 3D animation, decision journal"

# ─── Paths ────────────────────────────────────────────────────────────────────

_DIR = os.path.dirname(os.path.abspath(__file__))
JOURNAL_PATH = os.path.join(_DIR, "decision_journal.json")
PROFILES_PATH = os.path.join(_DIR, "dice_profiles.json")

# ─── Sound (Windows, no deps) ────────────────────────────────────────────────

try:
    import winsound
    HAS_SOUND = True
except ImportError:
    HAS_SOUND = False

def _beep_thread(freq, dur):
    if HAS_SOUND:
        try:
            winsound.Beep(freq, dur)
        except Exception:
            pass

def play_sound(kind: str):
    """Non-blocking sound effects via winsound.Beep."""
    sequences = {
        "roll":    [(300, 40), (400, 40), (500, 40), (350, 40)],
        "tick":    [(600, 15)],
        "yes":     [(523, 80), (659, 80), (784, 120)],
        "no":      [(400, 100), (300, 150)],
        "def_yes": [(523, 60), (659, 60), (784, 60), (1047, 180)],
        "def_no":  [(500, 80), (400, 80), (300, 80), (200, 200)],
    }
    notes = sequences.get(kind, [])
    if not notes:
        return
    def _play():
        for freq, dur in notes:
            _beep_thread(freq, dur)
    threading.Thread(target=_play, daemon=True).start()

# ─── Default outcomes ─────────────────────────────────────────────────────────

DEFAULT_OUTCOMES = [
    {"label": "YES",            "weight": 45, "color": "#22c55e", "glow": "#4ade80",
     "emoji": "✓",  "accent": "#166534", "sound": "yes",     "fx": "confetti"},
    {"label": "NO",             "weight": 45, "color": "#ef4444", "glow": "#f87171",
     "emoji": "✗",  "accent": "#7f1d1d", "sound": "no",      "fx": "rain"},
    {"label": "DEFINITELY YES", "weight": 5,  "color": "#facc15", "glow": "#fde047",
     "emoji": "★",  "accent": "#713f12", "sound": "def_yes", "fx": "fireworks"},
    {"label": "DEFINITELY NO",  "weight": 5,  "color": "#a855f7", "glow": "#c084fc",
     "emoji": "⚡", "accent": "#581c87", "sound": "def_no",  "fx": "lightning"},
]

DEFAULT_PROFILES = {
    "Standard (45/45/5/5)": [45, 45, 5, 5],
    "Coin Flip (50/50)": [50, 50, 0, 0],
    "Cautious (35/55/5/5)": [35, 55, 5, 5],
    "Bold (55/25/15/5)": [55, 25, 15, 5],
    "Chaos (25/25/25/25)": [25, 25, 25, 25],
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def hex_to_rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))

def rgb_to_hex(r, g, b):
    return f"#{max(0,min(255,int(r))):02x}{max(0,min(255,int(g))):02x}{max(0,min(255,int(b))):02x}"

def lerp_color(c1, c2, t):
    r1, g1, b1 = hex_to_rgb(c1)
    r2, g2, b2 = hex_to_rgb(c2)
    return rgb_to_hex(r1 + (r2-r1)*t, g1 + (g2-g1)*t, b1 + (b2-b1)*t)

def build_pool(outcomes):
    pool = []
    for o in outcomes:
        pool.extend([o] * max(0, o["weight"]))
    return pool if pool else [outcomes[0]]


# ─── Profile persistence ─────────────────────────────────────────────────────

def load_profiles():
    if os.path.exists(PROFILES_PATH):
        try:
            with open(PROFILES_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return dict(DEFAULT_PROFILES)

def save_profiles(profiles):
    try:
        with open(PROFILES_PATH, "w") as f:
            json.dump(profiles, f, indent=2)
    except Exception:
        pass


# ─── Journal persistence ─────────────────────────────────────────────────────

def load_journal():
    if os.path.exists(JOURNAL_PATH):
        try:
            with open(JOURNAL_PATH, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_journal(entries):
    try:
        with open(JOURNAL_PATH, "w") as f:
            json.dump(entries[-500:], f, indent=2)
    except Exception:
        pass


# ─── 3D Dice Renderer ────────────────────────────────────────────────────────

class Dice3D:
    """Renders a 3D cube with specular highlights, beveled edges, ambient glow."""

    def __init__(self, canvas: tk.Canvas):
        self.canvas = canvas
        self.cx = 0
        self.cy = 0
        self.size = 100
        self.angle_x = 0.0
        self.angle_y = 0.0
        self.angle_z = 0.0
        self.face_color = "#3b82f6"
        self.face_text = "?"
        self.face_emoji = ""
        self.glow_color = "#60a5fa"
        self.glow_pulse = 0.0        # 0..1 pulsing intensity for idle glow

    def set_result(self, color, text, emoji, glow):
        self.face_color = color
        self.face_text = text
        self.face_emoji = emoji
        self.glow_color = glow

    def _rotate(self, x, y, z):
        """Apply XYZ Euler rotation."""
        cx, sx = math.cos(self.angle_x), math.sin(self.angle_x)
        y, z = y*cx - z*sx, y*sx + z*cx
        cy, sy = math.cos(self.angle_y), math.sin(self.angle_y)
        x, z = x*cy + z*sy, -x*sy + z*cy
        cz, sz = math.cos(self.angle_z), math.sin(self.angle_z)
        x, y = x*cz - y*sz, x*sz + y*cz
        return x, y, z

    def _project(self, x, y, z):
        """Perspective projection."""
        d = 600
        scale = d / (d + z)
        return self.cx + x * scale, self.cy + y * scale, z

    def draw(self):
        self.canvas.delete("dice")
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10 or h < 10:
            return
        self.cx = w / 2
        self.cy = h / 2
        s = self.size

        # ─── Ambient glow behind dice ───
        if self.glow_pulse > 0.05:
            gr, gg, gb = hex_to_rgb(self.glow_color)
            for ring in range(5, 0, -1):
                radius = s * (1.2 + ring * 0.25)
                alpha = self.glow_pulse * (0.08 - ring * 0.012)
                alpha = max(0, min(1, alpha))
                cr = int(gr * alpha + 17 * (1 - alpha))
                cg = int(gg * alpha + 17 * (1 - alpha))
                cb = int(gb * alpha + 17 * (1 - alpha))
                c = rgb_to_hex(cr, cg, cb)
                self.canvas.create_oval(
                    self.cx - radius, self.cy - radius,
                    self.cx + radius, self.cy + radius,
                    fill=c, outline="", tags="dice"
                )

        # ─── Shadow ───
        shadow_y = self.cy + s * 1.35
        for i in range(4):
            sw = s * (1.8 - i * 0.15)
            sh = s * (0.5 - i * 0.05)
            shade = 8 + i * 3
            c = rgb_to_hex(shade, shade, shade)
            self.canvas.create_oval(
                self.cx - sw, shadow_y - sh, self.cx + sw, shadow_y + sh,
                fill=c, outline="", tags="dice"
            )

        # ─── Cube corners ───
        corners_local = [
            (-s, -s, -s), (s, -s, -s), (s, s, -s), (-s, s, -s),
            (-s, -s,  s), (s, -s,  s), (s, s,  s), (-s, s,  s),
        ]
        corners = [self._project(*self._rotate(*c)) for c in corners_local]

        # ─── Faces: indices, normal ───
        faces_def = [
            ([0,1,2,3], ( 0, 0,-1)),
            ([5,4,7,6], ( 0, 0, 1)),
            ([4,0,3,7], (-1, 0, 0)),
            ([1,5,6,2], ( 1, 0, 0)),
            ([4,5,1,0], ( 0,-1, 0)),
            ([3,2,6,7], ( 0, 1, 0)),
        ]

        # Sort by average z
        face_data = []
        for indices, normal in faces_def:
            pts = [corners[i] for i in indices]
            avg_z = sum(p[2] for p in pts) / 4
            # Rotated normal for lighting
            rnx, rny, rnz = self._rotate(*normal)
            face_data.append((avg_z, pts, rnx, rny, rnz))
        face_data.sort(key=lambda f: f[0], reverse=True)

        # Light direction (top-left-front)
        lx, ly, lz = 0.3, -0.5, -0.8
        lmag = math.sqrt(lx*lx + ly*ly + lz*lz)
        lx, ly, lz = lx/lmag, ly/lmag, lz/lmag

        fr, fg, fb = hex_to_rgb(self.face_color)

        for i, (avg_z, pts, nx, ny, nz) in enumerate(face_data):
            coords = []
            for px, py, pz in pts:
                coords.extend([px, py])

            # Diffuse lighting
            diffuse = max(0, -(nx*lx + ny*ly + nz*lz))
            ambient = 0.25
            brightness = min(1.0, ambient + diffuse * 0.75)

            # Specular highlight (Blinn-Phong)
            # Half-vector between light and view (0,0,-1)
            hx, hy, hz = lx, ly, lz - 1
            hmag = math.sqrt(hx*hx + hy*hy + hz*hz) or 1
            hx, hy, hz = hx/hmag, hy/hmag, hz/hmag
            spec = max(0, -(nx*hx + ny*hy + nz*hz)) ** 32
            spec_add = spec * 120

            cr = min(255, int(fr * brightness + spec_add))
            cg = min(255, int(fg * brightness + spec_add))
            cb = min(255, int(fb * brightness + spec_add))
            fill = rgb_to_hex(cr, cg, cb)

            # Bevel: slightly lighter edge
            er = min(255, cr + 20)
            eg = min(255, cg + 20)
            eb = min(255, cb + 20)
            edge = rgb_to_hex(er, eg, eb)

            self.canvas.create_polygon(
                coords, fill=fill, outline=edge, width=2,
                tags="dice", smooth=False
            )

            # Inner bevel line (inset border for depth)
            if len(pts) == 4:
                inset = 0.88
                fcx = sum(p[0] for p in pts) / 4
                fcy = sum(p[1] for p in pts) / 4
                inner = []
                for px, py, pz in pts:
                    ix = fcx + (px - fcx) * inset
                    iy = fcy + (py - fcy) * inset
                    inner.extend([ix, iy])
                inner_r = max(0, cr - 25)
                inner_g = max(0, cg - 25)
                inner_b = max(0, cb - 25)
                self.canvas.create_polygon(
                    inner, fill="", outline=rgb_to_hex(inner_r, inner_g, inner_b),
                    width=1, tags="dice"
                )

            # Draw text on the front-most face
            if i == len(face_data) - 1:
                fcx = sum(p[0] for p in pts) / 4
                fcy = sum(p[1] for p in pts) / 4

                # Emoji / symbol
                self.canvas.create_text(
                    fcx, fcy - 6, text=self.face_emoji,
                    font=("Segoe UI Emoji", max(16, int(s/4))),
                    fill=self.glow_color, tags="dice"
                )
                # Label text
                fs = max(10, int(s / 8))
                self.canvas.create_text(
                    fcx + 1, fcy + int(s/3.2) + 1, text=self.face_text,
                    font=("Segoe UI", fs, "bold"), fill="#000000",
                    tags="dice"
                )
                self.canvas.create_text(
                    fcx, fcy + int(s/3.2), text=self.face_text,
                    font=("Segoe UI", fs, "bold"), fill="white",
                    tags="dice"
                )


# ─── Particle FX System ──────────────────────────────────────────────────────

class Particle:
    __slots__ = ("x", "y", "vx", "vy", "life", "color", "size", "shape", "gravity", "drag")

    def __init__(self, x, y, color, vx=None, vy=None, size=None,
                 shape="circle", gravity=0.15, drag=0.99, life=1.0):
        self.x = x
        self.y = y
        self.vx = vx if vx is not None else random.uniform(-4, 4)
        self.vy = vy if vy is not None else random.uniform(-8, -1)
        self.life = life
        self.color = color
        self.size = size or random.uniform(3, 7)
        self.shape = shape
        self.gravity = gravity
        self.drag = drag


def spawn_confetti(cx, cy, color, glow, count=50):
    """Upward burst of colorful squares and circles."""
    particles = []
    colors = [color, glow, "#ffffff", lerp_color(color, "#ffffff", 0.5)]
    for _ in range(count):
        angle = random.uniform(-math.pi, 0)  # upward hemisphere
        speed = random.uniform(4, 14)
        p = Particle(
            cx + random.uniform(-20, 20), cy,
            random.choice(colors),
            vx=math.cos(angle) * speed,
            vy=math.sin(angle) * speed - 3,
            size=random.uniform(3, 8),
            shape=random.choice(["circle", "rect"]),
            gravity=0.22, drag=0.98, life=random.uniform(0.7, 1.0)
        )
        particles.append(p)
    return particles


def spawn_rain(cx, cy, color, glow, w, count=60):
    """Gentle falling drops from top."""
    particles = []
    colors = [color, glow, lerp_color(color, "#333333", 0.6)]
    for _ in range(count):
        p = Particle(
            random.uniform(0, w), random.uniform(-40, -5),
            random.choice(colors),
            vx=random.uniform(-0.5, 0.5),
            vy=random.uniform(3, 7),
            size=random.uniform(1.5, 3.5),
            shape="line",
            gravity=0.05, drag=1.0, life=random.uniform(0.6, 1.0)
        )
        particles.append(p)
    return particles


def spawn_fireworks(cx, cy, color, glow, count=80):
    """Multi-burst firework explosion."""
    particles = []
    colors = [color, glow, "#ffffff", "#ffd700", "#ff6b6b"]
    # 3 bursts at slightly different positions
    for burst in range(3):
        bx = cx + random.uniform(-60, 60)
        by = cy + random.uniform(-40, 20)
        for _ in range(count // 3):
            angle = random.uniform(0, 2 * math.pi)
            speed = random.uniform(2, 10)
            p = Particle(
                bx, by, random.choice(colors),
                vx=math.cos(angle) * speed,
                vy=math.sin(angle) * speed,
                size=random.uniform(2, 6),
                shape=random.choice(["circle", "star"]),
                gravity=0.08, drag=0.96, life=random.uniform(0.5, 1.0)
            )
            particles.append(p)
    return particles


def spawn_lightning(cx, cy, color, glow, h, count=30):
    """Jagged bolts from top + scattered sparks."""
    particles = []
    # Spark particles
    colors = [color, glow, "#ffffff", "#cc88ff"]
    for _ in range(count):
        angle = random.uniform(0, 2 * math.pi)
        speed = random.uniform(1, 6)
        p = Particle(
            cx + random.uniform(-80, 80), cy + random.uniform(-40, 40),
            random.choice(colors),
            vx=math.cos(angle) * speed,
            vy=math.sin(angle) * speed,
            size=random.uniform(2, 5),
            shape="circle",
            gravity=0.05, drag=0.95, life=random.uniform(0.3, 0.8)
        )
        particles.append(p)
    return particles


# ─── Main App ────────────────────────────────────────────────────────────────

class App(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        parent.title("Decision Dice")
        parent.geometry("560x740")
        parent.minsize(460, 620)
        parent.resizable(True, True)

        self.rolling = False
        self.roll_start = 0.0
        self.roll_duration = 2.0
        self.current_outcome = None
        self.particles: list = []
        self.lightning_bolts: list = []
        self.shake_offset_x = 0.0
        self.shake_offset_y = 0.0
        self.shake_time = 0.0
        self.idle_glow_phase = 0.0

        # Load data
        self.profiles = load_profiles()
        self.journal = load_journal()
        self.outcomes = [dict(o) for o in DEFAULT_OUTCOMES]
        self.current_profile = "Standard (45/45/5/5)"
        self.sound_enabled = True

        self._build_ui()
        self.pack(fill="both", expand=True)

        self.after(50, self._initial_draw)
        self.after(100, self._idle_glow_loop)

    def _initial_draw(self):
        self.canvas.update_idletasks()
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w > 1 and h > 1:
            self.dice.size = min(w, h) // 4.5
            self.dice.draw()

    def _idle_glow_loop(self):
        """Subtle ambient glow pulse when idle."""
        if not self.rolling:
            self.idle_glow_phase += 0.04
            pulse = (math.sin(self.idle_glow_phase) + 1) / 2  # 0..1
            self.dice.glow_pulse = 0.2 + pulse * 0.3
            self.dice.draw()
        self.after(50, self._idle_glow_loop)

    # ─── UI Build ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ─── Top bar: profile + settings ───
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(12, 0))

        ctk.CTkLabel(top, text="PROFILE", font=("Segoe UI", 9, "bold"),
                     text_color="#666666").pack(side="left", padx=(0, 6))

        self.profile_var = tk.StringVar(value=self.current_profile)
        self.profile_menu = ctk.CTkOptionMenu(
            top, variable=self.profile_var,
            values=list(self.profiles.keys()),
            command=self._on_profile_change,
            width=180, height=28, font=("Segoe UI", 10),
            fg_color="#1e1e1e", button_color="#333333",
            button_hover_color="#444444"
        )
        self.profile_menu.pack(side="left")

        # Right side buttons
        btn_frame = ctk.CTkFrame(top, fg_color="transparent")
        btn_frame.pack(side="right")

        self.sound_btn = ctk.CTkButton(
            btn_frame, text="🔊", width=32, height=28, corner_radius=6,
            fg_color="#1e1e1e", hover_color="#333333",
            command=self._toggle_sound, font=("Segoe UI", 13)
        )
        self.sound_btn.pack(side="left", padx=2)

        ctk.CTkButton(
            btn_frame, text="⚙", width=32, height=28, corner_radius=6,
            fg_color="#1e1e1e", hover_color="#333333",
            command=self._open_profile_editor, font=("Segoe UI", 13)
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            btn_frame, text="📖", width=32, height=28, corner_radius=6,
            fg_color="#1e1e1e", hover_color="#333333",
            command=self._open_journal, font=("Segoe UI", 13)
        ).pack(side="left", padx=2)

        # ─── Question input ───
        q_frame = ctk.CTkFrame(self, fg_color="transparent")
        q_frame.pack(fill="x", padx=20, pady=(10, 4))

        ctk.CTkLabel(q_frame, text="YOUR QUESTION", font=("Segoe UI", 10, "bold"),
                     text_color="#888888").pack(anchor="w")

        self.question_var = tk.StringVar(value="")
        self.question_entry = ctk.CTkEntry(
            q_frame, textvariable=self.question_var, height=38,
            font=("Segoe UI", 13), placeholder_text="Type your question here...",
            corner_radius=10
        )
        self.question_entry.pack(fill="x", pady=(4, 0))
        self.question_entry.bind("<Return>", lambda _e: self._roll())

        # ─── Canvas (dice area) ───
        self.canvas_frame = ctk.CTkFrame(self, fg_color="#111111", corner_radius=16)
        self.canvas_frame.pack(fill="both", expand=True, padx=20, pady=10)

        self.canvas = tk.Canvas(self.canvas_frame, bg="#111111", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True, padx=4, pady=4)

        self.dice = Dice3D(self.canvas)
        self.dice.face_color = "#3b82f6"
        self.dice.glow_color = "#60a5fa"
        self.dice.face_text = "?"
        self.dice.face_emoji = "🎲"

        # ─── Probability bar ───
        self.prob_canvas = tk.Canvas(self, bg="#1a1a1a", height=24, highlightthickness=0)
        self.prob_canvas.pack(fill="x", padx=20, pady=(0, 4))
        self.after(100, self._draw_prob_bar)

        # ─── Result label ───
        self.result_label = ctk.CTkLabel(
            self, text="Roll the dice!", font=("Segoe UI", 24, "bold"),
            text_color="#888888"
        )
        self.result_label.pack(pady=(2, 0))

        self.streak_label = ctk.CTkLabel(
            self, text="", font=("Segoe UI", 10), text_color="#555555"
        )
        self.streak_label.pack(pady=(0, 4))

        # ─── Roll button ───
        self.roll_btn = ctk.CTkButton(
            self, text="🎲  ROLL", font=("Segoe UI", 16, "bold"),
            height=50, corner_radius=14, command=self._roll,
            fg_color="#3b82f6", hover_color="#2563eb"
        )
        self.roll_btn.pack(fill="x", padx=60, pady=(2, 6))

        # ─── History ───
        hist_frame = ctk.CTkFrame(self, fg_color="transparent")
        hist_frame.pack(fill="x", padx=20, pady=(0, 12))

        ctk.CTkLabel(hist_frame, text="RECENT", font=("Segoe UI", 9, "bold"),
                     text_color="#555555").pack(anchor="w")

        self.history_frame = ctk.CTkFrame(hist_frame, fg_color="transparent", height=36)
        self.history_frame.pack(fill="x", pady=(2, 0))

        self.canvas.bind("<Configure>", self._on_canvas_resize)
        self._update_history()

    # ─── Probability bar ──────────────────────────────────────────────────────

    def _draw_prob_bar(self):
        c = self.prob_canvas
        c.delete("all")
        c.update_idletasks()
        w = c.winfo_width()
        h = 24
        if w < 10:
            self.after(200, self._draw_prob_bar)
            return

        total = sum(o["weight"] for o in self.outcomes)
        if total == 0:
            return
        x = 0
        for o in self.outcomes:
            seg_w = (o["weight"] / total) * w
            if seg_w < 1:
                continue
            c.create_rectangle(x, 2, x + seg_w, h - 2,
                               fill=o["accent"], outline="", tags="bar")
            if seg_w > 30:
                c.create_text(x + seg_w / 2, h / 2,
                              text=f'{o["weight"]}%', font=("Segoe UI", 8, "bold"),
                              fill=o["color"], tags="bar")
            x += seg_w

    # ─── Profile management ───────────────────────────────────────────────────

    def _on_profile_change(self, name):
        if name in self.profiles:
            weights = self.profiles[name]
            for i, w in enumerate(weights):
                if i < len(self.outcomes):
                    self.outcomes[i]["weight"] = w
            self.current_profile = name
            self._draw_prob_bar()

    def _toggle_sound(self):
        self.sound_enabled = not self.sound_enabled
        self.sound_btn.configure(text="🔊" if self.sound_enabled else "🔇")

    def _open_profile_editor(self):
        win = ctk.CTkToplevel(self.parent)
        win.title("Profile Editor")
        win.geometry("400x480")
        win.resizable(False, False)
        win.transient(self.parent)
        win.grab_set()

        ctk.CTkLabel(win, text="Edit Dice Weights",
                     font=("Segoe UI", 16, "bold")).pack(pady=(16, 4))
        ctk.CTkLabel(win, text="Adjust the probability for each outcome. Total must be 100%.",
                     font=("Segoe UI", 10), text_color="#888888").pack(pady=(0, 12))

        sliders = []
        slider_frame = ctk.CTkFrame(win)
        slider_frame.pack(fill="x", padx=20, pady=4)

        total_label = ctk.CTkLabel(win, text="Total: 100%",
                                   font=("Segoe UI", 12, "bold"), text_color="#22c55e")
        total_label.pack(pady=(8, 4))

        def on_slider_change(_=None):
            total = sum(int(sv.get()) for sv, _ in sliders)
            color = "#22c55e" if total == 100 else "#ef4444"
            total_label.configure(text=f"Total: {total}%", text_color=color)

        for i, o in enumerate(self.outcomes):
            row = ctk.CTkFrame(slider_frame, fg_color="transparent")
            row.pack(fill="x", pady=6)

            ctk.CTkLabel(row, text=f'{o["emoji"]} {o["label"]}',
                         font=("Segoe UI", 11, "bold"),
                         text_color=o["color"], width=140, anchor="w").pack(side="left")

            sv = tk.IntVar(value=o["weight"])
            val_lbl = ctk.CTkLabel(row, text=f'{o["weight"]}%',
                                   font=("Segoe UI", 11, "bold"),
                                   text_color="#cccccc", width=45)
            val_lbl.pack(side="right", padx=(4, 0))

            def make_cmd(var, lbl):
                def cmd(v):
                    var.set(int(float(v)))
                    lbl.configure(text=f"{int(float(v))}%")
                    on_slider_change()
                return cmd

            slider = ctk.CTkSlider(
                row, from_=0, to=100, variable=sv,
                command=make_cmd(sv, val_lbl),
                button_color=o["color"], button_hover_color=o["glow"],
                progress_color=o["accent"],
                width=160
            )
            slider.pack(side="right", padx=4)
            sliders.append((sv, val_lbl))

        # Profile name
        name_frame = ctk.CTkFrame(win, fg_color="transparent")
        name_frame.pack(fill="x", padx=20, pady=(8, 4))
        ctk.CTkLabel(name_frame, text="Save as:", font=("Segoe UI", 10),
                     text_color="#888888").pack(side="left")
        name_var = tk.StringVar(value=self.current_profile)
        ctk.CTkEntry(name_frame, textvariable=name_var, width=200,
                     height=28, font=("Segoe UI", 10)).pack(side="left", padx=8)

        def apply_weights():
            total = sum(int(sv.get()) for sv, _ in sliders)
            if total != 100:
                total_label.configure(text=f"Total: {total}% (must be 100!)",
                                     text_color="#ef4444")
                return
            weights = [int(sv.get()) for sv, _ in sliders]
            for i, w in enumerate(weights):
                self.outcomes[i]["weight"] = w
            # Save profile
            pname = name_var.get().strip() or "Custom"
            self.profiles[pname] = weights
            save_profiles(self.profiles)
            self.current_profile = pname
            self.profile_var.set(pname)
            self.profile_menu.configure(values=list(self.profiles.keys()))
            self._draw_prob_bar()
            win.destroy()

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(fill="x", padx=20, pady=(8, 16))
        ctk.CTkButton(btn_row, text="Apply & Save", command=apply_weights,
                      fg_color="#22c55e", hover_color="#16a34a",
                      height=36, font=("Segoe UI", 12, "bold")).pack(side="right", padx=4)
        ctk.CTkButton(btn_row, text="Cancel", command=win.destroy,
                      fg_color="#333333", hover_color="#444444",
                      height=36, font=("Segoe UI", 12)).pack(side="right", padx=4)

    def _open_journal(self):
        win = ctk.CTkToplevel(self.parent)
        win.title("Decision Journal")
        win.geometry("520x500")
        win.resizable(True, True)
        win.transient(self.parent)

        ctk.CTkLabel(win, text="Decision Journal",
                     font=("Segoe UI", 16, "bold")).pack(pady=(16, 4))

        # Stats
        total = len(self.journal)
        if total > 0:
            counts = {}
            for e in self.journal:
                lbl = e.get("outcome", "?")
                counts[lbl] = counts.get(lbl, 0) + 1
            stats = " · ".join(f'{k}: {v}' for k, v in sorted(counts.items()))
            ctk.CTkLabel(win, text=f"{total} decisions — {stats}",
                         font=("Segoe UI", 10), text_color="#888888").pack(pady=(0, 8))

        # Scrollable list
        scroll = ctk.CTkScrollableFrame(win)
        scroll.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        for entry in reversed(self.journal[-100:]):
            row = ctk.CTkFrame(scroll, fg_color="#1a1a1a", corner_radius=8)
            row.pack(fill="x", pady=2)

            outcome_label = entry.get("outcome", "?")
            # Find matching outcome for color
            oc = None
            for o in DEFAULT_OUTCOMES:
                if o["label"] == outcome_label:
                    oc = o
                    break

            color = oc["color"] if oc else "#888888"
            emoji = oc["emoji"] if oc else "?"

            ctk.CTkLabel(row, text=f'  {emoji} {outcome_label}',
                         font=("Segoe UI", 11, "bold"),
                         text_color=color, width=160, anchor="w").pack(side="left", padx=4, pady=4)

            q = entry.get("question", "—")
            ctk.CTkLabel(row, text=q[:50], font=("Segoe UI", 10),
                         text_color="#aaaaaa", anchor="w").pack(side="left", fill="x", expand=True, padx=4)

            ts = entry.get("time", "")
            ctk.CTkLabel(row, text=ts[:16], font=("Segoe UI", 9),
                         text_color="#555555").pack(side="right", padx=8, pady=4)

        # Clear button
        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(fill="x", padx=16, pady=(0, 12))

        def clear_journal():
            self.journal.clear()
            save_journal(self.journal)
            win.destroy()

        ctk.CTkButton(btn_row, text="Clear Journal", command=clear_journal,
                      fg_color="#333333", hover_color="#444444",
                      height=32, font=("Segoe UI", 10)).pack(side="left")
        ctk.CTkButton(btn_row, text="Close", command=win.destroy,
                      fg_color="#333333", hover_color="#444444",
                      height=32, font=("Segoe UI", 10)).pack(side="right")

    # ─── Canvas resize ────────────────────────────────────────────────────────

    def _on_canvas_resize(self, event):
        self.dice.size = min(event.width, event.height) // 4.5
        if not self.rolling:
            self.dice.draw()

    # ─── Rolling ──────────────────────────────────────────────────────────────

    def _roll(self):
        if self.rolling:
            return

        pool = build_pool(self.outcomes)
        self.current_outcome = random.choice(pool)
        self.rolling = True
        self.roll_start = time.time()
        self.particles.clear()
        self.lightning_bolts.clear()

        self.roll_btn.configure(state="disabled", fg_color="#1e3a5f", text="Rolling...")
        self.result_label.configure(text="...", text_color="#888888")
        self.streak_label.configure(text="")

        if self.sound_enabled:
            play_sound("roll")

        self._animate_roll()

    def _animate_roll(self):
        elapsed = time.time() - self.roll_start
        t = min(elapsed / self.roll_duration, 1.0)

        # Ease-out cubic
        ease = 1 - (1 - t) ** 3

        # Rotation decelerates
        speed = (1 - ease) * 0.5 + 0.005
        self.dice.angle_x += speed
        self.dice.angle_y += speed * 0.73
        self.dice.angle_z += speed * 0.31

        # Tick sound during fast phase
        if t < 0.6 and self.sound_enabled and random.random() < 0.15:
            play_sound("tick")

        # Show random faces during roll, lock to result in final phase
        if t < 0.8:
            interim = random.choice(DEFAULT_OUTCOMES)
            self.dice.set_result(interim["color"], interim["label"],
                                 interim["emoji"], interim["glow"])
            self.dice.glow_pulse = 0.1
        else:
            o = self.current_outcome
            self.dice.set_result(o["color"], o["label"], o["emoji"], o["glow"])
            self.dice.glow_pulse = 0.3 + (t - 0.8) * 3  # ramp up glow

        # Wobble settling
        if t > 0.65:
            wobble = (1 - t) * 0.2 * math.sin(elapsed * 22)
            self.dice.angle_x += wobble
            self.dice.angle_y += wobble * 0.7

        self.dice.draw()

        if t < 1.0:
            self.after(16, self._animate_roll)
        else:
            self._finish_roll()

    def _finish_roll(self):
        self.rolling = False
        o = self.current_outcome

        # Snap to front-face
        self.dice.angle_x = 0.0
        self.dice.angle_y = 0.0
        self.dice.angle_z = 0.0
        self.dice.set_result(o["color"], o["label"], o["emoji"], o["glow"])
        self.dice.glow_pulse = 0.8
        self.dice.draw()

        self.result_label.configure(text=o["label"], text_color=o["color"])
        self.roll_btn.configure(state="normal", fg_color="#3b82f6", text="🎲  ROLL")

        # Sound
        if self.sound_enabled:
            play_sound(o["sound"])

        # Screen shake for dramatic outcomes
        if o["fx"] in ("fireworks", "lightning"):
            self.shake_time = time.time()
            self._screen_shake()

        # Spawn FX particles
        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        cx, cy = w / 2, h / 2

        if o["fx"] == "confetti":
            self.particles = spawn_confetti(cx, cy, o["color"], o["glow"], 55)
        elif o["fx"] == "rain":
            self.particles = spawn_rain(cx, cy, o["color"], o["glow"], w, 50)
        elif o["fx"] == "fireworks":
            self.particles = spawn_fireworks(cx, cy, o["color"], o["glow"], 90)
        elif o["fx"] == "lightning":
            self.particles = spawn_lightning(cx, cy, o["color"], o["glow"], h, 40)
            self._spawn_lightning_bolts(cx, h)

        self._animate_particles()
        self._pulse_label(o["color"], 0)

        # Journal entry
        q = self.question_var.get().strip() or "—"
        entry = {
            "question": q,
            "outcome": o["label"],
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "profile": self.current_profile,
        }
        self.journal.append(entry)
        save_journal(self.journal)

        # Streak detection
        self._check_streak(o["label"])

        # Session history display
        if not hasattr(self, "session_history"):
            self.session_history = []
        self.session_history.insert(0, {"question": q, "outcome": o})
        self._update_history()

    # ─── Screen shake ─────────────────────────────────────────────────────────

    def _screen_shake(self):
        elapsed = time.time() - self.shake_time
        if elapsed > 0.4:
            self.canvas_frame.pack_configure(padx=20)
            return
        intensity = 6 * (1 - elapsed / 0.4)
        dx = random.uniform(-intensity, intensity)
        dy = random.uniform(-intensity, intensity)
        self.canvas_frame.pack_configure(padx=(20 + int(dx), 20 - int(dx)))
        self.after(30, self._screen_shake)

    # ─── Lightning bolts ──────────────────────────────────────────────────────

    def _spawn_lightning_bolts(self, cx, h):
        self.lightning_bolts = []
        for _ in range(3):
            bolt = []
            x = cx + random.uniform(-100, 100)
            y = 0
            while y < h:
                bolt.append((x, y))
                x += random.uniform(-25, 25)
                y += random.uniform(10, 30)
            bolt.append((x, h))
            self.lightning_bolts.append(bolt)
        self._flash_count = 0
        self._draw_lightning()

    def _draw_lightning(self):
        self.canvas.delete("lightning")
        if self._flash_count >= 6:
            self.lightning_bolts.clear()
            return
        if self._flash_count % 2 == 0:
            for bolt in self.lightning_bolts:
                for i in range(len(bolt) - 1):
                    x1, y1 = bolt[i]
                    x2, y2 = bolt[i + 1]
                    # Thick glow
                    self.canvas.create_line(x1, y1, x2, y2, fill="#c084fc",
                                           width=4, tags="lightning")
                    # Core
                    self.canvas.create_line(x1, y1, x2, y2, fill="#ffffff",
                                           width=2, tags="lightning")
        self._flash_count += 1
        self.after(80, self._draw_lightning)

    # ─── Streak detection ─────────────────────────────────────────────────────

    def _check_streak(self, label):
        streak = 0
        for e in reversed(self.journal):
            if e["outcome"] == label:
                streak += 1
            else:
                break
        if streak >= 3:
            total_w = 0
            for o in self.outcomes:
                if o["label"] == label:
                    total_w = o["weight"]
                    break
            prob = (total_w / 100) ** streak * 100 if total_w > 0 else 0
            self.streak_label.configure(
                text=f"🔥 {streak}x {label} streak! ({prob:.1f}% chance)",
                text_color="#ffa500"
            )
        else:
            self.streak_label.configure(text="")

    # ─── Pulse label ──────────────────────────────────────────────────────────

    def _pulse_label(self, color, step):
        if step >= 8:
            self.result_label.configure(text_color=color)
            return
        self.result_label.configure(
            text_color="white" if step % 2 == 0 else color
        )
        self.after(100, lambda: self._pulse_label(color, step + 1))

    # ─── Particles animation ──────────────────────────────────────────────────

    def _animate_particles(self):
        self.canvas.delete("particle")
        alive = []
        for p in self.particles:
            p.vx *= p.drag
            p.vy *= p.drag
            p.x += p.vx
            p.y += p.vy
            p.vy += p.gravity
            p.life -= 0.025
            if p.life <= 0:
                continue
            alive.append(p)
            alpha = max(0, min(1, p.life))
            sz = p.size * alpha

            r, g, b = hex_to_rgb(p.color)
            r, g, b = int(r * alpha), int(g * alpha), int(b * alpha)
            c = rgb_to_hex(r, g, b)

            if p.shape == "circle":
                self.canvas.create_oval(
                    p.x - sz, p.y - sz, p.x + sz, p.y + sz,
                    fill=c, outline="", tags="particle"
                )
            elif p.shape == "rect":
                self.canvas.create_rectangle(
                    p.x - sz, p.y - sz*0.6, p.x + sz, p.y + sz*0.6,
                    fill=c, outline="", tags="particle"
                )
            elif p.shape == "line":
                self.canvas.create_line(
                    p.x, p.y, p.x + p.vx * 2, p.y + p.vy * 2,
                    fill=c, width=max(1, sz * 0.5), tags="particle"
                )
            elif p.shape == "star":
                self.canvas.create_text(
                    p.x, p.y, text="✦", fill=c,
                    font=("Segoe UI", max(6, int(sz * 1.5))), tags="particle"
                )

        self.particles = alive
        if alive:
            self.after(20, self._animate_particles)

    # ─── Session history chips ────────────────────────────────────────────────

    def _update_history(self):
        for w in self.history_frame.winfo_children():
            w.destroy()

        history = getattr(self, "session_history", [])
        for entry in history[:10]:
            o = entry["outcome"]
            chip = ctk.CTkFrame(self.history_frame, fg_color=o["accent"],
                                corner_radius=6, height=28)
            chip.pack(side="left", padx=2, pady=2)
            chip.pack_propagate(False)

            q_short = entry["question"][:14] + ("…" if len(entry["question"]) > 14 else "")
            lbl_text = f' {o["emoji"]} {q_short} '
            ctk.CTkLabel(chip, text=lbl_text, font=("Segoe UI", 9),
                         text_color=o["color"]).pack(padx=4, pady=2)

    # ─── Cleanup ──────────────────────────────────────────────────────────────

    def force_stop(self):
        self.rolling = False
        self.parent.destroy()


# ─── Toolbox entrypoint ──────────────────────────────────────────────────────

def run_tool():
    try:
        if tk._default_root is None:
            root = ctk.CTkToplevel()
        else:
            root = ctk.CTkToplevel()
        app = App(root)
        root.protocol("WM_DELETE_WINDOW", app.force_stop)
        if tk._default_root is None:
            root.mainloop()
    except Exception as e:
        from tkinter import messagebox
        messagebox.showerror("Decision Dice", f"Startup error:\n{e}")


if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    root.title("Decision Dice")
    root.geometry("560x740")
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.force_stop)
    root.mainloop()
