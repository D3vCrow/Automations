"""
security_monitor_pro.py
STABLE VERSION – Safe for dynamic toolbox loading
Upgraded to CustomTkinter for premium UI.
"""

import tkinter as tk
import customtkinter as ctk
from tkinter import ttk, messagebox
import psutil
import threading
import time
import os
import json
import sys
from datetime import datetime

TOOL_NAME = "Security Monitor Pro"


# =============================
# CONFIG
# =============================

CPU_WARN = 40
CPU_HIGH = 70
RAM_WARN = 700
RAM_HIGH = 1500


# =============================
# DETECTION ENGINE
# =============================

def now():
    return datetime.now().strftime("%H:%M:%S")


def scan_processes():
    results = []

    # Prime CPU values
    for p in psutil.process_iter():
        try:
            p.cpu_percent(None)
        except:
            pass

    time.sleep(0.2)

    for p in psutil.process_iter():
        try:
            cpu = p.cpu_percent(None)
            ram = p.memory_info().rss / (1024 * 1024)
            exe = ""
            try:
                exe = p.exe().lower()
            except:
                pass

            score = 0
            reasons = []

            if cpu > CPU_HIGH:
                score += 30
                reasons.append(f"Very high CPU ({cpu:.1f}%)")
            elif cpu > CPU_WARN:
                score += 15
                reasons.append(f"High CPU ({cpu:.1f}%)")

            if ram > RAM_HIGH:
                score += 25
                reasons.append(f"Very high RAM ({ram:.0f} MB)")
            elif ram > RAM_WARN:
                score += 10
                reasons.append(f"High RAM ({ram:.0f} MB)")

            if "\\appdata\\" in exe or "\\temp\\" in exe:
                score += 25
                reasons.append("Running from AppData/Temp")

            severity = "INFO"
            if score >= 60:
                severity = "HIGH"
            elif score >= 30:
                severity = "WARN"

            results.append({
                "pid": p.pid,
                "name": p.name(),
                "cpu": cpu,
                "ram": ram,
                "exe": exe,
                "score": score,
                "severity": severity,
                "reasons": reasons
            })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# =============================
# GUI
# =============================

class SecurityMonitor(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Security Monitor Pro")
        parent.geometry("1100x650")
        
        # Focus window
        parent.attributes("-topmost", True)
        parent.after(100, lambda: parent.attributes("-topmost", False))

        self.running = True
        self.data = []

        self.build_ui()

        # Delay first scan until UI fully renders
        self.after(500, self.start_background_scan)

    def build_ui(self):
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", pady=15, padx=20)

        ctk.CTkButton(top, text="Scan Now", command=self.scan_now, fg_color="#3a7ebf", hover_color="#2b6194", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)
        ctk.CTkButton(top, text="Terminate Selected", command=self.kill_selected, fg_color="#bf3a3a", hover_color="#942b2b", font=ctk.CTkFont(weight="bold")).pack(side="left", padx=5)

        self.summary = ctk.CTkLabel(top, text="Initializing...", font=ctk.CTkFont(size=14, weight="bold"))
        self.summary.pack(side="right", padx=10)

        # Basic Treeview styling
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#2b2b2b", 
                        foreground="white", 
                        fieldbackground="#2b2b2b",
                        borderwidth=0,
                        rowheight=25)
        style.configure("Treeview.Heading", 
                        background="#565b5e", 
                        foreground="white", 
                        relief="flat",
                        font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', '#1f538d')])

        cols = ("severity", "score", "pid", "name", "cpu", "ram")
        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", style="Treeview")

        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=150)

        self.tree.pack(fill="both", expand=True, padx=1, pady=1)

        details_frame = ctk.CTkFrame(self, corner_radius=10)
        details_frame.pack(fill="x", padx=20, pady=(0, 20))

        self.details = ctk.CTkTextbox(details_frame, height=150, corner_radius=8, font=ctk.CTkFont(family="Consolas", size=13))
        self.details.pack(fill="x", padx=10, pady=10)

        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        self.pack(fill="both", expand=True)

    def start_background_scan(self):
        threading.Thread(target=self.background_loop, daemon=True).start()

    def background_loop(self):
        while self.running:
            try:
                self.data = scan_processes()
                self.after(0, self.refresh_ui)
            except Exception as e:
                print("Background scan error:", e)
            time.sleep(3)

    def scan_now(self):
        self.summary.configure(text="Scanning...")
        self.data = scan_processes()
        self.refresh_ui()

    def refresh_ui(self):
        self.tree.delete(*self.tree.get_children())

        warn = 0
        high = 0

        for row in self.data[:300]:
            self.tree.insert("", "end", iid=str(row["pid"]), values=(
                row["severity"],
                row["score"],
                row["pid"],
                row["name"],
                f"{row['cpu']:.1f}",
                f"{row['ram']:.0f}"
            ))

            if row["severity"] == "WARN":
                warn += 1
            if row["severity"] == "HIGH":
                high += 1

        self.summary.configure(text=f"Processes: {len(self.data)} | WARN: {warn} | HIGH: {high}")

    def show_details(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return

        pid = int(sel[0])
        row = next((x for x in self.data if x["pid"] == pid), None)
        if not row:
            return

        text = f"""Name: {row['name']}
PID: {row['pid']}
CPU: {row['cpu']:.1f}%
RAM: {row['ram']:.0f} MB
Score: {row['score']}
Severity: {row['severity']}

Executable:
{row['exe']}

Reasons:
"""

        for r in row["reasons"]:
            text += f" - {r}\n"

        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)

    def kill_selected(self):
        sel = self.tree.selection()
        if not sel:
            return

        pid = int(sel[0])

        if not messagebox.askyesno("Confirm", f"Terminate PID {pid}?"):
            return

        try:
            psutil.Process(pid).terminate()
            messagebox.showinfo("Success", f"Terminated {pid}")
            self.scan_now()
        except Exception as e:
            messagebox.showerror("Error", str(e))


def run_tool():
    try:
        if tk._default_root is None:
            root = ctk.CTkToplevel()
            root.withdraw()
        else:
            root = tk._default_root
        
        win = ctk.CTkToplevel(root)
        app = SecurityMonitor(win)
    except Exception as e:
        print("Startup error:", e)


if __name__ == "__main__":
    run_tool()
