"""
Security Audit — Portable / Standalone Launcher
-------------------------------------------------
Run this file directly:  python Security_Audit_Portable.py
Or double-click:         run_security_audit.bat

Requirements (pip install):  customtkinter  psutil
"""

import sys
import os

# Make sure the tool module can be found when this file is run from any location
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Dependency check with friendly error messages
_missing = []
try:
    import customtkinter as ctk
except ImportError:
    _missing.append("customtkinter")
try:
    import psutil  # noqa: F401
except ImportError:
    _missing.append("psutil")

if _missing:
    import tkinter as tk
    from tkinter import messagebox
    _root = tk.Tk()
    _root.withdraw()
    messagebox.showerror(
        "Missing Dependencies",
        "Please install the required packages:\n\n"
        f"  pip install {' '.join(_missing)}\n\n"
        "Then re-run this script."
    )
    sys.exit(1)

# Import the tool's App class from the renamed copy
try:
    from security_audit import App
except ImportError as e:
    import tkinter as tk
    from tkinter import messagebox
    _root = tk.Tk()
    _root.withdraw()
    messagebox.showerror(
        "Import Error",
        f"Could not load security_audit.py\n\n"
        f"Make sure it is in the same folder as this file.\n\nError: {e}"
    )
    sys.exit(1)

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    app = App(root)
    app.pack(fill="both", expand=True)
    root.protocol("WM_DELETE_WINDOW", root.destroy)
    root.mainloop()
