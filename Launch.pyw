"""
Launch.pyw — Console-free toolbox launcher.
Double-click this file to start the toolbox without a CMD window.
Uses pythonw.exe automatically (.pyw extension).
"""

import os
import sys

# Ensure we run from the correct directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# Add project root to path so tool imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Activate venv if present (so dependencies like customtkinter are found)
venv_site = os.path.join("venv", "Lib", "site-packages")
if os.path.isdir(venv_site):
    sys.path.insert(0, venv_site)

# Redirect stderr to a log file so crashes aren't silently lost
log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "toolbox_crash.log")
try:
    sys.stderr = open(log_path, "w", encoding="utf-8")
except Exception:
    pass

# Launch
import customtkinter as ctk
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

from Main import ToolboxApp
app = ToolboxApp()
app.mainloop()
