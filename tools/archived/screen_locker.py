"""
screen_locker.py

SCREEN LOCKER PRO
- Key combination unlock (Ctrl+Alt+U)
- ESC button toggle option
- Adjustable transparency
- Clock display on top right
- Break detection
- Session tracking

Dependencies:
  pip install pillow
"""

import os
import sys
import time
from datetime import datetime
from typing import Optional

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk

try:
    from PIL import Image, ImageTk, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

TOOL_NAME = "Screen Locker Pro"

# =============================
# Screen Locker Functions
# =============================

# =============================
# Main Application
# =============================

class ScreenLockerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Screen Locker Pro")
        self.root.geometry("450x400")
        
        self.locked = False
        self.lock_window = None
        self.esc_enabled = True  # ESC toggle option
        self.transparency = 0.9  # Default transparency
        
        self._build_setup_ui()
        
    def _build_setup_ui(self):
        """Setup UI for configuration"""
        # Main frame
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(main_frame, text="🔒 Screen Locker Pro", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        # Instructions
        instructions = """
🔑 UNLOCK: Ctrl+Alt+U
⚠️ ESC Toggle: Option below
🎨 Transparency: Adjustable slider
⏰ Clock: Top-right corner when locked
        """
        
        ctk.CTkLabel(main_frame, text=instructions, font=ctk.CTkFont(size=12), justify="left").pack(pady=20)
        
        # ESC Toggle Option
        esc_frame = ctk.CTkFrame(main_frame)
        esc_frame.pack(fill="x", pady=10)
        
        self.esc_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(esc_frame, text="Enable ESC Key Toggle", variable=self.esc_var,
                        command=self._toggle_esc_option).pack(pady=10)
        
        # Transparency Slider
        trans_frame = ctk.CTkFrame(main_frame)
        trans_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(trans_frame, text="Background Transparency:", font=ctk.CTkFont(size=14)).pack(pady=10)
        
        self.trans_var = tk.DoubleVar(value=0.9)
        self.trans_slider = ctk.CTkSlider(trans_frame, from_=0.3, to=1.0, variable=self.trans_var, 
                                       number_of_steps=70, width=300)
        self.trans_slider.pack(pady=10)
        
        self.trans_label = ctk.CTkLabel(trans_frame, text="90%", font=ctk.CTkFont(size=12))
        self.trans_label.pack(pady=5)
        
        self.trans_var.trace_add("write", self._update_trans_label)
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(pady=20)
        
        ctk.CTkButton(button_frame, text="🔒 Lock Screen", command=self._lock_screen, 
                     fg_color="#dc3545", hover_color="#c82333", width=150, height=40).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="❌ Exit", command=self.root.destroy, 
                     fg_color="#6c757d", hover_color="#5a6268", width=150, height=40).pack(side="left", padx=10)
        
        # Auto-resize window to fit content
        self.root.update_idletasks()
        self.root.geometry("")  # Reset geometry
        self.root.update_idletasks()  # Calculate required size
        self.root.geometry(f"{self.root.winfo_reqwidth()}x{self.root.winfo_reqheight()}")
        
    def _toggle_esc_option(self):
        """Toggle ESC option"""
        self.esc_enabled = self.esc_var.get()
        
    def _update_trans_label(self, *args):
        """Update transparency label"""
        value = self.trans_var.get()
        percentage = int(value * 100)
        self.trans_label.configure(text=f"{percentage}%")
        self.transparency = value
        
        # Update lock window transparency if locked
        if self.locked and self.lock_window:
            self.lock_window.attributes("-alpha", value)
        
    def _lock_screen(self):
        """Lock the screen"""
        # Hide setup window
        self.root.withdraw()
        
        # Create lock window
        self._create_lock_window()
        
    def _create_lock_window(self):
        """Create lock screen window"""
        self.lock_window = tk.Toplevel()
        self.lock_window.title("Screen Locked")
        self.lock_window.attributes("-fullscreen", True)
        self.lock_window.attributes("-topmost", True)
        self.lock_window.attributes("-alpha", self.transparency)
        self.lock_window.configure(bg="#1a1a1a")
        
        # Prevent Alt+Tab
        self.lock_window.grab_set()
        self.lock_window.focus_set()
        
        # Lock time
        self.lock_time = datetime.now()
        
        # Create lock UI
        self._build_lock_ui()
        
        # Set up key tracking
        self.ctrl_pressed = False
        self.alt_pressed = False
        
        # Bind individual key events
        self.lock_window.bind("<KeyPress>", self._on_key_press)
        self.lock_window.bind("<KeyRelease>", self._on_key_release)
        
        # Start break detection
        self._start_break_detection()
        
        self.locked = True
        
    def _on_key_press(self, event):
        """Handle key press events"""
        if event.keysym == "Control_L" or event.keysym == "Control_R":
            self.ctrl_pressed = True
        elif event.keysym == "Alt_L" or event.keysym == "Alt_R":
            self.alt_pressed = True
        elif event.keysym.lower() == "u" and self.ctrl_pressed and self.alt_pressed:
            self._key_combo_unlock()
        elif event.keysym == "Escape" and self.esc_enabled:
            self._esc_toggle()
            
        return "break"  # Prevent further processing
            
    def _on_key_release(self, event):
        """Handle key release events"""
        if event.keysym == "Control_L" or event.keysym == "Control_R":
            self.ctrl_pressed = False
        elif event.keysym == "Alt_L" or event.keysym == "Alt_R":
            self.alt_pressed = False
            
        return "break"  # Prevent further processing
        
    def _build_lock_ui(self):
        """Build lock screen UI"""
        # Main container
        main_frame = tk.Frame(self.lock_window, bg="#1a1a1a")
        main_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Lock icon and title
        title_frame = tk.Frame(main_frame, bg="#1a1a1a")
        title_frame.pack(pady=20)
        
        tk.Label(title_frame, text="🔒", font=("Arial", 64), bg="#1a1a1a", fg="#ff6b6b").pack()
        tk.Label(title_frame, text="SCREEN LOCKED", font=("Arial", 28, "bold"), 
                bg="#1a1a1a", fg="white").pack(pady=10)
        
        # Instructions
        instructions = "Press Ctrl+Alt+U to unlock"
        if self.esc_enabled:
            instructions += "\nPress ESC to toggle unlock option"
            
        tk.Label(main_frame, text=instructions, font=("Arial", 16), 
                bg="#1a1a1a", fg="#888888").pack(pady=10)
        
        # Clock in top-right corner
        self._create_clock()
        
        # Status label
        self.status_label = tk.Label(main_frame, text="", 
                                    font=("Arial", 12), bg="#1a1a1a", fg="#888888")
        self.status_label.pack(pady=5)
        
        # Update clock
        self._update_clock()
        
    def _create_clock(self):
        """Create clock display in top-right corner"""
        self.clock_frame = tk.Frame(self.lock_window, bg="#1a1a1a")
        self.clock_frame.place(relx=1.0, rely=0.0, anchor="ne")
        
        self.time_label = tk.Label(self.clock_frame, text="", 
                               font=("Arial", 20, "bold"), bg="#1a1a1a", fg="white",
                               padx=20, pady=10)
        self.time_label.pack()
        
        self.duration_label = tk.Label(self.clock_frame, text="", 
                                  font=("Arial", 12), bg="#1a1a1a", fg="#888888",
                                  padx=20)
        self.duration_label.pack()
        
    def _update_clock(self):
        """Update clock display"""
        if self.locked and self.lock_window:
            current_time = datetime.now().strftime("%H:%M:%S")
            lock_duration = datetime.now() - self.lock_time
            duration_str = str(lock_duration).split('.')[0]
            
            self.time_label.config(text=current_time)
            self.duration_label.config(text=f"Locked: {duration_str}")
            
            self.lock_window.after(1000, self._update_clock)
            
    def _key_combo_unlock(self, event=None):
        """Unlock with Ctrl+Alt+U"""
        self._unlock_screen()
        
    def _esc_toggle(self, event=None):
        """ESC key toggle"""
        if self.esc_enabled:
            result = messagebox.askyesno("Unlock Screen", "Unlock the screen?")
            if result:
                self._unlock_screen()
                
    def _unlock_screen(self):
        """Unlock the screen"""
        self.locked = False
        
        if self.lock_window:
            self.lock_window.destroy()
            self.lock_window = None
            
        # Show setup window
        self.root.deiconify()
        
    def _start_break_detection(self):
        """Start break detection (prevent closing)"""
        if self.locked and self.lock_window:
            try:
                # Check if window still exists
                self.lock_window.update()
                self.lock_window.after(100, self._start_break_detection)
            except tk.TclError:
                # Window was destroyed, attempt to recreate
                if self.locked:
                    self._create_lock_window()
                    
    def run(self):
        """Run the application"""
        self.root.mainloop()

# =============================
# Entry Point
# =============================

def run_tool():
    """Tool entry point"""
    try:
        app = ScreenLockerApp()
        app.run()
    except Exception as e:
        messagebox.showerror("Screen Locker Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
