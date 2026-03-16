"""
screen_locker.py

SCREEN LOCKER PRO - Simple Working Version
- Ctrl+Alt+U to unlock
- ESC toggle option
- Adjustable transparency
- Clock display
"""

import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import customtkinter as ctk

TOOL_NAME = "Screen Locker Pro"

class ScreenLockerApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Screen Locker Pro")
        self.root.geometry("400x350")
        
        self.locked = False
        self.lock_window = None
        self.esc_enabled = True
        self.transparency = 0.9
        
        self._build_setup_ui()
        
    def _build_setup_ui(self):
        """Setup UI"""
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(main_frame, text="🔒 Screen Locker Pro", 
                     font=ctk.CTkFont(size=18, weight="bold")).pack(pady=15)
        
        # Instructions
        ctk.CTkLabel(main_frame, text="Ctrl+Alt+U to unlock\nESC toggle option below", 
                     font=ctk.CTkFont(size=12)).pack(pady=10)
        
        # ESC Toggle
        self.esc_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(main_frame, text="Enable ESC Key", 
                        variable=self.esc_var).pack(pady=10)
        
        # Transparency
        ctk.CTkLabel(main_frame, text="Transparency:").pack(pady=5)
        self.trans_var = tk.DoubleVar(value=0.9)
        trans_slider = ctk.CTkSlider(main_frame, from_=0.3, to=1.0, 
                                   variable=self.trans_var, width=250)
        trans_slider.pack(pady=5)
        
        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(pady=15)
        
        ctk.CTkButton(button_frame, text="🔒 Lock Screen", 
                     command=self._lock_screen, fg_color="#dc3545", 
                     width=120, height=35).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="❌ Exit", 
                     command=self.root.destroy, fg_color="#6c757d", 
                     width=120, height=35).pack(side="left", padx=10)
        
        # Auto-resize
        self.root.update_idletasks()
        self.root.geometry(f"{self.root.winfo_reqwidth()}x{self.root.winfo_reqheight()}")
        
    def _lock_screen(self):
        """Lock the screen"""
        self.esc_enabled = self.esc_var.get()
        self.transparency = self.trans_var.get()
        
        # Hide setup window
        self.root.withdraw()
        
        # Create lock window
        self.lock_window = tk.Toplevel()
        self.lock_window.title("Locked")
        self.lock_window.attributes("-fullscreen", True)
        self.lock_window.attributes("-topmost", True)
        self.lock_window.attributes("-alpha", self.transparency)
        self.lock_window.configure(bg="#1a1a1a")
        
        # Lock time
        self.lock_time = datetime.now()
        
        # Create lock UI
        self._build_lock_ui()
        
        # Simple key binding
        self.lock_window.bind("<Control-Alt-u>", lambda e: self._unlock())
        self.lock_window.bind("<Escape>", self._check_esc)
        
        # Focus and grab
        self.lock_window.focus_set()
        self.lock_window.grab_set()
        
        self.locked = True
        
        # Start clock update
        self._update_clock()
        
    def _build_lock_ui(self):
        """Build lock screen UI"""
        # Center content
        center_frame = tk.Frame(self.lock_window, bg="#1a1a1a")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        # Lock icon
        tk.Label(center_frame, text="🔒", font=("Arial", 72), 
                bg="#1a1a1a", fg="#ff6b6b").pack(pady=20)
        
        # Status
        tk.Label(center_frame, text="SCREEN LOCKED", font=("Arial", 24, "bold"), 
                bg="#1a1a1a", fg="white").pack(pady=10)
        
        # Instructions
        tk.Label(center_frame, text="Press Ctrl+Alt+U to unlock", font=("Arial", 14), 
                bg="#1a1a1a", fg="#888888").pack(pady=10)
        
        # Clock in top-right
        self.clock_label = tk.Label(self.lock_window, text="", 
                                font=("Arial", 16, "bold"), bg="#1a1a1a", fg="white")
        self.clock_label.place(relx=1.0, rely=0.0, anchor="ne", padx=20, pady=20)
        
    def _update_clock(self):
        """Update clock"""
        if self.locked and self.lock_window:
            current_time = datetime.now().strftime("%H:%M:%S")
            duration = str(datetime.now() - self.lock_time).split('.')[0]
            self.clock_label.config(text=f"{current_time}\nLocked: {duration}")
            self.lock_window.after(1000, self._update_clock)
            
    def _check_esc(self, event):
        """Check ESC key - unlock directly"""
        if self.esc_enabled:
            self._unlock()
                
    def _unlock(self):
        """Unlock the screen"""
        self.locked = False
        
        if self.lock_window:
            self.lock_window.destroy()
            self.lock_window = None
            
        # Show setup window
        self.root.deiconify()
        
    def run(self):
        """Run the app"""
        self.root.mainloop()

def run_tool():
    """Tool entry point"""
    try:
        app = ScreenLockerApp()
        app.run()
    except Exception as e:
        messagebox.showerror("Screen Locker Pro", f"Error: {e}")

if __name__ == "__main__":
    run_tool()
