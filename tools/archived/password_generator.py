"""
password_generator.py

PASSWORD GENERATOR PRO
- Advanced password generation
- Password strength analysis
- Multiple password formats
- Customizable criteria
- Password history
- Export capabilities
- Secure password storage

Dependencies:
  pip install secrets
  pip install hashlib
"""

import os
import sys
import secrets
import hashlib
import json
import string
from datetime import datetime
from typing import Dict, List, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

TOOL_NAME = "Password Generator Pro"

# =============================
# Password Generation Functions
# =============================

def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True, 
                     use_digits: bool = True, use_symbols: bool = True, 
                     exclude_ambiguous: bool = False) -> str:
    """Generate secure password with specified criteria"""
    
    # Character sets
    chars = ""
    if use_lower:
        chars += string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Exclude ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = "0O1lI"
        chars = ''.join(c for c in chars if c not in ambiguous)
    
    if not chars:
        return ""
    
    # Generate password
    password = ''.join(secrets.choice(chars) for _ in range(length))
    
    # Ensure at least one character from each selected set
    if use_upper and not any(c.isupper() for c in password):
        password = password[:-1] + secrets.choice(string.ascii_uppercase)
    if use_lower and not any(c.islower() for c in password):
        password = password[:-1] + secrets.choice(string.ascii_lowercase)
    if use_digits and not any(c.isdigit() for c in password):
        password = password[:-1] + secrets.choice(string.digits)
    if use_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        password = password[:-1] + secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    
    return password

def analyze_password_strength(password: str) -> Dict[str, Any]:
    """Analyze password strength"""
    
    strength = {
        'score': 0,
        'level': 'Very Weak',
        'feedback': [],
        'has_upper': False,
        'has_lower': False,
        'has_digits': False,
        'has_symbols': False,
        'length': len(password),
        'entropy': 0
    }
    
    if not password:
        return strength
    
    # Check character types
    strength['has_upper'] = any(c.isupper() for c in password)
    strength['has_lower'] = any(c.islower() for c in password)
    strength['has_digits'] = any(c.isdigit() for c in password)
    strength['has_symbols'] = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
    
    # Calculate score
    score = 0
    
    # Length contribution
    if len(password) >= 8:
        score += 25
    if len(password) >= 12:
        score += 25
    if len(password) >= 16:
        score += 25
    
    # Character variety contribution
    char_types = sum([
        strength['has_upper'],
        strength['has_lower'],
        strength['has_digits'],
        strength['has_symbols']
    ])
    score += char_types * 6.25
    
    strength['score'] = min(100, score)
    
    # Determine strength level
    if strength['score'] >= 80:
        strength['level'] = 'Very Strong'
        strength['feedback'] = ['Excellent password!']
    elif strength['score'] >= 60:
        strength['level'] = 'Strong'
        strength['feedback'] = ['Good password!']
    elif strength['score'] >= 40:
        strength['level'] = 'Medium'
        strength['feedback'] = ['Consider adding more character types']
    elif strength['score'] >= 20:
        strength['level'] = 'Weak'
        strength['feedback'] = ['Password is too short or lacks variety']
    else:
        strength['level'] = 'Very Weak'
        strength['feedback'] = ['Password needs significant improvement']
    
    # Calculate entropy (simplified)
    char_pool = 0
    if strength['has_lower']:
        char_pool += 26
    if strength['has_upper']:
        char_pool += 26
    if strength['has_digits']:
        char_pool += 10
    if strength['has_symbols']:
        char_pool += 25
    
    if char_pool > 0:
        import math
        strength['entropy'] = len(password) * math.log2(char_pool)
    
    return strength

def generate_passphrase(word_count: int = 4, separator: str = "-", capitalize: bool = False) -> str:
    """Generate memorable passphrase from word list"""
    
    # Common words for passphrases
    words = [
        'apple', 'banana', 'orange', 'grape', 'lemon', 'peach', 'berry', 'melon',
        'table', 'chair', 'desk', 'shelf', 'couch', 'bed', 'lamp', 'clock',
        'happy', 'smile', 'laugh', 'joy', 'peace', 'calm', 'bright', 'shine',
        'ocean', 'river', 'mountain', 'forest', 'desert', 'meadow', 'garden', 'park',
        'quick', 'brown', 'fox', 'jumps', 'lazy', 'dog', 'cat', 'mouse',
        'purple', 'yellow', 'green', 'blue', 'red', 'orange', 'black', 'white',
        'music', 'dance', 'song', 'rhythm', 'beat', 'melody', 'harmony', 'sound',
        'coffee', 'water', 'juice', 'milk', 'tea', 'soda', 'drink', 'liquid'
    ]
    
    selected_words = [secrets.choice(words) for _ in range(word_count)]
    
    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]
    
    return separator.join(selected_words)

# =============================
# Main Application
# =============================

class PasswordGeneratorApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Password Generator Pro")
        parent.geometry("800x700")
        
        self.password_history = []
        self.max_history = 50
        
        self._build_ui()
        
    def _build_ui(self):
        # Main container
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Password Generation Section
        gen_frame = ctk.CTkFrame(main_frame)
        gen_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(gen_frame, text="🔐 Password Generator", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Password display
        self.password_display = ctk.CTkTextbox(gen_frame, height=60, font=ctk.CTkFont(size=14))
        self.password_display.pack(fill="x", padx=20, pady=(0, 10))
        self.password_display.insert("1.0", "Click 'Generate' to create password")
        self.password_display.configure(state="disabled")
        
        # Generation options
        options_frame = ctk.CTkFrame(gen_frame)
        options_frame.pack(fill="x", padx=20, pady=10)
        
        # Length slider
        length_frame = ctk.CTkFrame(options_frame)
        length_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(length_frame, text="Length:", width=80).pack(side="left", padx=10)
        self.length_var = tk.IntVar(value=16)
        self.length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, variable=self.length_var, number_of_steps=56)
        self.length_slider.pack(side="left", fill="x", expand=True, padx=10)
        self.length_label = ctk.CTkLabel(length_frame, text="16", width=30)
        self.length_label.pack(side="left", padx=10)
        
        self.length_var.trace_add("write", lambda *args: self.length_label.configure(text=str(self.length_var.get())))
        
        # Character type checkboxes
        char_frame = ctk.CTkFrame(options_frame)
        char_frame.pack(fill="x", pady=5)
        
        self.use_upper = tk.BooleanVar(value=True)
        self.use_lower = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)
        self.exclude_ambiguous = tk.BooleanVar(value=False)
        
        ctk.CTkCheckBox(char_frame, text="Uppercase (A-Z)", variable=self.use_upper).pack(side="left", padx=10)
        ctk.CTkCheckBox(char_frame, text="Lowercase (a-z)", variable=self.use_lower).pack(side="left", padx=10)
        ctk.CTkCheckBox(char_frame, text="Digits (0-9)", variable=self.use_digits).pack(side="left", padx=10)
        ctk.CTkCheckBox(char_frame, text="Symbols (!@#$)", variable=self.use_symbols).pack(side="left", padx=10)
        ctk.CTkCheckBox(char_frame, text="Exclude Ambiguous (0O1lI)", variable=self.exclude_ambiguous).pack(side="left", padx=10)
        
        # Action buttons
        button_frame = ctk.CTkFrame(gen_frame)
        button_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(button_frame, text="🔄 Generate Password", command=self._generate_password, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="📋 Copy", command=self._copy_password, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        ctk.CTkButton(button_frame, text="💾 Save", command=self._save_password, fg_color="#ffc107", hover_color="#e0a800").pack(side="left", padx=5)
        
        # Passphrase Section
        passphrase_frame = ctk.CTkFrame(main_frame)
        passphrase_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(passphrase_frame, text="🔑 Passphrase Generator", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Passphrase display
        self.passphrase_display = ctk.CTkTextbox(passphrase_frame, height=60, font=ctk.CTkFont(size=14))
        self.passphrase_display.pack(fill="x", padx=20, pady=(0, 10))
        self.passphrase_display.insert("1.0", "Click 'Generate' to create passphrase")
        self.passphrase_display.configure(state="disabled")
        
        # Passphrase options
        pass_options_frame = ctk.CTkFrame(passphrase_frame)
        pass_options_frame.pack(fill="x", padx=20, pady=10)
        
        # Word count
        word_frame = ctk.CTkFrame(pass_options_frame)
        word_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(word_frame, text="Words:", width=80).pack(side="left", padx=10)
        self.word_count_var = tk.IntVar(value=4)
        self.word_slider = ctk.CTkSlider(word_frame, from_=3, to=10, variable=self.word_count_var, number_of_steps=7)
        self.word_slider.pack(side="left", fill="x", expand=True, padx=10)
        self.word_label = ctk.CTkLabel(word_frame, text="4", width=30)
        self.word_label.pack(side="left", padx=10)
        
        self.word_count_var.trace_add("write", lambda *args: self.word_label.configure(text=str(self.word_count_var.get())))
        
        # Separator and capitalize options
        pass_char_frame = ctk.CTkFrame(pass_options_frame)
        pass_char_frame.pack(fill="x", pady=5)
        
        ctk.CTkLabel(pass_char_frame, text="Separator:", width=80).pack(side="left", padx=10)
        self.separator_var = tk.StringVar(value="-")
        separator_menu = ctk.CTkOptionMenu(pass_char_frame, variable=self.separator_var, values=["-", "_", " ", ".", ""])
        separator_menu.pack(side="left", padx=10)
        
        self.capitalize_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(pass_char_frame, text="Capitalize Words", variable=self.capitalize_var).pack(side="left", padx=20)
        
        # Passphrase buttons
        pass_button_frame = ctk.CTkFrame(passphrase_frame)
        pass_button_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkButton(pass_button_frame, text="🔄 Generate Passphrase", command=self._generate_passphrase, fg_color="#17a2b8", hover_color="#138496").pack(side="left", padx=5)
        ctk.CTkButton(pass_button_frame, text="📋 Copy", command=self._copy_passphrase, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        
        # Password Analysis Section
        analysis_frame = ctk.CTkFrame(main_frame)
        analysis_frame.pack(fill="both", expand=True, pady=10)
        
        ctk.CTkLabel(analysis_frame, text="📊 Password Analysis", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Analysis display
        self.analysis_display = ctk.CTkTextbox(analysis_frame, height=120, font=ctk.CTkFont(size=12))
        self.analysis_display.pack(fill="x", padx=20, pady=(0, 10))
        self.analysis_display.insert("1.0", "Generate a password to see its strength analysis")
        self.analysis_display.configure(state="disabled")
        
        # Strength indicator
        strength_frame = ctk.CTkFrame(analysis_frame)
        strength_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(strength_frame, text="Strength:", width=80).pack(side="left", padx=10)
        self.strength_bar = ctk.CTkProgressBar(strength_frame)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=10)
        self.strength_label = ctk.CTkLabel(strength_frame, text="N/A", width=100)
        self.strength_label.pack(side="left", padx=10)
        
        # History Section
        history_frame = ctk.CTkFrame(main_frame)
        history_frame.pack(fill="x", pady=10)
        
        ctk.CTkLabel(history_frame, text="📜 History", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # History list
        self.history_listbox = tk.Listbox(history_frame, height=6, bg="#2b2b2b", fg="white", selectbackground="#1f538d")
        self.history_listbox.pack(fill="x", padx=20, pady=(0, 10))
        
        # History buttons
        history_button_frame = ctk.CTkFrame(history_frame)
        history_button_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        ctk.CTkButton(history_button_frame, text="📋 Copy Selected", command=self._copy_history_item, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        ctk.CTkButton(history_button_frame, text="🗑️ Clear History", command=self._clear_history, fg_color="#dc3545", hover_color="#c82333").pack(side="left", padx=5)
        ctk.CTkButton(history_button_frame, text="📤 Export History", command=self._export_history, fg_color="#6c757d", hover_color="#5a6268").pack(side="right", padx=5)
        
        self.pack(fill="both", expand=True)
        
    def _generate_password(self):
        """Generate new password"""
        try:
            password = generate_password(
                length=self.length_var.get(),
                use_upper=self.use_upper.get(),
                use_lower=self.use_lower.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_ambiguous=self.exclude_ambiguous.get()
            )
            
            # Update display
            self.password_display.configure(state="normal")
            self.password_display.delete("1.0", "end")
            self.password_display.insert("1.0", password)
            self.password_display.configure(state="disabled")
            
            # Analyze password
            self._analyze_password(password)
            
            # Add to history
            self._add_to_history(password)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate password:\n{str(e)}")
            
    def _generate_passphrase(self):
        """Generate new passphrase"""
        try:
            passphrase = generate_passphrase(
                word_count=self.word_count_var.get(),
                separator=self.separator_var.get(),
                capitalize=self.capitalize_var.get()
            )
            
            # Update display
            self.passphrase_display.configure(state="normal")
            self.passphrase_display.delete("1.0", "end")
            self.passphrase_display.insert("1.0", passphrase)
            self.passphrase_display.configure(state="disabled")
            
            # Analyze passphrase
            self._analyze_password(passphrase)
            
            # Add to history
            self._add_to_history(passphrase)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate passphrase:\n{str(e)}")
            
    def _analyze_password(self, password: str):
        """Analyze password strength"""
        analysis = analyze_password_strength(password)
        
        # Update analysis display
        self.analysis_display.configure(state="normal")
        self.analysis_display.delete("1.0", "end")
        
        analysis_text = f"Strength Level: {analysis['level']}\n"
        analysis_text += f"Score: {analysis['score']}/100\n"
        analysis_text += f"Length: {analysis['length']} characters\n"
        analysis_text += f"Entropy: {analysis['entropy']:.1f} bits\n"
        analysis_text += f"Character Types: {sum([analysis['has_upper'], analysis['has_lower'], analysis['has_digits'], analysis['has_symbols']])}/4\n"
        
        if analysis['feedback']:
            analysis_text += f"Feedback: {', '.join(analysis['feedback'])}"
            
        self.analysis_display.insert("1.0", analysis_text)
        self.analysis_display.configure(state="disabled")
        
        # Update strength bar
        self.strength_bar.set(analysis['score'] / 100)
        
        # Update strength label with color
        strength_colors = {
            'Very Weak': '#dc3545',
            'Weak': '#fd7e14',
            'Medium': '#ffc107',
            'Strong': '#28a745',
            'Very Strong': '#20c997'
        }
        
        color = strength_colors.get(analysis['level'], '#6c757d')
        self.strength_label.configure(text=f"{analysis['level']} ({analysis['score']})", text_color=color)
        
    def _copy_password(self):
        """Copy password to clipboard"""
        password = self.password_display.get("1.0", "end-1c")
        if password and password != "Click 'Generate' to create password":
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
            
    def _copy_passphrase(self):
        """Copy passphrase to clipboard"""
        passphrase = self.passphrase_display.get("1.0", "end-1c")
        if passphrase and passphrase != "Click 'Generate' to create passphrase":
            self.clipboard_clear()
            self.clipboard_append(passphrase)
            messagebox.showinfo("Copied", "Passphrase copied to clipboard!")
            
    def _save_password(self):
        """Save password to file"""
        password = self.password_display.get("1.0", "end-1c")
        if not password or password == "Click 'Generate' to create password":
            messagebox.showwarning("No Password", "Please generate a password first")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Save Password",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(f"Password: {password}\n")
                    f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    
                messagebox.showinfo("Saved", f"Password saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save password:\n{str(e)}")
                
    def _add_to_history(self, password: str):
        """Add password to history"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        history_entry = f"{timestamp} - {password[:20]}{'...' if len(password) > 20 else ''}"
        
        self.password_history.append({
            'timestamp': timestamp,
            'password': password,
            'display': history_entry
        })
        
        # Limit history size
        if len(self.password_history) > self.max_history:
            self.password_history.pop(0)
            
        # Update listbox
        self._update_history_display()
        
    def _update_history_display(self):
        """Update history listbox"""
        self.history_listbox.delete(0, tk.END)
        for entry in self.password_history:
            self.history_listbox.insert(tk.END, entry['display'])
            
    def _copy_history_item(self):
        """Copy selected history item"""
        selection = self.history_listbox.curselection()
        if selection:
            index = selection[0]
            password = self.password_history[index]['password']
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
            
    def _clear_history(self):
        """Clear password history"""
        result = messagebox.askyesno("Clear History", "Are you sure you want to clear all password history?")
        if result:
            self.password_history = []
            self._update_history_display()
            
    def _export_history(self):
        """Export password history"""
        if not self.password_history:
            messagebox.showinfo("Export", "No history to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Password History",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if file_path:
            try:
                export_data = {
                    'export_time': datetime.now().isoformat(),
                    'passwords': self.password_history
                }
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
                messagebox.showinfo("Export Successful", f"History exported to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Error exporting history:\n{str(e)}")

# =============================
# Entry Point
# =============================

def run_tool():
    """Tool entry point"""
    try:
        if tk._default_root is None:
            root = ctk.CTkToplevel()
        else:
            root = ctk.CTkToplevel()
            
        app = PasswordGeneratorApp(root)
        root.protocol("WM_DELETE_WINDOW", lambda: root.destroy())
        
        # Center window on screen
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Bring to front
        root.lift()
        root.focus_force()
        root.attributes("-topmost", True)
        root.after(250, lambda: root.attributes("-topmost", False))
        
    except Exception as e:
        messagebox.showerror("Password Generator Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
