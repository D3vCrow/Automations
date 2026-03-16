"""
registry_cleaner.py

REGISTRY CLEANER PRO
- Safe registry scanning and cleaning
- Registry backup before cleaning
- Invalid entry detection
- Startup program management
- File association cleanup
- Registry optimization
- Export scan results

Dependencies:
  pip install psutil
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Any, Tuple
import json

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import psutil

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

TOOL_NAME = "Registry Cleaner Pro"

# =============================
# Registry Functions
# =============================

def is_admin() -> bool:
    """Check if running as administrator"""
    try:
        return os.getuid() == 0  # Unix
    except AttributeError:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows
        except:
            return False

def backup_registry_key(key_path: str, backup_dir: str) -> bool:
    """Backup registry key to file"""
    if not HAS_WINREG:
        return False
        
    try:
        # Create backup directory
        os.makedirs(backup_dir, exist_ok=True)
        
        # Export registry key using reg.exe
        backup_file = os.path.join(backup_dir, f"backup_{int(time.time())}.reg")
        cmd = f'reg export "{key_path}" "{backup_file}" /y'
        
        result = os.system(cmd)
        return result == 0
        
    except Exception:
        return False

def scan_registry_issues() -> Dict[str, List[Dict[str, Any]]]:
    """Scan for common registry issues"""
    issues = {
        'invalid_paths': [],
        'missing_files': [],
        'broken_associations': [],
        'startup_issues': [],
        'orphaned_entries': []
    }
    
    if not HAS_WINREG:
        return issues
        
    try:
        # Scan startup programs
        issues['startup_issues'] = scan_startup_programs()
        
        # Scan file associations
        issues['broken_associations'] = scan_file_associations()
        
        # Scan for invalid paths
        issues['invalid_paths'] = scan_invalid_paths()
        
    except Exception as e:
        print(f"Registry scan error: {e}")
        
    return issues

def scan_startup_programs() -> List[Dict[str, Any]]:
    """Scan startup programs for issues"""
    startup_issues = []
    
    try:
        # Check Run keys
        run_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
        ]
        
        for key_path in run_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        
                        # Check if the referenced file exists
                        if isinstance(value, str):
                            if value.startswith('"'):
                                file_path = value.split('"')[1]
                            else:
                                file_path = value.split()[0]
                                
                            if not os.path.exists(file_path):
                                startup_issues.append({
                                    'type': 'missing_file',
                                    'name': name,
                                    'value': value,
                                    'key_path': key_path,
                                    'severity': 'medium'
                                })
                                
                        i += 1
                    except OSError:
                        break
                        
                winreg.CloseKey(key)
                
            except OSError:
                continue
                
    except Exception:
        pass
        
    return startup_issues

def scan_file_associations() -> List[Dict[str, Any]]:
    """Scan file associations for issues"""
    issues = []
    
    try:
        # Check common file extensions
        extensions = ['.txt', '.jpg', '.png', '.mp3', '.mp4', '.pdf', '.doc', '.xls']
        
        for ext in extensions:
            try:
                key_path = f"SOFTWARE\\Classes\\{ext}"
                key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, key_path)
                
                try:
                    # Get the default value (file type)
                    file_type, _ = winreg.QueryValueEx(key, "")
                    
                    # Check if the file type exists
                    try:
                        type_key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, file_type)
                        winreg.CloseKey(type_key)
                    except OSError:
                        issues.append({
                            'type': 'broken_association',
                            'extension': ext,
                            'file_type': file_type,
                            'key_path': key_path,
                            'severity': 'low'
                        })
                        
                except OSError:
                    issues.append({
                        'type': 'missing_default',
                        'extension': ext,
                        'key_path': key_path,
                        'severity': 'low'
                    })
                    
                winreg.CloseKey(key)
                
            except OSError:
                continue
                
    except Exception:
        pass
        
    return issues

def scan_invalid_paths() -> List[Dict[str, Any]]:
    """Scan for invalid paths in registry"""
    invalid_paths = []
    
    try:
        # Check common path locations
        path_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
            r"Environment",
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        ]
        
        for key_path in path_keys:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                
                def scan_subkeys(current_key, current_path):
                    try:
                        i = 0
                        while True:
                            try:
                                subkey_name = winreg.EnumKey(current_key, i)
                                subkey = winreg.OpenKey(current_key, subkey_name)
                                scan_subkeys(subkey, f"{current_path}\\{subkey_name}")
                                winreg.CloseKey(subkey)
                                i += 1
                            except OSError:
                                break
                                
                        # Check values
                        j = 0
                        while True:
                            try:
                                name, value, reg_type = winreg.EnumValue(current_key, j)
                                
                                if isinstance(value, str) and '\\' in value:
                                    # Check if path exists (for common patterns)
                                    if value.startswith('C:\\') or value.startswith('D:\\'):
                                        if not os.path.exists(value):
                                            invalid_paths.append({
                                                'type': 'invalid_path',
                                                'name': name,
                                                'value': value,
                                                'key_path': current_path,
                                                'severity': 'medium'
                                            })
                                            
                                j += 1
                            except OSError:
                                break
                                
                    except Exception:
                        pass
                        
                scan_subkeys(key, key_path)
                winreg.CloseKey(key)
                
            except OSError:
                continue
                
    except Exception:
        pass
        
    return invalid_paths

def fix_registry_issue(issue: Dict[str, Any]) -> bool:
    """Fix a specific registry issue"""
    if not HAS_WINREG:
        return False
        
    try:
        if issue['type'] == 'missing_file' and issue['severity'] == 'medium':
            # Remove startup entry for missing file
            key_path = issue['key_path']
            name = issue['name']
            
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return True
            
        elif issue['type'] == 'invalid_path':
            # Remove invalid path entry
            key_path = issue['key_path']
            name = issue['name']
            
            # Navigate to the key
            key_parts = key_path.split('\\')
            current_key = winreg.HKEY_LOCAL_MACHINE
            
            for part in key_parts:
                current_key = winreg.OpenKey(current_key, part, 0, winreg.KEY_SET_VALUE)
                
            winreg.DeleteValue(current_key, name)
            winreg.CloseKey(current_key)
            return True
            
    except Exception as e:
        print(f"Fix error: {e}")
        
    return False

# =============================
# Main Application
# =============================

class RegistryCleanerApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Registry Cleaner Pro")
        parent.geometry("900x700")
        
        self.registry_issues = {}
        self.backup_dir = os.path.join(os.path.expanduser("~"), "registry_backups")
        
        self._build_ui()
        self._check_permissions()
        
    def _build_ui(self):
        # Header with admin check
        header_frame = ctk.CTkFrame(self)
        header_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        self.admin_label = ctk.CTkLabel(header_frame, text="Checking permissions...", font=ctk.CTkFont(size=12))
        self.admin_label.pack(side="left", padx=10)
        
        # Toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkButton(toolbar, text="🔍 Scan Registry", command=self._scan_registry, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="🔧 Fix Selected", command=self._fix_selected, fg_color="#ffc107", hover_color="#e0a800").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="💾 Create Backup", command=self._create_backup, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="📤 Export Results", command=self._export_results, fg_color="#6c757d", hover_color="#5a6268").pack(side="left", padx=5)
        
        # Main content with tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Issues tabs
        self._create_issues_tab("Startup Issues", "startup_issues")
        self._create_issues_tab("File Associations", "broken_associations")
        self._create_issues_tab("Invalid Paths", "invalid_paths")
        self._create_issues_tab("Missing Files", "missing_files")
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self)
        self.status_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready", font=ctk.CTkFont(size=11))
        self.status_label.pack(side="left", padx=10)
        
        self.scan_time_label = ctk.CTkLabel(self.status_frame, text="", font=ctk.CTkFont(size=11))
        self.scan_time_label.pack(side="right", padx=10)
        
        self.pack(fill="both", expand=True)
        
    def _create_issues_tab(self, tab_name: str, issue_type: str):
        """Create a tab for specific issue type"""
        tab_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(tab_frame, text=tab_name)
        
        # Treeview for issues
        tree_frame = ctk.CTkFrame(tab_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Configure treeview style
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', '#1f538d')])
        
        # Create treeview
        columns = ("name", "value", "severity", "key_path")
        tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        tree.heading("name", text="Name")
        tree.heading("value", text="Value")
        tree.heading("severity", text="Severity")
        tree.heading("key_path", text="Registry Path")
        
        tree.column("name", width=200)
        tree.column("value", width=300)
        tree.column("severity", width=80)
        tree.column("key_path", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=scrollbar.set)
        
        tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Store tree reference
        setattr(self, f"{issue_type}_tree", tree)
        
    def _check_permissions(self):
        """Check if running as administrator"""
        if not is_admin():
            self.admin_label.configure(text="⚠️ Running without administrator privileges - limited functionality", text_color="#ff6b6b")
        else:
            self.admin_label.configure(text="✅ Running with administrator privileges", text_color="#28a745")
            
        if not HAS_WINREG:
            self.admin_label.configure(text="❌ Windows registry module not available", text_color="#dc3545")
            
    def _scan_registry(self):
        """Scan registry for issues"""
        if not HAS_WINREG:
            messagebox.showerror("Error", "Windows registry module not available")
            return
            
        self.status_label.configure(text="Scanning registry...")
        self.parent.update()
        
        try:
            # Scan for issues
            self.registry_issues = scan_registry_issues()
            
            # Update all trees
            self._update_all_trees()
            
            # Calculate total issues
            total_issues = sum(len(issues) for issues in self.registry_issues.values())
            
            # Update status
            self.status_label.configure(text=f"Scan complete - Found {total_issues} issues")
            self.scan_time_label.configure(text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}")
            
            if total_issues == 0:
                messagebox.showinfo("Registry Scan", "No registry issues found!")
            else:
                messagebox.showinfo("Registry Scan", f"Found {total_issues} registry issues that can be fixed.")
                
        except Exception as e:
            messagebox.showerror("Scan Error", f"Failed to scan registry:\n{str(e)}")
            self.status_label.configure(text="Scan failed")
            
    def _update_all_trees(self):
        """Update all issue trees"""
        for issue_type, issues in self.registry_issues.items():
            tree = getattr(self, f"{issue_type}_tree", None)
            if tree:
                # Clear existing items
                for item in tree.get_children():
                    tree.delete(item)
                    
                # Add issues
                for issue in issues:
                    severity = issue.get('severity', 'unknown')
                    severity_color = {
                        'low': '#28a745',
                        'medium': '#ffc107',
                        'high': '#dc3545'
                    }.get(severity, '#6c757d')
                    
                    item = tree.insert("", "end", values=(
                        issue.get('name', ''),
                        issue.get('value', ''),
                        severity.upper(),
                        issue.get('key_path', '')
                    ))
                    
                    # Color code by severity
                    tree.set(item, "severity", severity.upper())
                    
    def _fix_selected(self):
        """Fix selected issues"""
        if not HAS_WINREG:
            messagebox.showerror("Error", "Windows registry module not available")
            return
            
        # Get selected issues from all trees
        selected_issues = []
        
        for issue_type, issues in self.registry_issues.items():
            tree = getattr(self, f"{issue_type}_tree", None)
            if tree:
                for item in tree.selection():
                    values = tree.item(item, "values")
                    if values:
                        # Find corresponding issue
                        for issue in issues:
                            if (issue.get('name', '') == values[0] and 
                                issue.get('value', '') == values[1]):
                                selected_issues.append((issue_type, issue))
                                break
                                
        if not selected_issues:
            messagebox.showwarning("No Selection", "Please select issues to fix")
            return
            
        # Confirm fix
        result = messagebox.askyesno(
            "Confirm Fix",
            f"Are you sure you want to fix {len(selected_issues)} issue(s)?\n\n"
            "A backup will be created automatically."
        )
        
        if result:
            # Create backup
            if not self._create_backup():
                messagebox.showerror("Backup Failed", "Failed to create registry backup")
                return
                
            # Fix issues
            fixed_count = 0
            for issue_type, issue in selected_issues:
                if fix_registry_issue(issue):
                    fixed_count += 1
                    # Remove from issues list
                    self.registry_issues[issue_type].remove(issue)
                    
            # Update trees
            self._update_all_trees()
            
            # Show results
            messagebox.showinfo("Fix Complete", f"Fixed {fixed_count} of {len(selected_issues)} issues")
            
    def _create_backup(self) -> bool:
        """Create registry backup"""
        if not HAS_WINREG:
            return False
            
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            
            # Backup common registry keys
            keys_to_backup = [
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Classes",
                r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths"
            ]
            
            for key_path in keys_to_backup:
                backup_registry_key(key_path, self.backup_dir)
                
            messagebox.showinfo("Backup", f"Registry backup created in:\n{self.backup_dir}")
            return True
            
        except Exception as e:
            messagebox.showerror("Backup Error", f"Failed to create backup:\n{str(e)}")
            return False
            
    def _export_results(self):
        """Export scan results"""
        if not self.registry_issues:
            messagebox.showinfo("Export", "No scan results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Registry Scan Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if not file_path:
            return
            
        try:
            export_data = {
                'scan_time': datetime.now().isoformat(),
                'total_issues': sum(len(issues) for issues in self.registry_issues.values()),
                'issues': self.registry_issues
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
                
            messagebox.showinfo("Export Successful", f"Results exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting results:\n{str(e)}")

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
            
        app = RegistryCleanerApp(root)
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
        messagebox.showerror("Registry Cleaner Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
