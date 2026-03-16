"""
process_monitor.py

PROCESS MONITOR PRO
- Real-time process monitoring
- CPU and memory usage tracking
- Process search and filtering
- Kill process functionality
- Process tree view
- Resource usage graphs
- Export process list

Dependencies:
  pip install psutil
"""

import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Any

import tkinter as tk
from tkinter import ttk, messagebox
import customtkinter as ctk
import psutil

TOOL_NAME = "Process Monitor Pro"

# =============================
# Process Monitor Functions
# =============================

def get_processes() -> List[Dict[str, Any]]:
    """Get list of all running processes"""
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'memory_info', 'create_time', 'status']):
        try:
            pinfo = proc.info
            
            # Get memory info
            memory_info = pinfo.get('memory_info', {})
            memory_rss = memory_info.get('rss', 0) if memory_info else 0
            memory_vms = memory_info.get('vms', 0) if memory_info else 0
            
            # Create process info dict
            process_info = {
                'pid': pinfo.get('pid', 0),
                'name': pinfo.get('name', ''),
                'username': pinfo.get('username', ''),
                'cpu_percent': pinfo.get('cpu_percent', 0),
                'memory_percent': pinfo.get('memory_percent', 0),
                'memory_rss': memory_rss,
                'memory_vms': memory_vms,
                'create_time': pinfo.get('create_time', 0),
                'status': pinfo.get('status', '')
            }
            
            processes.append(process_info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
    return processes

def format_bytes(bytes_value: int) -> str:
    """Format bytes into human readable format"""
    if bytes_value == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(bytes_value)
    
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"

def format_timestamp(timestamp: float) -> str:
    """Format timestamp into readable date"""
    if timestamp == 0:
        return "Unknown"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def kill_process(pid: int) -> bool:
    """Kill a process by PID"""
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        return True
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
        return False

# =============================
# Main Application
# =============================

class ProcessMonitorApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Process Monitor Pro")
        parent.geometry("1200x800")
        
        self.processes = []
        self.auto_refresh = True
        self.refresh_interval = 2000  # 2 seconds
        
        self._build_ui()
        self._start_monitoring()
        
    def _build_ui(self):
        # Toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))
        
        ctk.CTkButton(toolbar, text="Refresh", command=self._refresh_processes, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Kill Selected", command=self._kill_selected, fg_color="#dc3545", hover_color="#c82333").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Export", command=self._export_processes, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        
        # Auto refresh toggle
        self.auto_refresh_var = tk.BooleanVar(value=True)
        ctk.CTkSwitch(toolbar, text="Auto Refresh", variable=self.auto_refresh_var, command=self._toggle_auto_refresh).pack(side="left", padx=20)
        
        # Search box
        ctk.CTkLabel(toolbar, text="Search:").pack(side="left", padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        self.search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var, width=200)
        self.search_entry.pack(side="left", padx=5)
        
        # Status
        self.status_label = ctk.CTkLabel(toolbar, text="Processes: 0")
        self.status_label.pack(side="right", padx=10)
        
        # Main content - Process tree
        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Configure treeview style
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', '#1f538d')])
        
        # Create treeview with columns
        columns = ("pid", "name", "username", "cpu_percent", "memory_percent", "memory_rss", "memory_vms", "create_time", "status")
        self.process_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.process_tree.heading("pid", text="PID")
        self.process_tree.heading("name", text="Process Name")
        self.process_tree.heading("username", text="User")
        self.process_tree.heading("cpu_percent", text="CPU %")
        self.process_tree.heading("memory_percent", text="Memory %")
        self.process_tree.heading("memory_rss", text="Memory (RSS)")
        self.process_tree.heading("memory_vms", text="Memory (VMS)")
        self.process_tree.heading("create_time", text="Started")
        self.process_tree.heading("status", text="Status")
        
        # Configure column widths
        self.process_tree.column("pid", width=80, stretch=False)
        self.process_tree.column("name", width=200, stretch=True)
        self.process_tree.column("username", width=120, stretch=False)
        self.process_tree.column("cpu_percent", width=80, stretch=False)
        self.process_tree.column("memory_percent", width=100, stretch=False)
        self.process_tree.column("memory_rss", width=120, stretch=False)
        self.process_tree.column("memory_vms", width=120, stretch=False)
        self.process_tree.column("create_time", width=150, stretch=False)
        self.process_tree.column("status", width=100, stretch=False)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.process_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.process_tree.xview)
        self.process_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.process_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind right-click for context menu
        self.process_tree.bind("<Button-3>", self._show_context_menu)
        
        self.pack(fill="both", expand=True)
        
    def _start_monitoring(self):
        """Start process monitoring"""
        self._refresh_processes()
        self._schedule_refresh()
        
    def _schedule_refresh(self):
        """Schedule next refresh"""
        if self.auto_refresh:
            self.after(self.refresh_interval, self._start_monitoring)
            
    def _toggle_auto_refresh(self):
        """Toggle auto refresh"""
        self.auto_refresh = self.auto_refresh_var.get()
        if self.auto_refresh:
            self._start_monitoring()
            
    def _refresh_processes(self):
        """Refresh process list"""
        try:
            self.processes = get_processes()
            self._update_process_tree()
            
            # Update status
            self.status_label.configure(text=f"Processes: {len(self.processes)}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to refresh processes:\n{str(e)}")
            
    def _update_process_tree(self):
        """Update process tree view"""
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
            
        # Get search filter
        search_term = self.search_var.get().lower()
        
        # Add processes to tree
        for process in self.processes:
            # Apply search filter
            if search_term:
                if (search_term not in process['name'].lower() and 
                    search_term not in str(process['pid']) and
                    search_term not in process['username'].lower()):
                    continue
                    
            # Format values
            cpu_percent = f"{process['cpu_percent']:.1f}%"
            memory_percent = f"{process['memory_percent']:.1f}%"
            memory_rss = format_bytes(process['memory_rss'])
            memory_vms = format_bytes(process['memory_vms'])
            create_time = format_timestamp(process['create_time'])
            
            # Determine color based on CPU usage
            cpu_color = "white"
            if process['cpu_percent'] > 50:
                cpu_color = "#ff6b6b"  # Red
            elif process['cpu_percent'] > 20:
                cpu_color = "#ffd93d"  # Yellow
                
            # Determine color based on memory usage
            mem_color = "white"
            if process['memory_percent'] > 50:
                mem_color = "#ff6b6b"  # Red
            elif process['memory_percent'] > 20:
                mem_color = "#ffd93d"  # Yellow
                
            # Insert item
            item = self.process_tree.insert("", "end", values=(
                process['pid'],
                process['name'],
                process['username'],
                cpu_percent,
                memory_percent,
                memory_rss,
                memory_vms,
                create_time,
                process['status']
            ))
            
            # Tag with colors
            if process['cpu_percent'] > 0:
                self.process_tree.item(item, tags=(cpu_color,))
                
        # Configure tag colors
        self.process_tree.tag_configure("#ff6b6b", foreground="#ff6b6b")
        self.process_tree.tag_configure("#ffd93d", foreground="#ffd93d")
        
    def _on_search_change(self, *args):
        """Handle search change"""
        self._update_process_tree()
        
    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        # Select item under cursor
        item = self.process_tree.identify_row(event.y)
        if item:
            self.process_tree.selection_set(item)
            
            # Create context menu
            context_menu = tk.Menu(self.process_tree, tearoff=0)
            context_menu.add_command(label="Kill Process", command=self._kill_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Copy PID", command=self._copy_pid)
            context_menu.add_command(label="Copy Name", command=self._copy_name)
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
                
    def _kill_selected(self):
        """Kill selected process"""
        selection = self.process_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a process to kill")
            return
            
        item = selection[0]
        pid = int(self.process_tree.item(item, "values")[0])
        name = self.process_tree.item(item, "values")[1]
        
        # Confirm kill
        result = messagebox.askyesno(
            "Confirm Kill",
            f"Are you sure you want to kill process {pid} ({name})?\n\nThis may cause system instability!"
        )
        
        if result:
            success = kill_process(pid)
            if success:
                messagebox.showinfo("Success", f"Process {pid} ({name}) has been terminated")
                self._refresh_processes()
            else:
                messagebox.showerror("Error", f"Failed to kill process {pid} ({name})")
                
    def _copy_pid(self):
        """Copy PID to clipboard"""
        selection = self.process_tree.selection()
        if selection:
            item = selection[0]
            pid = self.process_tree.item(item, "values")[0]
            self.clipboard_clear()
            self.clipboard_append(str(pid))
            
    def _copy_name(self):
        """Copy process name to clipboard"""
        selection = self.process_tree.selection()
        if selection:
            item = selection[0]
            name = self.process_tree.item(item, "values")[1]
            self.clipboard_clear()
            self.clipboard_append(name)
            
    def _export_processes(self):
        """Export process list"""
        if not self.processes:
            messagebox.showinfo("Export", "No processes to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export Process List",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if not file_path:
            return
            
        try:
            import csv
            
            with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                
                # Write header
                writer.writerow(['PID', 'Process Name', 'Username', 'CPU %', 'Memory %', 
                               'Memory RSS', 'Memory VMS', 'Start Time', 'Status'])
                
                # Write data
                for process in self.processes:
                    writer.writerow([
                        process['pid'],
                        process['name'],
                        process['username'],
                        f"{process['cpu_percent']:.1f}%",
                        f"{process['memory_percent']:.1f}%",
                        format_bytes(process['memory_rss']),
                        format_bytes(process['memory_vms']),
                        format_timestamp(process['create_time']),
                        process['status']
                    ])
                    
            messagebox.showinfo("Export Successful", f"Process list exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting process list:\n{str(e)}")

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
            
        app = ProcessMonitorApp(root)
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
        messagebox.showerror("Process Monitor Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
