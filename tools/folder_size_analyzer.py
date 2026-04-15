"""
folder_size_analyzer.py

FOLDER SIZE ANALYZER PRO
- Analyzes folder sizes in any directory
- Sort by size/date/created/modified
- Visual size indicators with progress bars
- Export results to CSV/JSON
- Real-time scanning with progress updates
- Smart filtering and search capabilities
- Interactive folder navigation

Dependencies:
  pip install psutil
"""

import os
import sys
import time
import json
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import psutil

from tools._common.threadsafe import BoundedDeque

TOOL_NAME = "Folder Size Analyzer Pro"

# =============================
# Utilities
# =============================

def format_size(bytes_size: int) -> str:
    """Format bytes into human readable format"""
    if bytes_size == 0:
        return "0 B"
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    unit_index = 0
    size = float(bytes_size)
    
    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    else:
        return f"{size:.1f} {units[unit_index]}"

def format_date(timestamp: float) -> str:
    """Format timestamp into readable date"""
    if timestamp == 0:
        return "Unknown"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")

def get_folder_size(folder_path: str, progress_callback=None) -> Tuple[int, int, float, float, float]:
    """
    Calculate folder size and statistics using iterative os.walk.
    Returns: (total_size, file_count, created_time, modified_time, accessed_time)
    """
    total_size = 0
    file_count = 0
    created_time = float('inf')
    modified_time = 0
    accessed_time = 0

    for dirpath, dirnames, filenames in os.walk(folder_path):
        # Skip hidden directories
        dirnames[:] = [d for d in dirnames if not d.startswith('.')]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            try:
                stat = os.stat(filepath)
                total_size += stat.st_size
                file_count += 1

                created_time = min(created_time, stat.st_ctime)
                modified_time = max(modified_time, stat.st_mtime)
                accessed_time = max(accessed_time, stat.st_atime)

                if progress_callback and file_count % 100 == 0:
                    progress_callback(file_count)

            except (OSError, PermissionError):
                continue

    if created_time == float('inf'):
        created_time = 0

    return total_size, file_count, created_time, modified_time, accessed_time

def get_drive_info(path: str) -> Dict[str, int]:
    """Get drive information (total, used, free space)"""
    try:
        stat = psutil.disk_usage(path)
        return {
            'total': stat.total,
            'used': stat.used,
            'free': stat.free
        }
    except:
        return {'total': 0, 'used': 0, 'free': 0}

# =============================
# Data Models
# =============================

class FolderInfo:
    def __init__(self, path: str):
        self.path = path
        self.name = os.path.basename(path)
        self.size = 0
        self.file_count = 0
        self.created_time = 0
        self.modified_time = 0
        self.accessed_time = 0
        self.size_percentage = 0.0
        
    def __lt__(self, other):
        # For sorting, this will be overridden by sort key
        return True

# =============================
# Main Application
# =============================

class FolderSizeAnalyzerApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Folder Size Analyzer Pro")
        parent.geometry("1200x800")
        
        # Data — BoundedDeque keeps a fixed upper bound and allows thread-safe
        # snapshot reads from UI refresh paths.
        self.folders: BoundedDeque = BoundedDeque(maxlen=10_000)
        self.current_directory = os.path.expanduser("~")  # Start with user home
        self.sort_column = "size"
        self.sort_reverse = True  # Descending by default
        self.is_scanning = False
        self.scan_thread = None
        
        # UI Setup
        self._build_ui()
        self._load_initial_directory()
        
    def _build_ui(self):
        # Top toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))
        
        # Directory selection
        ctk.CTkLabel(toolbar, text="Directory:").pack(side="left", padx=(10, 5))
        
        self.directory_var = tk.StringVar(value=self.current_directory)
        self.directory_entry = ctk.CTkEntry(toolbar, textvariable=self.directory_var, width=400)
        self.directory_entry.pack(side="left", padx=5)
        
        ctk.CTkButton(toolbar, text="Browse", command=self._browse_directory, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Scan", command=self._start_scan, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Refresh", command=self._refresh_scan, fg_color="#17a2b8", hover_color="#138496").pack(side="left", padx=5)
        
        # Search box
        ctk.CTkLabel(toolbar, text="Search:").pack(side="left", padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        self.search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var, width=200)
        self.search_entry.pack(side="left", padx=5)
        
        # Sort options
        ctk.CTkLabel(toolbar, text="Sort by:").pack(side="left", padx=(20, 5))
        self.sort_var = tk.StringVar(value="Size (Desc)")
        sort_menu = ctk.CTkOptionMenu(toolbar, variable=self.sort_var, 
                                    values=["Size (Desc)", "Size (Asc)", "Name (Asc)", "Name (Desc)", 
                                           "Modified (Desc)", "Modified (Asc)", "Created (Desc)", "Created (Asc)"],
                                    command=self._on_sort_change)
        sort_menu.pack(side="left", padx=5)
        
        # Export button
        ctk.CTkButton(toolbar, text="Export", command=self._export_results, fg_color="#6c757d", hover_color="#5a6268").pack(side="right", padx=10)
        
        # Progress bar
        self.progress_frame = ctk.CTkFrame(self)
        self.progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress_label = ctk.CTkLabel(self.progress_frame, text="Ready")
        self.progress_label.pack(side="left", padx=10)
        
        self.progress_bar = ctk.CTkProgressBar(self.progress_frame)
        self.progress_bar.pack(side="left", fill="x", expand=True, padx=10)
        self.progress_bar.set(0)
        
        # Drive info
        self.drive_frame = ctk.CTkFrame(self)
        self.drive_frame.pack(fill="x", padx=10, pady=5)
        
        self.drive_label = ctk.CTkLabel(self.drive_frame, text="", font=ctk.CTkFont(size=11))
        self.drive_label.pack(side="left", padx=10)
        
        # Main content - Treeview
        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Configure treeview style
        style = ttk.Style()
        style.configure("Treeview", background="#2b2b2b", foreground="white",
                         fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white",
                         relief="flat", font=("Arial", 10, "bold"))
        style.map("Treeview",
                  background=[('selected', '#1f538d')],
                  foreground=[('selected', 'white')])
        
        # Create treeview with columns
        columns = ("name", "size", "files", "size_percentage", "created", "modified", "accessed")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.tree.heading("name", text="📁 Folder Name")
        self.tree.heading("size", text="📊 Size")
        self.tree.heading("files", text="📄 Files")
        self.tree.heading("size_percentage", text="📈 % of Total")
        self.tree.heading("created", text="🕐 Created")
        self.tree.heading("modified", text="🔄 Modified")
        self.tree.heading("accessed", text="👁️ Accessed")
        
        # Configure column widths
        self.tree.column("name", width=300, stretch=True)
        self.tree.column("size", width=120, stretch=False)
        self.tree.column("files", width=80, stretch=False)
        self.tree.column("size_percentage", width=100, stretch=False)
        self.tree.column("created", width=150, stretch=False)
        self.tree.column("modified", width=150, stretch=False)
        self.tree.column("accessed", width=150, stretch=False)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Status bar
        self.status_frame = ctk.CTkFrame(self)
        self.status_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(self.status_frame, text="Ready to scan folders", font=ctk.CTkFont(size=11))
        self.status_label.pack(side="left", padx=10)
        
        # Bind double-click to open folder
        self.tree.bind("<Double-1>", self._on_double_click)
        
        self.pack(fill="both", expand=True)
        
    def _load_initial_directory(self):
        """Load initial directory"""
        self._update_drive_info()
        self._start_scan()
        
    def _browse_directory(self):
        """Browse for directory"""
        directory = filedialog.askdirectory(initialdir=self.current_directory)
        if directory:
            self.current_directory = directory
            self.directory_var.set(directory)
            self._start_scan()
            
    def _on_search_change(self, *args):
        """Handle search change"""
        self._refresh_tree()
        
    def _on_sort_change(self, *args):
        """Handle sort change"""
        sort_text = self.sort_var.get()
        
        # Parse sort option
        if "Size" in sort_text:
            self.sort_column = "size"
        elif "Name" in sort_text:
            self.sort_column = "name"
        elif "Modified" in sort_text:
            self.sort_column = "modified_time"
        elif "Created" in sort_text:
            self.sort_column = "created_time"
        else:
            self.sort_column = "size"
            
        self.sort_reverse = "Desc" in sort_text
        
        self._refresh_tree()
        
    def _start_scan(self):
        """Start scanning directory"""
        if self.is_scanning:
            return
            
        if not os.path.exists(self.current_directory):
            messagebox.showerror("Error", f"Directory does not exist:\n{self.current_directory}")
            return
            
        self.is_scanning = True
        self.progress_bar.set(0)
        self.progress_label.configure(text="Scanning...")
        self.status_label.configure(text="Scanning folders...")
        
        # Start scan in background thread
        self.scan_thread = threading.Thread(target=self._scan_directory, daemon=True)
        self.scan_thread.start()
        
    def _scan_directory(self):
        """Scan directory in background thread"""
        try:
            # Get all folders in directory
            folder_paths = []
            try:
                for entry in os.listdir(self.current_directory):
                    full_path = os.path.join(self.current_directory, entry)
                    if os.path.isdir(full_path) and not entry.startswith('.'):
                        folder_paths.append(full_path)
            except PermissionError:
                self.after(0, lambda: self._after_scan([]))
                return
                
            # Calculate total size for percentage calculations
            total_size = 0
            folder_data = []
            
            for i, folder_path in enumerate(folder_paths):
                try:
                    size, files, created, modified, accessed = get_folder_size(folder_path)
                    folder_info = FolderInfo(folder_path)
                    folder_info.size = size
                    folder_info.file_count = files
                    folder_info.created_time = created
                    folder_info.modified_time = modified
                    folder_info.accessed_time = accessed
                    folder_data.append(folder_info)
                    total_size += size
                    
                    # Update progress on the main thread
                    progress = (i + 1) / len(folder_paths)
                    label_text = f"Scanning... {i+1}/{len(folder_paths)} folders"
                    self.after(0, lambda p=progress: self.progress_bar.set(p))
                    self.after(0, lambda t=label_text: self.progress_label.configure(text=t))
                    
                except (OSError, PermissionError):
                    continue
                    
            # Calculate percentages
            for folder in folder_data:
                if total_size > 0:
                    folder.size_percentage = (folder.size / total_size) * 100
                    
            self.after(0, lambda data=folder_data: self._after_scan(data))

        except Exception as e:
            self.after(0, lambda: self._after_scan([]))
            self.after(0, lambda err=e: messagebox.showerror("Scan Error", f"Error scanning directory:\n{str(err)}"))
            
    def _after_scan(self, folders: List[FolderInfo]):
        """Called after scan completes (always on the Tk main thread via self.after)."""
        # Rebuild deque from the sorted result so _refresh_tree always reads a
        # consistent snapshot even if a trace callback fires mid-iteration.
        self.folders.clear()
        self.is_scanning = False
        self.progress_bar.set(1.0)
        self.progress_label.configure(text="Scan complete")

        # Sort locally, then populate deque
        sorted_folders = self._sorted_copy(folders)
        self.folders.extend(sorted_folders)

        self._refresh_tree()

        total_size = sum(f.size for f in folders)
        total_files = sum(f.file_count for f in folders)
        self.status_label.configure(text=f"Found {len(folders)} folders, {total_files} files, {format_size(total_size)} total")

    def _sorted_copy(self, folders: List[FolderInfo]) -> List[FolderInfo]:
        """Return *folders* sorted by the current column/direction.

        Args:
            folders: Unsorted list of FolderInfo objects.

        Returns:
            New sorted list (original is not mutated).
        """
        reverse = self.sort_reverse
        if self.sort_column == "size":
            return sorted(folders, key=lambda f: f.size, reverse=reverse)
        if self.sort_column == "name":
            return sorted(folders, key=lambda f: f.name.lower(), reverse=reverse)
        if self.sort_column == "modified_time":
            return sorted(folders, key=lambda f: f.modified_time, reverse=reverse)
        if self.sort_column == "created_time":
            return sorted(folders, key=lambda f: f.created_time, reverse=reverse)
        return folders[:]

    def _sort_folders(self):
        """Re-sort the deque in-place (main thread only)."""
        snap = list(self.folders.snapshot())
        snap = self._sorted_copy(snap)
        self.folders.clear()
        self.folders.extend(snap)
            
    def _refresh_tree(self):
        """Refresh tree view"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        # Get search filter
        search_term = self.search_var.get().lower()
        
        # Snapshot once so the iteration is not affected by concurrent writes.
        for folder in self.folders.snapshot():
            # Apply search filter
            if search_term and search_term not in folder.name.lower():
                continue
                
            # Format values
            size_str = format_size(folder.size)
            percentage_str = f"{folder.size_percentage:.1f}%"
            created_str = format_date(folder.created_time)
            modified_str = format_date(folder.modified_time)
            accessed_str = format_date(folder.accessed_time)
            
            # Determine color based on size
            size_color = "white"
            if folder.size > 1024*1024*1024:  # > 1GB
                size_color = "#ff6b6b"  # Red
            elif folder.size > 1024*1024*100:  # > 100MB
                size_color = "#ffd93d"  # Yellow
            elif folder.size > 1024*1024*10:  # > 10MB
                size_color = "#6bcf7f"  # Green
                
            # Insert item
            item = self.tree.insert("", "end", values=(
                folder.name,
                size_str,
                folder.file_count,
                percentage_str,
                created_str,
                modified_str,
                accessed_str
            ))
            
            # Tag with color
            if folder.size > 0:
                self.tree.item(item, tags=(size_color,))
                
        # Configure tag colors
        self.tree.tag_configure("#ff6b6b", foreground="#ff6b6b")
        self.tree.tag_configure("#ffd93d", foreground="#ffd93d")
        self.tree.tag_configure("#6bcf7f", foreground="#6bcf7f")
        
    def _refresh_scan(self):
        """Refresh current scan"""
        self._start_scan()
        
    def _update_drive_info(self):
        """Update drive information"""
        drive_info = get_drive_info(self.current_directory)
        if drive_info['total'] > 0:
            used_percent = (drive_info['used'] / drive_info['total']) * 100
            drive_text = f"📀 Drive: {format_size(drive_info['used'])} used of {format_size(drive_info['total'])} ({used_percent:.1f}%) - {format_size(drive_info['free'])} free"
            self.drive_label.configure(text=drive_text)
        else:
            self.drive_label.configure(text="📀 Drive information unavailable")
            
    def _on_double_click(self, event):
        """Handle double-click on folder"""
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        folder_name = self.tree.item(item, "values")[0]
        folder_path = os.path.join(self.current_directory, folder_name)
        
        if os.path.isdir(folder_path):
            self.current_directory = folder_path
            self.directory_var.set(folder_path)
            self._start_scan()
            self._update_drive_info()
            
    def _export_results(self):
        """Export results to file"""
        if not self.folders:
            messagebox.showinfo("Export", "No data to export")
            return
            
        # Ask for file type
        file_types = [
            ("CSV files", "*.csv"),
            ("JSON files", "*.json"),
            ("All files", "*.*")
        ]
        
        file_path = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".csv",
            filetypes=file_types,
            initialdir=os.path.expanduser("~")
        )
        
        if not file_path:
            return
            
        try:
            if file_path.endswith('.json'):
                self._export_json(file_path)
            else:
                self._export_csv(file_path)
                
            messagebox.showinfo("Export Successful", f"Results exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting results:\n{str(e)}")
            
    def _export_csv(self, file_path: str):
        """Export to CSV"""
        import csv
        snap = self.folders.snapshot()
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Folder Name', 'Size (Bytes)', 'Size (Formatted)', 'File Count',
                             'Size Percentage', 'Created', 'Modified', 'Accessed', 'Full Path'])
            for folder in snap:
                writer.writerow([
                    folder.name,
                    folder.size,
                    format_size(folder.size),
                    folder.file_count,
                    f"{folder.size_percentage:.2f}%",
                    format_date(folder.created_time),
                    format_date(folder.modified_time),
                    format_date(folder.accessed_time),
                    folder.path
                ])

    def _export_json(self, file_path: str):
        """Export to JSON"""
        snap = self.folders.snapshot()
        data = {
            'scan_directory': self.current_directory,
            'scan_time': datetime.now().isoformat(),
            'total_folders': len(snap),
            'total_size': sum(f.size for f in snap),
            'total_files': sum(f.file_count for f in snap),
            'folders': []
        }

        for folder in snap:
            folder_data = {
                'name': folder.name,
                'path': folder.path,
                'size_bytes': folder.size,
                'size_formatted': format_size(folder.size),
                'file_count': folder.file_count,
                'size_percentage': folder.size_percentage,
                'created_time': folder.created_time,
                'modified_time': folder.modified_time,
                'accessed_time': folder.accessed_time,
                'created_formatted': format_date(folder.created_time),
                'modified_formatted': format_date(folder.modified_time),
                'accessed_formatted': format_date(folder.accessed_time)
            }
            data['folders'].append(folder_data)
            
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(data, jsonfile, indent=2, ensure_ascii=False)

# =============================
# Entry Point
# =============================

def run_tool():
    """Tool entry point"""
    try:
        if tk._default_root is None:
            root = ctk.CTk()
        else:
            root = ctk.CTkToplevel()
            
        app = FolderSizeAnalyzerApp(root)
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
        messagebox.showerror("Folder Size Analyzer Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
