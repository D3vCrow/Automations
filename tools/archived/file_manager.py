"""
file_manager.py

FILE MANAGER PRO
- Advanced file operations
- File search and filtering
- Batch file operations
- File properties viewer
- Duplicate file finder
- File organizer
- Export file lists

Dependencies:
  pip install send2trash
"""

import os
import sys
import shutil
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Set, Tuple
from pathlib import Path

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

try:
    from send2trash import send2trash
    HAS_SEND2TRASH = True
except ImportError:
    HAS_SEND2TRASH = False

TOOL_NAME = "File Manager Pro"

# =============================
# File Manager Functions
# =============================

def get_file_info(file_path: str) -> Dict[str, any]:
    """Get comprehensive file information"""
    try:
        stat = os.stat(file_path)
        return {
            'name': os.path.basename(file_path),
            'path': file_path,
            'size': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'is_dir': os.path.isdir(file_path),
            'is_file': os.path.isfile(file_path),
            'extension': os.path.splitext(file_path)[1].lower(),
            'permissions': oct(stat.st_mode)[-3:]
        }
    except (OSError, PermissionError):
        return None

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

def format_timestamp(timestamp: float) -> str:
    """Format timestamp into readable date"""
    if timestamp == 0:
        return "Unknown"
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def calculate_file_hash(file_path: str, chunk_size: int = 8192) -> str:
    """Calculate MD5 hash of file"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (OSError, PermissionError):
        return None

def find_duplicates(directory: str) -> Dict[str, List[str]]:
    """Find duplicate files in directory"""
    file_hashes = {}
    duplicates = {}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_file_hash(file_path)
            
            if file_hash:
                if file_hash in file_hashes:
                    if file_hash not in duplicates:
                        duplicates[file_hash] = [file_hashes[file_hash]]
                    duplicates[file_hash].append(file_path)
                else:
                    file_hashes[file_hash] = file_path
    
    return duplicates

def organize_files(directory: str, organize_by: str = 'extension') -> Dict[str, List[str]]:
    """Organize files by type, date, or size"""
    organized = {}
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            
            if organize_by == 'extension':
                category = os.path.splitext(file)[1].lower() or 'no_extension'
            elif organize_by == 'date':
                stat = os.stat(file_path)
                category = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m')
            elif organize_by == 'size':
                size = os.path.getsize(file_path)
                if size < 1024 * 1024:  # < 1MB
                    category = 'small'
                elif size < 1024 * 1024 * 100:  # < 100MB
                    category = 'medium'
                else:
                    category = 'large'
            else:
                category = 'other'
            
            if category not in organized:
                organized[category] = []
            organized[category].append(file_path)
    
    return organized

# =============================
# Main Application
# =============================

class FileManagerApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("File Manager Pro")
        parent.geometry("1200x800")
        
        self.current_directory = os.path.expanduser("~")
        self.files = []
        self.selected_files = []
        
        self._build_ui()
        self._load_directory()
        
    def _build_ui(self):
        # Toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))
        
        # Navigation
        ctk.CTkButton(toolbar, text="⬅️ Back", command=self._go_back, fg_color="#6c757d", hover_color="#5a6268").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="🏠 Home", command=self._go_home, fg_color="#6c757d", hover_color="#5a6268").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="📁 Browse", command=self._browse_directory, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="🔄 Refresh", command=self._load_directory, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        
        # Directory path
        ctk.CTkLabel(toolbar, text="Path:").pack(side="left", padx=(20, 5))
        self.path_var = tk.StringVar(value=self.current_directory)
        self.path_entry = ctk.CTkEntry(toolbar, textvariable=self.path_var, width=400)
        self.path_entry.pack(side="left", padx=5)
        self.path_entry.bind('<Return>', lambda e: self._navigate_to_path())
        
        # Search
        ctk.CTkLabel(toolbar, text="Search:").pack(side="left", padx=(20, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search_change)
        self.search_entry = ctk.CTkEntry(toolbar, textvariable=self.search_var, width=200)
        self.search_entry.pack(side="left", padx=5)
        
        # File operations
        ctk.CTkButton(toolbar, text="🗑️ Delete", command=self._delete_selected, fg_color="#dc3545", hover_color="#c82333").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="📋 Copy", command=self._copy_selected, fg_color="#ffc107", hover_color="#e0a800").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="✂️ Cut", command=self._cut_selected, fg_color="#17a2b8", hover_color="#138496").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="📄 Paste", command=self._paste_files, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        
        # Special operations
        ctk.CTkButton(toolbar, text="🔍 Find Duplicates", command=self._find_duplicates, fg_color="#6f42c1", hover_color="#5a32a3").pack(side="right", padx=5)
        ctk.CTkButton(toolbar, text="📦 Organize", command=self._organize_files, fg_color="#fd7e14", hover_color="#e85d04").pack(side="right", padx=5)
        
        # Main content area
        content_frame = ctk.CTkFrame(self)
        content_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # File tree
        tree_frame = ctk.CTkFrame(content_frame)
        tree_frame.pack(fill="both", expand=True)
        
        # Configure treeview style
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=("Arial", 10, "bold"))
        style.map("Treeview", background=[('selected', '#1f538d')])
        
        # Create treeview
        columns = ("name", "size", "type", "modified", "permissions")
        self.file_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
        
        # Configure columns
        self.file_tree.heading("name", text="📁 Name")
        self.file_tree.heading("size", text="📊 Size")
        self.file_tree.heading("type", text="📄 Type")
        self.file_tree.heading("modified", text="🕐 Modified")
        self.file_tree.heading("permissions", text="🔒 Permissions")
        
        # Configure column widths
        self.file_tree.column("name", width=400, stretch=True)
        self.file_tree.column("size", width=120, stretch=False)
        self.file_tree.column("type", width=100, stretch=False)
        self.file_tree.column("modified", width=150, stretch=False)
        self.file_tree.column("permissions", width=100, stretch=False)
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.file_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.file_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Bind events
        self.file_tree.bind("<Double-1>", self._on_double_click)
        self.file_tree.bind("<Button-3>", self._show_context_menu)
        
        # Status bar
        status_frame = ctk.CTkFrame(self)
        status_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.status_label = ctk.CTkLabel(status_frame, text="Ready")
        self.status_label.pack(side="left", padx=10)
        
        self.selection_label = ctk.CTkLabel(status_frame, text="")
        self.selection_label.pack(side="right", padx=10)
        
        # Clipboard for copy/paste operations
        self.clipboard_files = []
        self.clipboard_operation = None  # 'copy' or 'cut'
        
        self.pack(fill="both", expand=True)
        
    def _load_directory(self):
        """Load current directory"""
        try:
            self.files = []
            self.selected_files = []
            
            # Get directory contents
            items = []
            try:
                for item in os.listdir(self.current_directory):
                    item_path = os.path.join(self.current_directory, item)
                    file_info = get_file_info(item_path)
                    if file_info:
                        items.append(file_info)
            except PermissionError:
                messagebox.showerror("Access Denied", f"Cannot access directory:\n{self.current_directory}")
                return
            
            # Sort: directories first, then by name
            items.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))
            self.files = items
            
            # Update tree
            self._update_file_tree()
            
            # Update status
            file_count = len([f for f in self.files if f['is_file']])
            dir_count = len([f for f in self.files if f['is_dir']])
            total_size = sum(f['size'] for f in self.files if f['is_file'])
            
            self.status_label.configure(text=f"{file_count} files, {dir_count} directories, {format_size(total_size)}")
            self.path_var.set(self.current_directory)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load directory:\n{str(e)}")
            
    def _update_file_tree(self):
        """Update file tree view"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
        # Get search filter
        search_term = self.search_var.get().lower()
        
        # Add files to tree
        for file_info in self.files:
            # Apply search filter
            if search_term and search_term not in file_info['name'].lower():
                continue
                
            # Format values
            name = file_info['name']
            size = format_size(file_info['size']) if file_info['is_file'] else ''
            file_type = '📁 Directory' if file_info['is_dir'] else file_info['extension'] or 'File'
            modified = format_timestamp(file_info['modified'])
            permissions = file_info['permissions']
            
            # Determine icon based on type
            icon = '📁' if file_info['is_dir'] else '📄'
            if not file_info['is_dir']:
                ext = file_info['extension'].lower()
                if ext in ['.txt', '.md', '.py', '.js', '.html', '.css']:
                    icon = '📝'
                elif ext in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
                    icon = '🖼️'
                elif ext in ['.mp4', '.avi', '.mkv', '.mov']:
                    icon = '🎬'
                elif ext in ['.mp3', '.wav', '.flac']:
                    icon = '🎵'
                elif ext in ['.zip', '.rar', '.7z', '.tar']:
                    icon = '📦'
                elif ext in ['.exe', '.msi']:
                    icon = '⚙️'
                    
            display_name = f"{icon} {name}"
            
            # Insert item
            item = self.file_tree.insert("", "end", values=(
                display_name,
                size,
                file_type,
                modified,
                permissions
            ))
            
            # Store full path as item data
            self.file_tree.set(item, "full_path", file_info['path'])
            
    def _on_search_change(self, *args):
        """Handle search change"""
        self._update_file_tree()
        
    def _on_double_click(self, event):
        """Handle double-click on file/directory"""
        selection = self.file_tree.selection()
        if not selection:
            return
            
        item = selection[0]
        file_path = self.file_tree.set(item, "full_path")
        
        if os.path.isdir(file_path):
            self.current_directory = file_path
            self._load_directory()
        else:
            # Open file with default application
            try:
                os.startfile(file_path)
            except:
                messagebox.showinfo("File", f"Cannot open file:\n{file_path}")
                
    def _show_context_menu(self, event):
        """Show context menu on right-click"""
        # Select item under cursor
        item = self.file_tree.identify_row(event.y)
        if item:
            self.file_tree.selection_set(item)
            
            # Create context menu
            context_menu = tk.Menu(self.file_tree, tearoff=0)
            context_menu.add_command(label="Open", command=self._open_selected)
            context_menu.add_command(label="Rename", command=self._rename_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Copy", command=self._copy_selected)
            context_menu.add_command(label="Cut", command=self._cut_selected)
            context_menu.add_command(label="Paste", command=self._paste_files)
            context_menu.add_separator()
            context_menu.add_command(label="Delete", command=self._delete_selected)
            context_menu.add_separator()
            context_menu.add_command(label="Properties", command=self._show_properties)
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
                
    def _get_selected_files(self) -> List[str]:
        """Get list of selected file paths"""
        selected = []
        for item in self.file_tree.selection():
            file_path = self.file_tree.set(item, "full_path")
            selected.append(file_path)
        return selected
        
    def _open_selected(self):
        """Open selected file/directory"""
        selected = self._get_selected_files()
        if selected:
            if os.path.isdir(selected[0]):
                self.current_directory = selected[0]
                self._load_directory()
            else:
                try:
                    os.startfile(selected[0])
                except:
                    messagebox.showinfo("File", f"Cannot open file:\n{selected[0]}")
                    
    def _rename_selected(self):
        """Rename selected file/directory"""
        selected = self._get_selected_files()
        if not selected:
            return
            
        old_path = selected[0]
        old_name = os.path.basename(old_path)
        
        # Create rename dialog
        dialog = ctk.CTkInputDialog(text="Enter new name:", title="Rename")
        new_name = dialog.get_input(text=old_name)
        
        if new_name and new_name != old_name:
            new_path = os.path.join(os.path.dirname(old_path), new_name)
            try:
                os.rename(old_path, new_path)
                self._load_directory()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to rename:\n{str(e)}")
                
    def _copy_selected(self):
        """Copy selected files to clipboard"""
        selected = self._get_selected_files()
        if selected:
            self.clipboard_files = selected
            self.clipboard_operation = 'copy'
            self.selection_label.configure(text=f"Copied {len(selected)} items")
            
    def _cut_selected(self):
        """Cut selected files to clipboard"""
        selected = self._get_selected_files()
        if selected:
            self.clipboard_files = selected
            self.clipboard_operation = 'cut'
            self.selection_label.configure(text=f"Cut {len(selected)} items")
            
    def _paste_files(self):
        """Paste files from clipboard"""
        if not self.clipboard_files:
            return
            
        for file_path in self.clipboard_files:
            filename = os.path.basename(file_path)
            dest_path = os.path.join(self.current_directory, filename)
            
            try:
                if self.clipboard_operation == 'copy':
                    if os.path.isdir(file_path):
                        shutil.copytree(file_path, dest_path, dirs_exist_ok=True)
                    else:
                        shutil.copy2(file_path, dest_path)
                elif self.clipboard_operation == 'cut':
                    shutil.move(file_path, dest_path)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to paste {filename}:\n{str(e)}")
                
        if self.clipboard_operation == 'cut':
            self.clipboard_files = []
            self.clipboard_operation = None
            self.selection_label.configure(text="")
            
        self._load_directory()
        
    def _delete_selected(self):
        """Delete selected files"""
        selected = self._get_selected_files()
        if not selected:
            return
            
        # Confirm deletion
        result = messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete {len(selected)} item(s)?\n\nThis action cannot be undone!"
        )
        
        if result:
            for file_path in selected:
                try:
                    if HAS_SEND2TRASH:
                        send2trash(file_path)
                    else:
                        if os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                        else:
                            os.remove(file_path)
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to delete {file_path}:\n{str(e)}")
                    
            self._load_directory()
            
    def _show_properties(self):
        """Show file properties"""
        selected = self._get_selected_files()
        if not selected:
            return
            
        file_path = selected[0]
        file_info = get_file_info(file_path)
        
        if file_info:
            # Create properties window
            props_window = ctk.CTkToplevel(self)
            props_window.title("File Properties")
            props_window.geometry("400x300")
            
            # Display properties
            props_frame = ctk.CTkScrollableFrame(props_window)
            props_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            properties = [
                ("Name", file_info['name']),
                ("Path", file_info['path']),
                ("Size", format_size(file_info['size'])),
                ("Type", "Directory" if file_info['is_dir'] else "File"),
                ("Extension", file_info['extension'] or "N/A"),
                ("Created", format_timestamp(file_info['created'])),
                ("Modified", format_timestamp(file_info['modified'])),
                ("Accessed", format_timestamp(file_info['accessed'])),
                ("Permissions", file_info['permissions'])
            ]
            
            for label, value in properties:
                frame = ctk.CTkFrame(props_frame)
                frame.pack(fill="x", padx=10, pady=5)
                
                ctk.CTkLabel(frame, text=f"{label}:", width=120, anchor="w").pack(side="left", padx=10)
                ctk.CTkLabel(frame, text=str(value), anchor="w").pack(side="left", padx=10)
                
    def _go_back(self):
        """Navigate to parent directory"""
        parent = os.path.dirname(self.current_directory)
        if parent != self.current_directory:
            self.current_directory = parent
            self._load_directory()
            
    def _go_home(self):
        """Navigate to home directory"""
        self.current_directory = os.path.expanduser("~")
        self._load_directory()
        
    def _browse_directory(self):
        """Browse for directory"""
        directory = filedialog.askdirectory(initialdir=self.current_directory)
        if directory:
            self.current_directory = directory
            self._load_directory()
            
    def _navigate_to_path(self):
        """Navigate to path in entry"""
        path = self.path_var.get()
        if os.path.exists(path) and os.path.isdir(path):
            self.current_directory = path
            self._load_directory()
        else:
            messagebox.showerror("Error", f"Directory does not exist:\n{path}")
            
    def _find_duplicates(self):
        """Find duplicate files in current directory"""
        try:
            duplicates = find_duplicates(self.current_directory)
            
            if not duplicates:
                messagebox.showinfo("Duplicates", "No duplicate files found!")
                return
                
            # Create duplicates window
            dup_window = ctk.CTkToplevel(self)
            dup_window.title("Duplicate Files")
            dup_window.geometry("600x400")
            
            # Create treeview for duplicates
            tree_frame = ctk.CTkFrame(dup_window)
            tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
            
            columns = ("hash", "files")
            dup_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
            dup_tree.heading("hash", text="Hash")
            dup_tree.heading("files", text="Files")
            
            dup_tree.column("hash", width=200)
            dup_tree.column("files", width=380)
            
            dup_tree.pack(fill="both", expand=True)
            
            # Add duplicates to tree
            for file_hash, files in duplicates.items():
                file_list = "\n".join(files)
                dup_tree.insert("", "end", values=(file_hash[:8] + "...", file_list))
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to find duplicates:\n{str(e)}")
            
    def _organize_files(self):
        """Organize files in current directory"""
        # Create organize dialog
        dialog = ctk.CTkInputDialog(
            text="Organize by (extension/date/size):",
            title="Organize Files"
        )
        organize_by = dialog.get_input(text="extension")
        
        if organize_by and organize_by in ['extension', 'date', 'size']:
            try:
                organized = organize_files(self.current_directory, organize_by)
                
                # Create organize window
                org_window = ctk.CTkToplevel(self)
                org_window.title("Organized Files")
                org_window.geometry("500x400")
                
                # Create treeview for organized files
                tree_frame = ctk.CTkFrame(org_window)
                tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
                
                columns = ("category", "count", "size")
                org_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
                org_tree.heading("category", text="Category")
                org_tree.heading("count", text="Count")
                org_tree.heading("size", text="Total Size")
                
                org_tree.column("category", width=150)
                org_tree.column("count", width=100)
                org_tree.column("size", width=200)
                
                org_tree.pack(fill="both", expand=True)
                
                # Add organized categories
                for category, files in organized.items():
                    total_size = sum(os.path.getsize(f) for f in files if os.path.isfile(f))
                    org_tree.insert("", "end", values=(
                        category,
                        len(files),
                        format_size(total_size)
                    ))
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to organize files:\n{str(e)}")

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
            
        app = FileManagerApp(root)
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
        messagebox.showerror("File Manager Pro", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
