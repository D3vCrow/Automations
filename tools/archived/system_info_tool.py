"""
system_info_tool.py

SYSTEM INFORMATION TOOL
- Comprehensive system information display
- Hardware specifications
- Operating system details
- Network configuration
- Process monitoring
- Resource usage statistics
- Export system information

Dependencies:
  pip install psutil
  pip install platform
"""

import os
import sys
import platform
import subprocess
import json
from datetime import datetime
from typing import Dict, List, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import psutil

TOOL_NAME = "System Information Tool"

# =============================
# System Information Functions
# =============================

def get_system_info() -> Dict[str, Any]:
    """Get comprehensive system information"""
    info = {}
    
    # Basic system info
    info['system'] = {
        'platform': platform.platform(),
        'system': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'architecture': platform.architecture(),
        'hostname': platform.node(),
        'python_version': platform.python_version()
    }
    
    # CPU information
    info['cpu'] = {
        'physical_cores': psutil.cpu_count(logical=False),
        'logical_cores': psutil.cpu_count(logical=True),
        'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
        'min_frequency': psutil.cpu_freq().min if psutil.cpu_freq() else 0,
        'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else 0,
        'usage_percent': psutil.cpu_percent(interval=1)
    }
    
    # Memory information
    memory = psutil.virtual_memory()
    info['memory'] = {
        'total': memory.total,
        'available': memory.available,
        'used': memory.used,
        'free': memory.free,
        'percent': memory.percent
    }
    
    # Disk information
    info['disk'] = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            info['disk'].append({
                'device': partition.device,
                'mountpoint': partition.mountpoint,
                'fstype': partition.fstype,
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': (usage.used / usage.total) * 100
            })
        except PermissionError:
            continue
    
    # Network information
    info['network'] = {}
    net_io = psutil.net_io_counters()
    info['network']['io'] = {
        'bytes_sent': net_io.bytes_sent,
        'bytes_recv': net_io.bytes_recv,
        'packets_sent': net_io.packets_sent,
        'packets_recv': net_io.packets_recv
    }
    
    # Network interfaces
    info['network']['interfaces'] = {}
    for interface, addrs in psutil.net_if_addrs().items():
        info['network']['interfaces'][interface] = []
        for addr in addrs:
            info['network']['interfaces'][interface].append({
                'family': addr.family.name,
                'address': addr.address,
                'netmask': addr.netmask,
                'broadcast': addr.broadcast
            })
    
    # Boot time
    info['boot_time'] = psutil.boot_time()
    
    return info

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

# =============================
# Main Application
# =============================

class SystemInfoApp(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("System Information Tool")
        parent.geometry("900x700")
        
        self.system_info = {}
        
        self._build_ui()
        self._refresh_info()
        
    def _build_ui(self):
        # Toolbar
        toolbar = ctk.CTkFrame(self)
        toolbar.pack(fill="x", padx=10, pady=(10, 5))
        
        ctk.CTkButton(toolbar, text="Refresh", command=self._refresh_info, fg_color="#28a745", hover_color="#218838").pack(side="left", padx=5)
        ctk.CTkButton(toolbar, text="Export", command=self._export_info, fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=5)
        
        # Timestamp
        self.timestamp_label = ctk.CTkLabel(toolbar, text="")
        self.timestamp_label.pack(side="right", padx=10)
        
        # Main content with tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # System tab
        self.system_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.system_frame, text="System")
        self._build_system_tab()
        
        # CPU tab
        self.cpu_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.cpu_frame, text="CPU")
        self._build_cpu_tab()
        
        # Memory tab
        self.memory_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.memory_frame, text="Memory")
        self._build_memory_tab()
        
        # Disk tab
        self.disk_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.disk_frame, text="Disk")
        self._build_disk_tab()
        
        # Network tab
        self.network_frame = ctk.CTkFrame(self.notebook)
        self.notebook.add(self.network_frame, text="Network")
        self._build_network_tab()
        
        self.pack(fill="both", expand=True)
        
    def _build_system_tab(self):
        # System information display
        self.system_info_frame = ctk.CTkScrollableFrame(self.system_frame)
        self.system_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _build_cpu_tab(self):
        self.cpu_info_frame = ctk.CTkScrollableFrame(self.cpu_frame)
        self.cpu_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _build_memory_tab(self):
        self.memory_info_frame = ctk.CTkScrollableFrame(self.memory_frame)
        self.memory_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _build_disk_tab(self):
        # Disk treeview
        tree_frame = ctk.CTkFrame(self.disk_frame)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat", font=("Arial", 10, "bold"))
        
        columns = ("device", "mountpoint", "fstype", "total", "used", "free", "percent")
        self.disk_tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        
        self.disk_tree.heading("device", text="Device")
        self.disk_tree.heading("mountpoint", text="Mount Point")
        self.disk_tree.heading("fstype", text="Type")
        self.disk_tree.heading("total", text="Total")
        self.disk_tree.heading("used", text="Used")
        self.disk_tree.heading("free", text="Free")
        self.disk_tree.heading("percent", text="Usage %")
        
        self.disk_tree.column("device", width=100)
        self.disk_tree.column("mountpoint", width=150)
        self.disk_tree.column("fstype", width=80)
        self.disk_tree.column("total", width=120)
        self.disk_tree.column("used", width=120)
        self.disk_tree.column("free", width=120)
        self.disk_tree.column("percent", width=80)
        
        self.disk_tree.pack(fill="both", expand=True)
        
    def _build_network_tab(self):
        self.network_info_frame = ctk.CTkScrollableFrame(self.network_frame)
        self.network_info_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
    def _refresh_info(self):
        """Refresh all system information"""
        try:
            self.system_info = get_system_info()
            self._update_system_tab()
            self._update_cpu_tab()
            self._update_memory_tab()
            self._update_disk_tab()
            self._update_network_tab()
            
            # Update timestamp
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.timestamp_label.configure(text=f"Last updated: {current_time}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get system information:\n{str(e)}")
            
    def _update_system_tab(self):
        """Update system tab"""
        # Clear existing widgets
        for widget in self.system_info_frame.winfo_children():
            widget.destroy()
            
        system = self.system_info.get('system', {})
        
        # System information
        ctk.CTkLabel(self.system_info_frame, text="🖥️ System Information", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        info_items = [
            ("Platform", system.get('platform', 'Unknown')),
            ("System", system.get('system', 'Unknown')),
            ("Release", system.get('release', 'Unknown')),
            ("Version", system.get('version', 'Unknown')),
            ("Machine", system.get('machine', 'Unknown')),
            ("Processor", system.get('processor', 'Unknown')),
            ("Architecture", str(system.get('architecture', 'Unknown'))),
            ("Hostname", system.get('hostname', 'Unknown')),
            ("Python Version", system.get('python_version', 'Unknown'))
        ]
        
        for label, value in info_items:
            frame = ctk.CTkFrame(self.system_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text=f"{label}:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=str(value), anchor="w").pack(side="left", padx=10)
            
        # Boot time
        boot_time = self.system_info.get('boot_time', 0)
        if boot_time:
            boot_datetime = datetime.fromtimestamp(boot_time)
            uptime = datetime.now() - boot_datetime
            
            frame = ctk.CTkFrame(self.system_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text="Boot Time:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=boot_datetime.strftime("%Y-%m-%d %H:%M:%S"), anchor="w").pack(side="left", padx=10)
            
            frame = ctk.CTkFrame(self.system_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text="Uptime:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=str(uptime).split('.')[0], anchor="w").pack(side="left", padx=10)
            
    def _update_cpu_tab(self):
        """Update CPU tab"""
        # Clear existing widgets
        for widget in self.cpu_info_frame.winfo_children():
            widget.destroy()
            
        cpu = self.system_info.get('cpu', {})
        
        ctk.CTkLabel(self.cpu_info_frame, text="🔥 CPU Information", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # CPU information
        info_items = [
            ("Physical Cores", cpu.get('physical_cores', 0)),
            ("Logical Cores", cpu.get('logical_cores', 0)),
            ("Current Frequency", f"{cpu.get('current_frequency', 0):.2f} MHz"),
            ("Min Frequency", f"{cpu.get('min_frequency', 0):.2f} MHz"),
            ("Max Frequency", f"{cpu.get('max_frequency', 0):.2f} MHz"),
            ("Current Usage", f"{cpu.get('usage_percent', 0):.1f}%")
        ]
        
        for label, value in info_items:
            frame = ctk.CTkFrame(self.cpu_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text=f"{label}:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=str(value), anchor="w").pack(side="left", padx=10)
            
    def _update_memory_tab(self):
        """Update memory tab"""
        # Clear existing widgets
        for widget in self.memory_info_frame.winfo_children():
            widget.destroy()
            
        memory = self.system_info.get('memory', {})
        
        ctk.CTkLabel(self.memory_info_frame, text="💾 Memory Information", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Memory information
        info_items = [
            ("Total Memory", format_bytes(memory.get('total', 0))),
            ("Available Memory", format_bytes(memory.get('available', 0))),
            ("Used Memory", format_bytes(memory.get('used', 0))),
            ("Free Memory", format_bytes(memory.get('free', 0))),
            ("Usage Percentage", f"{memory.get('percent', 0):.1f}%")
        ]
        
        for label, value in info_items:
            frame = ctk.CTkFrame(self.memory_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text=f"{label}:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=str(value), anchor="w").pack(side="left", padx=10)
            
        # Memory usage bar
        usage_percent = memory.get('percent', 0)
        progress_frame = ctk.CTkFrame(self.memory_info_frame)
        progress_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(progress_frame, text="Memory Usage:").pack(side="left", padx=10)
        
        progress_bar = ctk.CTkProgressBar(progress_frame)
        progress_bar.pack(side="left", fill="x", expand=True, padx=10)
        progress_bar.set(usage_percent / 100)
        
        ctk.CTkLabel(progress_frame, text=f"{usage_percent:.1f}%").pack(side="right", padx=10)
        
    def _update_disk_tab(self):
        """Update disk tab"""
        # Clear existing items
        for item in self.disk_tree.get_children():
            self.disk_tree.delete(item)
            
        disks = self.system_info.get('disk', [])
        
        for disk in disks:
            self.disk_tree.insert("", "end", values=(
                disk.get('device', ''),
                disk.get('mountpoint', ''),
                disk.get('fstype', ''),
                format_bytes(disk.get('total', 0)),
                format_bytes(disk.get('used', 0)),
                format_bytes(disk.get('free', 0)),
                f"{disk.get('percent', 0):.1f}%"
            ))
            
    def _update_network_tab(self):
        """Update network tab"""
        # Clear existing widgets
        for widget in self.network_info_frame.winfo_children():
            widget.destroy()
            
        network = self.system_info.get('network', {})
        
        ctk.CTkLabel(self.network_info_frame, text="🌐 Network Information", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=10)
        
        # Network I/O
        io = network.get('io', {})
        ctk.CTkLabel(self.network_info_frame, text="Network I/O Statistics", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(20, 10))
        
        io_items = [
            ("Bytes Sent", format_bytes(io.get('bytes_sent', 0))),
            ("Bytes Received", format_bytes(io.get('bytes_recv', 0))),
            ("Packets Sent", f"{io.get('packets_sent', 0):,}"),
            ("Packets Received", f"{io.get('packets_recv', 0):,}")
        ]
        
        for label, value in io_items:
            frame = ctk.CTkFrame(self.network_info_frame)
            frame.pack(fill="x", padx=20, pady=5)
            
            ctk.CTkLabel(frame, text=f"{label}:", width=150, anchor="w").pack(side="left", padx=10)
            ctk.CTkLabel(frame, text=str(value), anchor="w").pack(side="left", padx=10)
            
        # Network interfaces
        interfaces = network.get('interfaces', {})
        if interfaces:
            ctk.CTkLabel(self.network_info_frame, text="Network Interfaces", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(20, 10))
            
            for interface_name, addrs in interfaces.items():
                ctk.CTkLabel(self.network_info_frame, text=f"📡 {interface_name}", font=ctk.CTkFont(size=12, weight="bold")).pack(pady=(10, 5))
                
                for addr in addrs:
                    frame = ctk.CTkFrame(self.network_info_frame)
                    frame.pack(fill="x", padx=40, pady=2)
                    
                    family = addr.get('family', '')
                    address = addr.get('address', '')
                    netmask = addr.get('netmask', '')
                    
                    addr_text = f"{family}: {address}"
                    if netmask:
                        addr_text += f" / {netmask}"
                        
                    ctk.CTkLabel(frame, text=addr_text, anchor="w").pack(side="left", padx=10)
                    
    def _export_info(self):
        """Export system information"""
        if not self.system_info:
            messagebox.showinfo("Export", "No data to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            title="Export System Information",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=os.path.expanduser("~")
        )
        
        if not file_path:
            return
            
        try:
            export_data = {
                'export_time': datetime.now().isoformat(),
                'system_info': self.system_info
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
                
            messagebox.showinfo("Export Successful", f"System information exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting system information:\n{str(e)}")

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
            
        app = SystemInfoApp(root)
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
        messagebox.showerror("System Information Tool", f"Startup error:\n{e}")

if __name__ == "__main__":
    run_tool()
