"""
System Health Monitor — Real-time system monitoring with process manager,
disk analysis, startup management, and configurable alerts.
"""

import os
import sys
import re
import json
import time
import queue
import threading
import subprocess
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Any

import tkinter as tk
from tkinter import ttk, messagebox

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False

try:
    import psutil
except ImportError:
    psutil = None

try:
    import winreg
except ImportError:
    winreg = None

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

TOOL_NAME = "System Health Monitor"
TOOL_DESCRIPTION = "Real-time CPU, RAM, disk, GPU monitoring with process manager and alerts"

_CNW = 0x08000000  # CREATE_NO_WINDOW

# Colors
C_GREEN  = "#00FF88"
C_YELLOW = "#FFD700"
C_RED    = "#FF4444"
C_CYAN   = "#00BFFF"
C_ORANGE = "#FFA500"
C_GRAY   = "#888888"
C_WHITE  = "#FFFFFF"
CARD_BG  = "#1e1e1e"
CANVAS_BG = "#1a1a1a"
TREE_BG  = "#2b2b2b"

# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def fmt_size(b: int) -> str:
    for u in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1024:
            return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.1f} PB"

def fmt_uptime(seconds: float) -> str:
    d = int(seconds // 86400)
    h = int((seconds % 86400) // 3600)
    m = int((seconds % 3600) // 60)
    if d > 0:
        return f"{d}d {h}h {m}m"
    return f"{h}h {m}m"

def color_pct(val: float, warn: float = 50, crit: float = 80) -> str:
    if val >= crit:
        return C_RED
    if val >= warn:
        return C_YELLOW
    return C_GREEN

def color_temp(val: Optional[float]) -> str:
    if val is None:
        return C_GRAY
    if val >= 80:
        return C_RED
    if val >= 65:
        return C_YELLOW
    return C_GREEN

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                            timeout=timeout, shell=False, creationflags=_CNW)
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:
        return 1, "", str(e)

def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

# ─────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────

@dataclass
class HealthSample:
    timestamp: float = 0.0
    cpu_percent: float = 0.0
    cpu_per_core: List[float] = field(default_factory=list)
    ram_used: int = 0
    ram_total: int = 0
    ram_percent: float = 0.0
    disk_usage: Dict[str, Dict] = field(default_factory=dict)
    disk_read_speed: float = 0.0  # bytes/sec
    disk_write_speed: float = 0.0
    net_down_speed: float = 0.0   # bytes/sec
    net_up_speed: float = 0.0
    gpu_temp: Optional[float] = None
    gpu_usage: Optional[float] = None
    gpu_name: Optional[str] = None
    cpu_temp: Optional[float] = None
    uptime_seconds: float = 0.0

@dataclass
class Alert:
    timestamp: str = ""
    level: str = "WARNING"   # WARNING | CRITICAL
    metric: str = ""
    message: str = ""
    value: float = 0.0
    threshold: float = 0.0

# ─────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────

class SystemHealthEngine:
    def __init__(self):
        self.samples: List[HealthSample] = []
        self.alerts: List[Alert] = []
        self.max_samples = 1800  # 30 min at 1s

        # GPU state
        self._gpu_available = True
        self._gpu_fail_count = 0
        self._gpu_name: Optional[str] = None

        # CPU temp state
        self._cpu_temp_method: Optional[str] = None  # "ohm", "wmi", None
        self._cpu_temp_tested = False

        # Delta tracking
        self._prev_disk_io: Optional[Any] = None
        self._prev_net_io: Optional[Any] = None
        self._prev_time: float = time.time()

        # Alert cooldowns
        self._alert_cooldown: Dict[str, float] = {}
        self._cooldown_sec = 60

        # Thresholds
        self.cpu_warn = 50
        self.cpu_crit = 80
        self.ram_warn = 70
        self.ram_crit = 90
        self.disk_warn_gb = 10
        self.gpu_temp_warn = 85
        self.gpu_temp_crit = 95
        self.cpu_temp_warn = 80
        self.cpu_temp_crit = 95

    # ── Sampling ──

    def collect_sample(self) -> HealthSample:
        now = time.time()
        dt = max(now - self._prev_time, 0.01)
        self._prev_time = now

        s = HealthSample(timestamp=now)

        # CPU
        s.cpu_percent = psutil.cpu_percent(interval=None)
        s.cpu_per_core = psutil.cpu_percent(percpu=True)

        # RAM
        mem = psutil.virtual_memory()
        s.ram_used = mem.used
        s.ram_total = mem.total
        s.ram_percent = mem.percent

        # Disk usage
        try:
            for part in psutil.disk_partitions():
                if 'cdrom' in part.opts.lower() or part.fstype == '':
                    continue
                try:
                    u = psutil.disk_usage(part.mountpoint)
                    s.disk_usage[part.mountpoint.rstrip('\\')] = {
                        "total": u.total, "used": u.used,
                        "free": u.free, "percent": u.percent,
                        "fstype": part.fstype
                    }
                except (PermissionError, OSError):
                    pass
        except Exception:
            pass

        # Disk I/O delta
        try:
            dio = psutil.disk_io_counters()
            if self._prev_disk_io and dio:
                s.disk_read_speed = (dio.read_bytes - self._prev_disk_io.read_bytes) / dt
                s.disk_write_speed = (dio.write_bytes - self._prev_disk_io.write_bytes) / dt
            self._prev_disk_io = dio
        except Exception:
            pass

        # Network I/O delta
        try:
            nio = psutil.net_io_counters()
            if self._prev_net_io and nio:
                s.net_down_speed = (nio.bytes_recv - self._prev_net_io.bytes_recv) / dt
                s.net_up_speed = (nio.bytes_sent - self._prev_net_io.bytes_sent) / dt
            self._prev_net_io = nio
        except Exception:
            pass

        # GPU
        gpu = self._get_gpu_info()
        s.gpu_temp, s.gpu_usage, s.gpu_name = gpu

        # CPU temp
        s.cpu_temp = self._get_cpu_temp()

        # Uptime
        try:
            s.uptime_seconds = now - psutil.boot_time()
        except Exception:
            pass

        # Store
        self.samples.append(s)
        if len(self.samples) > self.max_samples:
            self.samples = self.samples[-self.max_samples:]

        return s

    def _get_gpu_info(self) -> Tuple[Optional[float], Optional[float], Optional[str]]:
        if not self._gpu_available:
            return None, None, self._gpu_name
        try:
            rc, out, _ = safe_run([
                "nvidia-smi", "--query-gpu=temperature.gpu,utilization.gpu,name",
                "--format=csv,noheader,nounits"
            ], timeout=3)
            if rc == 0 and out.strip():
                parts = out.strip().split(", ")
                if len(parts) >= 3:
                    temp = float(parts[0])
                    usage = float(parts[1])
                    name = parts[2].strip()
                    self._gpu_name = name
                    self._gpu_fail_count = 0
                    return temp, usage, name
        except Exception:
            pass
        self._gpu_fail_count += 1
        if self._gpu_fail_count >= 3:
            self._gpu_available = False
        return None, None, self._gpu_name

    def _get_cpu_temp(self) -> Optional[float]:
        # Try cached method first
        if self._cpu_temp_tested:
            if self._cpu_temp_method == "ohm":
                return self._try_ohm_temp()
            elif self._cpu_temp_method == "wmi":
                return self._try_wmi_temp()
            return None

        # First call — test methods
        self._cpu_temp_tested = True

        val = self._try_ohm_temp()
        if val is not None:
            self._cpu_temp_method = "ohm"
            return val

        val = self._try_wmi_temp()
        if val is not None:
            self._cpu_temp_method = "wmi"
            return val

        self._cpu_temp_method = None
        return None

    def _try_ohm_temp(self) -> Optional[float]:
        """Try OpenHardwareMonitor / LibreHardwareMonitor WMI."""
        try:
            rc, out, _ = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-CimInstance -Namespace root/LibreHardwareMonitor -ClassName Sensor "
                "-Filter \"SensorType='Temperature' AND Name LIKE '%CPU Package%'\" "
                "-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Value; "
                "if(-not $?) { Get-CimInstance -Namespace root/OpenHardwareMonitor -ClassName Sensor "
                "-Filter \"SensorType='Temperature' AND Name LIKE '%CPU Package%'\" "
                "-ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Value }"
            ], timeout=5)
            if rc == 0 and out.strip():
                val = float(out.strip().splitlines()[0])
                if 0 < val < 150:
                    return val
        except Exception:
            pass
        return None

    def _try_wmi_temp(self) -> Optional[float]:
        """Try Windows WMI thermal zone."""
        try:
            rc, out, _ = safe_run([
                "powershell", "-NoProfile", "-Command",
                "(Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature "
                "-ErrorAction SilentlyContinue | Select-Object -First 1).CurrentTemperature"
            ], timeout=5)
            if rc == 0 and out.strip():
                raw = float(out.strip())
                # WMI returns temp in tenths of Kelvin
                celsius = (raw / 10.0) - 273.15
                if 0 < celsius < 150:
                    return round(celsius, 1)
        except Exception:
            pass
        return None

    # ── Alerts ──

    def check_alerts(self, s: HealthSample) -> List[Alert]:
        new_alerts = []
        now = time.time()

        checks = []
        # CPU
        if s.cpu_percent >= self.cpu_crit:
            checks.append(("CPU", "CRITICAL", s.cpu_percent, self.cpu_crit,
                           f"CPU at {s.cpu_percent:.0f}% (critical threshold: {self.cpu_crit}%)"))
        elif s.cpu_percent >= self.cpu_warn:
            checks.append(("CPU", "WARNING", s.cpu_percent, self.cpu_warn,
                           f"CPU at {s.cpu_percent:.0f}% (warning threshold: {self.cpu_warn}%)"))
        # RAM
        if s.ram_percent >= self.ram_crit:
            checks.append(("RAM", "CRITICAL", s.ram_percent, self.ram_crit,
                           f"RAM at {s.ram_percent:.0f}% ({fmt_size(s.ram_used)} / {fmt_size(s.ram_total)})"))
        elif s.ram_percent >= self.ram_warn:
            checks.append(("RAM", "WARNING", s.ram_percent, self.ram_warn,
                           f"RAM at {s.ram_percent:.0f}% ({fmt_size(s.ram_used)} / {fmt_size(s.ram_total)})"))
        # Disk
        for drive, info in s.disk_usage.items():
            free_gb = info["free"] / (1024 ** 3)
            if free_gb < self.disk_warn_gb:
                checks.append((f"DISK_{drive}", "WARNING", free_gb, self.disk_warn_gb,
                               f"{drive} only {free_gb:.1f} GB free"))
        # GPU temp
        if s.gpu_temp is not None:
            if s.gpu_temp >= self.gpu_temp_crit:
                checks.append(("GPU_TEMP", "CRITICAL", s.gpu_temp, self.gpu_temp_crit,
                               f"GPU temp {s.gpu_temp:.0f}°C (critical: {self.gpu_temp_crit}°C)"))
            elif s.gpu_temp >= self.gpu_temp_warn:
                checks.append(("GPU_TEMP", "WARNING", s.gpu_temp, self.gpu_temp_warn,
                               f"GPU temp {s.gpu_temp:.0f}°C (warning: {self.gpu_temp_warn}°C)"))
        # CPU temp
        if s.cpu_temp is not None:
            if s.cpu_temp >= self.cpu_temp_crit:
                checks.append(("CPU_TEMP", "CRITICAL", s.cpu_temp, self.cpu_temp_crit,
                               f"CPU temp {s.cpu_temp:.0f}°C (critical: {self.cpu_temp_crit}°C)"))
            elif s.cpu_temp >= self.cpu_temp_warn:
                checks.append(("CPU_TEMP", "WARNING", s.cpu_temp, self.cpu_temp_warn,
                               f"CPU temp {s.cpu_temp:.0f}°C (warning: {self.cpu_temp_warn}°C)"))

        for metric, level, value, thresh, msg in checks:
            last = self._alert_cooldown.get(metric, 0)
            if now - last < self._cooldown_sec:
                continue
            self._alert_cooldown[metric] = now
            a = Alert(timestamp=now_ts(), level=level, metric=metric,
                      message=msg, value=value, threshold=thresh)
            new_alerts.append(a)
            self.alerts.append(a)

        return new_alerts

    # ── Processes ──

    def get_processes(self) -> List[Dict]:
        procs = []
        cpu_count = psutil.cpu_count() or 1
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info',
                                       'memory_percent', 'status', 'exe']):
            try:
                info = p.info
                pid = info['pid']
                # Skip System Idle Process (PID 0) — shows misleading 2400% on multi-core
                if pid == 0:
                    continue
                mi = info.get('memory_info')
                ram_mb = mi.rss / (1024 * 1024) if mi else 0
                # Normalize CPU% to 0-100 range (psutil reports sum across all cores)
                raw_cpu = info.get('cpu_percent', 0) or 0
                norm_cpu = min(raw_cpu / cpu_count * 100, 100) if raw_cpu > 100 else raw_cpu
                procs.append({
                    "pid": pid,
                    "name": info.get('name', '?'),
                    "cpu": round(norm_cpu, 1),
                    "ram_mb": ram_mb,
                    "ram_pct": info.get('memory_percent', 0) or 0,
                    "status": info.get('status', '?'),
                    "path": info.get('exe') or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return procs

    # ── Startup ──

    def get_startup_items(self) -> List[Dict]:
        items = []
        if not winreg:
            return items

        # Load disabled items
        disabled = self._load_disabled_startup()

        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
        ]
        for hive, path, label in run_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append({
                            "name": name, "command": value, "source": label,
                            "enabled": True, "hive": hive, "reg_path": path
                        })
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, PermissionError):
                pass

        # Add disabled items
        for name, info in disabled.items():
            items.append({
                "name": name, "command": info.get("command", ""),
                "source": info.get("source", ""), "enabled": False,
                "hive": None, "reg_path": info.get("reg_path", "")
            })

        # Startup folder
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            sd = os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.isdir(sd):
                for f in os.listdir(sd):
                    items.append({
                        "name": f, "command": os.path.join(sd, f),
                        "source": "Startup Folder", "enabled": True,
                        "hive": None, "reg_path": ""
                    })

        return items

    def toggle_startup(self, item: Dict, enable: bool) -> str:
        """Toggle a startup item. Returns status message."""
        if item["source"] == "Startup Folder":
            return "Cannot toggle startup folder items from here."
        if "HKLM" in item.get("source", ""):
            return "Cannot modify HKLM entries (requires admin + risky)."

        disabled = self._load_disabled_startup()
        name = item["name"]

        if enable:
            # Re-enable: restore from disabled list
            if name not in disabled:
                return f"{name} is already enabled or not found."
            info = disabled.pop(name)
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, info["command"])
                winreg.CloseKey(key)
                self._save_disabled_startup(disabled)
                return f"Enabled: {name}"
            except Exception as e:
                return f"Failed to enable: {e}"
        else:
            # Disable: remove from registry, store in JSON
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE | winreg.KEY_READ)
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                except FileNotFoundError:
                    winreg.CloseKey(key)
                    return f"{name} not found in registry."
                winreg.DeleteValue(key, name)
                winreg.CloseKey(key)
                disabled[name] = {"command": value, "source": item["source"],
                                  "reg_path": item.get("reg_path", "")}
                self._save_disabled_startup(disabled)
                return f"Disabled: {name}"
            except Exception as e:
                return f"Failed to disable: {e}"

    def _disabled_startup_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "system_health_disabled_startup.json")

    def _load_disabled_startup(self) -> Dict:
        try:
            with open(self._disabled_startup_path(), "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_disabled_startup(self, data: Dict):
        with open(self._disabled_startup_path(), "w") as f:
            json.dump(data, f, indent=2)

    # ── Disk helpers ──

    def scan_large_files(self, paths: List[str], min_mb: int = 100,
                         callback=None) -> List[Dict]:
        """Scan directories for large files. callback(current_path) for progress."""
        min_bytes = min_mb * 1024 * 1024
        results = []
        for base in paths:
            if not os.path.isdir(base):
                continue
            try:
                for root, dirs, files in os.walk(base):
                    if callback:
                        callback(root)
                    # Skip system/hidden dirs
                    dirs[:] = [d for d in dirs if not d.startswith('.') and
                               d.lower() not in ('$recycle.bin', 'system volume information')]
                    for f in files:
                        try:
                            fp = os.path.join(root, f)
                            sz = os.path.getsize(fp)
                            if sz >= min_bytes:
                                results.append({
                                    "path": fp, "size": sz,
                                    "modified": os.path.getmtime(fp)
                                })
                        except (OSError, PermissionError):
                            continue
            except (OSError, PermissionError):
                continue
        results.sort(key=lambda x: x["size"], reverse=True)
        return results[:200]

    def get_temp_sizes(self) -> List[Dict]:
        """Get sizes of temporary file locations."""
        locations = []
        temp = os.environ.get("TEMP", "")
        if temp and os.path.isdir(temp):
            locations.append(("Windows Temp (%TEMP%)", temp))

        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            chrome_cache = os.path.join(local, r"Google\Chrome\User Data\Default\Cache")
            if os.path.isdir(chrome_cache):
                locations.append(("Chrome Cache", chrome_cache))
            edge_cache = os.path.join(local, r"Microsoft\Edge\User Data\Default\Cache")
            if os.path.isdir(edge_cache):
                locations.append(("Edge Cache", edge_cache))

        prefetch = r"C:\Windows\Prefetch"
        if os.path.isdir(prefetch):
            locations.append(("Windows Prefetch", prefetch))

        results = []
        for name, path in locations:
            try:
                total = 0
                for root, dirs, files in os.walk(path):
                    for f in files:
                        try:
                            total += os.path.getsize(os.path.join(root, f))
                        except (OSError, PermissionError):
                            pass
                results.append({"name": name, "path": path, "size": total})
            except (OSError, PermissionError):
                results.append({"name": name, "path": path, "size": 0})
        return results

    # ── System info ──

    def get_system_info(self) -> Dict:
        info = {}
        try:
            info["cpu_model"] = platform.processor() or "Unknown"
            info["cpu_cores_physical"] = psutil.cpu_count(logical=False)
            info["cpu_cores_logical"] = psutil.cpu_count(logical=True)
            freq = psutil.cpu_freq()
            info["cpu_freq"] = f"{freq.current:.0f} MHz" if freq else "N/A"
            info["ram_total"] = fmt_size(psutil.virtual_memory().total)
            info["gpu_name"] = self._gpu_name or "N/A"
            info["os_version"] = f"{platform.system()} {platform.release()} ({platform.version()})"
            info["boot_time"] = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        return info


# ─────────────────────────────────────────────
# App (UI)
# ─────────────────────────────────────────────

class App(ctk.CTkFrame if HAS_CTK else tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title(TOOL_NAME)
        parent.geometry("1340x800")
        parent.minsize(900, 600)

        self.running = True
        self.engine = SystemHealthEngine()

        # Queues
        self.work_q: queue.Queue = queue.Queue()
        self.result_q: queue.Queue = queue.Queue()

        # Chart data
        self._chart_window = 300  # seconds
        self._refresh_ms = 2000
        self._tick_counter = 0

        # Process sorting
        self._proc_sort_col = "ram_mb"
        self._proc_sort_rev = True
        self._proc_filter = ""

        # Build UI
        self._apply_tree_style()
        self._build_ui()

        # Start worker
        t = threading.Thread(target=self._worker_loop, daemon=True)
        t.start()

        # Prime CPU percent (first call always returns 0)
        psutil.cpu_percent(interval=None)

        # Schedule
        self.after(500, self._tick)
        self.after(100, self._process_queue)

    # ── Tree style (dark) ──

    def _apply_tree_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
            background=TREE_BG, foreground=C_WHITE, fieldbackground=TREE_BG,
            font=("Segoe UI", 9), rowheight=22, borderwidth=0)
        style.configure("Treeview.Heading",
            background="#333333", foreground=C_WHITE,
            font=("Segoe UI", 9, "bold"), borderwidth=1, relief="flat")
        style.map("Treeview",
            background=[('selected', '#1f538d')],
            foreground=[('selected', C_WHITE)])
        style.map("Treeview.Heading",
            background=[('active', '#444444')])

    # ── Build UI ──

    def _build_ui(self):
        self.pack(fill="both", expand=True)

        # Notebook
        self.nb = ctk.CTkTabview(self)
        self.nb.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_overview = self.nb.add("Overview")
        self.tab_processes = self.nb.add("Processes")
        self.tab_disk = self.nb.add("Disk")
        self.tab_startup = self.nb.add("Startup")
        self.tab_alerts = self.nb.add("Alerts")
        self.tab_settings = self.nb.add("Settings")

        self._build_overview()
        self._build_processes()
        self._build_disk()
        self._build_startup()
        self._build_alerts()
        self._build_settings()

    # ── Overview Tab ──

    def _build_overview(self):
        f = self.tab_overview

        # Scrollable wrapper
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True)

        # Metric cards
        dash = ctk.CTkFrame(scroll, fg_color="transparent")
        dash.pack(fill="x", padx=4, pady=(4, 0))

        cards = [
            ("CPU", "cpu", C_CYAN),
            ("CPU Temp", "cpu_temp", C_ORANGE),
            ("RAM Used", "ram_used", C_YELLOW),
            ("RAM %", "ram_pct", C_YELLOW),
            ("Disk C:", "disk_c", "#FF6347"),
            ("GPU Temp", "gpu_temp", C_ORANGE),
            ("Net Down", "net_down", C_GREEN),
            ("Uptime", "uptime", C_GRAY),
        ]
        self.dash_values: Dict[str, ctk.CTkLabel] = {}
        for i, (title, key, color) in enumerate(cards):
            card = ctk.CTkFrame(dash, fg_color=CARD_BG, corner_radius=8)
            card.grid(row=0, column=i, padx=3, pady=3, sticky="nsew")
            dash.columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=title, font=("Segoe UI", 9),
                         text_color=C_GRAY).pack(pady=(6, 0))
            lbl = ctk.CTkLabel(card, text="--", font=("Segoe UI", 20, "bold"),
                               text_color=color)
            lbl.pack(pady=(0, 6))
            self.dash_values[key] = lbl

        # Live chart
        chart_frame = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        chart_frame.pack(fill="x", padx=4, pady=4)
        ctk.CTkLabel(chart_frame, text="Live — Last 5 Minutes",
                     font=("Segoe UI", 10), text_color=C_GRAY).pack(anchor="w", padx=10, pady=(4, 0))
        self.live_chart = tk.Canvas(chart_frame, height=200, bg=CANVAS_BG, highlightthickness=0)
        self.live_chart.pack(fill="x", padx=8, pady=(2, 8))
        self._chart_width = 800
        self.live_chart.bind("<Configure>", lambda e: setattr(self, '_chart_width', e.width))

        # System info grid
        info_frame = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        info_frame.pack(fill="x", padx=4, pady=(0, 4))

        self.sys_info_labels: Dict[str, ctk.CTkLabel] = {}
        info_items = [
            ("CPU Model", "cpu_model"), ("Physical Cores", "cpu_cores_physical"),
            ("Logical Cores", "cpu_cores_logical"), ("CPU Frequency", "cpu_freq"),
            ("RAM Total", "ram_total"), ("GPU", "gpu_name"),
            ("OS", "os_version"), ("Boot Time", "boot_time"),
        ]
        for idx, (label, key) in enumerate(info_items):
            row = idx // 2
            col = (idx % 2) * 2
            ctk.CTkLabel(info_frame, text=f"{label}:", font=("Segoe UI", 10, "bold"),
                         text_color=C_GRAY).grid(row=row, column=col, padx=(10, 4),
                                                  pady=2, sticky="w")
            val = ctk.CTkLabel(info_frame, text="--", font=("Segoe UI", 10),
                               text_color=C_WHITE)
            val.grid(row=row, column=col + 1, padx=(0, 20), pady=2, sticky="w")
            self.sys_info_labels[key] = val
            info_frame.columnconfigure(col + 1, weight=1)

        # Fill system info immediately
        self.after(200, self._fill_system_info)

    def _fill_system_info(self):
        info = self.engine.get_system_info()
        for key, lbl in self.sys_info_labels.items():
            val = info.get(key, "N/A")
            lbl.configure(text=str(val))

    # ── Processes Tab ──

    def _build_processes(self):
        f = self.tab_processes

        # Top bar
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(4, 2))

        self._proc_search = ctk.CTkEntry(top, placeholder_text="Filter by name or PID...", width=250)
        self._proc_search.pack(side="left", padx=(0, 8))
        self._proc_search.bind("<KeyRelease>", lambda e: self._apply_proc_filter())

        self._proc_count_lbl = ctk.CTkLabel(top, text="0 processes", font=("Segoe UI", 10),
                                             text_color=C_GRAY)
        self._proc_count_lbl.pack(side="left", padx=8)

        ctk.CTkButton(top, text="Refresh", width=80, command=self._request_processes).pack(side="right", padx=4)
        ctk.CTkButton(top, text="Kill Selected", width=100, fg_color="#992222",
                      hover_color="#cc3333", command=self._kill_selected_process).pack(side="right", padx=4)

        # Treeview
        cols = ("pid", "name", "cpu", "ram_mb", "ram_pct", "status", "path")
        headers = ("PID", "Name", "CPU %", "RAM MB", "RAM %", "Status", "Path")
        widths = (60, 180, 65, 85, 65, 75, 300)

        tree_frame = ctk.CTkFrame(f)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)

        self.proc_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for col, hdr, w in zip(cols, headers, widths):
            self.proc_tree.heading(col, text=hdr,
                command=lambda c=col: self._sort_proc_tree(c))
            stretch = col == "path"
            self.proc_tree.column(col, width=w, minwidth=40, stretch=stretch)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=vsb.set)
        self.proc_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Context menu
        self._proc_menu = tk.Menu(self.proc_tree, tearoff=0, bg="#333", fg="white",
                                   activebackground="#555", activeforeground="white")
        self._proc_menu.add_command(label="Kill Process", command=self._kill_selected_process)
        self._proc_menu.add_command(label="Open File Location", command=self._open_proc_location)
        self._proc_menu.add_command(label="Copy PID", command=self._copy_proc_pid)
        self.proc_tree.bind("<Button-3>", self._show_proc_menu)

        # Store full process list for filtering
        self._all_procs: List[Dict] = []

    def _show_proc_menu(self, event):
        iid = self.proc_tree.identify_row(event.y)
        if iid:
            self.proc_tree.selection_set(iid)
            self._proc_menu.tk_popup(event.x_root, event.y_root)

    def _sort_proc_tree(self, col: str):
        if self._proc_sort_col == col:
            self._proc_sort_rev = not self._proc_sort_rev
        else:
            self._proc_sort_col = col
            self._proc_sort_rev = col in ("cpu", "ram_mb", "ram_pct")  # default desc for numeric
        self._populate_proc_tree(self._all_procs)

    def _apply_proc_filter(self):
        self._proc_filter = self._proc_search.get().lower()
        self._populate_proc_tree(self._all_procs)

    def _populate_proc_tree(self, procs: List[Dict]):
        self._all_procs = procs
        self.proc_tree.delete(*self.proc_tree.get_children())

        # Filter
        filt = self._proc_filter
        filtered = procs
        if filt:
            filtered = [p for p in procs if filt in p["name"].lower() or filt in str(p["pid"])]

        # Sort
        col = self._proc_sort_col
        def sort_key(p):
            val = p.get(col, "")
            if col in ("cpu", "ram_mb", "ram_pct", "pid"):
                try:
                    return float(val)
                except (ValueError, TypeError):
                    return 0
            return str(val).lower()

        filtered.sort(key=sort_key, reverse=self._proc_sort_rev)

        for p in filtered[:500]:  # cap display
            self.proc_tree.insert("", "end", values=(
                p["pid"], p["name"],
                f"{p['cpu']:.1f}", f"{p['ram_mb']:.0f}",
                f"{p['ram_pct']:.1f}", p["status"],
                p["path"]
            ))
        self._proc_count_lbl.configure(text=f"{len(filtered)} processes")

    def _kill_selected_process(self):
        sel = self.proc_tree.selection()
        if not sel:
            return
        vals = self.proc_tree.item(sel[0], "values")
        pid = int(vals[0])
        name = vals[1]
        if not messagebox.askyesno("Kill Process",
                f"Kill {name} (PID {pid})?\nThis may cause data loss."):
            return
        try:
            psutil.Process(pid).kill()
            messagebox.showinfo("Process Killed", f"{name} (PID {pid}) has been killed.")
            self._request_processes()
        except Exception as e:
            messagebox.showerror("Error", f"Could not kill process:\n{e}")

    def _open_proc_location(self):
        sel = self.proc_tree.selection()
        if not sel:
            return
        path = self.proc_tree.item(sel[0], "values")[6]
        if path and os.path.exists(path):
            subprocess.Popen(["explorer", "/select,", path], creationflags=_CNW)
        else:
            messagebox.showinfo("Info", "Path not available for this process.")

    def _copy_proc_pid(self):
        sel = self.proc_tree.selection()
        if not sel:
            return
        pid = self.proc_tree.item(sel[0], "values")[0]
        self.clipboard_clear()
        self.clipboard_append(str(pid))

    def _request_processes(self):
        self.work_q.put_nowait(("processes",))

    # ── Disk Tab ──

    def _build_disk(self):
        f = self.tab_disk
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Drive bars container
        self.disk_drives_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        self.disk_drives_frame.pack(fill="x", pady=(0, 4))
        self.disk_bars: Dict[str, Dict] = {}

        # Disk I/O card
        io_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        io_card.pack(fill="x", pady=4)
        ctk.CTkLabel(io_card, text="Disk I/O", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        io_row = ctk.CTkFrame(io_card, fg_color="transparent")
        io_row.pack(fill="x", padx=10, pady=(0, 8))
        self.disk_read_lbl = ctk.CTkLabel(io_row, text="Read: --", font=("Segoe UI", 10))
        self.disk_read_lbl.pack(side="left", padx=(0, 20))
        self.disk_write_lbl = ctk.CTkLabel(io_row, text="Write: --", font=("Segoe UI", 10))
        self.disk_write_lbl.pack(side="left")

        # Large files section
        lf_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        lf_card.pack(fill="x", pady=4)
        lf_top = ctk.CTkFrame(lf_card, fg_color="transparent")
        lf_top.pack(fill="x", padx=10, pady=(6, 4))
        ctk.CTkLabel(lf_top, text="Large Files Finder", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(side="left")
        self._lf_status = ctk.CTkLabel(lf_top, text="", font=("Segoe UI", 9),
                                        text_color=C_GRAY)
        self._lf_status.pack(side="left", padx=10)
        ctk.CTkButton(lf_top, text="Scan", width=70,
                      command=self._start_large_file_scan).pack(side="right")

        lf_tree_frame = ctk.CTkFrame(lf_card, fg_color="transparent")
        lf_tree_frame.pack(fill="x", padx=10, pady=(0, 8))
        self.lf_tree = ttk.Treeview(lf_tree_frame, columns=("path", "size", "modified"),
                                     show="headings", height=8)
        self.lf_tree.heading("path", text="Path")
        self.lf_tree.heading("size", text="Size")
        self.lf_tree.heading("modified", text="Modified")
        self.lf_tree.column("path", width=500, stretch=True)
        self.lf_tree.column("size", width=90, stretch=False)
        self.lf_tree.column("modified", width=130, stretch=False)
        self.lf_tree.pack(fill="x")

        # Temp files section
        temp_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        temp_card.pack(fill="x", pady=4)
        ctk.CTkLabel(temp_card, text="Temporary Files", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 0))
        self.temp_frame = ctk.CTkFrame(temp_card, fg_color="transparent")
        self.temp_frame.pack(fill="x", padx=10, pady=(0, 8))
        self._temp_labels: List[ctk.CTkLabel] = []

        # Load temp sizes on tab open
        self.after(1000, self._load_temp_sizes)

    def _update_drive_bars(self, disk_usage: Dict):
        # Create/update bars for each drive
        for drive, info in disk_usage.items():
            if drive not in self.disk_bars:
                card = ctk.CTkFrame(self.disk_drives_frame, fg_color=CARD_BG, corner_radius=8)
                card.pack(fill="x", pady=2)
                top_row = ctk.CTkFrame(card, fg_color="transparent")
                top_row.pack(fill="x", padx=10, pady=(6, 2))
                drive_lbl = ctk.CTkLabel(top_row, text=f"{drive}\\",
                    font=("Segoe UI", 11, "bold"), text_color=C_WHITE)
                drive_lbl.pack(side="left")
                info_lbl = ctk.CTkLabel(top_row, text="", font=("Segoe UI", 9),
                                         text_color=C_GRAY)
                info_lbl.pack(side="right")
                bar = ctk.CTkProgressBar(card, height=18, corner_radius=4)
                bar.pack(fill="x", padx=10, pady=(0, 8))
                self.disk_bars[drive] = {"bar": bar, "info_lbl": info_lbl}

            entry = self.disk_bars[drive]
            pct = info["percent"] / 100.0
            entry["bar"].set(pct)
            if info["percent"] >= 90:
                entry["bar"].configure(progress_color=C_RED)
            elif info["percent"] >= 70:
                entry["bar"].configure(progress_color=C_YELLOW)
            else:
                entry["bar"].configure(progress_color=C_GREEN)
            entry["info_lbl"].configure(
                text=f"{fmt_size(info['used'])} / {fmt_size(info['total'])} ({info['percent']:.0f}%) — {fmt_size(info['free'])} free")

    def _start_large_file_scan(self):
        self._lf_status.configure(text="Scanning...")
        user = os.path.expanduser("~")
        paths = [
            os.path.join(user, "Desktop"),
            os.path.join(user, "Documents"),
            os.path.join(user, "Downloads"),
            os.path.join(user, "Videos"),
        ]
        self.work_q.put_nowait(("large_files", paths, 100))

    def _load_temp_sizes(self):
        self.work_q.put_nowait(("temp_sizes",))

    # ── Startup Tab ──

    def _build_startup(self):
        f = self.tab_startup

        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(4, 2))

        ctk.CTkButton(top, text="Refresh", width=80,
                      command=self._request_startup).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Enable Selected", width=120,
                      fg_color="#226622", hover_color="#338833",
                      command=lambda: self._toggle_startup_sel(True)).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Disable Selected", width=120,
                      fg_color="#992222", hover_color="#cc3333",
                      command=lambda: self._toggle_startup_sel(False)).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Open Location", width=110,
                      command=self._open_startup_location).pack(side="left", padx=4)

        tree_frame = ctk.CTkFrame(f)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("name", "command", "source", "status")
        headers = ("Name", "Command", "Source", "Status")
        widths = (180, 400, 100, 80)

        self.startup_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse")
        for col, hdr, w in zip(cols, headers, widths):
            self.startup_tree.heading(col, text=hdr)
            self.startup_tree.column(col, width=w, stretch=(col == "command"))
        self.startup_tree.tag_configure("disabled", foreground="#666666")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.startup_tree.yview)
        self.startup_tree.configure(yscrollcommand=vsb.set)
        self.startup_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._startup_items: List[Dict] = []
        self.after(800, self._request_startup)

    def _request_startup(self):
        self.work_q.put_nowait(("startup",))

    def _populate_startup(self, items: List[Dict]):
        self._startup_items = items
        self.startup_tree.delete(*self.startup_tree.get_children())
        for item in items:
            status = "Enabled" if item["enabled"] else "Disabled"
            tags = () if item["enabled"] else ("disabled",)
            self.startup_tree.insert("", "end", values=(
                item["name"], item["command"][:200], item["source"], status
            ), tags=tags)

    def _toggle_startup_sel(self, enable: bool):
        sel = self.startup_tree.selection()
        if not sel:
            return
        idx = self.startup_tree.index(sel[0])
        if idx >= len(self._startup_items):
            return
        item = self._startup_items[idx]
        action = "enable" if enable else "disable"
        if not messagebox.askyesno("Confirm",
                f"Are you sure you want to {action} '{item['name']}'?"):
            return
        msg = self.engine.toggle_startup(item, enable)
        messagebox.showinfo("Startup", msg)
        self._request_startup()

    def _open_startup_location(self):
        sel = self.startup_tree.selection()
        if not sel:
            return
        idx = self.startup_tree.index(sel[0])
        if idx >= len(self._startup_items):
            return
        cmd = self._startup_items[idx]["command"]
        path = cmd.strip('"').split('"')[0].strip()
        if os.path.exists(path):
            subprocess.Popen(["explorer", "/select,", path], creationflags=_CNW)
        else:
            messagebox.showinfo("Info", f"Path not found: {path}")

    # ── Alerts Tab ──

    def _build_alerts(self):
        f = self.tab_alerts
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Active alerts
        self.active_alert_frame = ctk.CTkFrame(scroll, fg_color="#331111", corner_radius=8)
        self.active_alert_frame.pack(fill="x", pady=(0, 4))
        self.active_alert_lbl = ctk.CTkLabel(self.active_alert_frame,
            text="No active alerts", font=("Segoe UI", 11, "bold"),
            text_color=C_GREEN)
        self.active_alert_lbl.pack(padx=10, pady=8)

        # Threshold config
        thresh_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        thresh_card.pack(fill="x", pady=4)
        ctk.CTkLabel(thresh_card, text="Alert Thresholds", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 4))

        thresh_grid = ctk.CTkFrame(thresh_card, fg_color="transparent")
        thresh_grid.pack(fill="x", padx=10, pady=(0, 8))

        self._thresh_vars = {}
        thresholds = [
            ("CPU Warning %", "cpu_warn", 50, 0, 100),
            ("CPU Critical %", "cpu_crit", 80, 0, 100),
            ("RAM Warning %", "ram_warn", 70, 0, 100),
            ("RAM Critical %", "ram_crit", 90, 0, 100),
            ("Disk Free Warning (GB)", "disk_warn_gb", 10, 1, 100),
            ("GPU Temp Warning °C", "gpu_temp_warn", 85, 40, 110),
            ("CPU Temp Warning °C", "cpu_temp_warn", 80, 40, 110),
        ]
        for idx, (label, key, default, mn, mx) in enumerate(thresholds):
            row = idx // 2
            col = (idx % 2) * 3
            ctk.CTkLabel(thresh_grid, text=label, font=("Segoe UI", 9),
                         text_color=C_GRAY).grid(row=row, column=col, padx=4, pady=2, sticky="w")
            var = tk.IntVar(value=default)
            spin = tk.Spinbox(thresh_grid, from_=mn, to=mx, textvariable=var, width=5,
                              bg="#333", fg="white", insertbackground="white",
                              buttonbackground="#444", font=("Segoe UI", 9))
            spin.grid(row=row, column=col + 1, padx=4, pady=2)
            self._thresh_vars[key] = var
            thresh_grid.columnconfigure(col + 2, weight=1)

        ctk.CTkButton(thresh_card, text="Apply Thresholds", width=130,
                      command=self._apply_thresholds).pack(padx=10, pady=(0, 8))

        # Alert history
        hist_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        hist_card.pack(fill="x", pady=4)
        hist_top = ctk.CTkFrame(hist_card, fg_color="transparent")
        hist_top.pack(fill="x", padx=10, pady=(6, 4))
        ctk.CTkLabel(hist_top, text="Alert History", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(side="left")
        ctk.CTkButton(hist_top, text="Clear", width=60,
                      command=self._clear_alerts).pack(side="right")

        self.alert_tree = ttk.Treeview(hist_card, columns=("time", "level", "metric", "message"),
                                        show="headings", height=10)
        self.alert_tree.heading("time", text="Time")
        self.alert_tree.heading("level", text="Level")
        self.alert_tree.heading("metric", text="Metric")
        self.alert_tree.heading("message", text="Message")
        self.alert_tree.column("time", width=140, stretch=False)
        self.alert_tree.column("level", width=70, stretch=False)
        self.alert_tree.column("metric", width=80, stretch=False)
        self.alert_tree.column("message", width=400, stretch=True)
        self.alert_tree.tag_configure("CRITICAL", foreground=C_RED)
        self.alert_tree.tag_configure("WARNING", foreground=C_ORANGE)
        self.alert_tree.pack(fill="x", padx=10, pady=(0, 8))

    def _apply_thresholds(self):
        for key, var in self._thresh_vars.items():
            setattr(self.engine, key, var.get())
        messagebox.showinfo("Thresholds", "Alert thresholds updated.")

    def _clear_alerts(self):
        self.engine.alerts.clear()
        self.alert_tree.delete(*self.alert_tree.get_children())

    # ── Settings Tab ──

    def _build_settings(self):
        f = self.tab_settings
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Monitoring settings
        mon_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        mon_card.pack(fill="x", pady=4)
        ctk.CTkLabel(mon_card, text="Monitoring Settings", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 4))

        row1 = ctk.CTkFrame(mon_card, fg_color="transparent")
        row1.pack(fill="x", padx=10, pady=(0, 4))
        ctk.CTkLabel(row1, text="Refresh interval:", font=("Segoe UI", 10)).pack(side="left")
        self._interval_var = tk.IntVar(value=2)
        self._interval_lbl = ctk.CTkLabel(row1, text="2s", font=("Segoe UI", 10, "bold"),
                                           text_color=C_CYAN)
        self._interval_lbl.pack(side="right", padx=10)
        interval_slider = ctk.CTkSlider(row1, from_=1, to=10, number_of_steps=9,
            variable=self._interval_var,
            command=lambda v: (self._interval_lbl.configure(text=f"{int(v)}s"),
                               setattr(self, '_refresh_ms', int(v) * 1000)))
        interval_slider.pack(side="right", padx=10, fill="x", expand=True)

        # Chart settings
        chart_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        chart_card.pack(fill="x", pady=4)
        ctk.CTkLabel(chart_card, text="Chart Settings", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 4))

        chart_row = ctk.CTkFrame(chart_card, fg_color="transparent")
        chart_row.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(chart_row, text="Time window:", font=("Segoe UI", 10)).pack(side="left")
        chart_btns = ctk.CTkFrame(chart_row, fg_color="transparent")
        chart_btns.pack(side="left", padx=10)
        for sec, label in [(60, "1 min"), (300, "5 min"), (600, "10 min"), (1800, "30 min")]:
            ctk.CTkButton(chart_btns, text=label, width=60,
                command=lambda s=sec: setattr(self, '_chart_window', s)).pack(side="left", padx=2)

        # GPU settings
        gpu_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        gpu_card.pack(fill="x", pady=4)
        ctk.CTkLabel(gpu_card, text="GPU Monitoring", font=("Segoe UI", 11, "bold"),
                     text_color=C_WHITE).pack(anchor="w", padx=10, pady=(6, 4))
        self._gpu_enabled_var = tk.BooleanVar(value=True)
        ctk.CTkCheckBox(gpu_card, text="Enable nvidia-smi polling",
            variable=self._gpu_enabled_var,
            command=lambda: setattr(self.engine, '_gpu_available', self._gpu_enabled_var.get())
        ).pack(padx=10, pady=(0, 8), anchor="w")

    # ── Worker thread ──

    def _worker_loop(self):
        while self.running:
            try:
                job = self.work_q.get(timeout=0.3)
            except queue.Empty:
                continue
            try:
                if job[0] == "sample":
                    sample = self.engine.collect_sample()
                    alerts = self.engine.check_alerts(sample)
                    self.result_q.put(("sample", sample, alerts))
                elif job[0] == "processes":
                    procs = self.engine.get_processes()
                    self.result_q.put(("processes", procs))
                elif job[0] == "large_files":
                    files = self.engine.scan_large_files(job[1], job[2])
                    self.result_q.put(("large_files", files))
                elif job[0] == "temp_sizes":
                    sizes = self.engine.get_temp_sizes()
                    self.result_q.put(("temp_sizes", sizes))
                elif job[0] == "startup":
                    items = self.engine.get_startup_items()
                    self.result_q.put(("startup", items))
            except Exception:
                pass

    def _tick(self):
        if not self.running:
            return
        self.work_q.put_nowait(("sample",))
        self._tick_counter += 1
        # Auto-refresh processes every 3rd tick when tab is visible
        if self._tick_counter % 3 == 0:
            try:
                if self.nb.get() == "Processes":
                    self.work_q.put_nowait(("processes",))
            except Exception:
                pass
        self.after(self._refresh_ms, self._tick)

    def _process_queue(self):
        try:
            while True:
                try:
                    msg = self.result_q.get_nowait()
                except queue.Empty:
                    break
                if msg[0] == "sample":
                    self._on_sample(msg[1], msg[2])
                elif msg[0] == "processes":
                    self._populate_proc_tree(msg[1])
                elif msg[0] == "large_files":
                    self._on_large_files(msg[1])
                elif msg[0] == "temp_sizes":
                    self._on_temp_sizes(msg[1])
                elif msg[0] == "startup":
                    self._populate_startup(msg[1])
        except Exception:
            pass
        if self.running:
            self.after(100, self._process_queue)

    # ── Sample handler ──

    def _on_sample(self, s: HealthSample, alerts: List[Alert]):
        # Update dashboard cards
        self.dash_values["cpu"].configure(
            text=f"{s.cpu_percent:.0f}%",
            text_color=color_pct(s.cpu_percent))
        self.dash_values["cpu_temp"].configure(
            text=f"{s.cpu_temp:.0f}°C" if s.cpu_temp is not None else "N/A",
            text_color=color_temp(s.cpu_temp))
        self.dash_values["ram_used"].configure(
            text=f"{fmt_size(s.ram_used)}")
        self.dash_values["ram_pct"].configure(
            text=f"{s.ram_percent:.0f}%",
            text_color=color_pct(s.ram_percent, warn=70, crit=90))
        # Disk C:
        c_info = s.disk_usage.get("C:", s.disk_usage.get("C", {}))
        if c_info:
            free_gb = c_info["free"] / (1024 ** 3)
            clr = C_RED if free_gb < 10 else (C_YELLOW if free_gb < 30 else C_GREEN)
            self.dash_values["disk_c"].configure(text=f"{free_gb:.0f} GB", text_color=clr)
        self.dash_values["gpu_temp"].configure(
            text=f"{s.gpu_temp:.0f}°C" if s.gpu_temp is not None else "N/A",
            text_color=color_temp(s.gpu_temp))
        self.dash_values["net_down"].configure(
            text=f"{fmt_size(int(s.net_down_speed))}/s" if s.net_down_speed > 0 else "0 B/s")
        self.dash_values["uptime"].configure(text=fmt_uptime(s.uptime_seconds))

        # Update GPU name in system info if found
        if s.gpu_name and hasattr(self, 'sys_info_labels'):
            gpu_lbl = self.sys_info_labels.get("gpu_name")
            if gpu_lbl and gpu_lbl.cget("text") == "N/A":
                gpu_lbl.configure(text=s.gpu_name)

        # Update disk bars
        self._update_drive_bars(s.disk_usage)

        # Update disk I/O
        self.disk_read_lbl.configure(text=f"Read: {fmt_size(int(s.disk_read_speed))}/s")
        self.disk_write_lbl.configure(text=f"Write: {fmt_size(int(s.disk_write_speed))}/s")

        # Update chart
        self._update_chart()

        # Update alerts
        self._update_active_alerts(s)
        for a in alerts:
            self.alert_tree.insert("", 0, values=(
                a.timestamp, a.level, a.metric, a.message
            ), tags=(a.level,))

    def _update_active_alerts(self, s: HealthSample):
        """Update the active alerts panel based on current sample."""
        active = []
        if s.cpu_percent >= self.engine.cpu_crit:
            active.append(f"CPU: {s.cpu_percent:.0f}%")
        if s.ram_percent >= self.engine.ram_crit:
            active.append(f"RAM: {s.ram_percent:.0f}%")
        if s.gpu_temp and s.gpu_temp >= self.engine.gpu_temp_warn:
            active.append(f"GPU: {s.gpu_temp:.0f}°C")
        if s.cpu_temp and s.cpu_temp >= self.engine.cpu_temp_warn:
            active.append(f"CPU Temp: {s.cpu_temp:.0f}°C")
        for drive, info in s.disk_usage.items():
            if info["free"] / (1024 ** 3) < self.engine.disk_warn_gb:
                active.append(f"{drive}: {info['free'] / (1024**3):.0f} GB free")

        if active:
            self.active_alert_frame.configure(fg_color="#441111")
            self.active_alert_lbl.configure(
                text="⚠ ACTIVE: " + " | ".join(active),
                text_color=C_RED)
        else:
            self.active_alert_frame.configure(fg_color="#112211")
            self.active_alert_lbl.configure(text="✓ All systems normal", text_color=C_GREEN)

    # ── Chart ──

    def _update_chart(self):
        samples = self.engine.samples
        now = time.time()
        cutoff = now - self._chart_window
        recent = [s for s in samples if s.timestamp >= cutoff]
        if len(recent) < 2:
            return

        w = self._chart_width
        h = 200
        self._draw_line_chart(self.live_chart, recent, w, h)

    def _draw_line_chart(self, canvas: tk.Canvas, samples: List[HealthSample],
                          w: int, h: int):
        canvas.delete("all")
        if w < 50 or h < 50 or not samples:
            return

        pad_l, pad_r, pad_t, pad_b = 45, 10, 20, 25
        cw = w - pad_l - pad_r
        ch = h - pad_t - pad_b

        t_min = samples[0].timestamp
        t_max = samples[-1].timestamp
        t_range = max(t_max - t_min, 1)

        # Grid lines and Y labels (0-100%)
        for pct in (0, 25, 50, 75, 100):
            y = pad_t + ch - (pct / 100.0) * ch
            canvas.create_line(pad_l, y, w - pad_r, y, fill="#333333", dash=(2, 4))
            canvas.create_text(pad_l - 4, y, text=f"{pct}%", anchor="e",
                               fill="#666666", font=("Segoe UI", 7))

        # Time labels
        for i in range(5):
            frac = i / 4.0
            t = t_min + frac * t_range
            x = pad_l + frac * cw
            label = datetime.fromtimestamp(t).strftime("%H:%M:%S")
            canvas.create_text(x, h - 4, text=label, anchor="s",
                               fill="#666666", font=("Segoe UI", 7))

        # Draw series
        series = [
            ("CPU %", C_CYAN, [s.cpu_percent for s in samples]),
            ("RAM %", C_YELLOW, [s.ram_percent for s in samples]),
        ]

        for label, color, values in series:
            coords = []
            for i, s in enumerate(samples):
                frac_t = (s.timestamp - t_min) / t_range
                x = pad_l + frac_t * cw
                y = pad_t + ch - (values[i] / 100.0) * ch
                coords.extend([x, y])
            if len(coords) >= 4:
                canvas.create_line(*coords, fill=color, width=2)

        # Legend
        lx = pad_l + 8
        for i, (label, color, _) in enumerate(series):
            ly = pad_t + 4 + i * 14
            canvas.create_rectangle(lx, ly, lx + 10, ly + 8, fill=color, outline="")
            canvas.create_text(lx + 14, ly + 4, text=label, anchor="w",
                               fill=color, font=("Segoe UI", 8))

    # ── Large files / temp handlers ──

    def _on_large_files(self, files: List[Dict]):
        self.lf_tree.delete(*self.lf_tree.get_children())
        for f in files[:100]:
            mod = datetime.fromtimestamp(f["modified"]).strftime("%Y-%m-%d %H:%M")
            self.lf_tree.insert("", "end", values=(f["path"], fmt_size(f["size"]), mod))
        self._lf_status.configure(text=f"Found {len(files)} files")

    def _on_temp_sizes(self, sizes: List[Dict]):
        for w in self._temp_labels:
            w.destroy()
        self._temp_labels.clear()
        for info in sizes:
            row = ctk.CTkFrame(self.temp_frame, fg_color="transparent")
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text=info["name"], font=("Segoe UI", 10),
                         text_color=C_WHITE, width=200).pack(side="left")
            ctk.CTkLabel(row, text=fmt_size(info["size"]), font=("Segoe UI", 10, "bold"),
                         text_color=C_YELLOW if info["size"] > 500 * 1024 * 1024 else C_GRAY).pack(side="left", padx=10)
            btn = ctk.CTkButton(row, text="Open", width=50,
                command=lambda p=info["path"]: subprocess.Popen(["explorer", p], creationflags=_CNW))
            btn.pack(side="right")
            self._temp_labels.append(row)

    # ── Cleanup ──

    def force_stop(self):
        self.running = False
        try:
            self.parent.destroy()
        except Exception:
            pass


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def run_tool():
    try:
        if tk._default_root is None:
            root = ctk.CTk()
        else:
            root = ctk.CTkToplevel()

        app = App(root)
        root.protocol("WM_DELETE_WINDOW", app.force_stop)

        root.update_idletasks()
        w, h = 1340, 800
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.lift()
        root.focus_force()

        if tk._default_root == root:
            root.mainloop()
    except Exception as e:
        messagebox.showerror(TOOL_NAME, f"Startup error:\n{e}")


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.force_stop)
    root.mainloop()
