# Handoff Guide — Python Automations Toolbox

Quick-start guide for anyone picking up this project (new developer, new Claude session, or future self).

---

## Getting Started

```bash
# 1. Activate the virtual environment
cd F:\DevCrow\Python\Automations
venv\Scripts\activate

# 2. Launch the toolbox
python Main.py

# 3. Or run a single tool directly
python tools\system_health_monitor.py
```

---

## How to Create a New Tool

Create a file in `tools/` with this minimal structure:

```python
"""
My Tool — one-line description.
"""
import customtkinter as ctk

TOOL_NAME = "My Tool"
TOOL_DESCRIPTION = "What it does in one line"

class App(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title(TOOL_NAME)
        parent.geometry("1200x700")
        self.pack(fill="both", expand=True)
        # Build your UI here

    def force_stop(self):
        self.running = False
        try:
            self.parent.destroy()
        except Exception:
            pass

def run_tool():
    import tkinter as tk
    if tk._default_root is None:
        root = ctk.CTk()
    else:
        root = ctk.CTkToplevel()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.force_stop)
    if tk._default_root == root:
        root.mainloop()
```

The launcher auto-discovers it on next Refresh. No registration needed.

---

## Key Patterns to Follow

### Subprocess calls (CRITICAL on Windows)
Always use `CREATE_NO_WINDOW` to prevent console window flicker:
```python
subprocess.run(cmd, capture_output=True, text=True,
               creationflags=0x08000000)  # CREATE_NO_WINDOW
```

### Background work (threading)
Use the queue pattern — never update UI from a worker thread:
```python
self.work_q = queue.Queue()
self.result_q = queue.Queue()

# Worker thread
def _worker_loop(self):
    while self.running:
        job = self.work_q.get(timeout=0.3)
        result = do_work(job)
        self.result_q.put(result)

# UI thread drains results
def _process_queue(self):
    while True:
        msg = self.result_q.get_nowait()
        self._update_ui(msg)
    self.after(100, self._process_queue)
```

### Dark theme colors
```python
CARD_BG   = "#1e1e1e"
CANVAS_BG = "#1a1a1a"
TREE_BG   = "#2b2b2b"
C_GREEN   = "#00FF88"
C_YELLOW  = "#FFD700"
C_RED     = "#FF4444"
C_CYAN    = "#00BFFF"
C_GRAY    = "#888888"
```

### Treeview dark styling (do this ONCE per app)
```python
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview",
    background="#2b2b2b", foreground="#ffffff",
    fieldbackground="#2b2b2b", font=("Segoe UI", 9),
    rowheight=22, borderwidth=0)
style.configure("Treeview.Heading",
    background="#333333", foreground="#ffffff",
    font=("Segoe UI", 9, "bold"))
```

---

## Building Portable EXEs

```bash
cd portable\build

# Build a specific tool
python -m PyInstaller --clean --noconfirm ToolName.spec --distpath ..\dist

# Spec file template (see existing specs for reference)
# Key settings:
#   console=False (no console window)
#   uac_admin=True (for tools that need admin: Security Audit, Account Activity)
#   pathex=[os.path.abspath(os.path.join(SPECPATH, '..', '..'))]
#     -> repo root, so PyInstaller can find the canonical tools/ package
#   hiddenimports=['customtkinter', 'psutil', 'tools.<module>',
#                  'tools._common.threadsafe', ...]
#   collect_all('customtkinter') for CTk theme files
```

Launchers import from the canonical `tools/` package (e.g.
`from tools.account_activity_monitor import App`) — **do not copy
sources into `portable/`**. The `tests/test_no_portable_source_drift.py`
guard fails CI if duplicate sources reappear there.

---

## State & Data Files

| File | Location | Tool | Purpose |
|------|----------|------|---------|
| `nid_state.json` | tools/ | Intrusion Detector | Trusted MACs, known devices, gateway baseline |
| `connection_trust.json` | tools/ | Intrusion Detector | Trusted/untrusted remote IPs |
| `system_health_disabled_startup.json` | tools/ | Health Monitor | Disabled startup items backup |
| `favorites.json` | root | Main.py | User's favorited tools |
| `exports/*.json` | exports/ | Various | Exported reports |

---

## Recent Session History

### Tools built/modified (March-April 2026):

1. **FFmpeg Studio** — Full video recording/capture/convert tool with GPU encoder detection, visual area selector, color-correct encoding
2. **Network Intrusion Detector Pro** — Major upgrade: 5-level classification, SERVICE column, connection detail popup, threat detection (Flipper Zero, Tor, audio spying), IPv6 loopback fix
3. **Network Stability Monitor Pro** — Live chart, dynamic polling interval, incident dedup fix, Wi-Fi Analyzer tab (WlanScan API, channel scoring, visual channel map)
4. **Security Audit** — New tool: 10-category system security scan with smart noise reduction
5. **System Health Monitor** — New tool: real-time monitoring with process manager, disk analysis, startup management, alerts
6. **Account Activity Monitor** — New tool: Windows Event Log timeline, spy check (camera/mic access, remote tools), user accounts analysis, log size fixer

### Known issues addressed:
- Console window flicker: fixed with `CREATE_NO_WINDOW` flag globally
- Network monitor duplicate incidents: fixed by normalizing reason strings
- Security audit false positives: fixed VC_redist, MCP DLLs, expired certs, service install counts
- Wi-Fi scan inconsistency: fixed with native `WlanScan` API trigger via ctypes

---

## User's Environment

- **Primary dev machine:** modern multi-core desktop, Windows 10/11, NVIDIA GPU (used to test FFmpeg NVENC encoding)
- **Network:** consumer 2.4GHz Wi-Fi router + standard home LAN — the network tools were built and tested against a typical home setup
- **Second machine:** a laptop on the same LAN runs the portable tool builds

### User preferences:
- Dark theme throughout
- Tools should be self-contained single files
- Practical security focus (detecting real threats, not theoretical)
- Minimal noise — only show meaningful findings
- Clear on/off visual states for toggle buttons

---

## Where to Find Things

| Need | Look here |
|------|-----------|
| How tools are loaded | `Main.py` lines 266-322 |
| Tool module template | Any tool's `run_tool()` function |
| Dark theme constants | Top of any tool file |
| Network scanner | `network_stability_monitor.py` → `scan_wifi_networks()` |
| Event log querying | `account_activity_monitor.py` → `ActivityMonitorEngine._query_log()` |
| GPU detection | `ffmpeg_studio.py` → `_test_encoder()`, `_probe_hardware()` |
| Process management | `system_health_monitor.py` → `SystemHealthEngine.get_processes()` |
| Firewall blocking | `network_intrusion_detector_pro.py` → `block_ip_firewall()` |
| PyInstaller specs | `portable/build/*.spec` |
| Project memory | `C:\Users\Christophoros\.claude\projects\F--DevCrow-Python-Automations\memory\MEMORY.md` |
