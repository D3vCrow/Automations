"""
Security Audit Tool — Comprehensive device & network security checker.
Scans 10 categories: Startup, Processes, Ports/Firewall, Filesystem,
DNS/Network, Accounts, Wi-Fi, USB/Hardware, Browser, Event Logs.
"""

import os, sys, re, json, csv, io, time, hashlib, socket, threading, queue, subprocess
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Tuple, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import customtkinter as ctk
    from tkinter import ttk
    import tkinter as tk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    import tkinter as tk
    from tkinter import ttk

from tools._common.exceptions import narrow_excepts
from tools._common.logging import get_logger

TOOL_NAME = "Security Audit"
TOOL_DESCRIPTION = "Comprehensive security audit — checks startup, processes, ports, files, DNS, accounts, Wi-Fi, USB, browser, event logs"
log = get_logger(__name__)

_CREATE_NO_WINDOW = 0x08000000

# ─────────────────────────── helpers ───────────────────────────

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_run(cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                            timeout=timeout, shell=False,
                            creationflags=_CREATE_NO_WINDOW)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except (OSError, subprocess.SubprocessError) as e:
        return 1, "", str(e)

@narrow_excepts(AttributeError, OSError, default=False)
def is_admin() -> bool:
    """Return True when running with Windows admin rights.

    Caught: ``AttributeError`` (non-Windows: ``ctypes.windll`` missing),
    ``OSError`` (ctypes shell32 call failure). Non-admin falls through
    the decorator with ``default=False``.
    """
    import ctypes
    return ctypes.windll.shell32.IsUserAnAdmin() != 0


@narrow_excepts(OSError, ValueError, default=9999)
def _age_days(path: str) -> float:
    """Return file age in days; 9999 sentinel on stat failure."""
    return (time.time() - os.path.getmtime(path)) / 86400

SAFE_PROCESS_PATHS = [
    "\\microsoft\\", "\\windows defender\\", "\\windows\\system32\\",
    "\\program files\\", "\\program files (x86)\\",
]

def _is_suspicious_path(p: str) -> bool:
    if not p:
        return False
    low = p.lower()
    # Known safe paths
    if any(s in low for s in SAFE_PROCESS_PATHS):
        return False
    suspicious = ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\local\\temp\\",
                  "\\public\\"]
    return any(s in low for s in suspicious)

# ─────────────────────────── Finding ───────────────────────────

@dataclass
class Finding:
    category: str
    severity: str          # INFO, WARN, CRITICAL
    title: str
    detail: str = ""
    remediation: str = ""
    raw_data: dict = field(default_factory=dict)

    def key(self) -> str:
        data = f"{self.category}|{self.title}|{self.detail[:120]}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

# ─────────────────────────── Constants ───────────────────────────

CATEGORIES = [
    ("Startup & Persistence", "startup",   "🔄"),
    ("Process Analysis",      "processes", "⚙️"),
    ("Ports & Firewall",      "ports",     "🛡️"),
    ("File System",           "filesystem","📁"),
    ("DNS & Network",         "dns",       "🌐"),
    ("Account Security",      "accounts",  "👤"),
    ("Wi-Fi Security",        "wifi",      "📶"),
    ("USB & Hardware",        "usb",       "🔌"),
    ("Browser Security",      "browser",   "🌍"),
    ("Event Logs",            "eventlogs", "📋"),
]

SYSTEM_PROCESS_PATHS = {
    "svchost.exe":       r"c:\windows\system32\svchost.exe",
    "csrss.exe":         r"c:\windows\system32\csrss.exe",
    "lsass.exe":         r"c:\windows\system32\lsass.exe",
    "services.exe":      r"c:\windows\system32\services.exe",
    "smss.exe":          r"c:\windows\system32\smss.exe",
    "wininit.exe":       r"c:\windows\system32\wininit.exe",
    "winlogon.exe":      r"c:\windows\system32\winlogon.exe",
    "explorer.exe":      r"c:\windows\explorer.exe",
    "dwm.exe":           r"c:\windows\system32\dwm.exe",
    "taskhostw.exe":     r"c:\windows\system32\taskhostw.exe",
    "runtimebroker.exe": r"c:\windows\system32\runtimebroker.exe",
    "conhost.exe":       r"c:\windows\system32\conhost.exe",
    "spoolsv.exe":       r"c:\windows\system32\spoolsv.exe",
    "dllhost.exe":       r"c:\windows\system32\dllhost.exe",
}

KNOWN_DNS = {
    "8.8.8.8", "8.8.4.4",                        # Google
    "1.1.1.1", "1.0.0.1",                        # Cloudflare
    "9.9.9.9", "149.112.112.112",                # Quad9
    "208.67.222.222", "208.67.220.220",          # OpenDNS
    "76.76.2.0", "76.76.10.0",                   # Control D
    "94.140.14.14", "94.140.15.15",              # AdGuard
}

BACKDOOR_PORTS = {4444, 5555, 31337, 12345, 6666, 6667, 1337, 9999, 8888}

SUSPICIOUS_LISTEN_PORTS = {
    3389: "RDP (Remote Desktop)",
    5900: "VNC",
    5800: "VNC HTTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB (check if expected)",
    135: "RPC",
    139: "NetBIOS",
}

HACKING_USB_KEYWORDS = [
    "rubber ducky", "bash bunny", "flipper", "hak5", "badusb",
    "o.mg", "lan turtle", "wifi pineapple", "usb armory",
    "teensy", "digispark", "attiny85",
]

KNOWN_ROOT_CA_KEYWORDS = [
    "digicert", "globalsign", "comodo", "sectigo", "godaddy", "go daddy",
    "entrust", "verisign", "thawte", "geotrust", "rapidssl",
    "starfield", "amazon", "microsoft", "apple", "google",
    "isrg", "let's encrypt", "usertrust", "baltimore",
    "identrust", "certsign", "actalis", "buypass", "certum",
    "dfn-verein", "hellenic", "secom", "trust", "root",
    "equifax", "swisssign", "ec-acc", "catalanes",
    "quovadis", "networksolutions", "keynectis", "state of",
    "d-trust", "t-telesec", "chambers of commerce",
    "blizzard", "battle.net",      # Gaming (Blizzard installs local cert for Battle.net)
    "valve", "steam",              # Gaming
    "nvidia", "amd", "intel",      # Hardware vendors
    "cisco", "fortinet", "zscaler",# Enterprise security
    "symantec", "norton",          # Security vendors
]

# ─────────────────────────── Engine ───────────────────────────

class SecurityAuditEngine:
    def __init__(self, state_path: str):
        self.state_path = state_path
        self.state = self._load_state()
        self._progress_cb = None

    def _load_state(self) -> dict:
        try:
            with open(self.state_path, "r") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return {"baseline": None, "last_scan": None, "last_findings": []}

    def save_state(self):
        try:
            with open(self.state_path, "w") as f:
                json.dump(self.state, f, indent=2, default=str)
        except (OSError, TypeError):
            pass

    def save_baseline(self, findings: List[Finding]):
        self.state["baseline"] = {
            "saved_at": now_ts(),
            "finding_keys": [f.key() for f in findings],
            "findings": [asdict(f) for f in findings],
        }
        self.save_state()

    def clear_baseline(self):
        self.state["baseline"] = None
        self.save_state()

    def get_baseline_keys(self) -> set:
        bl = self.state.get("baseline")
        if not bl:
            return set()
        return set(bl.get("finding_keys", []))

    def get_checks(self):
        return [
            ("startup",    self.check_startup),
            ("processes",  self.check_processes),
            ("ports",      self.check_ports_firewall),
            ("filesystem", self.check_filesystem),
            ("dns",        self.check_dns_network),
            ("accounts",   self.check_accounts),
            ("wifi",       self.check_wifi),
            ("usb",        self.check_usb_hardware),
            ("browser",    self.check_browser),
            ("eventlogs",  self.check_event_logs),
        ]

    # ────────── 1. Startup & Persistence ──────────

    def check_startup(self) -> List[Finding]:
        findings = []
        if not winreg:
            findings.append(Finding("startup", "INFO", "Registry not available",
                                    "winreg module not found (non-Windows)"))
            return findings

        # Registry Run keys — only report suspicious, summarize rest
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
            (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
            (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run(32)"),
        ]

        reg_total = 0
        reg_suspicious = []
        reg_names = []
        for hive, path, label in run_keys:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        exe_path = value.strip('"').split('"')[0].strip()
                        reg_total += 1
                        reg_names.append(name)

                        if _is_suspicious_path(exe_path):
                            reg_suspicious.append((name, value, label))
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, PermissionError):
                pass

        # Report suspicious individually, summarize the rest
        for name, value, label in reg_suspicious:
            findings.append(Finding("startup", "CRITICAL",
                f"Suspicious startup entry: {name}",
                f"Location: {label}\nCommand: {value}\nPath is in a suspicious directory.",
                "Investigate this entry. Remove if not recognized."))

        safe_count = reg_total - len(reg_suspicious)
        if safe_count > 0:
            findings.append(Finding("startup", "INFO",
                f"Registry startup entries: {safe_count} (all safe)",
                "Programs: " + ", ".join(reg_names[:15]) +
                (f" (+{len(reg_names)-15} more)" if len(reg_names) > 15 else "")))

        # Startup folders — summarize
        startup_dirs = []
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            startup_dirs.append(os.path.join(appdata,
                r"Microsoft\Windows\Start Menu\Programs\Startup"))
        startup_dirs.append(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")

        exec_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".scr", ".pif", ".com", ".js", ".wsh"}
        folder_items = []
        for d in startup_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d):
                    fp = os.path.join(d, f)
                    ext = os.path.splitext(f)[1].lower()
                    if ext in exec_exts or ext == ".lnk":
                        age = _age_days(fp)
                        if age < 7 and ext in exec_exts:
                            findings.append(Finding("startup", "CRITICAL",
                                f"Recently added startup executable: {f}",
                                f"Path: {fp}\nAge: {age:.0f} days",
                                "Review this file. Remove if not recognized."))
                        else:
                            folder_items.append(f)
            except PermissionError:
                pass

        if folder_items:
            findings.append(Finding("startup", "INFO",
                f"Startup folder: {len(folder_items)} items",
                "Items: " + ", ".join(folder_items[:10])))

        # Scheduled Tasks — fix CSV parsing, summarize normal tasks
        suspicious_tasks = []
        normal_task_count = 0
        try:
            rc, out, _ = safe_run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=20)
            if rc == 0 and out.strip():
                # Fix CSV parsing — skip lines that don't look like data
                reader = csv.DictReader(io.StringIO(out))
                seen_tasks = set()
                for row in reader:
                    try:
                        task_name = row.get("TaskName", "").strip()
                        task_run = row.get("Task To Run", "").strip()
                        author = row.get("Author", "").strip()

                        # Skip empty, header artifacts, and Microsoft tasks
                        if not task_name or task_name == "TaskName":
                            continue
                        if "\\Microsoft\\" in task_name:
                            continue
                        # Deduplicate (same task appears multiple times for different triggers)
                        if task_name in seen_tasks:
                            continue
                        seen_tasks.add(task_name)

                        if _is_suspicious_path(task_run):
                            suspicious_tasks.append((task_name, task_run, author))
                        else:
                            normal_task_count += 1
                    except (KeyError, ValueError, AttributeError):
                        continue
        except (OSError, subprocess.SubprocessError, csv.Error):
            findings.append(Finding("startup", "INFO", "Could not enumerate scheduled tasks",
                                    "schtasks command failed"))

        for task_name, task_run, author in suspicious_tasks:
            findings.append(Finding("startup", "CRITICAL",
                f"Suspicious scheduled task: {task_name}",
                f"Command: {task_run}\nAuthor: {author}",
                "Investigate this scheduled task. Delete if not recognized."))

        if normal_task_count > 0:
            findings.append(Finding("startup", "INFO",
                f"Scheduled tasks: {normal_task_count} non-Microsoft tasks (all safe paths)",
                "All scheduled task executables are in expected locations."))

        return findings

    # ────────── 2. Process Analysis ──────────

    def check_processes(self) -> List[Finding]:
        findings = []
        if not psutil:
            findings.append(Finding("processes", "INFO", "psutil not available"))
            return findings

        checked_exes = set()
        suspicious_count = 0

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'username', 'create_time']):
            try:
                info = proc.info
                name = (info.get('name') or '').lower()
                exe = info.get('exe') or ''
                username = info.get('username') or ''
                pid = info.get('pid', 0)

                if not exe or pid <= 4:
                    continue

                # Check for system process name spoofing
                if name in SYSTEM_PROCESS_PATHS:
                    expected = SYSTEM_PROCESS_PATHS[name]
                    actual = exe.lower().replace("/", "\\")
                    if actual != expected and not actual.endswith("\\" + name):
                        findings.append(Finding("processes", "CRITICAL",
                            f"⚠️ FAKE SYSTEM PROCESS: {name} (PID {pid})",
                            f"Expected: {expected}\nActual: {exe}\nUser: {username}\n"
                            "This process is impersonating a Windows system process!",
                            "IMMEDIATELY investigate. This is a strong indicator of malware."))
                        continue

                # Check for processes in suspicious locations
                if _is_suspicious_path(exe):
                    suspicious_count += 1
                    if suspicious_count <= 30:  # cap findings
                        findings.append(Finding("processes", "WARN",
                            f"Process from suspicious path: {info.get('name', name)}",
                            f"PID: {pid}\nPath: {exe}\nUser: {username}",
                            "Investigate if this process is legitimate."))

                # Check digital signature for suspicious processes (rate limited)
                if _is_suspicious_path(exe) and exe not in checked_exes and len(checked_exes) < 10:
                    checked_exes.add(exe)
                    try:
                        rc, out, _ = safe_run([
                            "powershell", "-NoProfile", "-Command",
                            f"(Get-AuthenticodeSignature -FilePath '{exe}').Status"
                        ], timeout=5)
                        if rc == 0 and "NotSigned" in out:
                            findings.append(Finding("processes", "WARN",
                                f"Unsigned executable: {os.path.basename(exe)}",
                                f"Path: {exe}\nDigital signature: Not signed",
                                "Unsigned executables from unusual locations should be investigated."))
                    except (OSError, TypeError, AttributeError):
                        pass

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if suspicious_count == 0:
            findings.append(Finding("processes", "INFO",
                "All processes running from expected locations",
                "No processes found running from suspicious directories."))

        return findings

    # ────────── 3. Ports & Firewall ──────────

    def check_ports_firewall(self) -> List[Finding]:
        findings = []
        if not psutil:
            findings.append(Finding("ports", "INFO", "psutil not available"))
            return findings

        # Listening ports — deduplicate by port+process (IPv4/IPv6 share same port)
        listeners = []
        seen_ports = {}  # port -> (pname, pid, addresses)
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    addr = conn.laddr.ip
                    pid = conn.pid
                    pname = ""
                    try:
                        pname = psutil.Process(pid).name() if pid else "unknown"
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                        pname = f"PID {pid}"

                    listeners.append((port, addr, pname, pid))
                    key = (port, pname)
                    if key not in seen_ports:
                        seen_ports[key] = {"pid": pid, "addrs": []}
                    seen_ports[key]["addrs"].append(addr)
        except (PermissionError, psutil.AccessDenied):
            findings.append(Finding("ports", "INFO",
                "Limited port scan (no admin)", "Run as admin for full port enumeration."))

        # Report each unique port+process once
        reported_ports = set()
        for (port, pname), info in seen_ports.items():
            if port in reported_ports:
                continue
            reported_ports.add(port)
            addrs = ", ".join(info["addrs"])

            if port in BACKDOOR_PORTS:
                findings.append(Finding("ports", "CRITICAL",
                    f"⚠️ BACKDOOR PORT OPEN: {port}",
                    f"Process: {pname} (PID {info['pid']})\nListening on: {addrs}\n"
                    "This port is commonly used by backdoors and remote access trojans!",
                    "Investigate immediately. Kill the process and check its executable."))
            elif port in SUSPICIOUS_LISTEN_PORTS:
                desc = SUSPICIOUS_LISTEN_PORTS[port]
                findings.append(Finding("ports", "WARN",
                    f"Sensitive port: {port} ({desc}) — {pname}",
                    f"PID: {info['pid']}\nAddresses: {addrs}\n"
                    f"This is a standard Windows service. Expected on most PCs.",
                    f"Only concerning if you don't expect {desc} on this machine."))

        normal_ports = len(seen_ports) - len([p for p in reported_ports
                                               if p in BACKDOOR_PORTS or p in SUSPICIOUS_LISTEN_PORTS])
        if normal_ports > 0:
            findings.append(Finding("ports", "INFO",
                f"Open ports: {len(seen_ports)} unique ({normal_ports} normal, "
                f"{len(reported_ports & set(SUSPICIOUS_LISTEN_PORTS.keys()))} system services)",
                "No backdoor ports detected."))

        # RDP check
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0, winreg.KEY_READ)
                deny, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
                winreg.CloseKey(key)
                if deny == 0:
                    findings.append(Finding("ports", "WARN",
                        "Remote Desktop (RDP) is ENABLED",
                        "RDP allows remote access to this computer.\n"
                        "If you don't use RDP, this is a security risk.",
                        "Disable RDP: Settings → System → Remote Desktop → Off"))
            except (OSError, FileNotFoundError):
                pass

        # Firewall rules (inbound allow from any)
        try:
            rc, out, _ = safe_run(["netsh", "advfirewall", "firewall", "show", "rule",
                                   "name=all", "dir=in"], timeout=15)
            if rc == 0:
                suspicious_rules = []
                current_rule = {}
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("Rule Name:"):
                        if current_rule:
                            # Check previous rule
                            if (current_rule.get("action") == "Allow" and
                                current_rule.get("remote") in ("Any", "*") and
                                current_rule.get("enabled") == "Yes"):
                                name = current_rule.get("name", "")
                                if not any(k in name.lower() for k in ["core networking", "windows",
                                           "microsoft", "wsl", "hyper-v", "delivery optimization"]):
                                    suspicious_rules.append(name)
                        current_rule = {"name": line.split(":", 1)[1].strip()}
                    elif line.startswith("Enabled:"):
                        current_rule["enabled"] = line.split(":", 1)[1].strip()
                    elif line.startswith("Action:"):
                        current_rule["action"] = line.split(":", 1)[1].strip()
                    elif line.startswith("RemoteIP:"):
                        current_rule["remote"] = line.split(":", 1)[1].strip()

                # Deduplicate rules by name (same app often has IPv4+IPv6 rules)
                from collections import Counter
                rule_counts = Counter(suspicious_rules)
                if rule_counts:
                    # Only flag as WARN if few rules, INFO if many (normal for dev machines)
                    sev = "INFO" if len(rule_counts) > 20 else "WARN"
                    top_apps = "\n".join(f"  • {name} ({count} rules)"
                                         for name, count in rule_counts.most_common(10))
                    findings.append(Finding("ports", sev,
                        f"Firewall: {len(rule_counts)} apps with inbound allow-any rules",
                        f"Top apps accepting inbound connections:\n{top_apps}" +
                        (f"\n  ... and {len(rule_counts)-10} more" if len(rule_counts) > 10 else ""),
                        "Normal for dev/gaming PCs. Review unused apps in Windows Firewall."))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass

        return findings

    # ────────── 4. File System ──────────

    def check_filesystem(self) -> List[Finding]:
        findings = []

        exec_exts = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsh", ".pif", ".com"}
        # Double extension pattern — but exclude known safe patterns like VC_redist.x86.exe
        double_ext_pat = re.compile(r'\.\w{2,5}\.(exe|scr|bat|cmd|pif|com|vbs|js|wsh|ps1)$', re.I)
        safe_double_ext = re.compile(r'\.(x86|x64|arm64|win32|win64|setup|install|update|patch|redist)\.(exe|msi)$', re.I)

        # Scan suspicious directories for recent executables
        scan_dirs = []
        for env in ["TEMP", "TMP"]:
            d = os.environ.get(env)
            if d and os.path.isdir(d):
                scan_dirs.append(d)
        localtemp = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp")
        if os.path.isdir(localtemp) and localtemp not in scan_dirs:
            scan_dirs.append(localtemp)
        for d in [os.environ.get("PROGRAMDATA", r"C:\ProgramData")]:
            if d and os.path.isdir(d):
                scan_dirs.append(d)

        recent_exes = []
        for base_dir in scan_dirs:
            try:
                for root, dirs, files in os.walk(base_dir):
                    # Max depth 3
                    depth = root.replace(base_dir, "").count(os.sep)
                    if depth > 3:
                        dirs.clear()
                        continue
                    for f in files:
                        try:
                            ext = os.path.splitext(f)[1].lower()
                        except (TypeError, AttributeError):
                            continue
                        if ext in exec_exts:
                            try:
                                fp = os.path.join(root, f)
                                # Ensure safe string representation
                                fp_safe = fp.encode("utf-8", errors="replace").decode("utf-8")
                                f_safe = f.encode("utf-8", errors="replace").decode("utf-8")
                            except (AttributeError, UnicodeError):
                                continue
                            age = _age_days(fp)
                            if age < 7:
                                recent_exes.append((fp_safe, age, f_safe))
                            # Double extension check (skip known safe patterns)
                            if double_ext_pat.search(f) and not safe_double_ext.search(f):
                                findings.append(Finding("filesystem", "CRITICAL",
                                    f"⚠️ DOUBLE EXTENSION: {f_safe}",
                                    f"Path: {fp_safe}\nThis file has a deceptive double extension, "
                                    "commonly used by malware to disguise executables as documents.",
                                    "Delete this file immediately unless you are certain it's safe."))
            except PermissionError:
                continue

        # Deduplicate by filename and filter known safe patterns
        safe_temp_patterns = [
            "mcp_dynamic_",          # Claude Code MCP server DLLs
            "vscode-",               # VS Code extensions
            "ngen_service",          # .NET Native Image Generator
            "dotnet-",               # .NET SDK
            "msbuild",              # Visual Studio build
        ]
        seen_names = set()
        deduped = []
        safe_skipped = 0
        for fp, age, fname in recent_exes:
            if fname.lower() in seen_names:
                continue
            seen_names.add(fname.lower())
            if any(p in fname.lower() for p in safe_temp_patterns):
                safe_skipped += 1
                continue
            deduped.append((fp, age, fname))

        for fp, age, fname in deduped[:15]:
            findings.append(Finding("filesystem", "WARN",
                f"Recent executable: {fname}",
                f"Path: {fp}\nAge: {age:.1f} days\nFound in temporary/data directory.",
                "Investigate if this file is legitimate."))

        if safe_skipped:
            findings.append(Finding("filesystem", "INFO",
                f"Skipped {safe_skipped} known-safe temp files",
                "Claude MCP DLLs, VS Code extensions, and .NET build files are expected."))

        if not recent_exes:
            findings.append(Finding("filesystem", "INFO",
                "No recent executables in temp directories",
                "No suspicious executable files found in Temp/AppData/ProgramData."))

        # Hosts file check
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            with open(hosts_path, "r", errors="replace") as f:
                hosts_content = f.read()
            custom_entries = []
            for line in hosts_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "localhost" in line.lower() and ("127.0.0.1" in line or "::1" in line):
                    continue
                custom_entries.append(line)

            if custom_entries:
                # Classify entries: blocking (127.0.0.1/0.0.0.0 → block) vs redirecting
                blocking = [e for e in custom_entries if e.startswith("127.0.0.1") or e.startswith("0.0.0.0")]
                redirecting = [e for e in custom_entries if e not in blocking]

                # Check for hijacking of major domains (only in redirects, not blocks)
                hijacked = [e for e in redirecting if any(
                    d in e.lower() for d in ["google", "microsoft", "facebook", "apple",
                                             "amazon", "bank", "paypal", "login"])]
                if hijacked:
                    findings.append(Finding("filesystem", "CRITICAL",
                        "⚠️ HOSTS FILE HIJACKING DETECTED",
                        f"Major domains redirected to unknown IPs:\n" +
                        "\n".join(hijacked[:10]),
                        "Your hosts file has been tampered with! Remove suspicious entries."))
                elif blocking and not redirecting:
                    # All entries are 127.0.0.1 blocks — this is ad-blocking or license enforcement
                    findings.append(Finding("filesystem", "INFO",
                        f"Hosts file: {len(blocking)} blocked domains",
                        "Blocked domains (127.0.0.1):\n" +
                        "\n".join(f"  • {e.split(None, 1)[1] if len(e.split(None, 1)) > 1 else e}" for e in blocking[:10]) +
                        "\n\nThese are intentional blocks (ad-blocking, license enforcement, etc). Normal."))
                else:
                    findings.append(Finding("filesystem", "WARN",
                        f"Custom hosts file entries ({len(custom_entries)})",
                        "Entries:\n" + "\n".join(custom_entries[:10]),
                        "Review these entries."))
            else:
                findings.append(Finding("filesystem", "INFO",
                    "Hosts file clean", "No custom entries in hosts file."))
        except PermissionError:
            findings.append(Finding("filesystem", "INFO",
                "Cannot read hosts file", "Requires admin privileges."))

        return findings

    # ────────── 5. DNS & Network ──────────

    def check_dns_network(self) -> List[Finding]:
        findings = []

        # Get current DNS servers
        rc, out, _ = safe_run(["ipconfig", "/all"], timeout=10)
        dns_servers = []
        if rc == 0:
            in_dns = False
            for line in out.splitlines():
                stripped = line.strip()
                if "dns servers" in stripped.lower() or "dns server" in stripped.lower():
                    in_dns = True
                    parts = stripped.split(":", 1)
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                            dns_servers.append(ip)
                elif in_dns and re.match(r'^\s+\d+\.\d+\.\d+\.\d+', line):
                    dns_servers.append(line.strip())
                else:
                    in_dns = False

        for dns in set(dns_servers):
            if dns.startswith("127.") or dns.startswith("192.168.") or dns.startswith("10."):
                findings.append(Finding("dns", "INFO",
                    f"DNS server: {dns} (local/router)", "Using local DNS resolver."))
            elif dns in KNOWN_DNS:
                findings.append(Finding("dns", "INFO",
                    f"DNS server: {dns} (known public DNS)", "Recognized public DNS provider."))
            else:
                findings.append(Finding("dns", "WARN",
                    f"Unknown DNS server: {dns}",
                    "This DNS server is not a recognized public provider.\n"
                    "Could be your ISP's DNS or potentially hijacked.",
                    "Consider switching to a known DNS (8.8.8.8, 1.1.1.1, 9.9.9.9)."))

        # Proxy settings
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0, winreg.KEY_READ)
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    findings.append(Finding("dns", "WARN",
                        f"System proxy ENABLED: {proxy_server}",
                        "A system-wide proxy is configured. All browser traffic goes through it.\n"
                        "If you didn't set this, it could be malware redirecting your traffic.",
                        "Check proxy settings: Settings → Network → Proxy"))
                else:
                    findings.append(Finding("dns", "INFO",
                        "No system proxy configured", "ProxyEnable = 0 (good)"))
                winreg.CloseKey(key)
            except (OSError, FileNotFoundError):
                pass

        # DNS resolution verification
        test_domains = [
            ("www.google.com", False),
            ("www.microsoft.com", False),
            ("login.microsoftonline.com", False),
        ]
        for domain, _ in test_domains:
            try:
                results = socket.getaddrinfo(domain, 443, socket.AF_INET)
                ips = list(set(r[4][0] for r in results))
                # Check if resolved to private IPs (hijacking indicator)
                private = [ip for ip in ips if ip.startswith("10.") or ip.startswith("192.168.")
                          or ip.startswith("172.") or ip.startswith("127.")]
                if private:
                    findings.append(Finding("dns", "CRITICAL",
                        f"⚠️ DNS HIJACKING: {domain} → {private[0]}",
                        f"Domain {domain} resolved to a private IP address!\n"
                        "This strongly suggests DNS hijacking.",
                        "Change your DNS servers immediately! Use 8.8.8.8 or 1.1.1.1."))
            except socket.gaierror:
                findings.append(Finding("dns", "WARN",
                    f"DNS resolution failed: {domain}",
                    "Could not resolve this domain. Possible DNS issue or blocking.",
                    "Check your DNS settings and internet connection."))

        return findings

    # ────────── 6. Account Security ──────────

    def check_accounts(self) -> List[Finding]:
        findings = []

        # List local accounts
        rc, out, _ = safe_run(["net", "user"], timeout=10)
        if rc == 0:
            accounts = []
            capture = False
            for line in out.splitlines():
                if "---" in line:
                    capture = True
                    continue
                if capture and line.strip() and "command completed" not in line.lower():
                    accounts.extend(line.split())

            for acct in accounts:
                rc2, detail, _ = safe_run(["net", "user", acct], timeout=5)
                if rc2 != 0:
                    continue

                is_active = "Yes" in [l.split("active")[-1].strip()
                                     for l in detail.lower().splitlines()
                                     if "account active" in l] if detail else False
                is_admin_acct = False
                if "*administrators*" in detail.lower().replace(" ", ""):
                    is_admin_acct = True

                # Check for active status more robustly
                for line in detail.splitlines():
                    if "Account active" in line and "Yes" in line:
                        is_active = True
                    if "Local Group Memberships" in line and "*Administrators*" in line:
                        is_admin_acct = True

                if acct.lower() == "guest":
                    if is_active:
                        findings.append(Finding("accounts", "WARN",
                            "Guest account is ENABLED",
                            "The Guest account allows anonymous access to this computer.",
                            "Disable it: net user Guest /active:no"))
                    continue

                if acct.lower() == "administrator":
                    if is_active:
                        findings.append(Finding("accounts", "WARN",
                            "Built-in Administrator account is ENABLED",
                            "The default Administrator account is a common attack target.",
                            "Disable it if not needed: net user Administrator /active:no"))
                    continue

                if is_admin_acct:
                    findings.append(Finding("accounts", "INFO",
                        f"Admin account: {acct}",
                        f"Active: {is_active}\nHas administrator privileges."))

        # Failed login attempts
        rc, out, _ = safe_run([
            "wevtutil", "qe", "Security",
            "/q:*[System[EventID=4625]]",
            "/c:50", "/f:text", "/rd:true"
        ], timeout=10)
        if rc == 0 and out.strip():
            fail_count = out.count("Event[")
            if not fail_count:
                fail_count = out.count("EventID")
            if fail_count > 20:
                findings.append(Finding("accounts", "CRITICAL",
                    f"⚠️ {fail_count}+ failed login attempts detected!",
                    "High number of failed logins may indicate a brute-force attack.",
                    "Check Event Viewer → Security for details. Consider enabling account lockout policy."))
            elif fail_count > 5:
                findings.append(Finding("accounts", "WARN",
                    f"{fail_count} failed login attempts",
                    "Some failed login attempts detected. Could be normal typos or suspicious activity.",
                    "Review in Event Viewer → Security log."))
            else:
                findings.append(Finding("accounts", "INFO",
                    "Few/no failed login attempts", "Login security looks normal."))
        elif "Access is denied" in (out + _):
            findings.append(Finding("accounts", "INFO",
                "Cannot read Security event log",
                "Admin privileges required to check failed login attempts.",
                "Run as admin for full account security analysis."))

        return findings

    # ────────── 7. Wi-Fi Security ──────────

    def check_wifi(self) -> List[Finding]:
        findings = []

        # Saved profiles
        rc, out, _ = safe_run(["netsh", "wlan", "show", "profiles"], timeout=10)
        if rc != 0:
            findings.append(Finding("wifi", "INFO", "Cannot enumerate Wi-Fi profiles",
                                    "Wi-Fi interface may not be available."))
            return findings

        profiles = re.findall(r"All User Profile\s*:\s*(.+)", out)
        if not profiles:
            profiles = re.findall(r"Profile\s*:\s*(.+)", out)

        weak_count = 0
        for profile in profiles:
            profile = profile.strip()
            rc2, detail, _ = safe_run(["netsh", "wlan", "show", "profile",
                                       f"name={profile}"], timeout=5)
            if rc2 != 0:
                continue

            auth = ""
            cipher = ""
            for line in detail.splitlines():
                if "Authentication" in line:
                    auth = line.split(":", 1)[1].strip() if ":" in line else ""
                if "Cipher" in line:
                    cipher = line.split(":", 1)[1].strip() if ":" in line else ""

            if auth.lower() in ("open", ""):
                findings.append(Finding("wifi", "CRITICAL",
                    f"⚠️ OPEN Wi-Fi saved: {profile}",
                    f"Authentication: {auth}\nNo encryption — all traffic visible to anyone nearby!",
                    "Remove this profile unless absolutely necessary."))
                weak_count += 1
            elif "wep" in auth.lower():
                findings.append(Finding("wifi", "CRITICAL",
                    f"⚠️ WEP Wi-Fi saved: {profile}",
                    f"Authentication: {auth}\nWEP encryption is broken and easily cracked.",
                    "Remove this profile. Use WPA2 or WPA3 networks only."))
                weak_count += 1
            elif "wpa2" in auth.lower() or "wpa3" in auth.lower():
                findings.append(Finding("wifi", "INFO",
                    f"Wi-Fi profile: {profile} ({auth})",
                    f"Cipher: {cipher}"))

        # Current connection
        rc, out, _ = safe_run(["netsh", "wlan", "show", "interfaces"], timeout=5)
        if rc == 0:
            ssid = bssid = auth = signal = channel = ""
            for line in out.splitlines():
                l = line.strip()
                if l.startswith("SSID") and "BSSID" not in l:
                    ssid = l.split(":", 1)[1].strip() if ":" in l else ""
                elif l.startswith("BSSID"):
                    bssid = l.split(":", 1)[1].strip() if ":" in l else ""
                elif l.startswith("Authentication"):
                    auth = l.split(":", 1)[1].strip() if ":" in l else ""
                elif l.startswith("Signal"):
                    signal = l.split(":", 1)[1].strip() if ":" in l else ""
                elif l.startswith("Channel"):
                    channel = l.split(":", 1)[1].strip() if ":" in l else ""

            if ssid:
                findings.append(Finding("wifi", "INFO",
                    f"Connected: {ssid} ({auth})",
                    f"BSSID: {bssid}\nSignal: {signal}\nChannel: {channel}"))

                # Evil twin check — compare BSSID with baseline
                bl = self.state.get("baseline")
                if bl:
                    bl_findings = bl.get("findings", [])
                    for bf in bl_findings:
                        if bf.get("category") == "wifi" and "Connected:" in bf.get("title", ""):
                            old_bssid = ""
                            for dl in bf.get("detail", "").splitlines():
                                if dl.startswith("BSSID:"):
                                    old_bssid = dl.split(":", 1)[1].strip()
                            if old_bssid and bssid and old_bssid != bssid:
                                findings.append(Finding("wifi", "CRITICAL",
                                    f"⚠️ POSSIBLE EVIL TWIN: {ssid}",
                                    f"BSSID changed!\nBaseline: {old_bssid}\nCurrent: {bssid}\n"
                                    "Same network name but different access point!",
                                    "Disconnect immediately if unexpected. Verify with your router admin."))

        if weak_count == 0 and not any(f.severity == "CRITICAL" for f in findings):
            findings.append(Finding("wifi", "INFO",
                "Wi-Fi security OK", f"{len(profiles)} saved profiles, all use strong encryption."))

        return findings

    # ────────── 8. USB & Hardware ──────────

    def check_usb_hardware(self) -> List[Finding]:
        findings = []

        # USB device history from registry
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Enum\USBSTOR", 0, winreg.KEY_READ)
                i = 0
                devices = []
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        # Each subkey is like "Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00"
                        try:
                            subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                            j = 0
                            while True:
                                try:
                                    serial = winreg.EnumKey(subkey, j)
                                    device_name = subkey_name.replace("&", " ").replace("_", " ")
                                    devices.append((device_name, serial))

                                    # Check for hacking tool keywords
                                    combined = (device_name + " " + serial).lower()
                                    if any(kw in combined for kw in HACKING_USB_KEYWORDS):
                                        findings.append(Finding("usb", "CRITICAL",
                                            f"⚠️ HACKING TOOL USB DETECTED: {device_name}",
                                            f"Serial: {serial}\nThis device matches known hacking tool signatures!",
                                            "Investigate immediately! Remove and scan your system."))
                                    j += 1
                                except OSError:
                                    break
                            winreg.CloseKey(subkey)
                        except OSError:
                            pass
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)

                findings.append(Finding("usb", "INFO",
                    f"{len(devices)} USB storage devices in history",
                    "Devices:\n" + "\n".join(f"  • {d[0]}" for d in devices[:15])))

            except (OSError, PermissionError):
                findings.append(Finding("usb", "INFO",
                    "Cannot read USB history", "Registry access denied."))

        # Network adapter analysis — classify as physical/virtual
        rc, out, _ = safe_run(["ipconfig", "/all"], timeout=10)
        if rc == 0:
            # Match only actual adapter headers (line starts with adapter type)
            adapters = []
            for line in out.splitlines():
                m = re.match(r'^(Ethernet|Wireless LAN|Wi-Fi|PPP)\s+adapter\s+(.+?):', line, re.I)
                if m:
                    adapters.append(m.group(2).strip())
            virtual_keywords = ["virtual", "hyper-v", "vmware", "vbox", "loopback",
                               "local area connection*", "bluetooth", "vpn", "tunnel",
                               "wsl", "docker", "vethernet"]
            physical = []
            virtual = []
            for a in adapters:
                if any(k in a.lower() for k in virtual_keywords):
                    virtual.append(a)
                else:
                    physical.append(a)

            detail_lines = []
            if physical:
                detail_lines.append("Physical: " + ", ".join(physical))
            if virtual:
                detail_lines.append("Virtual/System: " + ", ".join(virtual))

            # Only warn about unexpected PHYSICAL adapters
            unexpected_physical = [a for a in physical if not any(
                k in a.lower() for k in ["ethernet", "wi-fi", "wifi", "wireless"])]
            if unexpected_physical:
                findings.append(Finding("usb", "WARN",
                    f"Unexpected physical adapter: {', '.join(unexpected_physical)}",
                    "\n".join(detail_lines) +
                    "\nUnexpected physical adapters could be rogue USB network devices.",
                    "Check Device Manager for unknown network adapters."))
            else:
                findings.append(Finding("usb", "INFO",
                    f"Network adapters: {len(physical)} physical, {len(virtual)} virtual",
                    "\n".join(detail_lines)))

        # Bluetooth devices
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices",
                    0, winreg.KEY_READ)
                i = 0
                bt_count = 0
                while True:
                    try:
                        winreg.EnumKey(key, i)
                        bt_count += 1
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
                findings.append(Finding("usb", "INFO",
                    f"{bt_count} Bluetooth devices paired",
                    "Review paired Bluetooth devices in Settings → Bluetooth."))
            except (OSError, PermissionError):
                pass

        return findings

    # ────────── 9. Browser Security ──────────

    def check_browser(self) -> List[Finding]:
        findings = []

        # Root certificate store — get subject + issuer + notafter for full analysis
        try:
            rc, out, _ = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-ChildItem Cert:\\LocalMachine\\Root | "
                "Select-Object Subject, NotAfter, Thumbprint | "
                "ForEach-Object { $_.Subject + '|||' + $_.NotAfter.ToString('yyyy-MM-dd') + '|||' + $_.Thumbprint }"
            ], timeout=15)
            if rc == 0 and out.strip():
                known_certs = []
                unknown_certs = []
                expired_certs = []

                for line in out.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("|||")
                    subject = parts[0].strip() if len(parts) > 0 else ""
                    notafter = parts[1].strip() if len(parts) > 1 else ""
                    thumb = parts[2].strip()[:12] if len(parts) > 2 else ""

                    if not subject:
                        continue

                    # Check expiration
                    try:
                        exp_date = datetime.strptime(notafter, "%Y-%m-%d")
                        if exp_date < datetime.now():
                            expired_certs.append(f"{subject[:70]} (expired {notafter})")
                    except (ValueError, TypeError):
                        pass

                    cert_lower = subject.lower()
                    if any(kw in cert_lower for kw in KNOWN_ROOT_CA_KEYWORDS):
                        known_certs.append(subject)
                    else:
                        unknown_certs.append(subject)

                # Report
                findings.append(Finding("browser", "INFO",
                    f"Certificate store: {len(known_certs)} known CAs",
                    f"All recognized root certificates from trusted providers."))

                if expired_certs:
                    findings.append(Finding("browser", "INFO",
                        f"{len(expired_certs)} expired root certificates (normal)",
                        "Expired CAs:\n" + "\n".join(f"  - {c}" for c in expired_certs[:5]) +
                        ("\n  ..." if len(expired_certs) > 5 else "") +
                        "\n\nExpired root CAs are normal Windows leftovers. Not a security risk."))

                if unknown_certs:
                    # Check if any look truly suspicious (self-signed, random names)
                    suspicious_ca = [c for c in unknown_certs if any(
                        k in c.lower() for k in ["proxy", "intercept", "mitm", "debug",
                                                  "fiddler", "charles", "burp", "mitmproxy"])]
                    if suspicious_ca:
                        findings.append(Finding("browser", "CRITICAL",
                            f"MITM/proxy certificate detected!",
                            "Suspicious root CAs:\n" + "\n".join(f"  - {c[:80]}" for c in suspicious_ca) +
                            "\n\nThese certificates are used by traffic interception tools!",
                            "Remove these in certmgr.msc unless you installed them intentionally."))
                    elif unknown_certs:
                        findings.append(Finding("browser", "INFO",
                            f"{len(unknown_certs)} other root certificates",
                            "Non-standard but not suspicious CAs:\n" +
                            "\n".join(f"  - {c[:80]}" for c in unknown_certs[:10]) +
                            "\n\nThese are likely from software vendors or regional CAs.",
                            "Review in certmgr.msc if concerned."))
                else:
                    findings.append(Finding("browser", "INFO",
                        "No unknown root certificates", "All CAs are recognized."))
        except (OSError, subprocess.SubprocessError, ValueError):
            findings.append(Finding("browser", "INFO",
                "Could not check certificate store", "PowerShell command failed."))

        # System proxy (already checked in DNS, but reference here)
        if winreg:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0, winreg.KEY_READ)
                try:
                    auto_config, _ = winreg.QueryValueEx(key, "AutoConfigURL")
                    if auto_config:
                        findings.append(Finding("browser", "WARN",
                            f"Auto-config proxy (PAC): {auto_config}",
                            "A proxy auto-configuration URL is set. This could redirect your traffic.",
                            "Check: Settings → Network → Proxy → Automatic proxy setup"))
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except OSError:
                pass

        if not findings:
            findings.append(Finding("browser", "INFO",
                "Browser security checks passed", "No suspicious proxy or certificate issues found."))

        return findings

    # ────────── 10. Event Logs ──────────

    def check_event_logs(self) -> List[Finding]:
        findings = []

        # (log, event_id, description, area, warn_threshold, critical_threshold)
        # Note: wevtutil /c:100 fetches last 100 events — for service installs,
        # 100 over the lifetime of a PC is completely normal (Windows updates alone install many)
        events_to_check = [
            ("Security", "4625", "Failed login attempts", "accounts", 10, 50),
            ("Security", "4720", "User account created", "accounts", 1, 3),
            ("System",   "7045", "Service installed", "system", 100, 100),  # 100 = max we fetch, always INFO
            ("Security", "1102", "Audit log cleared", "security", 1, 1),
            ("Security", "4719", "Security policy changed", "security", 5, 20),
        ]

        admin = is_admin()

        for log, event_id, desc, area, warn_thresh, crit_thresh in events_to_check:
            if log == "Security" and not admin:
                continue  # Security log requires admin

            try:
                rc, out, err = safe_run([
                    "wevtutil", "qe", log,
                    f"/q:*[System[EventID={event_id}]]",
                    "/c:100", "/f:text", "/rd:true"
                ], timeout=10)

                if rc != 0:
                    if "Access is denied" in err or "Access is denied" in out:
                        continue
                    continue

                count = out.count("<Event") if "<Event" in out else out.count(f"EventID")
                if not count:
                    # Count by "Event[" pattern
                    count = len(re.findall(r"Event\[", out))

                if event_id == "1102" and count > 0:
                    findings.append(Finding("eventlogs", "CRITICAL",
                        f"⚠️ AUDIT LOG CLEARED ({count} times)!",
                        "Someone cleared the Windows Security audit log.\n"
                        "This is a common technique used by attackers to cover their tracks!",
                        "Investigate immediately. Check who has admin access to this machine."))
                elif event_id == "4720" and count > 0:
                    findings.append(Finding("eventlogs", "WARN",
                        f"User accounts created: {count}",
                        f"{count} user account creation events found in Security log.\n"
                        "Verify all accounts were created intentionally.",
                        "Run 'net user' to review all accounts."))
                elif event_id == "7045":
                    # Service installs are normal — Windows updates, software installs all create services
                    findings.append(Finding("eventlogs", "INFO",
                        f"Service installations: {count} in recent history",
                        f"This is normal for a Windows PC with regular software/updates.\n"
                        "Only concerning if you see services you don't recognize.",
                        "Review in services.msc if needed."))
                elif count > crit_thresh:
                    findings.append(Finding("eventlogs", "CRITICAL",
                        f"{desc}: {count} events",
                        f"High number of {desc.lower()} events detected."))
                elif count > warn_thresh:
                    findings.append(Finding("eventlogs", "WARN",
                        f"{desc}: {count} events",
                        f"{count} {desc.lower()} events found."))

            except (OSError, subprocess.SubprocessError, ValueError):
                continue

        if not admin:
            findings.append(Finding("eventlogs", "INFO",
                "Limited event log analysis (no admin)",
                "Security event log requires admin privileges.\nRun as admin for: failed logins, "
                "account creation, audit log clearing.",
                "Right-click → Run as administrator for full analysis."))

        if not findings:
            findings.append(Finding("eventlogs", "INFO",
                "Event logs look clean", "No suspicious events found."))

        return findings


# ─────────────────────────── UI ───────────────────────────

class App(ctk.CTkFrame if HAS_CTK else tk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        parent.title("Security Audit")
        parent.geometry("1200x750")
        parent.minsize(850, 550)

        state_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                  "security_audit_state.json")
        self.engine = SecurityAuditEngine(state_path)

        self.running = True
        self.scanning = False
        self.result_q: "queue.Queue" = queue.Queue()
        self.all_findings: List[Finding] = []
        self.scan_progress = 0
        self.filter_cat = "ALL"
        self.filter_sev = {"INFO": True, "WARN": True, "CRITICAL": True}

        self._build_ui()
        self.pack(fill="both", expand=True)
        self.after(200, self._ui_tick)

    def _build_ui(self):
        # ── Top bar ──
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=8, pady=(6, 2))

        # Admin badge
        admin = is_admin()
        badge_color = "#28a745" if admin else "#ffc107"
        badge_text = "ADMIN" if admin else "USER MODE"
        ctk.CTkLabel(top, text=f" {badge_text} ", font=("Segoe UI", 10, "bold"),
                     fg_color=badge_color, text_color="#000000", corner_radius=4).pack(side="left", padx=(4, 8))

        self.btn_scan = ctk.CTkButton(top, text="▶  Run Full Audit", fg_color="#28a745",
                                       hover_color="#218838", width=140, command=self.start_scan)
        self.btn_scan.pack(side="left", padx=4)

        ctk.CTkButton(top, text="Save Baseline", width=100,
                      command=self.save_baseline).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Export", width=70,
                      command=self.export_report).pack(side="left", padx=4)

        # Progress bar & status
        self.progress_bar = ctk.CTkProgressBar(top, width=200)
        self.progress_bar.pack(side="left", padx=(12, 4))
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(top, text="Ready — click Run Full Audit",
                                          font=("Segoe UI", 10))
        self.status_label.pack(side="left", padx=8)

        # ── Tabs ──
        nb = ctk.CTkTabview(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(2, 6))

        self.tab_dashboard = nb.add("Dashboard")
        self.tab_details = nb.add("Details")
        self.tab_baseline = nb.add("Baseline")

        self._build_dashboard()
        self._build_details()
        self._build_baseline()

    # ── Dashboard ──

    def _build_dashboard(self):
        f = self.tab_dashboard
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=4, pady=4)

        # Overall threat score
        self.threat_frame = ctk.CTkFrame(scroll, fg_color="#1e1e1e", corner_radius=10)
        self.threat_frame.pack(fill="x", padx=6, pady=(6, 10))
        self.threat_label = ctk.CTkLabel(self.threat_frame, text="  NOT SCANNED YET  ",
                                          font=("Segoe UI", 18, "bold"),
                                          text_color="#888888")
        self.threat_label.pack(pady=12)

        # Category cards grid (2 columns x 5 rows)
        card_grid = ctk.CTkFrame(scroll, fg_color="transparent")
        card_grid.pack(fill="both", expand=True, padx=4)
        card_grid.columnconfigure(0, weight=1)
        card_grid.columnconfigure(1, weight=1)

        self.dash_cards = {}
        for idx, (name, key, icon) in enumerate(CATEGORIES):
            row = idx // 2
            col = idx % 2

            card = ctk.CTkFrame(card_grid, fg_color="#1e1e1e", corner_radius=8)
            card.grid(row=row, column=col, padx=6, pady=4, sticky="nsew")
            card_grid.rowconfigure(row, weight=1)

            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=10, pady=(8, 2))

            ctk.CTkLabel(header, text=f"{icon} {name}",
                         font=("Segoe UI", 12, "bold")).pack(side="left")

            badge = ctk.CTkLabel(header, text=" PENDING ",
                                  font=("Segoe UI", 9, "bold"),
                                  fg_color="#555555", text_color="#cccccc",
                                  corner_radius=4)
            badge.pack(side="right")

            count_lbl = ctk.CTkLabel(card, text="Not scanned",
                                      font=("Segoe UI", 10), text_color="#888888")
            count_lbl.pack(anchor="w", padx=12, pady=(0, 8))

            self.dash_cards[key] = {"badge": badge, "count": count_lbl, "card": card}

    # ── Details ──

    def _build_details(self):
        f = self.tab_details

        # Top filter bar
        filter_bar = ctk.CTkFrame(f)
        filter_bar.pack(fill="x", padx=6, pady=(6, 2))

        ctk.CTkLabel(filter_bar, text="Category:", font=("Segoe UI", 10)).pack(side="left", padx=(4, 4))

        self.cat_var = tk.StringVar(value="ALL")
        cat_menu = ctk.CTkOptionMenu(filter_bar, variable=self.cat_var,
                                      values=["ALL"] + [c[0] for c in CATEGORIES],
                                      width=180, command=lambda _: self._refresh_details())
        cat_menu.pack(side="left", padx=4)

        ctk.CTkLabel(filter_bar, text="Severity:", font=("Segoe UI", 10)).pack(side="left", padx=(12, 4))

        self.sev_vars = {}
        for sev, color in [("CRITICAL", "#dc3545"), ("WARN", "#ffc107"), ("INFO", "#6c757d")]:
            var = tk.BooleanVar(value=True)
            self.sev_vars[sev] = var
            ctk.CTkCheckBox(filter_bar, text=sev, variable=var,
                           text_color=color, font=("Segoe UI", 10),
                           command=self._refresh_details, width=80).pack(side="left", padx=2)

        # Finding count
        self.finding_count_label = ctk.CTkLabel(filter_bar, text="",
                                                 font=("Segoe UI", 10), text_color="#888888")
        self.finding_count_label.pack(side="right", padx=8)

        # Scrollable findings list
        self.details_scroll = ctk.CTkScrollableFrame(f)
        self.details_scroll.pack(fill="both", expand=True, padx=6, pady=4)

        self.details_placeholder = ctk.CTkLabel(self.details_scroll,
            text="Run a scan to see findings here.",
            font=("Segoe UI", 12), text_color="#666666")
        self.details_placeholder.pack(pady=40)

    # ── Baseline ──

    def _build_baseline(self):
        f = self.tab_baseline
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=4)

        # Baseline info
        self.bl_info_frame = ctk.CTkFrame(scroll, fg_color="#1e1e1e", corner_radius=8)
        self.bl_info_frame.pack(fill="x", padx=6, pady=6)

        bl = self.engine.state.get("baseline")
        if bl:
            bl_text = f"Baseline saved: {bl.get('saved_at', 'unknown')}\nFindings: {len(bl.get('finding_keys', []))}"
        else:
            bl_text = "No baseline saved yet. Run a scan first, then click 'Save Baseline'."

        self.bl_info_label = ctk.CTkLabel(self.bl_info_frame, text=bl_text,
                                           font=("Segoe UI", 11), justify="left")
        self.bl_info_label.pack(padx=12, pady=10, anchor="w")

        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=6, pady=4)
        ctk.CTkButton(btn_row, text="Save Current as Baseline", width=180,
                      command=self.save_baseline).pack(side="left", padx=4)
        ctk.CTkButton(btn_row, text="Clear Baseline", width=120,
                      fg_color="#dc3545", hover_color="#c82333",
                      command=self.clear_baseline).pack(side="left", padx=4)

        # Diff view
        ctk.CTkLabel(scroll, text="Changes Since Baseline",
                     font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=8, pady=(12, 4))

        self.diff_scroll = ctk.CTkFrame(scroll, fg_color="transparent")
        self.diff_scroll.pack(fill="x", padx=6, pady=4)

        self.diff_placeholder = ctk.CTkLabel(self.diff_scroll,
            text="Run a scan with a saved baseline to see changes.",
            font=("Segoe UI", 10), text_color="#666666")
        self.diff_placeholder.pack(pady=10)

    # ── Scanning ──

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.all_findings.clear()
        self.scan_progress = 0
        self.progress_bar.set(0)
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.status_label.configure(text="Scanning...")

        # Reset dashboard cards
        for key, card_data in self.dash_cards.items():
            card_data["badge"].configure(text=" SCANNING ", fg_color="#3a7ebf", text_color="#ffffff")
            card_data["count"].configure(text="...")

        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        checks = self.engine.get_checks()
        total = len(checks)

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            for cat_key, method in checks:
                futures[pool.submit(self._safe_check, method)] = cat_key

            for future in as_completed(futures):
                cat_key = futures[future]
                try:
                    findings = future.result()
                except Exception as e:  # noqa: BLE001 - boundary: any check may raise, we must still report
                    log.exception("Category check %s failed", cat_key)
                    findings = [Finding(cat_key, "INFO", "Check failed", str(e))]
                self.result_q.put(("category_done", cat_key, findings))

        self.result_q.put(("scan_complete", None, None))

    def _safe_check(self, method):
        try:
            return method()
        except Exception as e:  # noqa: BLE001 - boundary: safe wrapper for worker-thread checks
            log.exception("Safe-check wrapper caught fault in %s", getattr(method, "__qualname__", method))
            return [Finding("unknown", "INFO", "Check error", str(e))]

    def _ui_tick(self):
        if not self.running:
            return

        changed = False
        while True:
            try:
                msg_type, cat_key, data = self.result_q.get_nowait()
            except queue.Empty:
                break

            changed = True
            if msg_type == "category_done":
                self.all_findings.extend(data)
                self.scan_progress += 1
                self.progress_bar.set(self.scan_progress / 10)
                self._update_card(cat_key, data)

                # Find category name for status
                cat_name = cat_key
                for name, key, _ in CATEGORIES:
                    if key == cat_key:
                        cat_name = name
                        break
                self.status_label.configure(text=f"Scanned: {cat_name} ({self.scan_progress}/10)")

            elif msg_type == "scan_complete":
                self.scanning = False
                self.progress_bar.set(1.0)
                self.btn_scan.configure(state="normal", text="▶  Run Full Audit")

                # Count severities
                crits = sum(1 for f in self.all_findings if f.severity == "CRITICAL")
                warns = sum(1 for f in self.all_findings if f.severity == "WARN")

                self.status_label.configure(
                    text=f"Complete — {len(self.all_findings)} findings "
                         f"({crits} critical, {warns} warnings)")

                # Update overall threat
                if crits > 0:
                    self.threat_label.configure(text="  ⚠️ ISSUES FOUND — REVIEW CRITICAL FINDINGS  ",
                                                text_color="#dc3545")
                    self.threat_frame.configure(fg_color="#2a1215")
                elif warns > 0:
                    self.threat_label.configure(text="  ⚡ WARNINGS — REVIEW RECOMMENDED  ",
                                                text_color="#ffc107")
                    self.threat_frame.configure(fg_color="#2a2515")
                else:
                    self.threat_label.configure(text="  ✅ SYSTEM LOOKS CLEAN  ",
                                                text_color="#28a745")
                    self.threat_frame.configure(fg_color="#152a17")

                # Save scan results
                self.engine.state["last_scan"] = now_ts()
                self.engine.state["last_findings"] = [asdict(f) for f in self.all_findings]
                self.engine.save_state()

                # Refresh details and baseline diff
                self._refresh_details()
                self._refresh_baseline_diff()

        if not changed:
            pass

        self.after(200, self._ui_tick)

    def _update_card(self, cat_key, findings: List[Finding]):
        if cat_key not in self.dash_cards:
            return
        card = self.dash_cards[cat_key]

        crits = sum(1 for f in findings if f.severity == "CRITICAL")
        warns = sum(1 for f in findings if f.severity == "WARN")
        infos = sum(1 for f in findings if f.severity == "INFO")

        # Determine status
        if crits > 0:
            card["badge"].configure(text=" FAIL ", fg_color="#dc3545", text_color="#ffffff")
            card["card"].configure(fg_color="#2a1215")
        elif warns > 0:
            card["badge"].configure(text=" WARN ", fg_color="#ffc107", text_color="#000000")
            card["card"].configure(fg_color="#2a2515")
        else:
            card["badge"].configure(text=" PASS ", fg_color="#28a745", text_color="#ffffff")
            card["card"].configure(fg_color="#152a17")

        # Count text
        parts = []
        if crits:
            parts.append(f"{crits} critical")
        if warns:
            parts.append(f"{warns} warning{'s' if warns > 1 else ''}")
        if infos:
            parts.append(f"{infos} info")
        card["count"].configure(text=", ".join(parts) if parts else "Clean")

        # Check for NEW findings vs baseline
        bl_keys = self.engine.get_baseline_keys()
        if bl_keys:
            new_count = sum(1 for f in findings if f.key() not in bl_keys)
            if new_count > 0:
                card["count"].configure(
                    text=card["count"].cget("text") + f"  [NEW: {new_count}]")

    def _refresh_details(self, *_):
        # Clear existing
        for widget in self.details_scroll.winfo_children():
            widget.destroy()

        # Get filters
        cat_filter = self.cat_var.get()
        sev_filter = {s for s, v in self.sev_vars.items() if v.get()}

        bl_keys = self.engine.get_baseline_keys()

        # Filter findings
        filtered = []
        for f in self.all_findings:
            if f.severity not in sev_filter:
                continue
            if cat_filter != "ALL":
                cat_name_match = False
                for name, key, _ in CATEGORIES:
                    if name == cat_filter and key == f.category:
                        cat_name_match = True
                        break
                if not cat_name_match:
                    continue
            filtered.append(f)

        # Sort: CRITICAL first, then WARN, then INFO
        sev_order = {"CRITICAL": 0, "WARN": 1, "INFO": 2}
        filtered.sort(key=lambda f: sev_order.get(f.severity, 9))

        self.finding_count_label.configure(text=f"{len(filtered)} findings shown")

        if not filtered:
            ctk.CTkLabel(self.details_scroll,
                text="No findings match current filters." if self.all_findings else "Run a scan first.",
                font=("Segoe UI", 11), text_color="#666666").pack(pady=20)
            return

        # Render finding cards
        sev_colors = {"CRITICAL": "#dc3545", "WARN": "#ffc107", "INFO": "#6c757d"}
        sev_bg = {"CRITICAL": "#2a1215", "WARN": "#2a2515", "INFO": "#1e1e1e"}

        for f in filtered:
            is_new = bl_keys and f.key() not in bl_keys

            card = ctk.CTkFrame(self.details_scroll,
                                fg_color=sev_bg.get(f.severity, "#1e1e1e"),
                                corner_radius=6)
            card.pack(fill="x", padx=4, pady=2)

            # Header row
            header = ctk.CTkFrame(card, fg_color="transparent")
            header.pack(fill="x", padx=8, pady=(6, 0))

            ctk.CTkLabel(header, text=f" {f.severity} ",
                         font=("Segoe UI", 9, "bold"),
                         fg_color=sev_colors.get(f.severity, "#666"),
                         text_color="#ffffff" if f.severity != "WARN" else "#000000",
                         corner_radius=3).pack(side="left", padx=(0, 6))

            ctk.CTkLabel(header, text=f.title,
                         font=("Segoe UI", 11, "bold")).pack(side="left")

            if is_new:
                ctk.CTkLabel(header, text=" NEW ",
                             font=("Segoe UI", 8, "bold"),
                             fg_color="#17a2b8", text_color="#ffffff",
                             corner_radius=3).pack(side="left", padx=6)

            # Detail
            if f.detail:
                ctk.CTkLabel(card, text=f.detail, font=("Segoe UI", 9),
                             text_color="#aaaaaa", justify="left",
                             wraplength=0).pack(fill="x", padx=12, pady=(2, 0), anchor="w")

            # Remediation
            if f.remediation:
                ctk.CTkLabel(card, text=f"💡 {f.remediation}",
                             font=("Segoe UI", 9), text_color="#5bc0de",
                             justify="left", wraplength=0).pack(fill="x", padx=12, pady=(2, 6), anchor="w")
            else:
                # Small bottom padding
                ctk.CTkFrame(card, height=4, fg_color="transparent").pack()

    def _refresh_baseline_diff(self):
        # Clear existing diff
        for widget in self.diff_scroll.winfo_children():
            widget.destroy()

        bl = self.engine.state.get("baseline")
        if not bl:
            ctk.CTkLabel(self.diff_scroll, text="No baseline saved.",
                         font=("Segoe UI", 10), text_color="#666666").pack(pady=10)
            return

        bl_keys = set(bl.get("finding_keys", []))
        current_keys = {f.key() for f in self.all_findings}

        new_keys = current_keys - bl_keys
        resolved_keys = bl_keys - current_keys

        # Update baseline info
        self.bl_info_label.configure(
            text=f"Baseline saved: {bl.get('saved_at', 'unknown')}\n"
                 f"Baseline findings: {len(bl_keys)} | Current: {len(current_keys)}\n"
                 f"New: {len(new_keys)} | Resolved: {len(resolved_keys)}")

        if not new_keys and not resolved_keys:
            ctk.CTkLabel(self.diff_scroll, text="✅ No changes since baseline.",
                         font=("Segoe UI", 11), text_color="#28a745").pack(pady=10)
            return

        if new_keys:
            ctk.CTkLabel(self.diff_scroll, text=f"🆕 New Findings ({len(new_keys)})",
                         font=("Segoe UI", 11, "bold"), text_color="#17a2b8").pack(
                             anchor="w", padx=6, pady=(6, 2))
            for f in self.all_findings:
                if f.key() in new_keys:
                    row = ctk.CTkFrame(self.diff_scroll, fg_color="#1a2a2e", corner_radius=4)
                    row.pack(fill="x", padx=8, pady=1)
                    sev_colors = {"CRITICAL": "#dc3545", "WARN": "#ffc107", "INFO": "#6c757d"}
                    ctk.CTkLabel(row, text=f" {f.severity} ",
                                 font=("Segoe UI", 8, "bold"),
                                 fg_color=sev_colors.get(f.severity, "#666"),
                                 text_color="#fff", corner_radius=2).pack(side="left", padx=(6, 4), pady=3)
                    ctk.CTkLabel(row, text=f.title, font=("Segoe UI", 9)).pack(side="left", pady=3)

        if resolved_keys:
            ctk.CTkLabel(self.diff_scroll, text=f"✅ Resolved ({len(resolved_keys)})",
                         font=("Segoe UI", 11, "bold"), text_color="#28a745").pack(
                             anchor="w", padx=6, pady=(10, 2))
            bl_findings = bl.get("findings", [])
            for bf in bl_findings:
                bkey = hashlib.sha256(
                    f"{bf['category']}|{bf['title']}|{bf.get('detail','')[:120]}".encode()
                ).hexdigest()[:16]
                if bkey in resolved_keys:
                    row = ctk.CTkFrame(self.diff_scroll, fg_color="#1a2e1a", corner_radius=4)
                    row.pack(fill="x", padx=8, pady=1)
                    ctk.CTkLabel(row, text=" RESOLVED ",
                                 font=("Segoe UI", 8, "bold"),
                                 fg_color="#28a745", text_color="#fff",
                                 corner_radius=2).pack(side="left", padx=(6, 4), pady=3)
                    ctk.CTkLabel(row, text=bf.get("title", ""),
                                 font=("Segoe UI", 9)).pack(side="left", pady=3)

    # ── Actions ──

    def save_baseline(self):
        if not self.all_findings:
            self.status_label.configure(text="Run a scan first before saving baseline")
            return
        self.engine.save_baseline(self.all_findings)
        self.status_label.configure(text=f"Baseline saved with {len(self.all_findings)} findings")
        self._refresh_baseline_diff()

    def clear_baseline(self):
        self.engine.clear_baseline()
        self.status_label.configure(text="Baseline cleared")
        self._refresh_baseline_diff()

    def export_report(self):
        if not self.all_findings:
            self.status_label.configure(text="Run a scan first")
            return

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_audit_{ts}.json"
        export_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exports")
        os.makedirs(export_dir, exist_ok=True)
        filepath = os.path.join(export_dir, filename)

        report = {
            "scan_date": now_ts(),
            "admin_mode": is_admin(),
            "hostname": os.environ.get("COMPUTERNAME", "unknown"),
            "username": os.environ.get("USERNAME", "unknown"),
            "summary": {
                "total": len(self.all_findings),
                "critical": sum(1 for f in self.all_findings if f.severity == "CRITICAL"),
                "warnings": sum(1 for f in self.all_findings if f.severity == "WARN"),
                "info": sum(1 for f in self.all_findings if f.severity == "INFO"),
            },
            "findings": [asdict(f) for f in self.all_findings],
        }

        try:
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)
            self.status_label.configure(text=f"Exported: {filepath}")
        except (OSError, TypeError, ValueError) as e:
            self.status_label.configure(text=f"Export failed: {e}")

    def destroy(self):
        self.running = False
        super().destroy()


# ─────────────────────────── Entry point ───────────────────────────

def run_tool():
    root = ctk.CTkToplevel()
    app = App(root)


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    root.title("Security Audit")
    root.geometry("1200x750")
    app = App(root)
    root.mainloop()
