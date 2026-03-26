"""
network_stability_monitor_pro.py

NETWORK STABILITY MONITOR PRO - AI Enhanced (Windows 10)

Advanced Features:
- AI-powered root cause analysis (Router/ISP/DNS/Adapter/Suspicious)
- Suspicious behavior detection and security monitoring
- Human-readable explanations with evidence
- AI-friendly export for ChatGPT analysis (under 50KB)
- Intelligent probability-based reasoning

Dependencies:
  pip install psutil customtkinter
"""

import os
import re
import json
import time
import queue
import threading
import subprocess
import concurrent.futures
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Handle optional dependencies gracefully
try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False
    ctk = None

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    from network_intelligence_engine import (
        NetworkIntelligenceEngine,
        RootCauseProbability,
        SuspiciousIndicators,
        AnomalyFlags
    )
    HAS_INTELLIGENCE = True
except ImportError:
    HAS_INTELLIGENCE = False
    NetworkIntelligenceEngine = None
    RootCauseProbability = None
    SuspiciousIndicators = None
    AnomalyFlags = None

TOOL_NAME = "Network Stability Monitor Pro"

# =========================
# Auto Export Configuration
# =========================
AUTO_EXPORT_ENABLED = True
AUTO_EXPORT_TIME = "23:30"   # HH:MM
EXPORT_FOLDER = "exports"

# =========================
# Helpers
# =========================

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def safe_run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, shell=False)
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:
        return 1, "", str(e)

def parse_ipv4(s: str) -> List[str]:
    return re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", s)

def short(s: str, n: int = 220) -> str:
    s = s.replace("\r", "")
    return s[:n] + ("..." if len(s) > n else "")

def get_default_gateway() -> Optional[str]:
    rc, out, _ = safe_run(["route", "print"], timeout=10)
    if rc == 0:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0.0.0.0"):
                parts = re.split(r"\s+", line)
                if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                    gw = parts[2]
                    if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                        return gw
    return None

def get_dns_servers() -> List[str]:
    rc, out, _ = safe_run(["ipconfig", "/all"], timeout=12)
    if rc != 0:
        return []
    servers: List[str] = []
    collecting = False
    for line in out.splitlines():
        if "DNS Servers" in line:
            collecting = True
            servers.extend(parse_ipv4(line))
            continue
        if collecting:
            if line and not line.startswith(" "):
                collecting = False
            else:
                servers.extend(parse_ipv4(line))
    seen = set()
    res = []
    for s in servers:
        if s not in seen:
            seen.add(s)
            res.append(s)
    return res

def get_default_route_interface_ip() -> Tuple[str, str]:
    """
    Returns (local_ip, interface_name_guess)
    Uses: route print 0.0.0.0 -> Interface column (IPv4)
    Then maps that interface IP to a psutil interface name
    """
    rc, out, _ = safe_run(["route", "print", "0.0.0.0"], timeout=10)
    if rc != 0:
        return "", ""

    local_ip = ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("0.0.0.0"):
            parts = re.split(r"\s+", line)
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                iface_ip = parts[3]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", iface_ip):
                    local_ip = iface_ip
                    break

    if not local_ip:
        return "", ""

    if HAS_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            for ifname, addr_list in addrs.items():
                for a in addr_list:
                    if str(a.family) == "AddressFamily.AF_INET" or int(getattr(a.family, "value", 0) or 0) == 2:
                        if a.address == local_ip:
                            return local_ip, ifname
        except Exception:
            pass

    return local_ip, ""

def ping_once(target: str, timeout_ms: int = 800) -> Tuple[bool, Optional[float], str]:
    rc, out, err = safe_run(["ping", "-n", "1", "-w", str(timeout_ms), target], timeout=max(2, int(timeout_ms/200)+2))
    raw = out + ("\n" + err if err else "")
    m = re.search(r"time[=<]\s*(\d+)\s*ms", raw, re.IGNORECASE)
    rtt = float(m.group(1)) if m else None
    success = ("TTL=" in raw) or ("Reply from" in raw and "Destination host unreachable" not in raw)
    return success, rtt, raw

def nslookup(domain: str, server: Optional[str], timeout_s: int = 4) -> Tuple[str, str]:
    """
    Returns (dns_state, raw)
    dns_state: OK | SLOW | FAIL
    """
    cmd = ["nslookup", domain]
    if server:
        cmd.append(server)
    rc, out, err = safe_run(cmd, timeout=timeout_s)
    raw = out + ("\n" + err if err else "")
    low = raw.lower()

    has_ip = len(parse_ipv4(raw)) > 0
    has_timeout = "timed out" in low
    has_nxdomain = ("non-existent" in low) or ("can't find" in low)

    if has_nxdomain:
        return "FAIL", raw

    if has_timeout and has_ip:
        return "SLOW", raw
    if has_timeout and not has_ip:
        return "FAIL", raw

    return ("OK" if has_ip else "FAIL"), raw

def netsh_wlan_info() -> Dict[str, str]:
    rc, out, _ = safe_run(["netsh", "wlan", "show", "interfaces"], timeout=6)
    if rc != 0:
        return {}
    def grab(key: str) -> str:
        m = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+)\s*$", out, re.MULTILINE | re.IGNORECASE)
        return m.group(1).strip() if m else ""
    info = {
        "state": grab("State"),
        "ssid": grab("SSID"),
        "bssid": grab("BSSID"),
        "signal": grab("Signal"),
        "radio": grab("Radio type"),
        "channel": grab("Channel"),
        "rx_rate": grab("Receive rate (Mbps)"),
        "tx_rate": grab("Transmit rate (Mbps)"),
    }
    return {k: v for k, v in info.items() if v}

def parse_ts(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def duration_str(start_ts: str, end_ts: str) -> str:
    a = parse_ts(start_ts)
    b = parse_ts(end_ts)
    if not a or not b:
        return ""
    sec = int(max(0, (b - a).total_seconds()))
    if sec < 60:
        return f"{sec}s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{m}m {s}s"
    h, m = divmod(m, 60)
    return f"{h}h {m}m"


# =========================
# Data
# =========================

@dataclass
class Sample:
    timestamp: str
    local_ip: str
    iface: str
    gateway_ip: str
    dns_servers: List[str]
    wifi_state: str
    wifi_signal: str
    wifi_ssid: str

    gw_ok: bool
    gw_rtt: Optional[float]
    inet_ok: bool
    inet_rtt: Optional[float]
    inet2_ok: bool
    inet2_rtt: Optional[float]

    dns_state: str  # OK | SLOW | FAIL
    dns_raw_hint: str

    status: str     # OK | DEGRADED | DOWN
    reason: str     # summary

    # Wi-Fi details
    wifi_bssid: str = ""
    wifi_channel: str = ""
    wifi_radio: str = ""        # e.g. "802.11ac", "802.11ax"
    wifi_signal_pct: int = -1   # parsed integer signal %

    # Enhanced intelligence fields
    root_cause: Optional[RootCauseProbability] = None
    explanation: str = ""
    suspicion_level: str = "NONE"
    anomaly_flags: Optional[AnomalyFlags] = None

@dataclass
class Event:
    timestamp: str
    severity: str   # INFO|WARN|HIGH
    category: str   # LINK|GATEWAY|ISP|DNS|DEGRADED|CONFIG
    title: str
    details: Dict

@dataclass
class Incident:
    """
    Combined 'problem + recovery' record.
    """
    id: int
    start_time: str
    end_time: str             # empty until recovered
    duration: str             # computed at end
    severity: str             # highest severity seen during incident
    category: str             # primary category at start
    start_status: str         # DEGRADED/DOWN
    end_status: str           # OK
    cause: str                # reason
    details: Dict
    cause_timeline: List[Dict] = None  # New field for tracking cause changes

# =========================

class NetworkStabilityEngine:
    def __init__(self, state_path: str):
        self.state_path = state_path
        self.samples: List[Sample] = []
        self.events: List[Event] = []
        self.incidents: List[Incident] = []

        self.baseline_gateway: str = ""
        self.baseline_dns: List[str] = []

        self.last_status: str = ""
        self.last_reason: str = ""

        self.last_gateway_seen: str = ""
        self.last_dns_seen: List[str] = []

        self._baseline_gw_warn_fired: bool = False
        self._baseline_dns_warn_fired: bool = False
        self._last_diagnostic_event: float = 0.0
        self._start_time: float = time.time()

        # Latency thresholds (can be updated from the App)
        self.thresh_elevated: int = 200
        self.thresh_high: int = 400

        self.flap_window: List[Tuple[float, str]] = []
        self._last_flap_log_at: float = 0.0

        self.roll: Dict[str, List[Tuple[float, bool, Optional[float]]]] = {
            "gw": [],
            "inet1": [],
            "inet2": [],
        }

        # Wi-Fi signal tracking
        self.signal_history: List[Tuple[float, int]] = []  # (timestamp, signal_pct)
        self.baseline_bssid: str = ""
        self.last_bssid_seen: str = ""
        self._bssid_change_warned: bool = False

        # incident tracking
        self._next_incident_id = 1
        self.active_incidents: Dict[Tuple[str, str], int] = {}  # (category, reason) -> incident_id
        self.last_export_timestamp: Optional[datetime] = None
        self.last_export_minute_key: Optional[str] = None
        
        # Parse export time from AUTO_EXPORT_TIME
        self.export_hour = 23
        self.export_minute = 30
        try:
            h, m = AUTO_EXPORT_TIME.split(":")
            self.export_hour = int(h)
            self.export_minute = int(m)
        except Exception:
            pass
        
        # Enhanced intelligence engine (if available)
        if HAS_INTELLIGENCE:
            self.intelligence = NetworkIntelligenceEngine()
        else:
            self.intelligence = None

        self._load_state()

    def _load_state(self):
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.baseline_gateway = data.get("baseline_gateway", "") or ""
            self.baseline_dns = data.get("baseline_dns", []) or []
        except Exception:
            pass

    def save_state(self):
        try:
            data = {
                "baseline_gateway": self.baseline_gateway,
                "baseline_dns": self.baseline_dns,
                "saved_at": now_ts(),
            }
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def log_event(self, severity: str, category: str, title: str, details: Dict):
        self.events.append(Event(now_ts(), severity, category, title, details))
        if len(self.events) > 2000:
            self.events = self.events[-1600:]

    def add_sample(self, s: Sample):
        self.samples.append(s)
        if len(self.samples) > 3000:
            self.samples = self.samples[-2400:]

    def set_baseline(self, gateway: str, dns_servers: List[str], local_ip: str = ""):
        self.baseline_gateway = gateway
        self.baseline_dns = dns_servers[:]
        if self.intelligence:
            self.intelligence.update_baseline(gateway, dns_servers, local_ip)
        self.save_state()
        self.log_event("INFO", "CONFIG", "Baseline updated", {"gateway": gateway, "dns_servers": dns_servers})

    def _roll_add(self, key: str, ok: bool, rtt: Optional[float]):
        t = time.time()
        self.roll[key].append((t, ok, rtt))
        self.roll[key] = [(ts, o, r) for (ts, o, r) in self.roll[key] if t - ts <= 60]

    def _roll_loss(self, key: str) -> float:
        w = self.roll[key]
        if not w:
            return 0.0
        fails = sum(1 for _, ok, _ in w if not ok)
        return fails / max(1, len(w))

    def _roll_max_rtt(self, key: str) -> Optional[float]:
        rtts = [r for _, ok, r in self.roll[key] if ok and r is not None]
        return max(rtts) if rtts else None

    def classify(self,
                 local_ip: str,
                 wifi: Dict[str, str],
                 gw: str,
                 gw_ok: bool, gw_rtt: Optional[float],
                 inet_ok: bool, inet_rtt: Optional[float],
                 inet2_ok: bool, inet2_rtt: Optional[float],
                 dns_state: str) -> Tuple[str, str, str, str]:
        wifi_state = wifi.get("state", "").lower()
        wifi_connected = ("connected" in wifi_state) if wifi_state else True

        # Signal correlation hint — appended to reason when signal is weak
        sig_hint = ""
        sig_corr = self.signal_correlated_with_issue()
        if sig_corr:
            sig_hint = f" [Wi-Fi: {sig_corr}]"

        if not wifi_connected:
            return "DOWN", "Wi-Fi disconnected (link down)", "HIGH", "LINK"

        if not local_ip:
            return "DOWN", "No local IPv4 on default route (adapter/DHCP issue)", "HIGH", "LINK"

        if gw and (not gw_ok) and (not inet_ok) and (not inet2_ok):
            return "DOWN", f"Gateway unreachable and internet down (router/Wi-Fi issue){sig_hint}", "HIGH", "GATEWAY"

        if (not inet_ok) and (not inet2_ok) and (gw_ok or not gw):
            return "DOWN", f"Internet unreachable (ISP/WAN outage) while local network seems up{sig_hint}", "HIGH", "ISP"

        if (inet_ok or inet2_ok) and dns_state == "FAIL":
            return "DEGRADED", f"DNS failing while internet reachable (DNS issue){sig_hint}", "WARN", "DNS"
        if (inet_ok or inet2_ok) and dns_state == "SLOW":
            return "DEGRADED", f"DNS slow/timeouts (intermittent DNS issue){sig_hint}", "INFO", "DNS"

        loss1 = self._roll_loss("inet1")
        loss2 = self._roll_loss("inet2")
        if max(loss1, loss2) >= 0.25:
            return "DEGRADED", f"Packet loss detected (internet) ~{max(loss1, loss2)*100:.0f}% (last 60s){sig_hint}", "WARN", "DEGRADED"

        rtts = [r for r in [gw_rtt, inet_rtt, inet2_rtt] if r is not None]
        mx = max(rtts) if rtts else None
        if mx is not None:
            if mx >= self.thresh_high:
                return "DEGRADED", f"High latency detected (max {mx:.0f} ms){sig_hint}", "WARN", "DEGRADED"
            if mx >= self.thresh_elevated:
                return "DEGRADED", f"Latency elevated (max {mx:.0f} ms){sig_hint}", "INFO", "DEGRADED"

        if gw and (not gw_ok) and (inet_ok or inet2_ok):
            return "DEGRADED", f"Gateway ping failing but internet OK (router ICMP blocked/rate-limited){sig_hint}", "INFO", "GATEWAY"

        return "OK", "Stable", "INFO", "DEGRADED"

    def detect_config_changes(self, gateway_ip: str, dns_servers: List[str]):
        if gateway_ip and gateway_ip != self.last_gateway_seen:
            if self.last_gateway_seen:
                self.log_event("WARN", "CONFIG", "Gateway IP changed", {"old": self.last_gateway_seen, "new": gateway_ip})
            self.last_gateway_seen = gateway_ip

        if dns_servers != self.last_dns_seen:
            if self.last_dns_seen:
                self.log_event("WARN", "CONFIG", "DNS servers changed", {"old": self.last_dns_seen, "new": dns_servers})
            self.last_dns_seen = dns_servers[:]

        if self.baseline_gateway and gateway_ip and gateway_ip != self.baseline_gateway:
            if not self._baseline_gw_warn_fired:
                self._baseline_gw_warn_fired = True
                self.log_event("WARN", "CONFIG", "Current gateway differs from baseline", {"baseline": self.baseline_gateway, "current": gateway_ip})
        elif self.baseline_gateway and gateway_ip and gateway_ip == self.baseline_gateway:
            self._baseline_gw_warn_fired = False

        if self.baseline_dns and dns_servers and dns_servers != self.baseline_dns:
            if not self._baseline_dns_warn_fired:
                self._baseline_dns_warn_fired = True
                self.log_event("WARN", "CONFIG", "Current DNS differs from baseline", {"baseline": self.baseline_dns, "current": dns_servers})
        elif self.baseline_dns and dns_servers and dns_servers == self.baseline_dns:
            self._baseline_dns_warn_fired = False

    def detect_flapping(self, status: str):
        t = time.time()
        self.flap_window.append((t, status))
        self.flap_window = [(ts, st) for (ts, st) in self.flap_window if t - ts <= 300]

        transitions = 0
        prev = None
        for _, st in self.flap_window:
            if prev is None:
                prev = st
                continue
            if st != prev:
                transitions += 1
                prev = st

        if transitions >= 6:
            if (t - self._last_flap_log_at) >= 60:
                self._last_flap_log_at = t
                # NOTE: flapping is an event, not an incident
                self.log_event("WARN", "DEGRADED", "Frequent network state changes (flapping)", {"transitions_last_5min": transitions})

    # ---------- Wi-Fi signal & BSSID tracking ----------

    def track_signal(self, signal_pct: int):
        """Track Wi-Fi signal strength over time."""
        if signal_pct < 0:
            return
        t = time.time()
        self.signal_history.append((t, signal_pct))
        # Keep last 5 minutes
        self.signal_history = [(ts, s) for ts, s in self.signal_history if t - ts <= 300]

    def get_signal_avg(self, window_sec: int = 60) -> Optional[float]:
        """Average signal % over last N seconds."""
        t = time.time()
        vals = [s for ts, s in self.signal_history if t - ts <= window_sec]
        return sum(vals) / len(vals) if vals else None

    def get_signal_min(self, window_sec: int = 60) -> Optional[int]:
        """Min signal % over last N seconds."""
        t = time.time()
        vals = [s for ts, s in self.signal_history if t - ts <= window_sec]
        return min(vals) if vals else None

    def signal_correlated_with_issue(self) -> Optional[str]:
        """Check if current issues correlate with weak Wi-Fi signal."""
        avg = self.get_signal_avg(60)
        mn = self.get_signal_min(60)
        if avg is None:
            return None
        if avg < 30:
            return f"Very weak Wi-Fi signal ({avg:.0f}% avg) — likely cause of instability"
        if avg < 50 and mn is not None and mn < 25:
            return f"Weak Wi-Fi signal ({avg:.0f}% avg, dipped to {mn}%) — probable cause"
        if avg < 60:
            return f"Below-average Wi-Fi signal ({avg:.0f}% avg) — may contribute to issues"
        return None

    def detect_bssid_change(self, bssid: str, ssid: str):
        """Detect BSSID changes — potential evil twin AP attack."""
        if not bssid:
            return
        bssid_upper = bssid.upper().strip()

        # Set baseline on first observation
        if not self.baseline_bssid:
            self.baseline_bssid = bssid_upper
            self.last_bssid_seen = bssid_upper
            self.log_event("INFO", "CONFIG", "Wi-Fi BSSID baseline set",
                           {"bssid": bssid_upper, "ssid": ssid})
            return

        if bssid_upper != self.last_bssid_seen:
            old_bssid = self.last_bssid_seen
            self.last_bssid_seen = bssid_upper

            if bssid_upper != self.baseline_bssid:
                # BSSID changed from baseline — possible evil twin or roaming
                self.log_event("HIGH", "SECURITY",
                    "BSSID changed! Possible evil twin AP or Wi-Fi roaming",
                    {"baseline_bssid": self.baseline_bssid,
                     "previous_bssid": old_bssid,
                     "current_bssid": bssid_upper,
                     "ssid": ssid,
                     "warning": "If you have only ONE router, this is suspicious — "
                                "someone may have set up a fake access point with "
                                "the same SSID to intercept your traffic."})
            else:
                # Returned to baseline
                if old_bssid != self.baseline_bssid:
                    self.log_event("INFO", "CONFIG", "BSSID returned to baseline",
                                   {"bssid": bssid_upper, "ssid": ssid})

    # ---------- Incident logic ----------
    def _sev_rank(self, s: str) -> int:
        return {"INFO": 1, "WARN": 2, "HIGH": 3}.get(s, 0)

    def _sev_max(self, a: str, b: str) -> str:
        return a if self._sev_rank(a) >= self._sev_rank(b) else b

    def on_state_update(self, status: str, category: str, severity: str, reason: str, details: Dict):
        """
        Called every sample cycle after classify().
        Creates/updates incidents based on category and reason combinations.
        """
        # Normalize variable reasons so fluctuating values don't create separate incidents
        normalized_reason = reason
        if "Packet loss detected" in reason:
            normalized_reason = "Packet loss detected"
        elif "High latency detected" in reason:
            normalized_reason = "High latency detected"
        elif "Latency elevated" in reason:
            normalized_reason = "Latency elevated"
        elif "Gateway unreachable" in reason:
            normalized_reason = "Gateway unreachable and internet down"
        elif "Internet unreachable" in reason:
            normalized_reason = "Internet unreachable"
        elif "DNS slow" in reason:
            normalized_reason = "DNS slow/timeouts"
        elif "DNS failing" in reason:
            normalized_reason = "DNS failing"
        elif "Wi-Fi:" in reason:
            # Strip the signal correlation hint for grouping
            normalized_reason = reason.split(" [Wi-Fi:")[0]
            # Re-normalize after stripping hint
            if "High latency detected" in normalized_reason:
                normalized_reason = "High latency detected"
            elif "Latency elevated" in normalized_reason:
                normalized_reason = "Latency elevated"
            elif "Packet loss detected" in normalized_reason:
                normalized_reason = "Packet loss detected"

        key = (category, normalized_reason)
        
        # Start incident when leaving OK
        if status in ("DEGRADED", "DOWN"):
            # Create new incident if this (category, reason) combination doesn't exist
            if key not in self.active_incidents:
                inc = Incident(
                    id=self._next_incident_id,
                    start_time=now_ts(),
                    end_time="",
                    duration="",
                    severity=severity,
                    category=category,
                    start_status=status,
                    end_status="OK",
                    cause=reason,
                    details={
                        "start_reason": reason,
                        "start_category": category,
                        "start_severity": severity,
                        **(details or {}),
                    },
                    cause_timeline=[{
                        "timestamp": now_ts(),
                        "category": category,
                        "reason": reason
                    }]
                )
                self.active_incidents[key] = inc.id
                self._next_incident_id += 1
                self.incidents.append(inc)
            else:
                # Update existing incident with same category/reason
                incident_id = self.active_incidents[key]
                inc = self._find_incident(incident_id)
                if inc:
                    inc.severity = self._sev_max(inc.severity, severity)
                    inc.details["latest_reason"] = reason
                    inc.details["latest_category"] = category
                    inc.details["latest_severity"] = severity
                    inc.cause = reason
                    
                    # Add to cause timeline if reason changed
                    if inc.cause_timeline:
                        last_entry = inc.cause_timeline[-1]
                        if last_entry["reason"] != reason:
                            inc.cause_timeline.append({
                                "timestamp": now_ts(),
                                "category": category,
                                "reason": reason
                            })
        
        # End incidents on recovery to OK - close ALL active incidents
        if status == "OK":
            incidents_to_close = list(self.active_incidents.items())
            
            for (cat, rsn), incident_id in incidents_to_close:
                inc = self._find_incident(incident_id)
                if inc and not inc.end_time:
                    inc.end_time = now_ts()
                    inc.duration = duration_str(inc.start_time, inc.end_time)
                    inc.details["end_reason"] = reason
                del self.active_incidents[(cat, rsn)]

    def _find_incident(self, incident_id: int) -> Optional[Incident]:
        for inc in reversed(self.incidents):
            if inc.id == incident_id:
                return inc
        return None

    # ---------- Auto Export Methods ----------
    def auto_export_check(self, enabled_var, hour_var, folder_var):
        """Check if auto export should run and execute if needed"""
        if not enabled_var.get():  # Use UI variable
            return
            
        current_time = datetime.now()
        
        # Check if it's export hour AND minute
        minute_key = current_time.strftime("%Y%m%d_%H%M")
        
        if (
            current_time.hour == self.export_hour and
            current_time.minute == self.export_minute and
            self.last_export_minute_key != minute_key
        ):
            self.last_export_minute_key = minute_key
            self.run_auto_export(folder_var)
                
    def run_auto_export(self, folder_var):
        """Execute automatic export"""
        try:
            # Get export folder from UI variable
            export_folder = folder_var.get()
            
            # Create export folder if it doesn't exist
            os.makedirs(export_folder, exist_ok=True)
            
            # Generate export filename
            current_time = datetime.now()
            filename = f"network_export_{current_time.strftime('%Y%m%d_%H%M')}.json"
            filepath = os.path.join(export_folder, filename)
            
            # Prepare export data
            export_data = self._prepare_export_data(current_time)
            
            # Write export file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
                
            # Update last export timestamp
            self.last_export_timestamp = current_time
            
            # Log export event
            self.log_event("INFO", "EXPORT", "Auto export completed", {
                "filename": filename,
                "incidents_count": len(export_data["incidents"]),
                "events_count": len(export_data["events"])
            })
            
        except Exception as e:
            self.log_event("HIGH", "EXPORT", "Auto export failed", {"error": str(e)})
            
    def _prepare_export_data(self, current_time: datetime) -> Dict[str, Any]:
        """Prepare data for export"""
        # Filter incidents since last export
        incidents_to_export = []
        if self.last_export_timestamp:
            # Only include incidents after last export
            for inc in self.incidents:
                inc_start = parse_ts(inc.start_time)
                if inc_start and inc_start >= self.last_export_timestamp:
                    incidents_to_export.append(asdict(inc))
        else:
            # Include all incidents if no previous export
            incidents_to_export = [asdict(inc) for inc in self.incidents]
            
        # Filter events since last export
        events_to_export = []
        if self.last_export_timestamp:
            for event in self.events:
                event_time = parse_ts(event.timestamp)
                if event_time and event_time >= self.last_export_timestamp:
                    events_to_export.append(asdict(event))
        else:
            events_to_export = [asdict(event) for event in self.events]
            
        # Calculate statistics
        stats = self._calculate_export_statistics(incidents_to_export)
        
        # Determine period start/end
        period_start = self.last_export_timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.last_export_timestamp else incidents_to_export[0]["start_time"] if incidents_to_export else current_time.strftime("%Y-%m-%d %H:%M:%S")
        period_end = current_time.strftime("%Y-%m-%d %H:%M:%S")
        
        return {
            "export_time": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "period_start": period_start,
            "period_end": period_end,
            "incidents": incidents_to_export,
            "events": events_to_export,
            "stats": stats
        }
        
    def _calculate_export_statistics(self, incidents: List[Dict]) -> Dict[str, Any]:
        """Calculate statistics for export"""
        if not incidents:
            return {
                "total_incidents": 0,
                "incident_by_category": {},
                "average_duration_seconds": 0.0,
                "incidents_per_hour": {f"{i:02d}": 0 for i in range(24)}
            }
            
        # Count incidents by category
        incident_by_category = {}
        for inc in incidents:
            cat = inc["category"]
            incident_by_category[cat] = incident_by_category.get(cat, 0) + 1
            
        # Calculate average duration
        durations = []
        for inc in incidents:
            if inc["end_time"] and inc["start_time"]:
                start = parse_ts(inc["start_time"])
                end = parse_ts(inc["end_time"])
                if start and end:
                    durations.append((end - start).total_seconds())
                    
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        
        # Count incidents per hour
        incidents_per_hour = {f"{i:02d}": 0 for i in range(24)}
        for inc in incidents:
            start_time = parse_ts(inc["start_time"])
            if start_time:
                hour_key = f"{start_time.hour:02d}"
                incidents_per_hour[hour_key] += 1
                
        return {
            "total_incidents": len(incidents),
            "incident_by_category": incident_by_category,
            "average_duration_seconds": avg_duration,
            "incidents_per_hour": incidents_per_hour
        }

    # ---------- Enhanced Intelligence Methods ----------
    def get_rolling_stats(self) -> Dict[str, Any]:
        """Get comprehensive rolling statistics for intelligence analysis"""
        return {
            'gw_loss_percent': self._roll_loss('gw') * 100,
            'inet1_loss_percent': self._roll_loss('inet1') * 100,
            'inet2_loss_percent': self._roll_loss('inet2') * 100,
            'gw_max_latency': self._roll_max_rtt('gw') or 0,
            'inet1_max_latency': self._roll_max_rtt('inet1') or 0,
            'inet2_max_latency': self._roll_max_rtt('inet2') or 0,
            'max_latency_ms': max([self._roll_max_rtt('gw') or 0, 
                                   self._roll_max_rtt('inet1') or 0, 
                                   self._roll_max_rtt('inet2') or 0]),
            'packet_loss_percent': max(self._roll_loss('inet1'), self._roll_loss('inet2')) * 100,
            'dns_fail_rate': self._get_dns_fail_rate(),
            'state_transitions': len([i for i in range(len(self.flap_window)-1) 
                                    if self.flap_window[i][1] != self.flap_window[i+1][1]])
        }
    
    def _get_dns_fail_rate(self) -> float:
        """Calculate DNS failure rate from recent samples"""
        recent_samples = [s for s in self.samples[-30:] if s.dns_state in ['OK', 'FAIL', 'SLOW']]
        if not recent_samples:
            return 0.0
        fails = sum(1 for s in recent_samples if s.dns_state == 'FAIL')
        return (fails / len(recent_samples)) * 100
    
    def enhance_sample_with_intelligence(self, sample: Sample) -> Sample:
        """Enhance a sample with intelligence analysis"""
        # Convert sample to dict for analysis
        sample_dict = {
            'local_ip': sample.local_ip,
            'gateway_ip': sample.gateway_ip,
            'dns_servers': sample.dns_servers,
            'wifi_state': sample.wifi_state,
            'gw_ok': sample.gw_ok,
            'gw_rtt': sample.gw_rtt,
            'inet_ok': sample.inet_ok,
            'inet_rtt': sample.inet_rtt,
            'inet2_ok': sample.inet2_ok,
            'inet2_rtt': sample.inet2_rtt,
            'dns_state': sample.dns_state,
            'status': sample.status,
            'wifi_signal': sample.wifi_signal,
            'iface': sample.iface
        }
        
        rolling_stats = self.get_rolling_stats()
        
        # Track configuration and state changes
        current_time = time.time()
        self.intelligence.track_configuration(
            sample.gateway_ip, sample.dns_servers, sample.local_ip, current_time
        )
        self.intelligence.track_state_changes(sample.status, current_time)
        
        # Detect anomalies
        anomalies = self.intelligence.detect_anomalies(sample_dict, rolling_stats)
        
        # Calculate root cause probabilities
        root_cause = self.intelligence.calculate_root_cause_probability(
            sample_dict, rolling_stats, anomalies
        )
        
        # Generate explanation
        explanation = self.intelligence.generate_explanation(
            sample_dict, rolling_stats, anomalies, root_cause
        )
        
        # Get suspicion level
        suspicion_level = self.intelligence.detect_suspicious_indicators(current_time).suspicion_level()
        
        # Update sample with intelligence data
        sample.root_cause = root_cause
        sample.explanation = explanation
        sample.suspicion_level = suspicion_level
        sample.anomaly_flags = anomalies
        
        return sample
    
    def generate_ai_export(self) -> Dict[str, Any]:
        """Generate AI-friendly export data"""
        if not self.samples:
            return {}
        
        current_sample = self.samples[-1]
        rolling_stats = self.get_rolling_stats()
        incidents_data = [asdict(inc) for inc in self.incidents]
        
        # Handle missing intelligence engine gracefully
        if self.intelligence:
            try:
                return self.intelligence.generate_ai_export(
                    asdict(current_sample),
                    rolling_stats,
                    incidents_data,
                    current_sample.anomaly_flags or AnomalyFlags(),
                    current_sample.root_cause or RootCauseProbability()
                )
            except Exception as e:
                print(f"Intelligence export failed: {e}")
                # Fall back to basic export
        
        # Basic AI-friendly export without intelligence engine
        return {
            "summary": {
                "timestamp": current_sample.timestamp,
                "status": current_sample.status,
                "reason": current_sample.reason,
                "samples_collected": len(self.samples),
                "incidents_count": len(self.incidents),
                "events_count": len(self.events)
            },
            "current_metrics": {
                "local_ip": current_sample.local_ip,
                "gateway_ip": current_sample.gateway_ip,
                "dns_servers": current_sample.dns_servers,
                "wifi_state": current_sample.wifi_state,
                "wifi_signal": current_sample.wifi_signal,
                "wifi_ssid": current_sample.wifi_ssid,
                "gateway_ping": {"ok": current_sample.gw_ok, "rtt_ms": current_sample.gw_rtt},
                "internet_ping_1": {"ok": current_sample.inet_ok, "rtt_ms": current_sample.inet_rtt},
                "internet_ping_2": {"ok": current_sample.inet2_ok, "rtt_ms": current_sample.inet2_rtt},
                "dns_state": current_sample.dns_state
            },
            "rolling_stats": rolling_stats,
            "recent_incidents": incidents_data[-5:],  # Last 5 incidents
            "baseline": {
                "gateway": self.baseline_gateway,
                "dns_servers": self.baseline_dns
            }
        }
# Base class for App depending on available GUI framework
if HAS_CTK:
    AppBase = ctk.CTkFrame
else:
    AppBase = tk.Frame

class App(AppBase):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        parent.title("Network Stability Monitor Pro")
        parent.geometry("1280x780")
        
        # Remove aggressive focus management to prevent ghost trails
        # Just set window normally without topmost tricks
        
        self.state_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "net_stability_state.json")
        self.engine = NetworkStabilityEngine(self.state_path)

        self.running = True
        self.work_q: "queue.Queue[str]" = queue.Queue()

        self.interval_ms = tk.IntVar(value=3000)
        self.ping_timeout_ms = tk.IntVar(value=1500)

        # Auto export configuration
        self.auto_export_enabled = tk.BooleanVar(value=AUTO_EXPORT_ENABLED)
        _h, _m = 23, 30
        try:
            _h, _m = int(AUTO_EXPORT_TIME.split(":")[0]), int(AUTO_EXPORT_TIME.split(":")[1])
        except Exception:
            pass
        self.auto_export_hour = tk.IntVar(value=_h)
        self.auto_export_minute = tk.IntVar(value=_m)
        self.export_folder = tk.StringVar(value=EXPORT_FOLDER)

        # Latency threshold variables
        self.thresh_elevated = tk.IntVar(value=200)
        self.thresh_high = tk.IntVar(value=400)

        gw = get_default_gateway() or ""
        ip, ifname = get_default_route_interface_ip()
        dns = get_dns_servers()

        self.gateway = tk.StringVar(value=gw)
        self.localip = tk.StringVar(value=ip)
        self.iface = tk.StringVar(value=ifname)
        self.dns_text = tk.StringVar(value=", ".join(dns) if dns else "")

        self.target1 = tk.StringVar(value="8.8.8.8")
        self.target2 = tk.StringVar(value="1.1.1.1")
        self.dns_domain = tk.StringVar(value="google.com")

        self._last_sample: Optional[Sample] = None
        self._last_diag: Dict[str, str] = {}
        self._refresh_counter: int = 0

        # log filter state
        self.filter_category = tk.StringVar(value="ALL")

        # Set initial baseline if we have network info
        if gw or dns:
            self.engine.set_baseline(gw, dns, ip)
        
        # Log startup event
        self.engine.log_event(
            "INFO", 
            "CONFIG", 
            "Network Monitor Started",
            {
                "gateway": gw,
                "local_ip": ip,
                "interface": ifname,
                "dns_servers": dns,
                "has_intelligence": self.engine.intelligence is not None,
                "monitoring_interval_ms": 2000
            }
        )

        self._build_ui()

        threading.Thread(target=self._worker_loop, daemon=True).start()
        # Start monitoring immediately
        self.after(100, self.tick)

    def _build_ui(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(top, text="Local IP (default route)").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.localip, width=110).pack(side="left", padx=6)
        ctk.CTkLabel(top, text="Iface").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.iface, width=120).pack(side="left", padx=6)

        ctk.CTkLabel(top, text="Gateway").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.gateway, width=110).pack(side="left", padx=6)

        ctk.CTkLabel(top, text="DNS").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.dns_text, width=220).pack(side="left", padx=6)

        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)

        ctk.CTkLabel(top, text="Ping targets").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.target1, width=90).pack(side="left", padx=4)
        ctk.CTkEntry(top, textvariable=self.target2, width=90).pack(side="left", padx=4)

        ctk.CTkLabel(top, text="DNS domain").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.dns_domain, width=120).pack(side="left", padx=6)

        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)

        ctk.CTkButton(top, text="Settings", command=self.show_settings).pack(side="left", padx=6)
        ctk.CTkButton(top, text="AI Export", command=self.ai_export).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Export report", command=self.export_report).pack(side="left", padx=6)

        nb = ctk.CTkTabview(self)
        nb.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.tab_overview = nb.add("Overview")
        self.tab_incidents = nb.add("Incidents (combined)")
        self.tab_events = nb.add("Events (config/meta)")
        self.tab_diagnostics = nb.add("Diagnostics")

        self._build_overview()
        self._build_incidents()
        self._build_events()
        self._build_diagnostics()

        self.pack(fill="both", expand=True)

    def _build_overview(self):
        f = self.tab_overview

        # Use scrollable frame for the whole overview
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Status bar ---
        row = ctk.CTkFrame(scroll)
        row.pack(fill="x", padx=5, pady=(5, 2))

        self.status_label = ctk.CTkLabel(row, text="Status: (initializing)",
                                         font=("Segoe UI", 14, "bold"))
        self.status_label.pack(side="left")

        self.reason_label = ctk.CTkLabel(row, text="", font=("Segoe UI", 11))
        self.reason_label.pack(side="left", padx=15)

        # --- Dashboard cards (6 large metric cards) ---
        dash_frame = ctk.CTkFrame(scroll)
        dash_frame.pack(fill="x", padx=5, pady=(2, 4))

        self.dash_values = {}
        cards = [
            ("GW RTT", "gw_rtt", "#00BFFF"),
            ("INET 1", "inet1_rtt", "#FFD700"),
            ("INET 2", "inet2_rtt", "#FF6347"),
            ("SIGNAL", "wifi_sig", "#00FF88"),
            ("PKT LOSS", "pkt_loss", "#ccaa00"),
            ("DNS", "dns_st", "#44cc44"),
        ]
        for i, (title, key, default_color) in enumerate(cards):
            card = ctk.CTkFrame(dash_frame, fg_color="#1e1e1e", corner_radius=8)
            card.grid(row=0, column=i, padx=4, pady=4, sticky="nsew")
            dash_frame.columnconfigure(i, weight=1)

            ctk.CTkLabel(card, text=title, font=("Segoe UI", 9),
                         text_color="#888888").pack(pady=(6, 0))
            val_lbl = ctk.CTkLabel(card, text="--", font=("Segoe UI", 22, "bold"),
                                    text_color=default_color)
            val_lbl.pack(pady=(0, 6))
            self.dash_values[key] = val_lbl

        # --- Live chart (last 5 minutes) ---
        chart_frame = ctk.CTkFrame(scroll)
        chart_frame.pack(fill="x", padx=5, pady=(2, 4))
        ctk.CTkLabel(chart_frame, text="Live — Last 5 Minutes",
                     font=("Segoe UI", 10, "bold"), text_color="#888888").pack(
                         anchor="w", padx=10, pady=(4, 0))

        self.live_chart_canvas = tk.Canvas(chart_frame, height=180, bg="#1a1a1a",
                                           highlightthickness=0)
        self.live_chart_canvas.pack(fill="x", padx=8, pady=(2, 6))
        self._live_chart_width = 0
        self.live_chart_canvas.bind("<Configure>",
            lambda e: setattr(self, '_live_chart_width', e.width))

        # --- Compact info grid (secondary details) ---
        info_frame = ctk.CTkFrame(scroll)
        info_frame.pack(fill="x", padx=5, pady=(2, 4))

        grid = ctk.CTkFrame(info_frame)
        grid.pack(fill="x", padx=10, pady=6)

        self.kv = {}
        # Two-column layout for compact display
        left_fields = [
            ("Wi-Fi", "wifi"), ("SSID", "ssid"), ("BSSID", "bssid"),
            ("Channel / Band", "channel_band"), ("Signal quality", "signal_quality"),
        ]
        right_fields = [
            ("Local IP", "local"), ("Iface", "iface"), ("Gateway", "gw"),
            ("DNS servers", "dns_servers"), ("Suspicion", "suspicion"),
            ("Root cause", "root_cause"),
        ]

        for r, (label, key) in enumerate(left_fields):
            ctk.CTkLabel(grid, text=label, font=("Segoe UI", 9),
                         text_color="#999999").grid(row=r, column=0, sticky="w", padx=(0, 6), pady=1)
            v = ctk.CTkLabel(grid, text="—", font=("Segoe UI", 9))
            v.grid(row=r, column=1, sticky="w", padx=(0, 20), pady=1)
            self.kv[key] = v

        for r, (label, key) in enumerate(right_fields):
            ctk.CTkLabel(grid, text=label, font=("Segoe UI", 9),
                         text_color="#999999").grid(row=r, column=2, sticky="w", padx=(0, 6), pady=1)
            v = ctk.CTkLabel(grid, text="—", font=("Segoe UI", 9))
            v.grid(row=r, column=3, sticky="w", pady=1)
            self.kv[key] = v

        # Hidden KV entries still needed by refresh_overview but not displayed as primary
        for key in ["signal", "gw_ping", "inet1", "inet2", "dns"]:
            self.kv[key] = ctk.CTkLabel(grid, text="")  # hidden, not gridded

    def _build_category_bar(self, parent, on_change):
        bar = ctk.CTkFrame(parent)
        bar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(bar, text="Filter:").pack(side="left", padx=(0, 8))

        # categories you use
        cats = ["ALL", "LINK", "GATEWAY", "ISP", "DNS", "DEGRADED", "CONFIG", "SECURITY"]

        def set_cat(c):
            self.filter_category.set(c)
            on_change()

        for c in cats:
            ctk.CTkButton(bar, text=c, command=lambda cc=c: set_cat(cc)).pack(side="left", padx=4)

        ctk.CTkLabel(bar, text="(Click a category to filter)").pack(side="left", padx=10)

    def _sort_tree(self, tree, col, reverse):
        """Sort a Treeview by column on heading click."""
        data = [(tree.set(k, col), k) for k in tree.get_children("")]
        try:
            data.sort(key=lambda t: t[0], reverse=reverse)
        except Exception:
            pass
        for idx, (_val, k) in enumerate(data):
            tree.move(k, "", idx)
        tree.heading(col, command=lambda: self._sort_tree(tree, col, not reverse))

    def _build_incidents(self):
        f = self.tab_incidents

        self._build_category_bar(f, self.refresh_incidents)

        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b", borderwidth=0)
        style.configure("Treeview.Heading", background="#565b5e", foreground="white", relief="flat")
        style.map("Treeview", background=[('selected', '#1f538d')])

        # Create main container for side-by-side layout
        main_container = ctk.CTkFrame(f)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Left side - Incident tree
        left_frame = ctk.CTkFrame(main_container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        cols = ("start", "end", "duration", "severity", "category", "cause")
        tree_frame = tk.Frame(left_frame, bg="#2b2b2b")
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.inc_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=20)
        inc_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.inc_tree.yview)
        self.inc_tree.configure(yscrollcommand=inc_scroll.set)
        self.inc_tree.pack(side="left", fill="both", expand=True)
        inc_scroll.pack(side="right", fill="y")
        headings = {
            "start": "START",
            "end": "END",
            "duration": "DURATION",
            "severity": "SEVERITY",
            "category": "CATEGORY",
            "cause": "CAUSE (LATEST)",
        }
        widths = {
            "start": 150,
            "end": 150,
            "duration": 80,
            "severity": 80,
            "category": 100,
            "cause": 200,
        }
        for c in cols:
            self.inc_tree.heading(c, text=headings[c],
                                  command=lambda _c=c: self._sort_tree(self.inc_tree, _c, False))
            self.inc_tree.column(c, width=widths[c], stretch=(c == "cause"))
        self.inc_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_incident_details())

        # Configure row tags for coloring
        self.inc_tree.tag_configure("high", foreground="#ff4444")
        self.inc_tree.tag_configure("warn", foreground="#ff8800")
        self.inc_tree.tag_configure("info", foreground="#aaaaaa")
        self.inc_tree.tag_configure("security", background="#441111")
        self.inc_tree.tag_configure("open", background="#333333")

        # Right side - Incident details + graph
        right_frame = ctk.CTkFrame(main_container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))

        ctk.CTkLabel(right_frame, text="Incident Details", font=("Segoe UI", 12, "bold")).pack(pady=(5, 2))

        # Incident graph canvas
        self.inc_graph_canvas = tk.Canvas(right_frame, height=140, bg="#1a1a1a",
                                          highlightthickness=0)
        self.inc_graph_canvas.pack(fill="x", padx=5, pady=(2, 4))

        self.inc_details = ctk.CTkTextbox(right_frame, height=10, wrap="word")
        self.inc_details.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        self.inc_details.configure(state="disabled")

        # Bottom - Clear button
        row = ctk.CTkFrame(f)
        row.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(row, text="Clear incidents", command=self.clear_incidents).pack(side="left")

    def _build_events(self):
        f = self.tab_events

        self._build_category_bar(f, self.refresh_events)

        # Create main container for side-by-side layout (like Incidents)
        main_container = ctk.CTkFrame(f)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        # Left side - Event tree with better columns
        left_frame = ctk.CTkFrame(main_container)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))

        cols = ("time", "severity", "category", "title")
        tree_frame = tk.Frame(left_frame, bg="#2b2b2b")
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        self.event_tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=20)
        evt_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.event_tree.yview)
        self.event_tree.configure(yscrollcommand=evt_scroll.set)
        self.event_tree.pack(side="left", fill="both", expand=True)
        evt_scroll.pack(side="right", fill="y")
        headings = {
            "time": "TIME",
            "severity": "SEVERITY",
            "category": "CATEGORY",
            "title": "EVENT",
        }
        widths = {
            "time": 150,
            "severity": 80,
            "category": 100,
            "title": 280,
        }
        for c in cols:
            self.event_tree.heading(c, text=headings[c],
                                     command=lambda _c=c: self._sort_tree(self.event_tree, _c, False))
            self.event_tree.column(c, width=widths[c], stretch=(c == "title"))
        self.event_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_event_details())

        # Configure row tags for coloring
        self.event_tree.tag_configure("high", foreground="#ff4444")
        self.event_tree.tag_configure("warn", foreground="#ff8800")
        self.event_tree.tag_configure("info", foreground="#aaaaaa")
        self.event_tree.tag_configure("security", background="#441111")
        
        # Right side - Event details with more space
        right_frame = ctk.CTkFrame(main_container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        ctk.CTkLabel(right_frame, text="Event Details", font=("Segoe UI", 12, "bold")).pack(pady=(5, 5))
        self.event_details = ctk.CTkTextbox(right_frame, height=15, wrap="word")
        self.event_details.pack(fill="both", expand=True, padx=5, pady=5)
        self.event_details.configure(state="disabled")

        # Bottom - Clear button
        row = ctk.CTkFrame(f)
        row.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkButton(row, text="Clear events", command=self.clear_events).pack(side="left")

    def _build_diagnostics(self):
        f = self.tab_diagnostics

        # Scrollable container
        outer = ctk.CTkScrollableFrame(f)
        outer.pack(fill="both", expand=True, padx=10, pady=10)

        # --- Wi-Fi panel ---
        wifi_panel = ctk.CTkFrame(outer)
        wifi_panel.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(wifi_panel, text="Wi-Fi Info", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=10, pady=(6, 2))
        self.diag_wifi_grid = ctk.CTkFrame(wifi_panel)
        self.diag_wifi_grid.pack(fill="x", padx=10, pady=(0, 8))
        self.diag_wifi_labels: Dict[str, ctk.CTkLabel] = {}
        wifi_fields = ["state", "ssid", "bssid", "signal", "channel", "radio"]
        for idx, key in enumerate(wifi_fields):
            ctk.CTkLabel(self.diag_wifi_grid, text=key.upper(), font=("Segoe UI", 10, "bold")).grid(row=0, column=idx, padx=6, pady=2, sticky="w")
            lbl = ctk.CTkLabel(self.diag_wifi_grid, text="--", font=("Segoe UI", 10))
            lbl.grid(row=1, column=idx, padx=6, pady=2, sticky="w")
            self.diag_wifi_labels[key] = lbl

        # --- Ping results panel ---
        ping_panel = ctk.CTkFrame(outer)
        ping_panel.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(ping_panel, text="Ping Results", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=10, pady=(6, 2))
        self.diag_ping_grid = ctk.CTkFrame(ping_panel)
        self.diag_ping_grid.pack(fill="x", padx=10, pady=(0, 8))
        self.diag_ping_labels: Dict[str, ctk.CTkLabel] = {}
        ping_cols = ["Gateway", "Target 1", "Target 2"]
        for idx, name in enumerate(ping_cols):
            ctk.CTkLabel(self.diag_ping_grid, text=name, font=("Segoe UI", 10, "bold")).grid(row=0, column=idx, padx=14, pady=2, sticky="w")
            lbl = ctk.CTkLabel(self.diag_ping_grid, text="--", font=("Segoe UI", 10))
            lbl.grid(row=1, column=idx, padx=14, pady=2, sticky="w")
            self.diag_ping_labels[name] = lbl

        # --- Rolling stats panel ---
        roll_panel = ctk.CTkFrame(outer)
        roll_panel.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(roll_panel, text="Rolling Stats (last 60s)", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=10, pady=(6, 2))
        self.diag_roll_grid = ctk.CTkFrame(roll_panel)
        self.diag_roll_grid.pack(fill="x", padx=10, pady=(0, 8))
        self.diag_roll_bars: Dict[str, Tuple[tk.Canvas, ctk.CTkLabel]] = {}
        roll_items = [("GW Loss", "gw"), ("Inet1 Loss", "inet1"), ("Inet2 Loss", "inet2")]
        for idx, (label, key) in enumerate(roll_items):
            ctk.CTkLabel(self.diag_roll_grid, text=label, font=("Segoe UI", 10, "bold")).grid(row=idx, column=0, padx=6, pady=2, sticky="w")
            canvas = tk.Canvas(self.diag_roll_grid, width=160, height=16, bg="#2b2b2b", highlightthickness=0)
            canvas.grid(row=idx, column=1, padx=6, pady=2)
            val_lbl = ctk.CTkLabel(self.diag_roll_grid, text="0%", font=("Segoe UI", 10))
            val_lbl.grid(row=idx, column=2, padx=6, pady=2, sticky="w")
            self.diag_roll_bars[key] = (canvas, val_lbl)
        # Max RTT labels
        self.diag_rtt_labels: Dict[str, ctk.CTkLabel] = {}
        rtt_items = [("GW max RTT", "gw_rtt"), ("Inet1 max RTT", "inet1_rtt"), ("Inet2 max RTT", "inet2_rtt")]
        for idx, (label, key) in enumerate(rtt_items):
            ctk.CTkLabel(self.diag_roll_grid, text=label, font=("Segoe UI", 10, "bold")).grid(row=idx, column=3, padx=12, pady=2, sticky="w")
            lbl = ctk.CTkLabel(self.diag_roll_grid, text="--", font=("Segoe UI", 10))
            lbl.grid(row=idx, column=4, padx=6, pady=2, sticky="w")
            self.diag_rtt_labels[key] = lbl

        # --- DNS panel ---
        dns_panel = ctk.CTkFrame(outer)
        dns_panel.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(dns_panel, text="DNS", font=("Segoe UI", 13, "bold")).pack(anchor="w", padx=10, pady=(6, 2))
        self.diag_dns_frame = ctk.CTkFrame(dns_panel)
        self.diag_dns_frame.pack(fill="x", padx=10, pady=(0, 8))
        self.diag_dns_status = ctk.CTkLabel(self.diag_dns_frame, text="--", font=("Segoe UI", 10))
        self.diag_dns_status.pack(anchor="w", padx=6, pady=2)
        self.diag_dns_summary = ctk.CTkLabel(self.diag_dns_frame, text="", font=("Segoe UI", 9), wraplength=600, justify="left")
        self.diag_dns_summary.pack(anchor="w", padx=6, pady=2)

    # ---------------------
    # Actions
    # ---------------------

    def force_stop(self):
        self.running = False
        try:
            self.parent.destroy()
        except Exception:
            pass

    def set_baseline(self):
        gw = self.gateway.get().strip()
        dns = [x.strip() for x in self.dns_text.get().split(",") if x.strip()]
        local_ip = self.localip.get().strip()
        if not gw:
            messagebox.showerror("Baseline", "Gateway is empty.")
            return
        if not dns:
            dns = get_dns_servers()
        self.engine.set_baseline(gw, dns, local_ip)
        messagebox.showinfo("Baseline", "Baseline saved (gateway + DNS + local IP).")

    def show_settings(self):
        """Show settings popup window"""
        settings_window = ctk.CTkToplevel(self.parent)
        settings_window.title("Network Monitor Settings")
        settings_window.geometry("560x750")
        settings_window.transient(self.parent)
        settings_window.grab_set()
        
        # Main container
        main_frame = ctk.CTkFrame(settings_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        ctk.CTkLabel(main_frame, text="⚙️ Settings", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=10)
        
        # Monitoring Settings
        monitor_frame = ctk.CTkFrame(main_frame)
        monitor_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(monitor_frame, text="📡 Monitoring Settings", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        # Interval
        interval_row = ctk.CTkFrame(monitor_frame)
        interval_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(interval_row, text="Interval (ms):").pack(side="left", padx=(0, 10))
        ttk.Spinbox(interval_row, from_=800, to=30000, increment=200, textvariable=self.interval_ms, width=10).pack(side="left")
        
        # Ping timeout
        timeout_row = ctk.CTkFrame(monitor_frame)
        timeout_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(timeout_row, text="Ping timeout (ms):").pack(side="left", padx=(0, 10))
        ttk.Spinbox(timeout_row, from_=300, to=5000, increment=100, textvariable=self.ping_timeout_ms, width=10).pack(side="left")
        
        # Network Configuration
        network_frame = ctk.CTkFrame(main_frame)
        network_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(network_frame, text="🌐 Network Configuration", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        # Gateway
        gw_row = ctk.CTkFrame(network_frame)
        gw_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(gw_row, text="Gateway:").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(gw_row, textvariable=self.gateway, width=150).pack(side="left")
        
        # DNS
        dns_row = ctk.CTkFrame(network_frame)
        dns_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(dns_row, text="DNS servers:").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(dns_row, textvariable=self.dns_text, width=200).pack(side="left")
        
        # Ping targets
        targets_frame = ctk.CTkFrame(network_frame)
        targets_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(targets_frame, text="Ping targets:").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(targets_frame, textvariable=self.target1, width=80).pack(side="left", padx=2)
        ctk.CTkEntry(targets_frame, textvariable=self.target2, width=80).pack(side="left", padx=2)
        
        # DNS domain
        domain_row = ctk.CTkFrame(network_frame)
        domain_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(domain_row, text="DNS domain:").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(domain_row, textvariable=self.dns_domain, width=150).pack(side="left")
        
        # Sensitivity / Latency Threshold Presets
        sens_frame = ctk.CTkFrame(main_frame)
        sens_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(sens_frame, text="Sensitivity (Latency Thresholds)", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

        preset_row = ctk.CTkFrame(sens_frame)
        preset_row.pack(fill="x", padx=10, pady=5)
        presets = [
            ("Strict", 80, 150),
            ("Normal", 120, 250),
            ("Relaxed", 200, 400),
            ("Wi-Fi tolerant", 300, 600),
        ]
        def apply_preset(elev, high):
            self.thresh_elevated.set(elev)
            self.thresh_high.set(high)
        for name, elev, high in presets:
            ctk.CTkButton(preset_row, text=name, width=100,
                          command=lambda e=elev, h=high: apply_preset(e, h)).pack(side="left", padx=4)

        thresh_row = ctk.CTkFrame(sens_frame)
        thresh_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(thresh_row, text="Elevated (ms):").pack(side="left", padx=(0, 4))
        ttk.Spinbox(thresh_row, from_=20, to=1000, increment=10, textvariable=self.thresh_elevated, width=6).pack(side="left", padx=(0, 14))
        ctk.CTkLabel(thresh_row, text="High (ms):").pack(side="left", padx=(0, 4))
        ttk.Spinbox(thresh_row, from_=50, to=2000, increment=10, textvariable=self.thresh_high, width=6).pack(side="left")

        # Auto Export Settings
        export_frame = ctk.CTkFrame(main_frame)
        export_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(export_frame, text="Auto Export Settings", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)

        # Enable checkbox
        enable_row = ctk.CTkFrame(export_frame)
        enable_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkCheckBox(enable_row, text="Enable auto export", variable=self.auto_export_enabled).pack(side="left")

        # Export time — spinboxes for hour and minute
        hour_row = ctk.CTkFrame(export_frame)
        hour_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(hour_row, text="Export time:").pack(side="left", padx=(0, 6))
        ttk.Spinbox(hour_row, from_=0, to=23, increment=1, textvariable=self.auto_export_hour, width=4, wrap=True).pack(side="left")
        ctk.CTkLabel(hour_row, text=":").pack(side="left")
        ttk.Spinbox(hour_row, from_=0, to=59, increment=1, textvariable=self.auto_export_minute, width=4, wrap=True).pack(side="left")
        # Preset buttons
        time_presets = [("06:00", 6, 0), ("12:00", 12, 0), ("18:00", 18, 0), ("23:30", 23, 30)]
        for label, h, m in time_presets:
            ctk.CTkButton(hour_row, text=label, width=56,
                          command=lambda hh=h, mm=m: (self.auto_export_hour.set(hh), self.auto_export_minute.set(mm))).pack(side="left", padx=3)

        # Export folder
        folder_row = ctk.CTkFrame(export_frame)
        folder_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(folder_row, text="Export folder:").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(folder_row, textvariable=self.export_folder, width=200).pack(side="left")

        # Buttons
        button_frame = ctk.CTkFrame(main_frame)
        button_frame.pack(fill="x", pady=20)
        
        ctk.CTkButton(button_frame, text="💾 Save & Close", command=lambda: self.save_settings(settings_window)).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="❌ Cancel", command=settings_window.destroy).pack(side="left", padx=10)
        ctk.CTkButton(button_frame, text="📋 Set Baseline", command=self.set_baseline).pack(side="left", padx=10)
        
    def save_settings(self, window):
        """Save settings and close window"""
        window.destroy()

    def clear_events(self):
        self.engine.events.clear()
        self.refresh_events()

    def clear_incidents(self):
        self.engine.incidents.clear()
        self.engine.active_incidents.clear()
        self.refresh_incidents()

    def ai_export(self):
        """Quick AI-friendly export"""
        try:
            # Check if we have any data
            if not self.engine.samples:
                messagebox.showwarning("AI Export", "No data to export yet. Please wait for monitoring to collect some samples.")
                return
            
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("AI export", "*.json")],
                title="Save AI-friendly lightweight export"
            )
            if not path:
                return

            ai_export = self.engine.generate_ai_export()
            
            if not ai_export:
                messagebox.showwarning("AI Export", "No data available for export.")
                return
            
            with open(path, "w", encoding="utf-8") as f:
                json.dump(ai_export, f, indent=2, ensure_ascii=False)
            
            size_kb = len(str(ai_export))/1024
            messagebox.showinfo("AI Export", f"AI-friendly export saved:\n{path}\n\nSize: {size_kb:.1f} KB\n\nPerfect for ChatGPT analysis!")
        except Exception as e:
            messagebox.showerror("Export failed", f"AI Export failed:\n{str(e)}")

    def export_report(self):
        # Ask user what type of export they want
        choice = messagebox.askyesnocancel(
            "Export Type", 
            "Choose export type:\n\nYES = Full detailed report\nNO = AI-friendly lightweight export\nCANCEL = Abort",
            icon='question'
        )
        
        if choice is None:  # CANCEL
            return
        
        if choice:  # YES - Full report
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON report", "*.json")],
                title="Save full network stability report"
            )
            if not path:
                return

            report = {
                "generated_at": now_ts(),
                "settings": {
                    "interval_ms": int(self.interval_ms.get()),
                    "ping_timeout_ms": int(self.ping_timeout_ms.get()),
                    "target1": self.target1.get().strip(),
                    "target2": self.target2.get().strip(),
                    "dns_domain": self.dns_domain.get().strip(),
                },
                "baseline": {
                    "gateway": self.engine.baseline_gateway,
                    "dns_servers": self.engine.baseline_dns,
                },
                "last_sample": asdict(self._last_sample) if self._last_sample else None,
                "incidents": [asdict(i) for i in self.engine.incidents],
                "events": [asdict(e) for e in self.engine.events],
                "samples_tail": [asdict(s) for s in self.engine.samples[-500:]],
            }

            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Export", f"Full report saved:\n{path}")
            except Exception as e:
                messagebox.showerror("Export failed", str(e))
        
        else:  # NO - AI-friendly export
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("AI export", "*.json")],
                title="Save AI-friendly lightweight export"
            )
            if not path:
                return

            try:
                ai_export = self.engine.generate_ai_export()
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(ai_export, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Export", f"AI-friendly export saved:\n{path}\n\nSize: {len(str(ai_export))/1024:.1f} KB")
            except Exception as e:
                messagebox.showerror("Export failed", str(e))

    def tick(self):
        if not self.running:
            return

        # Snapshot StringVar values on the main thread before passing to worker
        sample_params = {
            "gateway": self.gateway.get().strip(),
            "target1": self.target1.get().strip() or "8.8.8.8",
            "target2": self.target2.get().strip() or "1.1.1.1",
            "dns_domain": self.dns_domain.get().strip() or "google.com",
            "ping_timeout_ms": int(self.ping_timeout_ms.get()),
        }

        try:
            self.work_q.put_nowait(("sample", sample_params))
        except Exception:
            pass

        # Sync latency thresholds to engine
        self.engine.thresh_elevated = self.thresh_elevated.get()
        self.engine.thresh_high = self.thresh_high.get()

        # Sync export hour/minute to engine and check for auto export
        self.engine.export_hour = self.auto_export_hour.get()
        self.engine.export_minute = self.auto_export_minute.get()
        self.engine.auto_export_check(self.auto_export_enabled, self.auto_export_hour, self.export_folder)

        # Reduce refresh frequency to improve performance
        self.refresh_overview()
        # Only refresh incidents and events every 5th tick (further reduced)
        self._refresh_counter += 1
        
        if self._refresh_counter % 5 == 0:
            self.refresh_incidents()
            self.refresh_events()
        if self._refresh_counter % 10 == 0:
            self.refresh_diagnostics()

        # Dynamic interval: faster polling during active incidents
        base_ms = int(self.interval_ms.get())
        status = self.engine.last_status
        has_active = bool(self.engine.active_incidents)

        if status == "DOWN" or (has_active and any(
                self.engine._sev_rank(self.engine._find_incident(iid).severity) >= 3
                for iid in self.engine.active_incidents.values()
                if self.engine._find_incident(iid))):
            # Critical/DOWN: poll every 1.5s for precise timing
            interval = max(1500, base_ms // 3)
        elif status == "DEGRADED" or has_active:
            # Active incident: poll every 2s
            interval = max(2000, base_ms // 2)
        else:
            # Stable: use configured interval (default 3s)
            interval = max(1500, base_ms)

        self.after(interval, self.tick)

    def _worker_loop(self):
        while self.running:
            try:
                job = self.work_q.get(timeout=0.2)
            except queue.Empty:
                continue

            if isinstance(job, tuple) and job[0] == "sample":
                try:
                    self._do_sample(job[1])
                except Exception as e:
                    self.engine.log_event("WARN", "DEGRADED", "Sampling error", {"error": str(e)})

    def _do_sample(self, params: Dict[str, Any]):
        local_ip, ifname = get_default_route_interface_ip()
        gw = get_default_gateway() or params["gateway"]

        dns = get_dns_servers()
        dns_server_for_test = dns[0] if dns else (gw if gw else None)

        wifi = netsh_wlan_info()
        wifi_state = wifi.get("state", "")
        wifi_signal = wifi.get("signal", "")
        wifi_ssid = wifi.get("ssid", "")
        wifi_bssid = wifi.get("bssid", "")
        wifi_channel = wifi.get("channel", "")
        wifi_radio = wifi.get("radio", "")

        # Parse signal % as integer for tracking
        wifi_signal_pct = -1
        if wifi_signal:
            m = re.search(r"(\d+)", wifi_signal)
            if m:
                wifi_signal_pct = int(m.group(1))

        # Feed signal and BSSID to engine for tracking
        self.engine.track_signal(wifi_signal_pct)
        self.engine.detect_bssid_change(wifi_bssid, wifi_ssid)

        timeout_ms = params["ping_timeout_ms"]
        t1 = params["target1"]
        t2 = params["target2"]

        # Run ping calls concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            gw_future = pool.submit(ping_once, gw, timeout_ms) if gw else None
            inet_future = pool.submit(ping_once, t1, timeout_ms)
            inet2_future = pool.submit(ping_once, t2, timeout_ms)

        gw_ok, gw_rtt, gw_raw = gw_future.result() if gw_future else (True, None, "")
        inet_ok, inet_rtt, inet_raw = inet_future.result()
        inet2_ok, inet2_rtt, inet2_raw = inet2_future.result()

        self.engine._roll_add("gw", gw_ok, gw_rtt)
        self.engine._roll_add("inet1", inet_ok, inet_rtt)
        self.engine._roll_add("inet2", inet2_ok, inet2_rtt)

        domain = params["dns_domain"]
        dns_state, dns_raw = nslookup(domain, dns_server_for_test, timeout_s=4)

        status, reason, sev, cat = self.engine.classify(
            local_ip, wifi, gw,
            gw_ok, gw_rtt,
            inet_ok, inet_rtt,
            inet2_ok, inet2_rtt,
            dns_state
        )

        # Combined incident handling (problem + recovery)
        self.engine.on_state_update(
            status=status,
            category=cat,
            severity=sev,
            reason=reason,
            details={
                "local_ip": local_ip,
                "iface": ifname,
                "gateway": gw,
                "dns_state": dns_state,
                "wifi_signal": wifi_signal,
                "wifi_signal_pct": wifi_signal_pct,
                "wifi_bssid": wifi_bssid,
                "wifi_channel": wifi_channel,
                "wifi_radio": wifi_radio,
            },
        )

        self.engine.last_status = status
        self.engine.last_reason = reason

        self.engine.detect_config_changes(gw, dns)
        self.engine.detect_flapping(status)

        # Add periodic diagnostic events to show tool is working
        current_time = time.time()
        if current_time - self.engine._last_diagnostic_event >= 300:  # Every 5 minutes
            self.engine._last_diagnostic_event = current_time
            sample_count = len(self.engine.samples)
            incident_count = len(self.engine.incidents)
            event_count = len(self.engine.events)
            
            # Log a diagnostic event
            self.engine.log_event(
                "INFO", 
                "DIAGNOSTIC", 
                "Monitoring Status Update",
                {
                    "samples_collected": sample_count,
                    "active_incidents": len([i for i in self.engine.incidents if not i.end_time]),
                    "total_incidents": incident_count,
                    "total_events": event_count,
                    "current_status": status,
                    "uptime_minutes": int((current_time - self.engine._start_time) / 60)
                }
            )

        s = Sample(
            timestamp=now_ts(),
            local_ip=local_ip,
            iface=ifname,
            gateway_ip=gw,
            dns_servers=dns,
            wifi_state=wifi_state,
            wifi_signal=wifi_signal,
            wifi_ssid=wifi_ssid,
            gw_ok=gw_ok,
            gw_rtt=gw_rtt,
            inet_ok=inet_ok,
            inet_rtt=inet_rtt,
            inet2_ok=inet2_ok,
            inet2_rtt=inet2_rtt,
            dns_state=dns_state,
            dns_raw_hint=short(dns_raw, 260),
            status=status,
            reason=reason,
            wifi_bssid=wifi_bssid,
            wifi_channel=wifi_channel,
            wifi_radio=wifi_radio,
            wifi_signal_pct=wifi_signal_pct,
        )
        
        # Enhance with intelligence analysis
        if self.engine.intelligence:
            try:
                s = self.engine.enhance_sample_with_intelligence(s)
            except Exception as e:
                # If intelligence fails, continue with basic analysis
                print(f"Intelligence analysis failed: {e}")
        self.engine.add_sample(s)
        self._last_sample = s

        self._last_diag = {
            "wifi": json.dumps(wifi, indent=2, ensure_ascii=False) if wifi else "(netsh wlan info unavailable)",
            "ping_gateway": short(gw_raw, 400) if gw else "(no gateway)",
            "ping_target1": short(inet_raw, 400),
            "ping_target2": short(inet2_raw, 400),
            "dns": short(dns_raw, 500),
            "roll": json.dumps({
                "loss_gw_last60s": round(self.engine._roll_loss("gw") * 100, 1),
                "loss_inet1_last60s": round(self.engine._roll_loss("inet1") * 100, 1),
                "loss_inet2_last60s": round(self.engine._roll_loss("inet2") * 100, 1),
                "max_rtt_gw_last60s": self.engine._roll_max_rtt("gw"),
                "max_rtt_inet1_last60s": self.engine._roll_max_rtt("inet1"),
                "max_rtt_inet2_last60s": self.engine._roll_max_rtt("inet2"),
            }, indent=2)
        }

        if local_ip:
            self.localip.set(local_ip)
        if ifname:
            self.iface.set(ifname)
        if gw:
            self.gateway.set(gw)
        if dns:
            self.dns_text.set(", ".join(dns))

    # ---------------------
    # UI refresh
    # ---------------------

    def refresh_overview(self):
        s = self._last_sample
        if not s:
            self.status_label.configure(text="Status: (initializing)")
            return

        self.status_label.configure(text=f"Status: {s.status}")
        self.reason_label.configure(text=s.reason)

        self.kv["wifi"].configure(text=s.wifi_state or "(unknown)")
        self.kv["signal"].configure(text=s.wifi_signal or "—")
        self.kv["ssid"].configure(text=s.wifi_ssid or "—")
        self.kv["bssid"].configure(text=s.wifi_bssid or "—")

        # Channel + band display
        ch_text = s.wifi_channel or "—"
        if s.wifi_radio:
            ch_text += f"  ({s.wifi_radio})"
        if s.wifi_channel:
            try:
                ch_num = int(s.wifi_channel)
                band = "2.4 GHz" if ch_num <= 14 else "5 GHz"
                ch_text = f"Ch {ch_num} — {band}"
                if s.wifi_radio:
                    ch_text += f"  ({s.wifi_radio})"
            except ValueError:
                pass
        self.kv["channel_band"].configure(text=ch_text)

        # Signal quality assessment
        sig_q = "—"
        if s.wifi_signal_pct >= 0:
            pct = s.wifi_signal_pct
            avg = self.engine.get_signal_avg(60)
            mn = self.engine.get_signal_min(60)
            if pct >= 80:
                sig_q = f"Excellent ({pct}%)"
            elif pct >= 60:
                sig_q = f"Good ({pct}%)"
            elif pct >= 40:
                sig_q = f"Fair ({pct}%)"
            elif pct >= 20:
                sig_q = f"Weak ({pct}%) — may cause issues"
            else:
                sig_q = f"Very weak ({pct}%) — likely causing problems"
            if avg is not None and mn is not None:
                sig_q += f"  [avg {avg:.0f}%, min {mn}% last 60s]"
        self.kv["signal_quality"].configure(text=sig_q)

        self.kv["gw_ping"].configure(text=("OK" if s.gw_ok else "FAIL") + (f" ({s.gw_rtt:.0f} ms)" if s.gw_rtt is not None else ""))
        self.kv["inet1"].configure(text=("OK" if s.inet_ok else "FAIL") + (f" ({s.inet_rtt:.0f} ms)" if s.inet_rtt is not None else ""))
        self.kv["inet2"].configure(text=("OK" if s.inet2_ok else "FAIL") + (f" ({s.inet2_rtt:.0f} ms)" if s.inet2_rtt is not None else ""))

        self.kv["dns"].configure(text=s.dns_state)
        self.kv["local"].configure(text=s.local_ip or "—")
        self.kv["iface"].configure(text=s.iface or "—")
        self.kv["gw"].configure(text=s.gateway_ip or "—")
        self.kv["dns_servers"].configure(text=", ".join(s.dns_servers) if s.dns_servers else "—")

        # Show intelligence information
        self.kv["suspicion"].configure(text=s.suspicion_level)
        if s.root_cause:
            max_prob = max([s.root_cause.router_issue, s.root_cause.isp_issue, s.root_cause.dns_issue,
                           s.root_cause.local_adapter_issue, s.root_cause.possible_malicious_activity])
            if max_prob > 0.3:
                if s.root_cause.router_issue == max_prob:
                    cause_text = f"Router ({max_prob:.2f})"
                elif s.root_cause.isp_issue == max_prob:
                    cause_text = f"ISP ({max_prob:.2f})"
                elif s.root_cause.dns_issue == max_prob:
                    cause_text = f"DNS ({max_prob:.2f})"
                elif s.root_cause.local_adapter_issue == max_prob:
                    cause_text = f"Adapter ({max_prob:.2f})"
                elif s.root_cause.possible_malicious_activity == max_prob:
                    cause_text = f"Suspicious ({max_prob:.2f})"
                else:
                    cause_text = "Unknown"
                self.kv["root_cause"].configure(text=cause_text)
            else:
                self.kv["root_cause"].configure(text="Stable")

        # --- Dashboard cards ---
        # GW RTT
        if s.gw_ok and s.gw_rtt is not None:
            self.dash_values["gw_rtt"].configure(
                text=f"{s.gw_rtt:.0f} ms", text_color=self._rtt_color(s.gw_rtt))
        elif not s.gw_ok:
            self.dash_values["gw_rtt"].configure(text="FAIL", text_color="#cc4444")
        else:
            self.dash_values["gw_rtt"].configure(text="--", text_color="#888888")

        # Inet 1
        if s.inet_ok and s.inet_rtt is not None:
            self.dash_values["inet1_rtt"].configure(
                text=f"{s.inet_rtt:.0f} ms", text_color=self._rtt_color(s.inet_rtt))
        elif not s.inet_ok:
            self.dash_values["inet1_rtt"].configure(text="FAIL", text_color="#cc4444")
        else:
            self.dash_values["inet1_rtt"].configure(text="--", text_color="#888888")

        # Inet 2
        if s.inet2_ok and s.inet2_rtt is not None:
            self.dash_values["inet2_rtt"].configure(
                text=f"{s.inet2_rtt:.0f} ms", text_color=self._rtt_color(s.inet2_rtt))
        elif not s.inet2_ok:
            self.dash_values["inet2_rtt"].configure(text="FAIL", text_color="#cc4444")
        else:
            self.dash_values["inet2_rtt"].configure(text="--", text_color="#888888")

        # Wi-Fi signal
        if s.wifi_signal_pct >= 0:
            self.dash_values["wifi_sig"].configure(
                text=f"{s.wifi_signal_pct}%",
                text_color=self._signal_color(s.wifi_signal_pct))
        else:
            self.dash_values["wifi_sig"].configure(text="N/A", text_color="#888888")

        # Packet loss (max of all targets)
        loss_pct = max(self.engine._roll_loss("gw"),
                       self.engine._roll_loss("inet1"),
                       self.engine._roll_loss("inet2")) * 100
        self.dash_values["pkt_loss"].configure(
            text=f"{loss_pct:.1f}%",
            text_color=self._loss_bar_color(loss_pct))

        # DNS
        self.dash_values["dns_st"].configure(
            text=s.dns_state, text_color=self._dns_color(s.dns_state))

        # --- Live chart ---
        self._update_live_chart()

    def refresh_incidents(self):
        for i in self.inc_tree.get_children():
            self.inc_tree.delete(i)

        fc = self.filter_category.get()
        incidents = list(self.engine.incidents)

        # newest first
        incidents.reverse()

        for inc in incidents[:1200]:
            if fc != "ALL" and inc.category != fc:
                continue

            end = inc.end_time if inc.end_time else "(open)"
            dur = inc.duration if inc.duration else ""

            tags = []
            sev_lower = inc.severity.upper()
            if sev_lower == "HIGH":
                tags.append("high")
            elif sev_lower == "WARN":
                tags.append("warn")
            else:
                tags.append("info")
            if inc.category == "SECURITY":
                tags.append("security")
            if not inc.end_time:
                tags.append("open")

            self.inc_tree.insert(
                "",
                "end",
                iid=f"inc-{inc.id}",
                values=(inc.start_time, end, dur, inc.severity, inc.category, inc.cause),
                tags=tags,
            )

    def show_incident_details(self):
        sel = self.inc_tree.selection()
        if not sel:
            return
        iid = sel[0]
        try:
            inc_id = int(iid.split("-")[1])
        except Exception:
            return

        inc = None
        for x in self.engine.incidents:
            if x.id == inc_id:
                inc = x
                break
        if not inc:
            return

        # Draw incident graph
        self._draw_incident_graph(inc)

        # Create human-friendly explanation
        friendly_explanation = self._get_friendly_explanation(inc)

        text = json.dumps(asdict(inc), indent=2, ensure_ascii=False)
        friendly_text = f"{friendly_explanation}\n\n--- Technical Details ---\n{text}"

        self.inc_details.configure(state="normal")
        self.inc_details.delete("1.0", "end")
        self.inc_details.insert("1.0", friendly_text)
        self.inc_details.configure(state="disabled")

    def _get_friendly_explanation(self, inc) -> str:
        """Generate human-friendly explanation for non-technical users"""
        category = inc.category.lower()
        severity = inc.severity.lower()
        cause = inc.cause.lower() if inc.cause else ""
        
        explanations = {
            "link": {
                "title": "🔌 Connection Problem (Your PC/Router)",
                "what_happened": "Your computer lost connection to the router or Wi-Fi network.",
                "who_fixes": "You or your family can fix this:",
                "steps": [
                    "✓ Check if Wi-Fi is working on your phone",
                    "✓ Restart your router (unplug for 30 seconds, plug back in)",
                    "✓ Check if network cable is connected properly",
                    "✓ Move closer to the router if using Wi-Fi"
                ],
                "not_hacker": "This is NOT a hacker - just a connection issue"
            },
            "gateway": {
                "title": "🏠 Router Problem (Your Network Equipment)",
                "what_happened": "Your router is not responding properly to connections.",
                "who_fixes": "You can usually fix this:",
                "steps": [
                    "✓ Restart the router (unplug for 30 seconds)",
                    "✓ Check if router lights are normal",
                    "✓ Too many devices connected? Disconnect some",
                    "✓ Router might be overheating - give it space"
                ],
                "not_hacker": "This is NOT hacking - router needs restart"
            },
            "isp": {
                "title": "🌐 Internet Provider Problem (External)",
                "what_happened": "Your internet service provider is having issues.",
                "who_fixes": "Only your internet provider can fix this:",
                "steps": [
                    "✓ Check if neighbors have same issue",
                    "✓ Call your internet provider's support number",
                    "✓ Check provider's website for outage reports",
                    "✓ Wait - provider is already working on it"
                ],
                "not_hacker": "This is NOT hacking - provider maintenance/outage"
            },
            "dns": {
                "title": "🔍 Address Lookup Problem (Internet Directory)",
                "what_happened": "Your computer can't translate website names to addresses.",
                "who_fixes": "Usually fixes itself, but you can try:",
                "steps": [
                    "✓ Wait 5-10 minutes (often fixes itself)",
                    "✓ Restart your computer",
                    "✓ Change DNS to Google (8.8.8.8) in router settings",
                    "✓ Restart router if problem continues"
                ],
                "not_hacker": "This is NOT hacking - just internet directory issues"
            },
            "degraded": {
                "title": "⚠ Slow Internet (Performance Issue)",
                "what_happened": "Internet is working but much slower than normal.",
                "who_fixes": "You can try these fixes:",
                "steps": [
                    "✓ Restart router",
                    "✓ Close unnecessary programs/tabs",
                    "✓ Check if someone is downloading/streaming heavily",
                    "✓ Try connecting with cable instead of Wi-Fi"
                ],
                "not_hacker": "This is NOT hacking - just temporary slowness"
            },
            "security": {
                "title": "🔴 Security Alert (Possible Attack)",
                "what_happened": "A suspicious change was detected on your network.",
                "who_fixes": "Investigate immediately:",
                "steps": [
                    "✓ Check the BSSID — did your router's MAC address change?",
                    "✓ If you have only ONE router, a BSSID change is suspicious",
                    "✓ Someone may have set up a fake Wi-Fi access point (evil twin)",
                    "✓ Disconnect from Wi-Fi and use mobile data until verified"
                ],
                "not_hacker": "This COULD be an attack — investigate before dismissing!"
            }
        }

        # Get the appropriate explanation
        base_explanation = explanations.get(category, explanations["degraded"])

        # Add severity context
        severity_info = ""
        if severity == "high":
            severity_info = "\n🚨 This is a serious problem - internet barely works!"
        elif severity == "warn":
            severity_info = "\n⚠️ This is annoying but internet still works partially."
        else:
            severity_info = "\n✅ This is a minor issue or just informational."

        # Add Wi-Fi signal context from incident details
        signal_info = ""
        details = inc.details or {}
        sig_pct = details.get("wifi_signal_pct", -1)
        if isinstance(sig_pct, int) and sig_pct >= 0:
            if sig_pct < 30:
                signal_info = f"\n📶 Wi-Fi signal was VERY WEAK ({sig_pct}%) when this started — likely the cause!"
            elif sig_pct < 50:
                signal_info = f"\n📶 Wi-Fi signal was weak ({sig_pct}%) — probably contributing to the problem."
            elif sig_pct < 70:
                signal_info = f"\n📶 Wi-Fi signal was fair ({sig_pct}%) — signal alone unlikely to be the cause."
            else:
                signal_info = f"\n📶 Wi-Fi signal was strong ({sig_pct}%) — signal is NOT the problem."

        wifi_detail = ""
        ch = details.get("wifi_channel", "")
        radio = details.get("wifi_radio", "")
        bssid = details.get("wifi_bssid", "")
        if ch or radio or bssid:
            parts = []
            if ch:
                try:
                    ch_num = int(ch)
                    band = "2.4 GHz" if ch_num <= 14 else "5 GHz"
                    parts.append(f"Channel {ch} ({band})")
                except ValueError:
                    parts.append(f"Channel {ch}")
            if radio:
                parts.append(radio)
            if bssid:
                parts.append(f"BSSID {bssid}")
            wifi_detail = "\n🔗 " + " | ".join(parts)

        # Build friendly explanation
        friendly = f"""
{base_explanation['title']}

What happened:
{base_explanation['what_happened']}

{severity_info}
{signal_info}
{wifi_detail}

{base_explanation['who_fixes']}
{chr(10).join(base_explanation['steps'])}

{base_explanation['not_hacker']}

Time started: {inc.start_time}
Duration: {inc.duration or 'Still ongoing'}
"""

        return friendly

    def refresh_events(self):
        for i in self.event_tree.get_children():
            self.event_tree.delete(i)

        fc = self.filter_category.get()
        events = list(self.engine.events)
        events.reverse()

        for idx, e in enumerate(events[:1200]):
            if fc != "ALL" and e.category != fc:
                continue
            tags = []
            if e.severity == "HIGH":
                tags.append("high")
            elif e.severity == "WARN":
                tags.append("warn")
            else:
                tags.append("info")
            if e.category == "SECURITY":
                tags.append("security")
            self.event_tree.insert("", "end", iid=f"e-{idx}", values=(e.timestamp, e.severity, e.category, e.title), tags=tags)

    def show_event_details(self):
        sel = self.event_tree.selection()
        if not sel:
            return
        iid = sel[0]
        idx = int(iid.split("-")[1])
        recent = list(reversed(self.engine.events[-1600:]))
        if idx < 0 or idx >= len(recent):
            return
        e = recent[idx]
        text = json.dumps(asdict(e), indent=2, ensure_ascii=False)
        self.event_details.configure(state="normal")
        self.event_details.delete("1.0", "end")
        self.event_details.insert("1.0", text)
        self.event_details.configure(state="disabled")

    def _loss_bar_color(self, pct: float) -> str:
        if pct < 5:
            return "#44cc44"
        if pct < 25:
            return "#ccaa00"
        return "#cc4444"

    def _signal_color(self, pct: int) -> str:
        if pct >= 70:
            return "#44cc44"
        if pct >= 40:
            return "#ccaa00"
        return "#cc4444"

    def _rtt_color(self, rtt_ms: Optional[float], ok: bool = True) -> str:
        if not ok or rtt_ms is None:
            return "#cc4444"
        if rtt_ms < 60:
            return "#44cc44"
        if rtt_ms < 200:
            return "#ccaa00"
        return "#cc4444"

    def _dns_color(self, state: str) -> str:
        if state == "OK":
            return "#44cc44"
        if state == "SLOW":
            return "#ccaa00"
        return "#cc4444"

    # ---- Reusable Canvas line chart ----

    def _draw_line_chart(self, canvas, series_list, width, height, show_legend=True):
        """Draw a multi-series line chart on a tkinter Canvas.

        series_list: list of dicts with keys:
            label (str), color (str), points (list of (float_ts, float_val)),
            axis ("left" or "right")
        """
        canvas.delete("all")
        if width < 80 or height < 40:
            return

        ml, mr, mt, mb = 50, 50, 18, 22  # margins
        dw = width - ml - mr
        dh = height - mt - mb
        if dw < 20 or dh < 20:
            return

        # Collect all timestamps for X range
        all_ts = []
        for s in series_list:
            for t, _ in s["points"]:
                all_ts.append(t)
        if not all_ts:
            canvas.create_text(width // 2, height // 2, text="No data yet",
                               fill="#666666", font=("Segoe UI", 10))
            return

        t_min, t_max = min(all_ts), max(all_ts)
        if t_max - t_min < 1:
            t_max = t_min + 1

        # Compute Y ranges per axis
        def y_range(axis):
            vals = [v for s in series_list if s.get("axis", "left") == axis
                    for _, v in s["points"] if v is not None]
            if not vals:
                return 0, 100
            lo, hi = 0, max(vals) * 1.15
            if hi < 10:
                hi = 10
            return lo, hi

        left_lo, left_hi = y_range("left")
        right_lo, right_hi = y_range("right")

        def map_x(t):
            return ml + (t - t_min) / (t_max - t_min) * dw

        def map_y(v, axis="left"):
            lo, hi = (left_lo, left_hi) if axis == "left" else (right_lo, right_hi)
            if hi == lo:
                return mt + dh // 2
            return mt + (1 - (v - lo) / (hi - lo)) * dh

        # Grid lines (horizontal)
        for i in range(5):
            y = mt + i * dh // 4
            canvas.create_line(ml, y, ml + dw, y, fill="#333333", dash=(2, 4))
            # Left axis labels
            val = left_hi - i * (left_hi - left_lo) / 4
            canvas.create_text(ml - 4, y, text=f"{val:.0f}", anchor="e",
                               fill="#888888", font=("Segoe UI", 7))
            # Right axis labels
            val_r = right_hi - i * (right_hi - right_lo) / 4
            canvas.create_text(ml + dw + 4, y, text=f"{val_r:.0f}", anchor="w",
                               fill="#888888", font=("Segoe UI", 7))

        # Axis unit labels
        canvas.create_text(ml - 4, mt - 8, text="ms", anchor="e",
                           fill="#888888", font=("Segoe UI", 7))
        canvas.create_text(ml + dw + 4, mt - 8, text="%", anchor="w",
                           fill="#888888", font=("Segoe UI", 7))

        # X-axis time labels (~5 labels)
        span = t_max - t_min
        step = max(1, span / 5)
        t_cur = t_min
        while t_cur <= t_max:
            x = map_x(t_cur)
            try:
                lbl = datetime.fromtimestamp(t_cur).strftime("%H:%M:%S")
            except Exception:
                lbl = ""
            canvas.create_text(x, mt + dh + 12, text=lbl,
                               fill="#888888", font=("Segoe UI", 7))
            canvas.create_line(x, mt, x, mt + dh, fill="#2a2a2a", dash=(1, 6))
            t_cur += step

        # Draw series
        for s in series_list:
            pts = s["points"]
            axis = s.get("axis", "left")
            color = s["color"]
            coords = []
            for t, v in pts:
                if v is None:
                    # Break the line at None values
                    if len(coords) >= 4:
                        canvas.create_line(*coords, fill=color, width=2, smooth=False)
                    coords = []
                    continue
                coords.extend([map_x(t), map_y(v, axis)])
            if len(coords) >= 4:
                canvas.create_line(*coords, fill=color, width=2, smooth=False)

        # Legend
        if show_legend:
            lx = ml + 6
            ly = mt + 4
            for s in series_list:
                canvas.create_rectangle(lx, ly, lx + 10, ly + 8, fill=s["color"], outline="")
                canvas.create_text(lx + 14, ly + 4, text=s["label"], anchor="w",
                                   fill="#cccccc", font=("Segoe UI", 7))
                lx += len(s["label"]) * 6 + 28

    def _samples_to_ts(self, samples):
        """Convert sample timestamps to float timestamps once."""
        result = []
        for s in samples:
            dt = parse_ts(s.timestamp)
            if dt:
                result.append((dt.timestamp(), s))
        return result

    def _update_live_chart(self):
        """Redraw the live scrolling chart with last 5 minutes of data."""
        canvas = self.live_chart_canvas
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 100 or h < 40:
            return

        cutoff = time.time() - 300
        recent = self._samples_to_ts(self.engine.samples)
        recent = [(t, s) for t, s in recent if t >= cutoff]

        series = [
            {"label": "GW RTT", "color": "#00BFFF", "axis": "left",
             "points": [(t, s.gw_rtt) for t, s in recent]},
            {"label": "Inet 1", "color": "#FFD700", "axis": "left",
             "points": [(t, s.inet_rtt) for t, s in recent]},
            {"label": "Inet 2", "color": "#FF6347", "axis": "left",
             "points": [(t, s.inet2_rtt) for t, s in recent]},
            {"label": "Signal %", "color": "#00FF88", "axis": "right",
             "points": [(t, s.wifi_signal_pct if s.wifi_signal_pct >= 0 else None)
                        for t, s in recent]},
        ]
        self._draw_line_chart(canvas, series, w, h)

    def _draw_incident_graph(self, inc):
        """Draw a graph of metrics during an incident's lifetime."""
        canvas = self.inc_graph_canvas
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 80 or h < 30:
            canvas.delete("all")
            return

        start_dt = parse_ts(inc.start_time)
        end_dt = parse_ts(inc.end_time) if inc.end_time else datetime.now()
        if not start_dt:
            canvas.delete("all")
            canvas.create_text(w // 2, h // 2, text="No timestamp",
                               fill="#666666", font=("Segoe UI", 9))
            return

        # Add 30s buffer on each side
        start_f = start_dt.timestamp() - 30
        end_f = end_dt.timestamp() + 30

        all_ts = self._samples_to_ts(self.engine.samples)
        incident_data = [(t, s) for t, s in all_ts if start_f <= t <= end_f]

        if not incident_data:
            canvas.delete("all")
            canvas.create_text(w // 2, h // 2,
                               text="No sample data for this incident\n(data may have been pruned)",
                               fill="#666666", font=("Segoe UI", 9), justify="center")
            return

        series = [
            {"label": "GW RTT", "color": "#00BFFF", "axis": "left",
             "points": [(t, s.gw_rtt) for t, s in incident_data]},
            {"label": "Inet 1", "color": "#FFD700", "axis": "left",
             "points": [(t, s.inet_rtt) for t, s in incident_data]},
            {"label": "Inet 2", "color": "#FF6347", "axis": "left",
             "points": [(t, s.inet2_rtt) for t, s in incident_data]},
        ]
        self._draw_line_chart(canvas, series, w, h, show_legend=True)

        # Draw incident start/end markers
        if incident_data:
            t_min_d = min(t for t, _ in incident_data)
            t_max_d = max(t for t, _ in incident_data)
            span = t_max_d - t_min_d
            if span < 1:
                span = 1
            ml, mr, mt_m, mb_m = 50, 50, 18, 22
            dw = w - ml - mr

            def mx(t):
                return ml + (t - t_min_d) / span * dw

            # Start marker (red dashed)
            sx = mx(start_dt.timestamp())
            if ml <= sx <= ml + dw:
                canvas.create_line(sx, mt_m, sx, h - mb_m, fill="#ff4444", dash=(4, 3), width=1)
                canvas.create_text(sx, h - mb_m + 8, text="START", fill="#ff4444",
                                   font=("Segoe UI", 6))

            # End marker (green dashed)
            if inc.end_time:
                ex = mx(end_dt.timestamp())
                if ml <= ex <= ml + dw:
                    canvas.create_line(ex, mt_m, ex, h - mb_m, fill="#44cc44", dash=(4, 3), width=1)
                    canvas.create_text(ex, h - mb_m + 8, text="END", fill="#44cc44",
                                       font=("Segoe UI", 6))

    def refresh_diagnostics(self):
        s = self._last_sample
        d = self._last_diag
        if not d and not s:
            return

        # --- Wi-Fi panel ---
        if s:
            wifi_data = {
                "state": s.wifi_state or "--",
                "ssid": s.wifi_ssid or "--",
                "bssid": s.wifi_bssid or "--",
                "signal": s.wifi_signal or "--",
                "channel": s.wifi_channel or "--",
                "radio": s.wifi_radio or "--",
            }
            for key, val in wifi_data.items():
                lbl = self.diag_wifi_labels.get(key)
                if lbl:
                    lbl.configure(text=val)
                    if key == "signal" and s.wifi_signal_pct >= 0:
                        lbl.configure(text_color=self._signal_color(s.wifi_signal_pct))
                    elif key == "state":
                        clr = "#44cc44" if "connected" in val.lower() else "#cc4444"
                        lbl.configure(text_color=clr)

        # --- Ping panel ---
        if s:
            def ping_text(ok, rtt):
                st = "OK" if ok else "FAIL"
                rt = f" ({rtt:.0f} ms)" if rtt is not None else ""
                return st + rt
            def ping_color(ok):
                return "#44cc44" if ok else "#cc4444"
            mapping = [
                ("Gateway", s.gw_ok, s.gw_rtt),
                ("Target 1", s.inet_ok, s.inet_rtt),
                ("Target 2", s.inet2_ok, s.inet2_rtt),
            ]
            for name, ok, rtt in mapping:
                lbl = self.diag_ping_labels.get(name)
                if lbl:
                    lbl.configure(text=ping_text(ok, rtt), text_color=ping_color(ok))

        # --- Rolling stats bars ---
        loss_map = {
            "gw": self.engine._roll_loss("gw") * 100,
            "inet1": self.engine._roll_loss("inet1") * 100,
            "inet2": self.engine._roll_loss("inet2") * 100,
        }
        for key, pct in loss_map.items():
            canvas, val_lbl = self.diag_roll_bars[key]
            canvas.delete("all")
            bar_w = min(int(pct / 100 * 160), 160)
            color = self._loss_bar_color(pct)
            if bar_w > 0:
                canvas.create_rectangle(0, 0, bar_w, 16, fill=color, outline="")
            val_lbl.configure(text=f"{pct:.1f}%", text_color=color)

        rtt_map = {
            "gw_rtt": self.engine._roll_max_rtt("gw"),
            "inet1_rtt": self.engine._roll_max_rtt("inet1"),
            "inet2_rtt": self.engine._roll_max_rtt("inet2"),
        }
        for key, val in rtt_map.items():
            lbl = self.diag_rtt_labels.get(key)
            if lbl:
                lbl.configure(text=f"{val:.0f} ms" if val is not None else "--")

        # --- DNS panel ---
        if s:
            dns_st = s.dns_state
            dns_clr = "#44cc44" if dns_st == "OK" else ("#ccaa00" if dns_st == "SLOW" else "#cc4444")
            self.diag_dns_status.configure(text=f"DNS: {dns_st}", text_color=dns_clr)
            hint = s.dns_raw_hint or ""
            self.diag_dns_summary.configure(text=hint[:300])

# Toolbox entrypoint
# =========================

def run_tool():
    try:
        if tk._default_root is None:
            if HAS_CTK:
                root = ctk.CTkToplevel()
            else:
                root = tk.Toplevel()
            app = App(root)
            root.protocol("WM_DELETE_WINDOW", app.force_stop)
            root.mainloop()
        else:
            if HAS_CTK:
                win = ctk.CTkToplevel()
            else:
                win = tk.Toplevel()
            app = App(win)
            win.protocol("WM_DELETE_WINDOW", app.force_stop)
    except Exception as e:
        messagebox.showerror("Network Stability Monitor Pro", f"Startup error:\n{e}")


if __name__ == "__main__":
    run_tool()
