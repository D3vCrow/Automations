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
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
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

        self.flap_window: List[Tuple[float, str]] = []
        self._last_flap_log_at: float = 0.0

        self.roll: Dict[str, List[Tuple[float, bool, Optional[float]]]] = {
            "gw": [],
            "inet1": [],
            "inet2": [],
        }

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

        if not wifi_connected:
            return "DOWN", "Wi-Fi disconnected (link down)", "HIGH", "LINK"

        if not local_ip:
            return "DOWN", "No local IPv4 on default route (adapter/DHCP issue)", "HIGH", "LINK"

        if gw and (not gw_ok) and (not inet_ok) and (not inet2_ok):
            return "DOWN", "Gateway unreachable and internet down (router/Wi-Fi issue)", "HIGH", "GATEWAY"

        if (not inet_ok) and (not inet2_ok) and (gw_ok or not gw):
            return "DOWN", "Internet unreachable (ISP/WAN outage) while local network seems up", "HIGH", "ISP"

        if (inet_ok or inet2_ok) and dns_state == "FAIL":
            return "DEGRADED", "DNS failing while internet reachable (DNS issue)", "WARN", "DNS"
        if (inet_ok or inet2_ok) and dns_state == "SLOW":
            return "DEGRADED", "DNS slow/timeouts (intermittent DNS issue)", "INFO", "DNS"

        loss1 = self._roll_loss("inet1")
        loss2 = self._roll_loss("inet2")
        if max(loss1, loss2) >= 0.25:
            return "DEGRADED", f"Packet loss detected (internet) ~{max(loss1, loss2)*100:.0f}% (last 60s)", "WARN", "DEGRADED"

        rtts = [r for r in [gw_rtt, inet_rtt, inet2_rtt] if r is not None]
        mx = max(rtts) if rtts else None
        if mx is not None:
            if mx >= 250:
                return "DEGRADED", f"High latency detected (max {mx:.0f} ms)", "WARN", "DEGRADED"
            if mx >= 120:
                return "DEGRADED", f"Latency elevated (max {mx:.0f} ms)", "INFO", "DEGRADED"

        if gw and (not gw_ok) and (inet_ok or inet2_ok):
            return "DEGRADED", "Gateway ping failing but internet OK (router ICMP blocked/rate-limited)", "INFO", "GATEWAY"

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
            self.log_event("WARN", "CONFIG", "Current gateway differs from baseline", {"baseline": self.baseline_gateway, "current": gateway_ip})

        if self.baseline_dns and dns_servers and dns_servers != self.baseline_dns:
            self.log_event("WARN", "CONFIG", "Current DNS differs from baseline", {"baseline": self.baseline_dns, "current": dns_servers})

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
        # Normalize packet loss reasons to treat different percentages as same incident
        normalized_reason = reason
        if "Packet loss detected" in reason:
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

        self.interval_ms = tk.IntVar(value=2000)
        self.ping_timeout_ms = tk.IntVar(value=900)
        
        # Auto export configuration
        self.auto_export_enabled = tk.BooleanVar(value=AUTO_EXPORT_ENABLED)
        self.auto_export_time = tk.StringVar(value=AUTO_EXPORT_TIME)
        self.export_folder = tk.StringVar(value=EXPORT_FOLDER)

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

        # log filter state
        self.filter_category = tk.StringVar(value="ALL")

        # Set initial baseline if we have network info
        if gw or dns:
            self.engine.set_baseline(gw, dns, ip)
        
        # Initialize start time for tracking
        self.engine._start_time = time.time()
        
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
        ctk.CTkButton(top, text="Force stop", command=self.force_stop).pack(side="left", padx=6)

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

        row = ctk.CTkFrame(f)
        row.pack(fill="x", padx=10, pady=10)

        self.status_label = ctk.CTkLabel(row, text="Status: (initializing)", font=("Segoe UI", 12, "bold"))
        self.status_label.pack(side="left")

        self.reason_label = ctk.CTkLabel(row, text="", font=("Segoe UI", 11))
        self.reason_label.pack(side="left", padx=15)

        box = ctk.CTkFrame(f)
        box.pack(fill="x", padx=10, pady=(0, 10))
        ctk.CTkLabel(box, text="Live metrics (latest cycle)", font=("Segoe UI", 12, "bold")).pack(pady=(10, 0))

        grid = ctk.CTkFrame(box)
        grid.pack(fill="x", padx=10, pady=10)

        self.kv = {}
        fields = [
            ("Wi-Fi", "wifi"),
            ("Signal", "signal"),
            ("SSID", "ssid"),
            ("Gateway ping", "gw_ping"),
            ("Internet ping 1", "inet1"),
            ("Internet ping 2", "inet2"),
            ("DNS", "dns"),
            ("Local IP", "local"),
            ("Iface", "iface"),
            ("Gateway", "gw"),
            ("DNS servers", "dns_servers"),
            ("Suspicion", "suspicion"),
            ("Root cause", "root_cause"),
        ]
        for r, (label, key) in enumerate(fields):
            ctk.CTkLabel(grid, text=label).grid(row=r, column=0, sticky="w", padx=(0, 10), pady=2)
            v = ctk.CTkLabel(grid, text="—")
            v.grid(row=r, column=1, sticky="w", pady=2)
            self.kv[key] = v

        expl = ctk.CTkFrame(f)
        expl.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        ctk.CTkLabel(expl, text="How it decides the cause", font=("Segoe UI", 12, "bold")).pack(pady=(10, 0))

        self.expl_text = ctk.CTkTextbox(expl, wrap="word", height=12)
        self.expl_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.expl_text.insert("1.0",
            "Enhanced Classification Logic with Intelligence:\n"
            "Basic Rules:\n"
            "- If Wi-Fi says Disconnected OR no local IP on default route: LINK DOWN\n"
            "- If gateway ping fails AND internet pings fail: ROUTER/Wi-Fi issue\n"
            "- If internet pings fail (both) while local seems up: ISP/WAN outage\n"
            "- If internet reachable but DNS FAIL: DNS issue\n"
            "- If DNS SLOW: Degraded (intermittent DNS)\n"
            "- If packet loss (last 60s) >= 25%: Degraded\n"
            "- If latency high: Degraded\n"
            "- If gateway ping fails but internet OK: Degraded (ICMP rate-limit)\n\n"
            "Intelligence Features:\n"
            "- Root cause probability analysis (Router/ISP/DNS/Adapter/Suspicious)\n"
            "- Suspicious behavior detection (config changes, flapping, anomalies)\n"
            "- Human-readable explanations based on evidence\n"
            "- AI-friendly lightweight export (under 50KB)\n"
            "- Configuration tracking and anomaly detection\n\n"
            "UX:\n"
            "- Incidents tab combines problem+recovery into one row.\n"
            "- Click a category button to filter incidents.\n"
            "- Export: YES=Full report, NO=AI-friendly export\n"
        )
        self.expl_text.configure(state="disabled")

    def _build_category_bar(self, parent, on_change):
        bar = ctk.CTkFrame(parent)
        bar.pack(fill="x", padx=10, pady=(10, 0))

        ctk.CTkLabel(bar, text="Filter:").pack(side="left", padx=(0, 8))

        # categories you use
        cats = ["ALL", "LINK", "GATEWAY", "ISP", "DNS", "DEGRADED", "CONFIG"]

        def set_cat(c):
            self.filter_category.set(c)
            on_change()

        for c in cats:
            ctk.CTkButton(bar, text=c, command=lambda cc=c: set_cat(cc)).pack(side="left", padx=4)

        ctk.CTkLabel(bar, text="(Click a category to filter)").pack(side="left", padx=10)

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
        self.inc_tree = ttk.Treeview(left_frame, columns=cols, show="headings", height=20)
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
            "cause": 200,  # Reduced width since details are on right
        }
        for c in cols:
            self.inc_tree.heading(c, text=headings[c])
            self.inc_tree.column(c, width=widths[c], stretch=(c == "cause"))
        self.inc_tree.pack(fill="both", expand=True, padx=5, pady=5)
        self.inc_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_incident_details())

        # Right side - Incident details
        right_frame = ctk.CTkFrame(main_container)
        right_frame.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        ctk.CTkLabel(right_frame, text="Incident Details", font=("Segoe UI", 12, "bold")).pack(pady=(5, 5))
        self.inc_details = ctk.CTkTextbox(right_frame, height=15, wrap="word")
        self.inc_details.pack(fill="both", expand=True, padx=5, pady=5)
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
        self.event_tree = ttk.Treeview(left_frame, columns=cols, show="headings", height=20)
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
            self.event_tree.heading(c, text=headings[c])
            self.event_tree.column(c, width=widths[c], stretch=(c == "title"))
        self.event_tree.pack(fill="both", expand=True, padx=5, pady=5)
        self.event_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_event_details())
        
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

        box = ctk.CTkFrame(f)
        box.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(box, text="Latest raw outputs (troubleshooting)", font=("Segoe UI", 12, "bold")).pack(pady=(10, 0))

        self.diag_text = ctk.CTkTextbox(box, wrap="word")
        self.diag_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.diag_text.configure(state="disabled")

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
        settings_window.geometry("500x600")
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
        
        # Auto Export Settings
        export_frame = ctk.CTkFrame(main_frame)
        export_frame.pack(fill="x", pady=10)
        ctk.CTkLabel(export_frame, text="📤 Auto Export Settings", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=5)
        
        # Enable checkbox
        enable_row = ctk.CTkFrame(export_frame)
        enable_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkCheckBox(enable_row, text="Enable auto export", variable=self.auto_export_enabled).pack(side="left")
        
        # Export time
        hour_row = ctk.CTkFrame(export_frame)
        hour_row.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(hour_row, text="Export time (HH:MM):").pack(side="left", padx=(0, 10))
        ctk.CTkEntry(hour_row, textvariable=self.auto_export_time, width=8).pack(side="left")
        
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
        # Apply settings immediately
        self.set_baseline()
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
        try:
            self.work_q.put_nowait("sample")
        except Exception:
            pass

        # Check for auto export
        self.engine.auto_export_check(self.auto_export_enabled, self.auto_export_time, self.export_folder)

        # Reduce refresh frequency to improve performance
        self.refresh_overview()
        # Only refresh incidents and events every 5th tick (further reduced)
        if not hasattr(self, '_refresh_counter'):
            self._refresh_counter = 0
        self._refresh_counter += 1
        
        if self._refresh_counter % 5 == 0:
            self.refresh_incidents()
            self.refresh_events()
        if self._refresh_counter % 10 == 0:
            self.refresh_diagnostics()

        # Even longer interval to reduce CPU usage
        self.after(max(1500, int(self.interval_ms.get())), self.tick)

    def _worker_loop(self):
        while self.running:
            try:
                job = self.work_q.get(timeout=0.2)
            except queue.Empty:
                continue

            if job == "sample":
                try:
                    self._do_sample()
                except Exception as e:
                    self.engine.log_event("WARN", "DEGRADED", "Sampling error", {"error": str(e)})

    def _do_sample(self):
        local_ip, ifname = get_default_route_interface_ip()
        gw = get_default_gateway() or self.gateway.get().strip()

        dns = get_dns_servers()
        dns_server_for_test = dns[0] if dns else (gw if gw else None)

        wifi = netsh_wlan_info()
        wifi_state = wifi.get("state", "")
        wifi_signal = wifi.get("signal", "")
        wifi_ssid = wifi.get("ssid", "")

        timeout_ms = int(self.ping_timeout_ms.get())

        gw_ok, gw_rtt, gw_raw = (True, None, "")
        if gw:
            gw_ok, gw_rtt, gw_raw = ping_once(gw, timeout_ms=timeout_ms)

        t1 = self.target1.get().strip() or "8.8.8.8"
        t2 = self.target2.get().strip() or "1.1.1.1"
        inet_ok, inet_rtt, inet_raw = ping_once(t1, timeout_ms=timeout_ms)
        inet2_ok, inet2_rtt, inet2_raw = ping_once(t2, timeout_ms=timeout_ms)

        self.engine._roll_add("gw", gw_ok, gw_rtt)
        self.engine._roll_add("inet1", inet_ok, inet_rtt)
        self.engine._roll_add("inet2", inet2_ok, inet2_rtt)

        domain = self.dns_domain.get().strip() or "google.com"
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
            },
        )

        self.engine.last_status = status
        self.engine.last_reason = reason

        self.engine.detect_config_changes(gw, dns)
        self.engine.detect_flapping(status)

        # Add periodic diagnostic events to show tool is working
        current_time = time.time()
        if not hasattr(self.engine, '_last_diagnostic_event'):
            self.engine._last_diagnostic_event = 0
        
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
                    "uptime_minutes": int((current_time - getattr(self.engine, '_start_time', current_time)) / 60)
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
            reason=reason
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

        self.kv["gw_ping"].configure(text=("OK" if s.gw_ok else "FAIL") + (f" ({s.gw_rtt:.0f} ms)" if s.gw_rtt is not None else ""))
        self.kv["inet1"].configure(text=("OK" if s.inet_ok else "FAIL") + (f" ({s.inet_rtt:.0f} ms)" if s.inet_rtt is not None else ""))
        self.kv["inet2"].configure(text=("OK" if s.inet2_ok else "FAIL") + (f" ({s.inet2_rtt:.0f} ms)" if s.inet2_rtt is not None else ""))

        self.kv["dns"].configure(text=s.dns_state)
        self.kv["local"].configure(text=s.local_ip or "—")
        self.kv["iface"].configure(text=s.iface or "—")
        self.kv["gw"].configure(text=s.gateway_ip or "—")
        self.kv["dns_servers"].configure(text=", ".join(s.dns_servers) if s.dns_servers else "—")
        
        # Show intelligence information
        if hasattr(s, 'suspicion_level'):
            self.kv["suspicion"].configure(text=s.suspicion_level)
        if hasattr(s, 'root_cause') and s.root_cause:
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
            self.inc_tree.insert(
                "",
                "end",
                iid=f"inc-{inc.id}",
                values=(inc.start_time, end, dur, inc.severity, inc.category, inc.cause),
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
        
        # Build friendly explanation
        friendly = f"""
{base_explanation['title']}

What happened:
{base_explanation['what_happened']}

{severity_info}

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
            self.event_tree.insert("", "end", iid=f"e-{idx}", values=(e.timestamp, e.severity, e.category, e.title))

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

    def refresh_diagnostics(self):
        d = self._last_diag
        if not d:
            return
        text = (
            f"Wi-Fi (netsh wlan show interfaces)\n{d.get('wifi','')}\n\n"
            f"Ping Gateway\n{d.get('ping_gateway','')}\n\n"
            f"Ping Target 1\n{d.get('ping_target1','')}\n\n"
            f"Ping Target 2\n{d.get('ping_target2','')}\n\n"
            f"DNS (nslookup)\n{d.get('dns','')}\n\n"
            f"Rolling window (last 60s)\n{d.get('roll','')}\n"
        )
        self.diag_text.configure(state="normal")
        self.diag_text.delete("1.0", "end")
        self.diag_text.insert("1.0", text)
        self.diag_text.configure(state="disabled")

    def force_stop(self):
        self.running = False
        try:
            self.parent.destroy()
        except Exception:
            pass

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
