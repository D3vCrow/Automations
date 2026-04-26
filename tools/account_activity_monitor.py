"""
Account Activity Monitor — Historical timeline and live monitoring of
Windows account changes, logon activity, device events, system changes,
security policy modifications, and software installations.
"""

import os
import sys
import re
import json
import time
import queue
import threading
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Optional, Set

from tools._common.threadsafe import BoundedDeque

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import customtkinter as ctk
    HAS_CTK = True
except ImportError:
    HAS_CTK = False

try:
    import winreg
except ImportError:
    winreg = None

try:
    import psutil
except ImportError:
    psutil = None

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

TOOL_NAME = "Account Activity Monitor"
TOOL_DESCRIPTION = "Track account changes, logon activity, device events, and system modifications"

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
TREE_BG  = "#2b2b2b"

# Severity colors
SEV_COLORS = {
    "CRITICAL": C_RED,
    "WARNING": C_ORANGE,
    "INFO": C_WHITE,
}

# ─────────────────────────────────────────────
# Event Definitions
# ─────────────────────────────────────────────

@dataclass
class EventDef:
    event_id: int
    log: str
    category: str
    severity: str
    title: str
    description: str = ""

# All tracked events organized by category
EVENT_DEFS: Dict[int, EventDef] = {}

def _reg(eid, log, cat, sev, title, desc=""):
    EVENT_DEFS[eid] = EventDef(eid, log, cat, sev, title, desc)

# ── Account Management ──
_reg(4720, "Security", "Account", "CRITICAL", "User account created")
_reg(4726, "Security", "Account", "CRITICAL", "User account deleted")
_reg(4722, "Security", "Account", "WARNING",  "User account enabled")
_reg(4725, "Security", "Account", "WARNING",  "User account disabled")
_reg(4738, "Security", "Account", "WARNING",  "User account changed")
_reg(4724, "Security", "Account", "WARNING",  "Password reset attempted")
_reg(4723, "Security", "Account", "INFO",     "Password change attempted")
_reg(4732, "Security", "Account", "WARNING",  "Member added to security group")
_reg(4733, "Security", "Account", "WARNING",  "Member removed from security group")
_reg(4781, "Security", "Account", "WARNING",  "Account name changed")

# ── Logon Activity ──
# Note: 4624 (successful logon) excluded — too noisy (hundreds/day from services)
# Note: 4634 (logoff) excluded — pairs with 4624, equally noisy
_reg(4625, "Security", "Logon", "WARNING",  "Failed logon attempt")
_reg(4648, "Security", "Logon", "WARNING",  "Logon using explicit credentials")
_reg(4800, "Security", "Logon", "INFO",     "Workstation locked")
_reg(4801, "Security", "Logon", "INFO",     "Workstation unlocked")
_reg(1149, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
     "Logon", "WARNING", "RDP connection established")

# ── Device Changes ──
_reg(20001, "Microsoft-Windows-UserPnp/DeviceInstall", "Device", "WARNING",
     "Driver installed")
_reg(20003, "Microsoft-Windows-UserPnp/DeviceInstall", "Device", "INFO",
     "Driver service added")
_reg(6416, "Security", "Device", "WARNING", "New external device recognized")
_reg(400,  "Microsoft-Windows-Kernel-PnP/Device Configuration",
     "Device", "INFO", "Device connected (PnP)")
_reg(410,  "Microsoft-Windows-Kernel-PnP/Device Configuration",
     "Device", "INFO", "Device disconnected (PnP)")

# ── System Changes ──
# Note: 6013 (uptime) excluded — fires every 12h, no security value
# Note: 1 (time changed) excluded — NTP sync fires constantly, not suspicious
_reg(6005, "System", "System", "INFO",     "System boot")
_reg(6006, "System", "System", "INFO",     "System shutdown")
_reg(6008, "System", "System", "WARNING",  "Unexpected shutdown (crash/power loss)")
_reg(19,   "System", "System", "INFO",     "Windows Update installed")

# ── Security Policy ──
_reg(4719, "Security", "Security", "CRITICAL", "System audit policy changed")
_reg(1102, "Security", "Security", "CRITICAL", "Audit log cleared")
_reg(4946, "Security", "Security", "WARNING",  "Firewall rule added")
_reg(4947, "Security", "Security", "WARNING",  "Firewall rule modified")
_reg(4948, "Security", "Security", "WARNING",  "Firewall rule deleted")
_reg(5001, "Microsoft-Windows-Windows Defender/Operational",
     "Security", "CRITICAL", "Windows Defender real-time protection disabled")
_reg(5010, "Microsoft-Windows-Windows Defender/Operational",
     "Security", "WARNING",  "Windows Defender scan disabled")
# Note: 5007 (Defender config changed) excluded — fires 50+ times/day from signature updates

# ── Software ──
# Note: 7040 (service start type changed) excluded — BITS service alone generates 20+/day
# Note: 1033/1034 (MSI completed) excluded — duplicates 11707/11724
_reg(7045, "System",      "Software", "WARNING", "Service installed")
_reg(11707, "Application", "Software", "INFO",    "Application installed")
_reg(11724, "Application", "Software", "WARNING", "Application removed")

# Group by log source for efficient querying
EVENTS_BY_LOG: Dict[str, List[int]] = {}
for eid, edef in EVENT_DEFS.items():
    EVENTS_BY_LOG.setdefault(edef.log, []).append(eid)

ALL_CATEGORIES = ["Account", "Logon", "Device", "System", "Security", "Software"]

CATEGORY_ICONS = {
    "Account":  "👤",
    "Logon":    "🔑",
    "Device":   "🔌",
    "System":   "⚙️",
    "Security": "🛡️",
    "Software": "📦",
}

# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def safe_run(cmd: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                            timeout=timeout, shell=False, creationflags=_CNW)
        return cp.returncode, cp.stdout, cp.stderr
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        return 1, "", str(e)

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except (ImportError, OSError, AttributeError):
        return False

def fmt_time(dt_str: str) -> str:
    """Parse ISO timestamp from event XML and return readable format."""
    try:
        # Handle both formats: 2026-03-30T12:00:00.000Z and 2026-03-30T12:00:00.0000000Z
        dt_str = dt_str.rstrip('Z')
        if '.' in dt_str:
            # Truncate fractional seconds to 6 digits max
            parts = dt_str.split('.')
            frac = parts[1][:6]
            dt_str = f"{parts[0]}.{frac}"
            dt = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(dt_str, "%Y-%m-%dT%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, AttributeError, IndexError):
        return dt_str[:19] if len(dt_str) >= 19 else dt_str


# ─────────────────────────────────────────────
# Parsed Event
# ─────────────────────────────────────────────

@dataclass
class ParsedEvent:
    timestamp: str         # formatted time string
    timestamp_raw: str     # original ISO for sorting
    event_id: int
    category: str
    severity: str
    title: str
    details: str           # extracted meaningful info
    log_source: str
    computer: str = ""
    user: str = ""
    raw_xml: str = ""
    parsed_data: Dict = field(default_factory=dict)  # all extracted key-value pairs

    def sort_key(self):
        return self.timestamp_raw


# ─────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────

class ActivityMonitorEngine:
    def __init__(self):
        self._admin = is_admin()
        self._last_seen: Dict[str, str] = {}  # log -> last timestamp seen

    def query_events(self, hours: int = 24, categories: Optional[Set[str]] = None,
                     callback=None) -> List[ParsedEvent]:
        """Query historical events from the last N hours."""
        if categories is None:
            categories = set(ALL_CATEGORIES)

        # Calculate time filter
        since = datetime.utcnow() - timedelta(hours=hours)
        time_filter = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        all_events = []
        total_logs = len(EVENTS_BY_LOG)

        for idx, (log, event_ids) in enumerate(EVENTS_BY_LOG.items()):
            if callback:
                callback(f"Querying {log}...", idx / total_logs)

            # Filter event IDs to only requested categories
            filtered_ids = [eid for eid in event_ids
                           if EVENT_DEFS[eid].category in categories]
            if not filtered_ids:
                continue

            # Skip Security log if not admin
            if log == "Security" and not self._admin:
                continue

            events = self._query_log(log, filtered_ids, time_filter)
            all_events.extend(events)

        # Sort by timestamp descending (newest first)
        all_events.sort(key=lambda e: e.timestamp_raw, reverse=True)

        # Aggregate repeated events (same event_id within 5 minutes)
        all_events = self._aggregate_events(all_events)

        if callback:
            callback(f"Done — {len(all_events)} events found", 1.0)

        return all_events

    def query_new_events(self, categories: Optional[Set[str]] = None) -> List[ParsedEvent]:
        """Query events newer than last seen. For live monitoring."""
        if categories is None:
            categories = set(ALL_CATEGORIES)

        all_events = []

        for log, event_ids in EVENTS_BY_LOG.items():
            filtered_ids = [eid for eid in event_ids
                           if EVENT_DEFS[eid].category in categories]
            if not filtered_ids:
                continue

            if log == "Security" and not self._admin:
                continue

            # Use last seen timestamp or last 60 seconds
            last = self._last_seen.get(log)
            if not last:
                since = datetime.utcnow() - timedelta(seconds=60)
                last = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

            events = self._query_log(log, filtered_ids, last)

            # Update last seen
            if events:
                newest = max(e.timestamp_raw for e in events)
                # Add 1ms to avoid re-fetching the same event
                self._last_seen[log] = newest
            elif log not in self._last_seen:
                self._last_seen[log] = datetime.utcnow().strftime(
                    "%Y-%m-%dT%H:%M:%S.000Z")

            all_events.extend(events)

        all_events.sort(key=lambda e: e.timestamp_raw, reverse=True)
        return all_events

    def _aggregate_events(self, events: List[ParsedEvent]) -> List[ParsedEvent]:
        """Collapse repeated events of the same type within 5 minutes into one entry."""
        if not events:
            return events

        aggregated = []
        i = 0
        while i < len(events):
            e = events[i]
            # Count consecutive events of the same type
            count = 1
            j = i + 1
            while j < len(events):
                other = events[j]
                if other.event_id != e.event_id:
                    break
                # Check if within 5 minutes
                try:
                    t1 = e.timestamp_raw.rstrip('Z')
                    t2 = other.timestamp_raw.rstrip('Z')
                    if '.' in t1:
                        t1 = t1.split('.')[0]
                    if '.' in t2:
                        t2 = t2.split('.')[0]
                    dt1 = datetime.strptime(t1, "%Y-%m-%dT%H:%M:%S")
                    dt2 = datetime.strptime(t2, "%Y-%m-%dT%H:%M:%S")
                    if abs((dt1 - dt2).total_seconds()) > 300:
                        break
                except (ValueError, AttributeError, TypeError):
                    break
                count += 1
                j += 1

            if count > 1:
                # Create aggregated event
                agg = ParsedEvent(
                    timestamp=e.timestamp,
                    timestamp_raw=e.timestamp_raw,
                    event_id=e.event_id,
                    category=e.category,
                    severity=e.severity,
                    title=f"{e.title} ({count}x in 5min)",
                    details=e.details,
                    log_source=e.log_source,
                    computer=e.computer,
                    user=e.user,
                    raw_xml=e.raw_xml,
                )
                aggregated.append(agg)
            else:
                aggregated.append(e)
            i = j

        return aggregated

    def _query_log(self, log: str, event_ids: List[int],
                   time_filter: str) -> List[ParsedEvent]:
        """Query a specific event log for specific event IDs since a timestamp."""
        events = []

        # Build XPath query for multiple event IDs
        id_conditions = " or ".join(f"EventID={eid}" for eid in event_ids)
        xpath = f"*[System[({id_conditions}) and TimeCreated[@SystemTime>='{time_filter}']]]"

        try:
            rc, out, err = safe_run([
                "wevtutil", "qe", log,
                f"/q:{xpath}",
                "/f:xml",
                "/rd:true",  # reverse direction (newest first)
                "/c:500",    # cap at 500 per log
            ], timeout=20)

            if rc != 0 or not out.strip():
                return events

            # Parse XML events — wevtutil outputs multiple <Event> elements
            # Wrap in root to make valid XML
            xml_str = f"<Events>{out}</Events>"
            try:
                root = ET.fromstring(xml_str)
            except ET.ParseError:
                # Try parsing individual events
                return self._parse_events_fallback(out, event_ids)

            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event_elem in root.findall(".//e:Event", ns):
                parsed = self._parse_event_xml(event_elem, ns)
                if parsed:
                    events.append(parsed)

        except (AttributeError, ValueError, TypeError):
            pass

        return events

    def _parse_event_xml(self, event_elem, ns) -> Optional[ParsedEvent]:
        """Parse a single Event XML element into a ParsedEvent."""
        try:
            sys_elem = event_elem.find("e:System", ns)
            if sys_elem is None:
                return None

            eid_elem = sys_elem.find("e:EventID", ns)
            eid = int(eid_elem.text) if eid_elem is not None and eid_elem.text else 0

            if eid not in EVENT_DEFS:
                return None

            edef = EVENT_DEFS[eid]

            # Timestamp
            tc_elem = sys_elem.find("e:TimeCreated", ns)
            ts_raw = tc_elem.get("SystemTime", "") if tc_elem is not None else ""

            # Computer
            comp_elem = sys_elem.find("e:Computer", ns)
            computer = comp_elem.text if comp_elem is not None and comp_elem.text else ""

            # Extract event data
            details, parsed_data = self._extract_details(event_elem, ns, eid)
            user = self._extract_user(event_elem, ns)

            # Raw XML for detail popup
            try:
                raw = ET.tostring(event_elem, encoding="unicode")
            except (TypeError, ValueError):
                raw = ""

            # Filter out known Windows-internal noise
            if self._is_internal_noise(eid, parsed_data):
                return None

            return ParsedEvent(
                timestamp=fmt_time(ts_raw),
                timestamp_raw=ts_raw,
                event_id=eid,
                category=edef.category,
                severity=edef.severity,
                title=edef.title,
                details=details,
                log_source=edef.log,
                computer=computer,
                user=user,
                raw_xml=raw,
                parsed_data=parsed_data,
            )
        except (AttributeError, ValueError, KeyError):
            return None

    def _is_internal_noise(self, eid: int, data: Dict) -> bool:
        """Filter out Windows-internal events that look scary but are normal."""
        target_user = data.get("TargetUserName", "").lower()
        target_domain = data.get("TargetDomainName", "").lower()
        subject_user = data.get("SubjectUserName", "").lower()
        process = data.get("ProcessName", "").lower()

        # 4648: Explicit credential logons from Windows internals
        if eid == 4648:
            # DWM (Desktop Window Manager) sessions — every boot
            if target_domain == "window manager" or target_user.startswith("dwm-"):
                return True
            # UMFD (User Mode Font Driver) — every boot
            if target_user.startswith("umfd-"):
                return True
            # SYSTEM account logging into localhost services
            if subject_user.endswith("$") and target_user == subject_user:
                return True

        # 4624/4625: Filter service/system logons (type 5 = service, type 0 = system)
        if eid in (4624, 4625):
            logon_type = data.get("LogonType", "")
            if logon_type in ("0", "5"):  # System and Service logons
                return True
            # SYSTEM, LOCAL SERVICE, NETWORK SERVICE accounts
            if target_user in ("system", "local service", "network service"):
                return True
            # Anonymous logon (Windows internal)
            if target_user == "anonymous logon":
                return True

        # 4634: Logoff from service/system accounts
        if eid == 4634:
            if target_user in ("system", "local service", "network service",
                               "anonymous logon") or target_user.startswith("dwm-") \
                               or target_user.startswith("umfd-"):
                return True

        return False

    def _extract_details(self, event_elem, ns, eid: int) -> Tuple[str, Dict]:
        """Extract meaningful details from event data fields."""
        data_elems = event_elem.findall(".//e:EventData/e:Data", ns)
        if not data_elems:
            # Try UserData
            data_elems = event_elem.findall(".//{http://schemas.microsoft.com/win/2004/08/events/event}UserData//*")

        data = {}
        for d in data_elems:
            name = d.get("Name", "")
            value = d.text or ""
            if name and value.strip():
                data[name] = value.strip()

        # Build meaningful detail string based on event type
        parts = []

        if eid in (4720, 4726, 4722, 4725, 4738, 4781):
            # Account events
            target = data.get("TargetUserName", data.get("NewTargetUserName", ""))
            actor = data.get("SubjectUserName", "")
            if target:
                parts.append(f"Account: {target}")
            if actor and actor != "-":
                parts.append(f"By: {actor}")
            if eid == 4781:
                old = data.get("OldTargetUserName", "")
                new = data.get("NewTargetUserName", "")
                if old and new:
                    parts.append(f"Renamed: {old} → {new}")

        elif eid in (4624, 4625, 4634, 4648):
            # Logon events
            user = data.get("TargetUserName", "")
            domain = data.get("TargetDomainName", "")
            logon_type = data.get("LogonType", "")
            ip = data.get("IpAddress", "")
            if user:
                parts.append(f"User: {domain}\\{user}" if domain and domain != "-" else f"User: {user}")
            if logon_type:
                type_names = {
                    "2": "Interactive", "3": "Network", "4": "Batch",
                    "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
                    "10": "RemoteInteractive", "11": "CachedInteractive",
                }
                parts.append(f"Type: {type_names.get(logon_type, logon_type)}")
            if ip and ip not in ("-", "::1", "127.0.0.1"):
                parts.append(f"IP: {ip}")
            if eid == 4625:
                reason = data.get("FailureReason", data.get("Status", ""))
                if reason:
                    parts.append(f"Reason: {reason}")

        elif eid == 7045:
            # Service installed
            svc = data.get("ServiceName", "")
            path = data.get("ImagePath", "")
            if svc:
                parts.append(f"Service: {svc}")
            if path:
                parts.append(f"Path: {path[:150]}")

        elif eid in (11707, 11724, 1033, 1034):
            # Software install/remove
            product = data.get("Product", data.get("ProductName", ""))
            if product:
                parts.append(f"Product: {product}")

        elif eid == 19:
            # Windows Update
            title = data.get("updateTitle", "")
            if title:
                parts.append(f"Update: {title}")

        elif eid in (4946, 4947, 4948):
            # Firewall rules
            rule = data.get("RuleName", "")
            if rule:
                parts.append(f"Rule: {rule}")

        elif eid == 1149:
            # RDP
            user = data.get("Param1", "")
            domain = data.get("Param2", "")
            ip = data.get("Param3", "")
            if user:
                parts.append(f"User: {domain}\\{user}" if domain else f"User: {user}")
            if ip:
                parts.append(f"From: {ip}")

        elif eid in (4732, 4733):
            # Group membership
            member = data.get("MemberName", data.get("MemberSid", ""))
            group = data.get("TargetUserName", "")
            if member:
                parts.append(f"Member: {member}")
            if group:
                parts.append(f"Group: {group}")

        elif eid in (6416, 20001, 20003, 400, 410):
            # Device events
            desc = data.get("DeviceDescription", "")
            class_name = data.get("ClassName", "")
            device_id = data.get("DeviceId", data.get("DeviceInstanceId", ""))
            if desc:
                parts.append(f"Device: {desc}")
            elif device_id:
                # Extract friendly name from device ID
                short_id = device_id.split("\\")[-1] if "\\" in device_id else device_id
                parts.append(f"Device: {short_id}")
            if class_name:
                # Map class names to friendly descriptions
                class_friendly = {
                    "AudioEndpoint": "Audio Device",
                    "Bluetooth": "Bluetooth Device",
                    "USB": "USB Device",
                    "HIDClass": "Input Device (keyboard/mouse)",
                    "DiskDrive": "Disk Drive",
                    "Net": "Network Adapter",
                    "Monitor": "Display/Monitor",
                    "Camera": "Camera/Webcam",
                    "Image": "Scanner/Imaging Device",
                    "Printer": "Printer",
                    "WPD": "Portable Device (phone/tablet)",
                }
                friendly = class_friendly.get(class_name, class_name)
                parts.append(f"Type: {friendly}")
            # Driver info for install events
            driver = data.get("DriverName", data.get("DriverProvider", ""))
            if driver:
                parts.append(f"Driver: {driver}")

        elif eid in (5001, 5010):
            # Defender disabled events
            parts.append("Windows Defender protection was disabled!")

        elif eid == 6008:
            # Unexpected shutdown
            parts.append("System was not shut down cleanly (crash, power loss, or forced)")

        # Fallback: show first few data fields
        if not parts and data:
            for k, v in list(data.items())[:3]:
                if v and v != "-":
                    parts.append(f"{k}: {v[:100]}")

        detail_str = " | ".join(parts) if parts else EVENT_DEFS.get(eid, EventDef(0, "", "", "", "")).description
        return detail_str, data

    def _extract_user(self, event_elem, ns) -> str:
        """Extract the user/subject from event."""
        data_elems = event_elem.findall(".//e:EventData/e:Data", ns)
        for d in data_elems:
            name = d.get("Name", "")
            if name in ("TargetUserName", "SubjectUserName") and d.text:
                return d.text.strip()
        return ""

    def _parse_events_fallback(self, raw: str, event_ids: List[int]) -> List[ParsedEvent]:
        """Fallback parser when XML is malformed."""
        events = []
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        # Split by <Event and try each one
        chunks = re.split(r'(?=<Event\s)', raw)
        for chunk in chunks:
            chunk = chunk.strip()
            if not chunk.startswith("<Event"):
                continue
            try:
                elem = ET.fromstring(chunk)
                parsed = self._parse_event_xml(elem, ns)
                if parsed:
                    events.append(parsed)
            except (ET.ParseError, AttributeError, ValueError):
                continue
        return events

    def get_user_accounts(self) -> List[Dict]:
        """Get all local user accounts with details."""
        accounts = []
        try:
            rc, out, _ = safe_run([
                "powershell", "-NoProfile", "-Command",
                "Get-LocalUser | Select-Object Name, Enabled, LastLogon, "
                "PasswordLastSet, Description, SID, "
                "@{N='Created';E={$_.PrincipalSource}} | ConvertTo-Json -Depth 2"
            ], timeout=10)
            if rc == 0 and out.strip():
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for u in data:
                    accounts.append({
                        "name": u.get("Name", ""),
                        "enabled": u.get("Enabled", False),
                        "last_logon": u.get("LastLogon", ""),
                        "password_set": u.get("PasswordLastSet", ""),
                        "description": u.get("Description", ""),
                        "sid": str(u.get("SID", {}).get("Value", "")) if isinstance(u.get("SID"), dict) else str(u.get("SID", "")),
                    })
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
            pass

        # Enrich with net user details (creation date, groups)
        for acc in accounts:
            try:
                rc, out, _ = safe_run(["net", "user", acc["name"]], timeout=5)
                if rc == 0:
                    for line in out.splitlines():
                        line = line.strip()
                        if line.startswith("Full Name"):
                            acc["full_name"] = line.split(None, 2)[-1].strip() if len(line.split(None, 2)) > 2 else ""
                        elif line.startswith("Account active"):
                            acc["active_str"] = line.split(None, 2)[-1].strip()
                        elif "Password last set" in line:
                            acc["password_last_set_str"] = line.split(None, 3)[-1].strip() if len(line.split(None, 3)) > 3 else ""
                        elif "Last logon" in line:
                            acc["last_logon_str"] = line.split(None, 2)[-1].strip() if len(line.split(None, 2)) > 2 else ""
                        elif "Local Group" in line:
                            groups = re.findall(r'\*(\S+)', line)
                            acc["groups"] = groups
                        elif "Account expires" in line:
                            acc["expires"] = line.split(None, 2)[-1].strip() if len(line.split(None, 2)) > 2 else ""
            except (IndexError, ValueError, AttributeError):
                pass

            # SID analysis: SID-1001 = first user created during setup
            sid = acc.get("sid", "")
            rid = sid.split("-")[-1] if sid else ""
            if rid.isdigit():
                rid_int = int(rid)
                if rid_int == 500:
                    acc["sid_note"] = "Built-in Administrator"
                elif rid_int == 501:
                    acc["sid_note"] = "Built-in Guest"
                elif rid_int == 503:
                    acc["sid_note"] = "DefaultAccount (system)"
                elif rid_int == 504:
                    acc["sid_note"] = "WDAGUtilityAccount (Defender)"
                elif rid_int == 1001:
                    acc["sid_note"] = "First user created during Windows setup"
                elif rid_int > 1001:
                    acc["sid_note"] = "Created after initial setup (added later)"
                else:
                    acc["sid_note"] = ""
            else:
                acc["sid_note"] = ""

        return accounts

    def get_account_events_all_time(self) -> List[ParsedEvent]:
        """Query ALL account-related events with no time limit. Requires admin."""
        if not self._admin:
            return []
        account_ids = [e.event_id for e in EVENT_DEFS.values() if e.category == "Account"]
        return self._query_log("Security", account_ids, "2000-01-01T00:00:00.000Z")

    # ── Spy Check ──

    def run_spy_check(self) -> List[Dict]:
        """Run comprehensive spy/intrusion checks. Returns list of findings."""
        findings = []

        # 1. Camera access history
        findings.extend(self._check_capability_access("webcam", "Camera"))

        # 2. Microphone access history
        findings.extend(self._check_capability_access("microphone", "Microphone"))

        # 3. Remote access settings
        findings.extend(self._check_remote_access())

        # 4. Suspicious user accounts
        findings.extend(self._check_suspicious_accounts())

        # 5. Recent user profile changes
        findings.extend(self._check_profile_changes())

        # 6. Event log tampering
        findings.extend(self._check_log_tampering())

        # 7. Suspicious scheduled tasks
        findings.extend(self._check_suspicious_tasks())

        # 8. Recent remote access tools
        findings.extend(self._check_remote_tools())

        return findings

    def _check_capability_access(self, capability: str, label: str) -> List[Dict]:
        """Check Windows Privacy camera/mic access history."""
        findings = []
        if not winreg:
            return findings

        base_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{capability}"

        for hive, hive_name in [(winreg.HKEY_CURRENT_USER, "User"),
                                 (winreg.HKEY_LOCAL_MACHINE, "System")]:
            try:
                key = winreg.OpenKey(hive, base_path, 0, winreg.KEY_READ)
                # Check global allow/deny
                try:
                    val, _ = winreg.QueryValueEx(key, "Value")
                    if val == "Deny":
                        findings.append({
                            "category": label,
                            "severity": "INFO",
                            "title": f"{label} access is BLOCKED globally",
                            "detail": f"No apps can access your {capability}. This is safe.",
                            "icon": "✓",
                        })
                except FileNotFoundError:
                    pass

                # Enumerate apps
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                        try:
                            start_raw, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStart")
                            stop_raw, _ = winreg.QueryValueEx(subkey, "LastUsedTimeStop")

                            # Convert Windows FILETIME to datetime
                            start_dt = self._filetime_to_datetime(start_raw)
                            stop_dt = self._filetime_to_datetime(stop_raw)

                            # Clean up app name
                            app_name = subkey_name.replace("#", "\\")
                            # Extract readable name
                            if "_" in app_name and "." in app_name:
                                # UWP app — extract base name
                                parts = app_name.split("_")
                                app_name = parts[0]

                            start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S") if start_dt else "Unknown"
                            stop_str = stop_dt.strftime("%Y-%m-%d %H:%M:%S") if stop_dt else "Still active"

                            # Determine if currently active
                            is_active = stop_raw == 0 or (stop_dt and start_dt and stop_dt < start_dt)

                            severity = "WARNING" if is_active else "INFO"
                            status = "ACTIVE NOW" if is_active else "Last used"

                            findings.append({
                                "category": label,
                                "severity": severity,
                                "title": f"{app_name} accessed {capability}",
                                "detail": f"{status}: {start_str} — {stop_str}",
                                "icon": "🔴" if is_active else "📋",
                            })
                        except FileNotFoundError:
                            pass
                        winreg.CloseKey(subkey)
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except (OSError, PermissionError):
                pass

        if not any(f["category"] == label for f in findings):
            findings.append({
                "category": label,
                "severity": "INFO",
                "title": f"No {capability} access history found",
                "detail": "No apps have accessed this device recently.",
                "icon": "✓",
            })

        return findings

    def _filetime_to_datetime(self, ft) -> Optional[datetime]:
        """Convert Windows FILETIME (100ns intervals since 1601) to datetime."""
        if not ft or ft == 0:
            return None
        try:
            # FILETIME epoch is Jan 1, 1601
            EPOCH_DIFF = 116444736000000000  # 100ns intervals between 1601 and 1970
            timestamp = (ft - EPOCH_DIFF) / 10000000  # Convert to seconds
            return datetime.fromtimestamp(timestamp)
        except (ValueError, OSError, OverflowError):
            return None

    def _check_remote_access(self) -> List[Dict]:
        """Check if remote access is enabled."""
        findings = []
        if not winreg:
            return findings

        # RDP
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server", 0, winreg.KEY_READ)
            deny, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            if deny == 0:
                findings.append({
                    "category": "Remote Access",
                    "severity": "CRITICAL",
                    "title": "Remote Desktop (RDP) is ENABLED",
                    "detail": "Someone can remotely control this PC if they have credentials.\n"
                              "Disable: Settings → System → Remote Desktop → Off",
                    "icon": "⚠",
                })
            else:
                findings.append({
                    "category": "Remote Access",
                    "severity": "INFO",
                    "title": "Remote Desktop is disabled",
                    "detail": "RDP is off. No one can remote desktop into this PC.",
                    "icon": "✓",
                })
        except OSError:
            pass

        # Remote Assistance
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Remote Assistance", 0, winreg.KEY_READ)
            allow, _ = winreg.QueryValueEx(key, "fAllowToGetHelp")
            winreg.CloseKey(key)
            if allow:
                findings.append({
                    "category": "Remote Access",
                    "severity": "WARNING",
                    "title": "Remote Assistance is ENABLED",
                    "detail": "Someone could send a remote assistance invitation.\n"
                              "Disable: System Properties → Remote → uncheck 'Allow Remote Assistance'",
                    "icon": "⚠",
                })
        except OSError:
            pass

        # Check for remote access software running
        if psutil:
            remote_tools = {
                "teamviewer": "TeamViewer",
                "anydesk": "AnyDesk",
                "rustdesk": "RustDesk",
                "vnc": "VNC Server",
                "ammyy": "Ammyy Admin",
                "supremo": "Supremo",
                "logmein": "LogMeIn",
                "splashtop": "Splashtop",
                "remotepc": "RemotePC",
            }
            for proc in psutil.process_iter(['name', 'exe']):
                try:
                    pname = proc.info['name'].lower()
                    for key, label in remote_tools.items():
                        if key in pname:
                            findings.append({
                                "category": "Remote Access",
                                "severity": "WARNING",
                                "title": f"{label} is RUNNING",
                                "detail": f"Process: {proc.info['name']}\n"
                                          f"Path: {proc.info.get('exe', 'Unknown')}",
                                "icon": "⚠",
                            })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        return findings

    def _check_suspicious_accounts(self) -> List[Dict]:
        """Check for suspicious user accounts."""
        findings = []
        try:
            rc, out, _ = safe_run(["net", "user"], timeout=10)
            if rc == 0:
                lines = out.splitlines()
                for line in lines:
                    if line.startswith("---") or line.startswith("User accounts") or \
                       line.startswith("The command") or not line.strip():
                        continue
                    for name in line.split():
                        name = name.strip()
                        if not name:
                            continue
                        # Check each account
                        rc2, detail, _ = safe_run(["net", "user", name], timeout=5)
                        if rc2 != 0:
                            continue
                        is_active = "Yes" in [l.split()[-1] for l in detail.splitlines()
                                              if "Account active" in l]
                        is_admin = "Administrators" in detail

                        # Flag unknown active admin accounts
                        if is_active and is_admin and name.lower() not in (
                            "administrator", "christophoros", "chrpa"):
                            findings.append({
                                "category": "Accounts",
                                "severity": "CRITICAL",
                                "title": f"Unknown admin account: {name}",
                                "detail": "This active administrator account is not recognized.\n"
                                          "Could be created by an attacker for persistent access.",
                                "icon": "⚠",
                            })
        except (IndexError, AttributeError, ValueError):
            pass

        if not findings:
            findings.append({
                "category": "Accounts",
                "severity": "INFO",
                "title": "No suspicious accounts found",
                "detail": "All active admin accounts are recognized.",
                "icon": "✓",
            })

        return findings

    def _check_profile_changes(self) -> List[Dict]:
        """Check for signs someone modified user profile/desktop."""
        findings = []
        if not winreg:
            return findings

        # Wallpaper source check
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Control Panel\Desktop", 0, winreg.KEY_READ)
            wp, _ = winreg.QueryValueEx(key, "Wallpaper")
            winreg.CloseKey(key)
            if wp:
                findings.append({
                    "category": "Profile",
                    "severity": "INFO",
                    "title": "Current wallpaper",
                    "detail": wp,
                    "icon": "🖼",
                })
        except OSError:
            pass

        # Check if screensaver has password protection
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Control Panel\Desktop", 0, winreg.KEY_READ)
            try:
                ss_secure, _ = winreg.QueryValueEx(key, "ScreenSaverIsSecure")
                if ss_secure == "0":
                    findings.append({
                        "category": "Profile",
                        "severity": "WARNING",
                        "title": "Screen saver NOT password-protected",
                        "detail": "When the screen saver activates, no password is required to unlock.\n"
                                  "Anyone can access the PC when you step away.",
                        "icon": "⚠",
                    })
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except OSError:
            pass

        # Check auto-lock timeout
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Control Panel\Desktop", 0, winreg.KEY_READ)
            try:
                timeout, _ = winreg.QueryValueEx(key, "ScreenSaveTimeOut")
                timeout_min = int(timeout) // 60 if timeout else 0
                if timeout_min > 15 or timeout_min == 0:
                    findings.append({
                        "category": "Profile",
                        "severity": "WARNING",
                        "title": f"Screen auto-lock: {timeout_min} min" if timeout_min else "Screen auto-lock: DISABLED",
                        "detail": "Long timeout or disabled auto-lock means the PC stays unlocked\n"
                                  "when you walk away. Recommended: 5 minutes or less.",
                        "icon": "⚠",
                    })
            except FileNotFoundError:
                findings.append({
                    "category": "Profile",
                    "severity": "WARNING",
                    "title": "Screen auto-lock: NOT CONFIGURED",
                    "detail": "No screen timeout is set. PC won't auto-lock when idle.",
                    "icon": "⚠",
                })
            winreg.CloseKey(key)
        except OSError:
            pass

        return findings

    def _check_log_tampering(self) -> List[Dict]:
        """Check if event logs show signs of tampering."""
        findings = []

        # Check if Security log was recently cleared (Event 1102)
        if self._admin:
            events = self._query_log("Security", [1102], "2000-01-01T00:00:00.000Z")
            if events:
                # Extract who cleared it
                last = events[0]
                who = last.parsed_data.get("SubjectUserName", "Unknown")
                sid = last.parsed_data.get("SubjectUserSid", "")
                detail = f"Someone cleared the Windows Security audit log.\n" \
                         f"Last cleared: {last.timestamp}\n" \
                         f"Cleared by: {who} (SID: {sid})\n"
                # Check if it was a known user
                if who.endswith("$"):
                    detail += "This was done by the SYSTEM account (unusual — investigate)."
                else:
                    detail += f"This was done by user '{who}'."
                findings.append({
                    "category": "Log Integrity",
                    "severity": "CRITICAL",
                    "title": f"Security log was CLEARED ({len(events)} times) — by {who}",
                    "detail": detail,
                    "icon": "⚠",
                })
            else:
                findings.append({
                    "category": "Log Integrity",
                    "severity": "INFO",
                    "title": "Security log has NOT been cleared",
                    "detail": "No evidence of log tampering.",
                    "icon": "✓",
                })

        # Check log sizes (too small = events being lost)
        for log_name in ["Security", "System", "Application"]:
            try:
                rc, out, _ = safe_run(["wevtutil", "gl", log_name], timeout=5)
                if rc == 0:
                    for line in out.splitlines():
                        if "maxSize" in line:
                            max_bytes = int(line.split(":")[-1].strip())
                            max_mb = max_bytes / (1024 * 1024)
                            if max_mb <= 20:
                                findings.append({
                                    "category": "Log Integrity",
                                    "severity": "WARNING",
                                    "title": f"{log_name} log too small ({max_mb:.0f} MB)",
                                    "detail": f"Default 20 MB only keeps ~3 days of history.\n"
                                              "Click 'Fix Log Sizes' below to increase to 200 MB (~6-12 months).",
                                    "icon": "⚠",
                                    "fixable": "log_size",
                                    "fix_target": log_name,
                                })
            except (ValueError, IndexError, AttributeError):
                pass

        return findings

    def _check_suspicious_tasks(self) -> List[Dict]:
        """Check for suspicious scheduled tasks."""
        findings = []
        suspicious_paths = [r"\appdata\local\temp", r"\users\public",
                           r"\programdata", r"\downloads", "cmd.exe /c",
                           "powershell.exe -e", "powershell.exe -enc"]
        try:
            rc, out, _ = safe_run(["schtasks", "/query", "/fo", "CSV", "/v"], timeout=20)
            if rc == 0 and out.strip():
                import csv, io
                reader = csv.DictReader(io.StringIO(out))
                seen = set()
                for row in reader:
                    task_name = row.get("TaskName", "").strip()
                    task_run = row.get("Task To Run", "").strip()
                    if not task_name or task_name in seen or task_name == "TaskName":
                        continue
                    if "\\Microsoft\\" in task_name:
                        continue
                    seen.add(task_name)

                    for susp in suspicious_paths:
                        if susp.lower() in task_run.lower():
                            findings.append({
                                "category": "Scheduled Tasks",
                                "severity": "WARNING",
                                "title": f"Suspicious task: {task_name.split(chr(92))[-1]}",
                                "detail": f"Command: {task_run[:200]}\n"
                                          "Running from a suspicious location.",
                                "icon": "⚠",
                            })
                            break
        except (csv.Error, KeyError, AttributeError):
            pass

        return findings

    def _check_remote_tools(self) -> List[Dict]:
        """Check for installed remote access tools (not just running)."""
        findings = []
        remote_indicators = [
            (r"SOFTWARE\TeamViewer", "TeamViewer"),
            (r"SOFTWARE\AnyDesk", "AnyDesk"),
            (r"SOFTWARE\WOW6432Node\TeamViewer", "TeamViewer (32-bit)"),
        ]
        if winreg:
            for reg_path, name in remote_indicators:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0, winreg.KEY_READ)
                    winreg.CloseKey(key)
                    findings.append({
                        "category": "Remote Access",
                        "severity": "WARNING",
                        "title": f"{name} is INSTALLED",
                        "detail": f"Found in registry: HKLM\\{reg_path}\n"
                                  "If you don't use this, remove it — it allows remote control.",
                        "icon": "⚠",
                    })
                except FileNotFoundError:
                    pass
                except OSError:
                    pass

        return findings

    def export_events(self, events: List[ParsedEvent], path: str):
        """Export events to JSON."""
        data = {
            "exported_at": now_ts(),
            "total_events": len(events),
            "events": [
                {
                    "timestamp": e.timestamp,
                    "event_id": e.event_id,
                    "category": e.category,
                    "severity": e.severity,
                    "title": e.title,
                    "details": e.details,
                    "user": e.user,
                    "computer": e.computer,
                    "log_source": e.log_source,
                }
                for e in events
            ]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


# ─────────────────────────────────────────────
# App (UI)
# ─────────────────────────────────────────────

class App(ctk.CTkFrame if HAS_CTK else tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title(TOOL_NAME)
        parent.geometry("1300x750")
        parent.minsize(900, 550)

        self.running = True
        self.engine = ActivityMonitorEngine()

        # Queues
        self.work_q: queue.Queue = queue.Queue()
        self.result_q: queue.Queue = queue.Queue()

        # State
        self._hist_events: List[ParsedEvent] = []
        self._live_events: BoundedDeque = BoundedDeque(maxlen=5000)
        self._live_paused = False
        self._live_counter = 0
        self._poll_interval = 5000  # ms
        self._active_categories: Set[str] = set(ALL_CATEGORIES)
        self._active_severities: Set[str] = {"CRITICAL", "WARNING", "INFO"}
        # Guards _active_categories / _active_severities against UI-toggle
        # writes racing with worker-thread or after()-callback reads.
        self._filter_lock = threading.RLock()
        self._search_text = ""
        self._hist_hours = 24

        # Build
        self._apply_tree_style()
        self._build_ui()

        # Worker
        t = threading.Thread(target=self._worker_loop, daemon=True)
        t.start()

        # Schedule
        self.after(100, self._process_queue)
        self.after(500, self._load_historical)
        self.after(2000, self._start_live_poll)

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

        # Admin banner
        if not self.engine._admin:
            banner = ctk.CTkFrame(self, fg_color="#442200", height=30)
            banner.pack(fill="x", padx=6, pady=(6, 0))
            ctk.CTkLabel(banner,
                text="⚠ Running without admin — Security log events (Account, Logon, Security Policy) are unavailable. Run as Administrator for full access.",
                font=("Segoe UI", 10), text_color=C_ORANGE).pack(padx=10, pady=4)

        # Notebook
        self.nb = ctk.CTkTabview(self)
        self.nb.pack(fill="both", expand=True, padx=6, pady=6)

        self.tab_spy = self.nb.add("Spy Check")
        self.tab_accounts = self.nb.add("User Accounts")
        self.tab_historical = self.nb.add("Historical Timeline")
        self.tab_live = self.nb.add("Live Monitor")
        self.tab_settings = self.nb.add("Settings")

        self._build_spy_check()
        self._build_accounts()
        self._build_historical()
        self._build_live()
        self._build_settings()

    # ── Category filter builder (shared) ──

    def _build_category_filters(self, parent, on_change) -> Dict[str, ctk.CTkButton]:
        """Build category toggle buttons. Returns dict of category -> button."""
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.pack(fill="x", padx=6, pady=(4, 2))

        ctk.CTkLabel(frame, text="Filter:", font=("Segoe UI", 10),
                     text_color=C_GRAY).pack(side="left", padx=(0, 6))

        buttons = {}
        for cat in ALL_CATEGORIES:
            icon = CATEGORY_ICONS.get(cat, "")
            btn = ctk.CTkButton(frame, text=f"{icon} {cat}", width=90, height=26,
                fg_color="#1f538d", hover_color="#2b6194",
                font=("Segoe UI", 9),
                command=lambda c=cat: self._toggle_category(c, buttons, on_change))
            btn.pack(side="left", padx=2)
            buttons[cat] = btn

        # Severity filter
        ctk.CTkLabel(frame, text="  Severity:", font=("Segoe UI", 10),
                     text_color=C_GRAY).pack(side="left", padx=(10, 4))

        self._sev_buttons: Dict[str, ctk.CTkButton] = {}
        sev_configs = [
            ("CRITICAL", C_RED, "#661111"),
            ("WARNING", C_ORANGE, "#664400"),
            ("INFO", C_GRAY, "#333333"),
        ]
        for sev, active_color, hover in sev_configs:
            btn = ctk.CTkButton(frame, text=sev, width=70, height=26,
                fg_color=active_color, hover_color=hover,
                font=("Segoe UI", 9),
                command=lambda s=sev: self._toggle_severity(s, on_change))
            btn.pack(side="left", padx=2)
            self._sev_buttons[sev] = btn

        return buttons

    def _toggle_category(self, cat: str, buttons: Dict, on_change):
        icon = CATEGORY_ICONS.get(cat, "")
        with self._filter_lock:
            if cat in self._active_categories:
                self._active_categories.discard(cat)
                buttons[cat].configure(fg_color="#2a2a2a", text=f"[OFF] {cat}",
                                        text_color="#555555", border_width=1,
                                        border_color="#444444")
            else:
                self._active_categories.add(cat)
                buttons[cat].configure(fg_color="#1f538d", text=f"{icon} {cat}",
                                        text_color=C_WHITE, border_width=0)
        on_change()

    def _toggle_severity(self, sev: str, on_change):
        colors = {"CRITICAL": C_RED, "WARNING": C_ORANGE, "INFO": C_GRAY}
        with self._filter_lock:
            if sev in self._active_severities:
                self._active_severities.discard(sev)
                self._sev_buttons[sev].configure(fg_color="#2a2a2a", text=f"[OFF] {sev}",
                                                  text_color="#555555", border_width=1,
                                                  border_color="#444444")
            else:
                self._active_severities.add(sev)
                self._sev_buttons[sev].configure(fg_color=colors[sev], text=sev,
                                                  text_color=C_WHITE, border_width=0)
        on_change()

    def _snapshot_filters(self) -> Tuple[frozenset, frozenset]:
        """Return an atomic snapshot of the active category/severity filters.

        Callers iterate or membership-test against the returned frozensets so
        that concurrent toggle writes cannot mutate the sets mid-read.
        """
        with self._filter_lock:
            return frozenset(self._active_categories), frozenset(self._active_severities)

    # ── Historical Timeline Tab ──

    # ── User Accounts Tab ──

    # ── Spy Check Tab ──

    def _build_spy_check(self):
        f = self.tab_spy
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Header
        top = ctk.CTkFrame(scroll, fg_color="transparent")
        top.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(top, text="🔍 Spy & Intrusion Check",
                     font=("Segoe UI", 16, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Run Scan", width=100, height=30,
                      fg_color="#1f538d", hover_color="#2b6194",
                      command=self._run_spy_check).pack(side="right")
        self._spy_status = ctk.CTkLabel(top, text="", font=("Segoe UI", 10),
                                         text_color=C_GRAY)
        self._spy_status.pack(side="right", padx=10)

        # Results container
        self._spy_results_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        self._spy_results_frame.pack(fill="x")

        # Initial message
        ctk.CTkLabel(self._spy_results_frame,
            text="Click 'Run Scan' to check for:\n\n"
                 "  • Camera & Microphone access history (which apps, when)\n"
                 "  • Remote access tools (TeamViewer, AnyDesk, RDP)\n"
                 "  • Suspicious user accounts\n"
                 "  • Screen lock settings\n"
                 "  • Event log tampering\n"
                 "  • Suspicious scheduled tasks",
            font=("Segoe UI", 11), text_color=C_GRAY,
            justify="left").pack(pady=30, padx=20, anchor="w")

        self.after(500, self._run_spy_check)

    def _run_spy_check(self):
        self._spy_status.configure(text="Scanning...")
        self.work_q.put_nowait(("spy_check",))

    def _populate_spy_results(self, findings: List[Dict]):
        """Build spy check result cards grouped by category."""
        for w in self._spy_results_frame.winfo_children():
            w.destroy()

        if not findings:
            ctk.CTkLabel(self._spy_results_frame, text="No findings",
                         font=("Segoe UI", 12)).pack(pady=20)
            return

        # Count severities
        crits = sum(1 for f in findings if f["severity"] == "CRITICAL")
        warns = sum(1 for f in findings if f["severity"] == "WARNING")
        infos = sum(1 for f in findings if f["severity"] == "INFO")

        # Overall status banner
        if crits > 0:
            banner_color = "#441111"
            banner_text = f"⚠ {crits} CRITICAL issue{'s' if crits != 1 else ''} found!"
            text_color = C_RED
        elif warns > 0:
            banner_color = "#332200"
            banner_text = f"⚠ {warns} warning{'s' if warns != 1 else ''} — review recommended"
            text_color = C_ORANGE
        else:
            banner_color = "#112211"
            banner_text = "✓ No spy indicators detected"
            text_color = C_GREEN

        banner = ctk.CTkFrame(self._spy_results_frame, fg_color=banner_color,
                               corner_radius=8)
        banner.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(banner, text=banner_text, font=("Segoe UI", 13, "bold"),
                     text_color=text_color).pack(padx=12, pady=8)

        # Group by category
        categories = {}
        for f in findings:
            cat = f["category"]
            categories.setdefault(cat, []).append(f)

        for cat, cat_findings in categories.items():
            # Category header
            cat_frame = ctk.CTkFrame(self._spy_results_frame, fg_color=CARD_BG,
                                      corner_radius=8)
            cat_frame.pack(fill="x", pady=3)

            # Determine category status
            cat_crits = sum(1 for f in cat_findings if f["severity"] == "CRITICAL")
            cat_warns = sum(1 for f in cat_findings if f["severity"] == "WARNING")
            if cat_crits:
                status_icon = "🔴"
            elif cat_warns:
                status_icon = "🟡"
            else:
                status_icon = "🟢"

            hdr = ctk.CTkFrame(cat_frame, fg_color="transparent")
            hdr.pack(fill="x", padx=10, pady=(6, 2))
            ctk.CTkLabel(hdr, text=f"{status_icon} {cat}",
                         font=("Segoe UI", 12, "bold")).pack(side="left")

            # Findings in this category
            for finding in cat_findings:
                row = ctk.CTkFrame(cat_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=2)

                sev_color = SEV_COLORS.get(finding["severity"], C_WHITE)
                icon = finding.get("icon", "•")

                ctk.CTkLabel(row, text=icon, font=("Segoe UI", 10),
                             width=25).pack(side="left")
                ctk.CTkLabel(row, text=finding["title"],
                             font=("Segoe UI", 10, "bold"),
                             text_color=sev_color).pack(side="left", padx=(0, 8))

                if finding.get("detail"):
                    detail_row = ctk.CTkFrame(cat_frame, fg_color="transparent")
                    detail_row.pack(fill="x", padx=(45, 10), pady=(0, 2))
                    ctk.CTkLabel(detail_row, text=finding["detail"],
                                 font=("Segoe UI", 9), text_color="#999999",
                                 wraplength=700, justify="left").pack(anchor="w")

            # Pad bottom
            ctk.CTkLabel(cat_frame, text="", font=("Segoe UI", 2)).pack()

        # Add "Fix Log Sizes" button if any fixable log findings
        fixable_logs = [f for f in findings if f.get("fixable") == "log_size"]
        if fixable_logs:
            fix_frame = ctk.CTkFrame(self._spy_results_frame, fg_color="#1a2a3a",
                                      corner_radius=8)
            fix_frame.pack(fill="x", pady=6)
            ctk.CTkLabel(fix_frame, text="🔧 Quick Fix Available",
                         font=("Segoe UI", 11, "bold"),
                         text_color=C_CYAN).pack(anchor="w", padx=10, pady=(6, 2))
            log_names = [f["fix_target"] for f in fixable_logs]
            ctk.CTkLabel(fix_frame,
                text=f"Increase {', '.join(log_names)} logs from 20 MB to 200 MB\n"
                     "This keeps ~6-12 months of history instead of ~3 days.",
                font=("Segoe UI", 9), text_color=C_GRAY,
                justify="left").pack(anchor="w", padx=10, pady=(0, 4))
            ctk.CTkButton(fix_frame, text="Fix Log Sizes (requires admin)", width=220,
                          height=30, fg_color="#226622", hover_color="#338833",
                          command=lambda logs=log_names: self._fix_log_sizes(logs)
                          ).pack(padx=10, pady=(0, 8))

        self._spy_status.configure(
            text=f"Done — {crits} critical, {warns} warnings, {infos} info")

    # ── User Accounts Tab ──

    def _build_accounts(self):
        f = self.tab_accounts
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Header
        top = ctk.CTkFrame(scroll, fg_color="transparent")
        top.pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(top, text="👤 Local User Accounts",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        ctk.CTkButton(top, text="Refresh", width=70, height=26,
                      command=self._load_accounts).pack(side="right")
        ctk.CTkButton(top, text="Scan Account History", width=150, height=26,
                      fg_color="#1f538d", hover_color="#2b6194",
                      command=self._scan_account_history).pack(side="right", padx=4)

        self._accounts_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        self._accounts_frame.pack(fill="x")

        # Account history section (populated on scan)
        self._acct_hist_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        self._acct_hist_frame.pack(fill="x", pady=(8, 0))

        self.after(300, self._load_accounts)

    def _load_accounts(self):
        self.work_q.put_nowait(("accounts",))

    def _scan_account_history(self):
        """Scan all account events from Security log (all time, needs admin)."""
        if not self.engine._admin:
            messagebox.showinfo("Admin Required",
                "Scanning account history from Security log requires administrator privileges.\n\n"
                "Right-click the app → Run as administrator.")
            return
        self.work_q.put_nowait(("account_history",))

    def _populate_accounts(self, accounts: List[Dict]):
        """Build account cards."""
        for w in self._accounts_frame.winfo_children():
            w.destroy()

        for acc in accounts:
            # Determine if this is a notable account
            is_system = acc.get("sid_note", "").startswith("Built-in") or \
                        acc.get("sid_note", "").endswith("(system)") or \
                        acc.get("sid_note", "").endswith("(Defender)")
            is_enabled = acc.get("enabled", False)

            if is_system and not is_enabled:
                border_color = "#333333"
                dim = True
            elif is_enabled:
                border_color = C_GREEN
                dim = False
            else:
                border_color = C_ORANGE
                dim = False

            card = ctk.CTkFrame(self._accounts_frame, fg_color=CARD_BG,
                                corner_radius=8, border_width=2,
                                border_color=border_color)
            card.pack(fill="x", pady=3)

            # Header row
            hdr = ctk.CTkFrame(card, fg_color="transparent")
            hdr.pack(fill="x", padx=10, pady=(6, 2))

            name_text = acc.get("name", "?")
            full_name = acc.get("full_name", "")
            if full_name and full_name != name_text:
                name_text += f"  ({full_name})"
            text_color = "#666666" if dim else C_WHITE
            ctk.CTkLabel(hdr, text=name_text, font=("Segoe UI", 12, "bold"),
                         text_color=text_color).pack(side="left")

            status_text = "ACTIVE" if is_enabled else "DISABLED"
            status_color = C_GREEN if is_enabled else "#666666"
            ctk.CTkLabel(hdr, text=status_text, font=("Segoe UI", 10, "bold"),
                         text_color=status_color).pack(side="right")

            # Details grid
            details = ctk.CTkFrame(card, fg_color="transparent")
            details.pack(fill="x", padx=10, pady=(0, 6))

            fields = []
            fields.append(("SID", acc.get("sid", "")))
            if acc.get("sid_note"):
                fields.append(("SID Note", acc["sid_note"]))
            fields.append(("Last Logon", acc.get("last_logon_str", acc.get("last_logon", "")) or "Never"))
            fields.append(("Password Set", acc.get("password_last_set_str", acc.get("password_set", "")) or "Never"))
            groups = acc.get("groups", [])
            if groups:
                fields.append(("Groups", ", ".join(groups)))
            if acc.get("description"):
                fields.append(("Description", acc["description"]))
            if acc.get("expires"):
                fields.append(("Expires", acc["expires"]))

            for i, (label, value) in enumerate(fields):
                row_idx = i // 2
                col_idx = (i % 2) * 2
                lbl_color = "#555555" if dim else C_GRAY
                val_color = "#555555" if dim else C_WHITE
                ctk.CTkLabel(details, text=f"{label}:", font=("Segoe UI", 9, "bold"),
                             text_color=lbl_color, width=90, anchor="w"
                             ).grid(row=row_idx, column=col_idx, padx=(0, 4), pady=1, sticky="w")
                ctk.CTkLabel(details, text=str(value)[:120], font=("Segoe UI", 9),
                             text_color=val_color
                             ).grid(row=row_idx, column=col_idx + 1, padx=(0, 20), pady=1, sticky="w")

            for c in range(4):
                details.columnconfigure(c, weight=1 if c % 2 else 0)

    def _populate_account_history(self, events: List):
        """Show account-related events from Security log."""
        for w in self._acct_hist_frame.winfo_children():
            w.destroy()

        if not events:
            ctk.CTkLabel(self._acct_hist_frame,
                text="No account events found in Security log.\n"
                     "Run as Administrator and click 'Scan Account History' to search.",
                font=("Segoe UI", 10), text_color=C_GRAY).pack(pady=10)
            return

        header = ctk.CTkFrame(self._acct_hist_frame, fg_color="transparent")
        header.pack(fill="x", pady=(4, 2))
        ctk.CTkLabel(header, text=f"🔍 Account History — {len(events)} events found (all time)",
                     font=("Segoe UI", 12, "bold")).pack(side="left")

        # Treeview for account history
        tree_frame = ctk.CTkFrame(self._acct_hist_frame)
        tree_frame.pack(fill="x", pady=4)

        cols = ("time", "severity", "event", "details")
        self._acct_hist_tree = ttk.Treeview(tree_frame, columns=cols,
                                             show="headings", height=12)
        self._acct_hist_tree.heading("time", text="Time")
        self._acct_hist_tree.heading("severity", text="Severity")
        self._acct_hist_tree.heading("event", text="Event")
        self._acct_hist_tree.heading("details", text="Details")
        self._acct_hist_tree.column("time", width=140, stretch=False)
        self._acct_hist_tree.column("severity", width=70, stretch=False)
        self._acct_hist_tree.column("event", width=200, stretch=False)
        self._acct_hist_tree.column("details", width=500, stretch=True)
        self._acct_hist_tree.tag_configure("CRITICAL", foreground=C_RED)
        self._acct_hist_tree.tag_configure("WARNING", foreground=C_ORANGE)
        self._acct_hist_tree.tag_configure("INFO", foreground="#cccccc")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                             command=self._acct_hist_tree.yview)
        self._acct_hist_tree.configure(yscrollcommand=vsb.set)
        self._acct_hist_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._acct_hist_events = events
        for e in events:
            self._acct_hist_tree.insert("", "end", values=(
                e.timestamp, e.severity, e.title, e.details[:200]
            ), tags=(e.severity,))

        self._acct_hist_tree.bind("<Double-1>", lambda ev: self._show_event_detail(
            self._acct_hist_tree, self._acct_hist_events))

    # ── Historical Timeline Tab ──

    def _build_historical(self):
        f = self.tab_historical

        # Top bar: time range + search + export
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(4, 0))

        ctk.CTkLabel(top, text="Range:", font=("Segoe UI", 10),
                     text_color=C_GRAY).pack(side="left")
        self._range_buttons: Dict[int, ctk.CTkButton] = {}
        for hours, label in [(24, "1d"), (168, "7d"), (720, "30d"), (0, "All")]:
            btn = ctk.CTkButton(top, text=label, width=45, height=26,
                fg_color="#1f538d" if hours == 24 else "#444444",
                hover_color="#2b6194", font=("Segoe UI", 9),
                command=lambda h=hours: self._set_range(h))
            btn.pack(side="left", padx=2)
            self._range_buttons[hours] = btn

        self._hist_search = ctk.CTkEntry(top, placeholder_text="Search events...", width=220)
        self._hist_search.pack(side="left", padx=(12, 4))
        self._hist_search.bind("<KeyRelease>", lambda e: self._filter_historical())

        self._hist_count = ctk.CTkLabel(top, text="0 events", font=("Segoe UI", 10),
                                         text_color=C_GRAY)
        self._hist_count.pack(side="left", padx=10)

        self._hist_progress = ctk.CTkLabel(top, text="", font=("Segoe UI", 9),
                                            text_color=C_CYAN)
        self._hist_progress.pack(side="left", padx=4)

        ctk.CTkButton(top, text="Refresh", width=70, height=26,
                      command=self._load_historical).pack(side="right", padx=4)
        ctk.CTkButton(top, text="Export", width=60, height=26,
                      fg_color="#444444", hover_color="#555555",
                      command=self._export_historical).pack(side="right", padx=2)

        # Category filters
        self._hist_cat_buttons = self._build_category_filters(f, self._filter_historical)

        # Treeview
        tree_frame = ctk.CTkFrame(f)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("time", "category", "severity", "event_id", "title", "details")
        headers = ("Time", "Category", "Severity", "ID", "Event", "Details")
        widths = (140, 80, 70, 45, 200, 450)

        self.hist_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                       selectmode="browse")
        for col, hdr, w in zip(cols, headers, widths):
            self.hist_tree.heading(col, text=hdr)
            self.hist_tree.column(col, width=w, stretch=(col == "details"),
                                  minwidth=35)

        self.hist_tree.tag_configure("CRITICAL", foreground=C_RED)
        self.hist_tree.tag_configure("WARNING", foreground=C_ORANGE)
        self.hist_tree.tag_configure("INFO", foreground="#cccccc")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb.set)
        self.hist_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.hist_tree.bind("<Double-1>", self._show_event_detail_hist)

    def _set_range(self, hours: int):
        self._hist_hours = hours
        for h, btn in self._range_buttons.items():
            btn.configure(fg_color="#1f538d" if h == hours else "#444444")
        self._load_historical()

    def _load_historical(self):
        hours = self._hist_hours if self._hist_hours > 0 else 8760  # "All" = 1 year
        self._hist_progress.configure(text="Loading...")
        cats, _ = self._snapshot_filters()
        self.work_q.put_nowait(("historical", hours, cats))

    def _filter_historical(self):
        """Apply category, severity, and text filters to historical events."""
        self._search_text = self._hist_search.get().lower() if hasattr(self, '_hist_search') else ""
        cats, sevs = self._snapshot_filters()
        self._populate_tree(self.hist_tree, self._hist_events,
                           cats, sevs, self._search_text)

    def _populate_tree(self, tree: ttk.Treeview, events: List[ParsedEvent],
                       categories: Set[str], severities: Set[str],
                       search: str = ""):
        """Populate a treeview with filtered events."""
        tree.delete(*tree.get_children())
        count = 0
        for e in events:
            if e.category not in categories:
                continue
            if e.severity not in severities:
                continue
            if search:
                searchable = f"{e.title} {e.details} {e.user} {e.category}".lower()
                if search not in searchable:
                    continue

            tree.insert("", "end", values=(
                e.timestamp, e.category, e.severity,
                e.event_id, e.title, e.details[:200]
            ), tags=(e.severity,))
            count += 1
            if count >= 5000:
                break

        if tree == self.hist_tree:
            self._hist_count.configure(text=f"{count} events")

    def _export_historical(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"activity_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not path:
            return
        try:
            # Export filtered events
            cats, sevs = self._snapshot_filters()
            filtered = [e for e in self._hist_events
                       if e.category in cats
                       and e.severity in sevs]
            self.engine.export_events(filtered, path)
            messagebox.showinfo("Export", f"Exported {len(filtered)} events to:\n{path}")
        except (OSError, TypeError) as e:
            messagebox.showerror("Export Error", str(e))

    def _show_event_detail_hist(self, event):
        self._show_event_detail(self.hist_tree, self._hist_events)

    def _show_event_detail(self, tree: ttk.Treeview, events: List[ParsedEvent]):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], "values")
        # Find matching event
        ts, cat, sev, eid = vals[0], vals[1], vals[2], vals[3]
        match = None
        for e in events:
            if e.timestamp == ts and str(e.event_id) == str(eid) and e.category == cat:
                match = e
                break
        if not match:
            return

        # Detail popup
        popup = ctk.CTkToplevel(self)
        popup.title("Event Detail")
        popup.geometry("700x550")
        popup.transient(self.parent)

        scroll = ctk.CTkScrollableFrame(popup)
        scroll.pack(fill="both", expand=True, padx=10, pady=10)

        # Header with severity badge
        hdr = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        hdr.pack(fill="x", pady=(0, 8))
        title_row = ctk.CTkFrame(hdr, fg_color="transparent")
        title_row.pack(fill="x", padx=10, pady=6)
        icon = CATEGORY_ICONS.get(match.category, "")
        ctk.CTkLabel(title_row, text=f"{icon} {match.title}",
                     font=("Segoe UI", 14, "bold")).pack(side="left")
        sev_color = SEV_COLORS.get(match.severity, C_WHITE)
        ctk.CTkLabel(title_row, text=match.severity,
                     font=("Segoe UI", 12, "bold"),
                     text_color=sev_color).pack(side="right")

        # Summary line
        if match.details:
            summary = ctk.CTkFrame(scroll, fg_color="#1a2a1a" if match.severity == "INFO"
                                   else "#2a1a1a", corner_radius=8)
            summary.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(summary, text=match.details,
                         font=("Segoe UI", 11), wraplength=600,
                         justify="left").pack(padx=10, pady=8)

        # Core info
        info = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        info.pack(fill="x", pady=(0, 8))
        ctk.CTkLabel(info, text="Event Info", font=("Segoe UI", 11, "bold"),
                     text_color=C_CYAN).pack(anchor="w", padx=10, pady=(6, 2))
        core_fields = [
            ("Time", match.timestamp),
            ("Event ID", str(match.event_id)),
            ("Category", match.category),
            ("Log Source", match.log_source),
            ("Computer", match.computer),
        ]
        for label, value in core_fields:
            if not value:
                continue
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(row, text=f"{label}:", font=("Segoe UI", 10, "bold"),
                         text_color=C_GRAY, width=100, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Segoe UI", 10),
                         wraplength=500, justify="left").pack(side="left")
        # Pad bottom
        ctk.CTkLabel(info, text="", font=("Segoe UI", 2)).pack()

        # Parsed data fields — the meaningful extracted data
        if match.parsed_data:
            data_frame = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
            data_frame.pack(fill="x", pady=(0, 8))
            ctk.CTkLabel(data_frame, text="Event Data (Parsed)",
                         font=("Segoe UI", 11, "bold"),
                         text_color=C_CYAN).pack(anchor="w", padx=10, pady=(6, 2))

            # Friendly labels for common field names
            friendly_names = {
                "SubjectUserName": "Acting User",
                "SubjectDomainName": "Acting Domain",
                "SubjectUserSid": "Acting User SID",
                "TargetUserName": "Target Account",
                "TargetDomainName": "Target Domain",
                "TargetUserSid": "Target SID",
                "LogonType": "Logon Type",
                "IpAddress": "Source IP",
                "IpPort": "Source Port",
                "WorkstationName": "Workstation",
                "DeviceDescription": "Device Name",
                "DeviceId": "Device ID",
                "ClassName": "Device Class",
                "ClassId": "Class ID",
                "VendorIds": "Vendor",
                "CompatibleIds": "Compatible IDs",
                "ServiceName": "Service Name",
                "ImagePath": "Executable Path",
                "ServiceType": "Service Type",
                "StartType": "Start Type",
                "AccountName": "Account Name",
                "RuleName": "Firewall Rule",
                "updateTitle": "Update Name",
                "MemberName": "Group Member",
                "MemberSid": "Member SID",
                "OldTargetUserName": "Old Username",
                "NewTargetUserName": "New Username",
                "FailureReason": "Failure Reason",
                "Status": "Status Code",
                "SubStatus": "Sub-Status",
                "DriverName": "Driver Name",
                "DriverProvider": "Driver Provider",
                "LocationInformation": "Location",
            }

            # Skip noisy/technical fields
            skip_fields = {"SubjectLogonId", "Keywords", "PrivilegeList",
                           "RestrictedAdminMode", "VirtualAccount",
                           "TransmittedServices", "LmPackageName",
                           "KeyLength", "ProcessId", "ProcessName",
                           "ElevatedToken", "TargetLinkedLogonId",
                           "TargetOutboundUserName", "TargetOutboundDomainName",
                           "TargetLogonId", "LogonGuid", "LogonProcessName",
                           "AuthenticationPackageName", "ImpersonationLevel"}

            for key, value in match.parsed_data.items():
                if key in skip_fields:
                    continue
                if not value or value == "-":
                    continue
                # Truncate long values
                display_val = value[:300]
                friendly = friendly_names.get(key, key)

                row = ctk.CTkFrame(data_frame, fg_color="transparent")
                row.pack(fill="x", padx=10, pady=1)
                ctk.CTkLabel(row, text=f"{friendly}:", font=("Segoe UI", 10, "bold"),
                             text_color=C_GRAY, width=130, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=display_val, font=("Segoe UI", 10),
                             wraplength=450, justify="left").pack(side="left", fill="x")

            ctk.CTkLabel(data_frame, text="", font=("Segoe UI", 2)).pack()

        # Raw XML — collapsed by default
        if match.raw_xml:
            xml_frame = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
            xml_frame.pack(fill="x", pady=(0, 8))

            xml_header = ctk.CTkFrame(xml_frame, fg_color="transparent")
            xml_header.pack(fill="x", padx=10, pady=(6, 2))
            ctk.CTkLabel(xml_header, text="Raw XML",
                         font=("Segoe UI", 10, "bold"),
                         text_color="#555555").pack(side="left")

            xml_container = ctk.CTkFrame(xml_frame, fg_color="transparent")
            xml_visible = [False]

            def toggle_xml():
                if xml_visible[0]:
                    xml_container.pack_forget()
                    show_btn.configure(text="Show XML")
                    xml_visible[0] = False
                else:
                    xml_container.pack(fill="x", padx=10, pady=(0, 8))
                    xml_visible[0] = True
                    show_btn.configure(text="Hide XML")
                    # Lazy-load XML content
                    if not xml_container.winfo_children():
                        xml_text = ctk.CTkTextbox(xml_container, height=150,
                                                   font=("Consolas", 8), fg_color="#1a1a1a")
                        xml_text.pack(fill="x")
                        try:
                            from xml.dom.minidom import parseString
                            pretty = parseString(match.raw_xml).toprettyxml(indent="  ")
                            lines = pretty.split("\n")
                            if lines and lines[0].startswith("<?xml"):
                                lines = lines[1:]
                            xml_text.insert("1.0", "\n".join(lines))
                        except Exception:  # noqa: BLE001 - boundary: xml prettifier fallback
                            xml_text.insert("1.0", match.raw_xml)
                        xml_text.configure(state="disabled")

            show_btn = ctk.CTkButton(xml_header, text="Show XML", width=80, height=24,
                                      fg_color="#333333", hover_color="#444444",
                                      font=("Segoe UI", 9), command=toggle_xml)
            show_btn.pack(side="right")

        # Close button
        ctk.CTkButton(scroll, text="Close", width=100,
                      command=popup.destroy).pack(pady=8)

    # ── Live Monitor Tab ──

    def _build_live(self):
        f = self.tab_live

        # Top bar
        top = ctk.CTkFrame(f, fg_color="transparent")
        top.pack(fill="x", padx=6, pady=(4, 0))

        self._live_status = ctk.CTkLabel(top, text="● MONITORING",
            font=("Segoe UI", 11, "bold"), text_color=C_GREEN)
        self._live_status.pack(side="left")

        self._live_count_lbl = ctk.CTkLabel(top, text="0 events captured",
            font=("Segoe UI", 10), text_color=C_GRAY)
        self._live_count_lbl.pack(side="left", padx=15)

        self._pause_btn = ctk.CTkButton(top, text="Pause", width=70, height=26,
            fg_color="#664400", hover_color="#885500",
            command=self._toggle_live_pause)
        self._pause_btn.pack(side="right", padx=4)

        ctk.CTkButton(top, text="Clear", width=60, height=26,
            fg_color="#444444", hover_color="#555555",
            command=self._clear_live).pack(side="right", padx=2)

        ctk.CTkButton(top, text="Export", width=60, height=26,
            fg_color="#444444", hover_color="#555555",
            command=self._export_live).pack(side="right", padx=2)

        self._live_search = ctk.CTkEntry(top, placeholder_text="Filter...", width=180)
        self._live_search.pack(side="right", padx=(0, 8))
        self._live_search.bind("<KeyRelease>", lambda e: self._filter_live())

        # Category filters (reuse builder)
        self._live_cat_buttons = self._build_category_filters(f, self._filter_live)

        # Treeview
        tree_frame = ctk.CTkFrame(f)
        tree_frame.pack(fill="both", expand=True, padx=6, pady=4)

        cols = ("time", "category", "severity", "event_id", "title", "details")
        headers = ("Time", "Category", "Severity", "ID", "Event", "Details")
        widths = (140, 80, 70, 45, 200, 450)

        self.live_tree = ttk.Treeview(tree_frame, columns=cols, show="headings",
                                       selectmode="browse")
        for col, hdr, w in zip(cols, headers, widths):
            self.live_tree.heading(col, text=hdr)
            self.live_tree.column(col, width=w, stretch=(col == "details"),
                                  minwidth=35)

        self.live_tree.tag_configure("CRITICAL", foreground=C_RED)
        self.live_tree.tag_configure("WARNING", foreground=C_ORANGE)
        self.live_tree.tag_configure("INFO", foreground="#cccccc")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.live_tree.yview)
        self.live_tree.configure(yscrollcommand=vsb.set)
        self.live_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self.live_tree.bind("<Double-1>", self._show_event_detail_live)

    def _toggle_live_pause(self):
        self._live_paused = not self._live_paused
        if self._live_paused:
            self._pause_btn.configure(text="Resume", fg_color="#226622")
            self._live_status.configure(text="⏸ PAUSED", text_color=C_YELLOW)
        else:
            self._pause_btn.configure(text="Pause", fg_color="#664400")
            self._live_status.configure(text="● MONITORING", text_color=C_GREEN)

    def _clear_live(self):
        self._live_events.clear()
        self._live_counter = 0
        self.live_tree.delete(*self.live_tree.get_children())
        self._live_count_lbl.configure(text="0 events captured")

    def _filter_live(self):
        search = self._live_search.get().lower() if hasattr(self, '_live_search') else ""
        # Reverse so _populate_tree shows newest events at the top.
        snap = tuple(reversed(self._live_events.snapshot()))
        cats, sevs = self._snapshot_filters()
        self._populate_tree(self.live_tree, snap, cats, sevs, search)

    def _export_live(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"live_activity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        if not path:
            return
        try:
            snap = self._live_events.snapshot()
            self.engine.export_events(snap, path)
            messagebox.showinfo("Export", f"Exported {len(snap)} events to:\n{path}")
        except (OSError, TypeError) as e:
            messagebox.showerror("Export Error", str(e))

    def _show_event_detail_live(self, event):
        self._show_event_detail(self.live_tree, self._live_events.snapshot())

    def _start_live_poll(self):
        if not self.running:
            return
        if not self._live_paused:
            cats, _ = self._snapshot_filters()
            self.work_q.put_nowait(("live", cats))
        self.after(self._poll_interval, self._start_live_poll)

    # ── Settings Tab ──

    def _build_settings(self):
        f = self.tab_settings
        scroll = ctk.CTkScrollableFrame(f)
        scroll.pack(fill="both", expand=True, padx=6, pady=6)

        # Poll interval
        poll_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        poll_card.pack(fill="x", pady=4)
        ctk.CTkLabel(poll_card, text="Live Monitor Settings",
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(6, 4))

        row = ctk.CTkFrame(poll_card, fg_color="transparent")
        row.pack(fill="x", padx=10, pady=(0, 8))
        ctk.CTkLabel(row, text="Poll interval:", font=("Segoe UI", 10)).pack(side="left")
        self._poll_lbl = ctk.CTkLabel(row, text="5s", font=("Segoe UI", 10, "bold"),
                                       text_color=C_CYAN)
        self._poll_lbl.pack(side="right", padx=10)
        poll_slider = ctk.CTkSlider(row, from_=3, to=15, number_of_steps=12,
            command=lambda v: (
                self._poll_lbl.configure(text=f"{int(v)}s"),
                setattr(self, '_poll_interval', int(v) * 1000)))
        poll_slider.set(5)
        poll_slider.pack(side="right", padx=10, fill="x", expand=True)

        # Admin status
        admin_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        admin_card.pack(fill="x", pady=4)
        ctk.CTkLabel(admin_card, text="Admin Status",
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(6, 4))
        status = "✓ Running as Administrator" if self.engine._admin else "⚠ Not Administrator"
        color = C_GREEN if self.engine._admin else C_ORANGE
        ctk.CTkLabel(admin_card, text=status, font=("Segoe UI", 10),
                     text_color=color).pack(anchor="w", padx=10, pady=(0, 4))
        if not self.engine._admin:
            ctk.CTkLabel(admin_card,
                text="Security log events (Account, Logon, Security Policy) require admin.\n"
                     "Device, System, and Software events work without admin.",
                font=("Segoe UI", 9), text_color=C_GRAY,
                justify="left").pack(anchor="w", padx=10, pady=(0, 8))

        # Event reference
        ref_card = ctk.CTkFrame(scroll, fg_color=CARD_BG, corner_radius=8)
        ref_card.pack(fill="x", pady=4)
        ctk.CTkLabel(ref_card, text="Monitored Events",
                     font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=10, pady=(6, 4))

        for cat in ALL_CATEGORIES:
            icon = CATEGORY_ICONS.get(cat, "")
            cat_events = [e for e in EVENT_DEFS.values() if e.category == cat]
            events_str = ", ".join(f"{e.event_id} ({e.title})" for e in cat_events)
            row = ctk.CTkFrame(ref_card, fg_color="transparent")
            row.pack(fill="x", padx=10, pady=1)
            ctk.CTkLabel(row, text=f"{icon} {cat}:", font=("Segoe UI", 9, "bold"),
                         text_color=C_CYAN, width=90, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=events_str, font=("Segoe UI", 8),
                         text_color=C_GRAY, wraplength=800,
                         justify="left").pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(ref_card, text="", font=("Segoe UI", 1)).pack(pady=2)

    # ── Worker ──

    def _worker_loop(self):
        while self.running:
            try:
                job = self.work_q.get(timeout=0.3)
            except queue.Empty:
                continue
            try:
                if job[0] == "historical":
                    hours, cats = job[1], job[2]
                    def progress_cb(msg, pct):
                        self.result_q.put(("hist_progress", msg))
                    events = self.engine.query_events(hours, cats, callback=progress_cb)
                    self.result_q.put(("historical", events))
                elif job[0] == "live":
                    cats = job[1]
                    events = self.engine.query_new_events(cats)
                    if events:
                        self.result_q.put(("live", events))
                elif job[0] == "spy_check":
                    findings = self.engine.run_spy_check()
                    self.result_q.put(("spy_check", findings))
                elif job[0] == "accounts":
                    accounts = self.engine.get_user_accounts()
                    self.result_q.put(("accounts", accounts))
                elif job[0] == "account_history":
                    events = self.engine.get_account_events_all_time()
                    self.result_q.put(("account_history", events))
            except Exception:  # noqa: BLE001 - boundary: _worker_loop daemon
                pass

    def _process_queue(self):
        try:
            while True:
                try:
                    msg = self.result_q.get_nowait()
                except queue.Empty:
                    break
                if msg[0] == "spy_check":
                    self._populate_spy_results(msg[1])
                elif msg[0] == "accounts":
                    self._populate_accounts(msg[1])
                elif msg[0] == "account_history":
                    self._populate_account_history(msg[1])
                elif msg[0] == "historical":
                    self._hist_events = msg[1]
                    self._filter_historical()
                    self._hist_progress.configure(text="")
                elif msg[0] == "hist_progress":
                    self._hist_progress.configure(text=msg[1])
                elif msg[0] == "live":
                    new_events = msg[1]
                    # BoundedDeque enforces the 5000 cap via maxlen; oldest items
                    # are evicted automatically when capacity is exceeded.
                    self._live_events.extend(new_events)
                    self._live_counter += len(new_events)
                    self._live_count_lbl.configure(
                        text=f"{self._live_counter} events captured")
                    # Insert at top of tree — snapshot filters once so a toggle
                    # firing mid-loop can't mutate the sets during iteration.
                    search = self._live_search.get().lower() if hasattr(self, '_live_search') else ""
                    cats, sevs = self._snapshot_filters()
                    for e in reversed(new_events):
                        if e.category not in cats:
                            continue
                        if e.severity not in sevs:
                            continue
                        if search:
                            searchable = f"{e.title} {e.details} {e.user} {e.category}".lower()
                            if search not in searchable:
                                continue
                        self.live_tree.insert("", 0, values=(
                            e.timestamp, e.category, e.severity,
                            e.event_id, e.title, e.details[:200]
                        ), tags=(e.severity,))
                    # Trim tree to 5000
                    children = self.live_tree.get_children()
                    if len(children) > 5000:
                        for iid in children[5000:]:
                            self.live_tree.delete(iid)
        except Exception:  # noqa: BLE001 - boundary: _process_queue UI
            pass
        if self.running:
            self.after(100, self._process_queue)

    # ── Cleanup ──

    def _fix_log_sizes(self, log_names: List[str]):
        """Increase event log sizes to 200 MB."""
        if not is_admin():
            messagebox.showinfo("Admin Required",
                "Changing event log sizes requires administrator privileges.\n\n"
                "Right-click the app and select 'Run as administrator', then try again.")
            return

        results = []
        target_size = 209715200  # 200 MB
        for log in log_names:
            rc, _, err = safe_run(["wevtutil", "sl", log, f"/ms:{target_size}"], timeout=10)
            if rc == 0:
                results.append(f"  {log}: increased to 200 MB")
            else:
                results.append(f"  {log}: FAILED — {err[:100]}")

        messagebox.showinfo("Log Sizes Updated",
            "Results:\n\n" + "\n".join(results) +
            "\n\nEvent logs will now keep ~6-12 months of history.")

        # Re-run spy check to update the display
        self._run_spy_check()

    def force_stop(self):
        self.running = False
        try:
            self.parent.destroy()
        except tk.TclError:
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
        w, h = 1300, 750
        x = (root.winfo_screenwidth() - w) // 2
        y = (root.winfo_screenheight() - h) // 2
        root.geometry(f"{w}x{h}+{x}+{y}")
        root.lift()
        root.focus_force()

        if tk._default_root == root:
            root.mainloop()
    except Exception as e:  # noqa: BLE001 - boundary: run_tool entry point
        messagebox.showerror(TOOL_NAME, f"Startup error:\n{e}")


if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    root = ctk.CTk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.force_stop)
    root.mainloop()
