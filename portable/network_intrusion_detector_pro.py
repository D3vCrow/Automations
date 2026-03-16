"""
network_intrusion_detector_pro.py

NETWORK INTRUSION DETECTOR PRO (Windows 10, Home WiFi)
- Active scanning: finds devices on your LAN (ARP scan + ping sweep fallback)
- Passive monitoring: watches for ARP spoofing/MITM indicators and suspicious scan patterns
- Outbound visibility: shows active network connections and processes
- Trust list (allowlist) + baseline persistence
- Advanced threat detection: Flipper Zero/BadUSB, Tor activity, audio spying, network recon
- 5-level connection classification: SAFE / KNOWN / UNKNOWN / SUSPICIOUS / DANGEROUS
- Threats tab with Kill/Block/Investigate actions
- Double-click connection → open file location in Explorer
- UX/perf improvements:
  - Filters (category + severity)
  - Alert de-duplication + rate limiting
  - Clear alerts button
  - Multicast/broadcast MAC filtered

IMPORTANT WINDOWS NOTES
- For full passive packet detection (ARP spoofing + scan detection), you need Npcap:
  Install Npcap (WinPcap-compatible mode recommended).
- Run this tool "as Administrator" for best results.

Dependencies:
  pip install psutil
Optional:
  pip install scapy
  pip install watchdog
  pip install pyshark
  pip install python-nmap
  pip install requests
"""

import os
import re
import sys
import json
import time
import queue
import socket
import random
import threading
import subprocess
import hashlib
import fnmatch
import requests
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk

import psutil

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

TOOL_NAME = "Network Intrusion Detector Pro"

# ─────────────────────────────────────────────────────────────────────────────
# Scapy lazy loader (SAFE)
# ─────────────────────────────────────────────────────────────────────────────

HAS_SCAPY = False
ARP = None
Ether = None
srp = None
sniff = None


def try_load_scapy():
    global HAS_SCAPY, ARP, Ether, srp, sniff
    if HAS_SCAPY:
        return True
    try:
        import importlib
        scapy_all = importlib.import_module("scapy.all")
        ARP = scapy_all.ARP
        Ether = scapy_all.Ether
        srp = scapy_all.srp
        sniff = scapy_all.sniff
        HAS_SCAPY = True
        return True
    except Exception:
        HAS_SCAPY = False
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def now_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_CREATE_NO_WINDOW = 0x08000000


def safe_run(cmd: List[str], timeout: int = 10) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            shell=False,
            creationflags=_CREATE_NO_WINDOW,
        )
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:
        return 1, "", str(e)


# ─────────────────────────────────────────────────────────────────────────────
# IP Geolocation & 5-level Connection Classification
# ─────────────────────────────────────────────────────────────────────────────

_ip_geo_cache: Dict[str, Dict] = {}

# Countries that warrant SUSPICIOUS classification (user may legitimately use
# VPN exit nodes here — we flag but do NOT auto-escalate to DANGEROUS)
SUSPICIOUS_COUNTRIES: Set[str] = {
    "Russia", "China", "North Korea", "Iran",
    "Belarus", "Syria", "Cuba", "Venezuela",
}

# Ports that warrant SUSPICIOUS classification
SUSPICIOUS_PORTS: Set[int] = {
    9050, 9150,          # Tor SOCKS
    9001, 9030, 9040,    # Tor relay / directory
    6667, 6668, 6669,    # IRC (often botnet C2)
    1080,                # SOCKS proxy
    4444, 5555, 31337,   # Classic backdoor ports
}

# Ports that warrant DANGEROUS classification
DANGEROUS_PORTS: Set[int] = {
    # Tor (outbound confirms Tor circuit, stronger signal than just listening)
    9050, 9150,
    # Known bad / exploit frameworks
    4444, 31337,
}

KNOWN_SAFE_ORGS: Set[str] = {
    "Microsoft", "Google", "Amazon", "Cloudflare", "Akamai",
    "Fastly", "Facebook", "Apple", "GitHub", "GitLab",
    "DigitalOcean", "Linode", "OVH", "Hetzner", "Twitch",
    "Netflix", "Spotify", "Adobe", "Dropbox", "Zoom",
}

TOR_PROCESSES: Set[str] = {
    "tor.exe", "tor", "privoxy", "obfs4proxy", "meek-client",
}

# ─────────────────────────────────────────────────────────────────────────────
# Port → human-readable service name + description
# ─────────────────────────────────────────────────────────────────────────────
PORT_SERVICES: Dict[int, Tuple[str, str]] = {
    # (short_name, explanation)
    20:   ("FTP-Data",   "File Transfer Protocol – data channel"),
    21:   ("FTP",        "File Transfer Protocol – control channel"),
    22:   ("SSH",        "Secure Shell – remote terminal / SFTP"),
    23:   ("Telnet",     "Unencrypted remote terminal (legacy, insecure)"),
    25:   ("SMTP",       "Email sending (mail server)"),
    53:   ("DNS",        "Domain Name resolution"),
    67:   ("DHCP",       "IP address assignment (server)"),
    68:   ("DHCP",       "IP address assignment (client)"),
    80:   ("HTTP",       "Unencrypted web traffic"),
    110:  ("POP3",       "Email retrieval (legacy)"),
    119:  ("NNTP",       "Usenet / news groups"),
    123:  ("NTP",        "Network Time Protocol – clock sync"),
    135:  ("RPC",        "Windows Remote Procedure Call"),
    137:  ("NetBIOS-NS", "Windows NetBIOS name service"),
    138:  ("NetBIOS-DG", "Windows NetBIOS datagram service"),
    139:  ("NetBIOS-SS", "Windows file/printer sharing (legacy)"),
    143:  ("IMAP",       "Email retrieval (modern)"),
    161:  ("SNMP",       "Network device monitoring"),
    389:  ("LDAP",       "Directory service / Active Directory"),
    443:  ("HTTPS",      "Encrypted web traffic (TLS)"),
    445:  ("SMB",        "Windows file sharing / named pipes — normal Windows IPC"),
    465:  ("SMTPS",      "Encrypted email sending"),
    500:  ("IKE",        "IPsec VPN key exchange"),
    514:  ("Syslog",     "System log forwarding"),
    587:  ("SMTP-Sub",   "Email submission (authenticated)"),
    631:  ("IPP",        "Internet Printing Protocol"),
    636:  ("LDAPS",      "Encrypted LDAP / Active Directory"),
    993:  ("IMAPS",      "Encrypted email retrieval"),
    995:  ("POP3S",      "Encrypted email retrieval (legacy)"),
    1080: ("SOCKS",      "⚠ SOCKS proxy — can tunnel any traffic"),
    1194: ("OpenVPN",    "OpenVPN encrypted tunnel"),
    1433: ("MSSQL",      "Microsoft SQL Server"),
    1434: ("MSSQL-Mon",  "Microsoft SQL Server monitor"),
    1701: ("L2TP",       "Layer 2 VPN tunnelling"),
    1723: ("PPTP",       "PPTP VPN (outdated, insecure)"),
    1900: ("SSDP/UPnP",  "Device discovery on LAN"),
    2049: ("NFS",        "Network File System"),
    3074: ("Xbox Live",  "Xbox Live gaming service"),
    3306: ("MySQL",      "MySQL database"),
    3389: ("RDP",        "Windows Remote Desktop — ensure this is expected"),
    3478: ("STUN/TURN",  "WebRTC relay / VoIP NAT traversal"),
    4444: ("Metasploit", "⛔ Classic Metasploit reverse shell port"),
    5000: ("UPnP/Dev",   "Various dev servers / UPnP"),
    5353: ("mDNS",       "Multicast DNS — local device discovery"),
    5355: ("LLMNR",      "Link-Local Multicast Name Resolution"),
    5555: ("ADB/Alt",    "⚠ Android Debug Bridge or backdoor"),
    5900: ("VNC",        "Virtual Network Computing — remote desktop"),
    6667: ("IRC",        "⚠ Internet Relay Chat — common botnet C2 channel"),
    6668: ("IRC",        "⚠ Internet Relay Chat — common botnet C2 channel"),
    6669: ("IRC",        "⚠ Internet Relay Chat — common botnet C2 channel"),
    7680: ("WUDO",       "Windows Update Delivery Optimisation (peer)"),
    8080: ("HTTP-Alt",   "Alternative HTTP / proxy"),
    8443: ("HTTPS-Alt",  "Alternative HTTPS"),
    9050: ("Tor-SOCKS",  "⛔ Tor SOCKS proxy — anonymous routing"),
    9150: ("Tor-Browser","⛔ Tor Browser SOCKS proxy"),
    9001: ("Tor-Relay",  "⛔ Tor relay port"),
    9030: ("Tor-Dir",    "⛔ Tor directory server"),
    27015: ("Steam",     "Steam game server / matchmaking"),
    27036: ("Steam-IPC", "Steam local IPC"),
    31337: ("Back Orifice","⛔ Classic backdoor / hacking tool port"),
    49152: ("Ephemeral",  "Dynamic / ephemeral Windows port"),
}

def port_service(port: int) -> Tuple[str, str]:
    """Return (short_name, description) for a port number."""
    if port in PORT_SERVICES:
        return PORT_SERVICES[port]
    if 49152 <= port <= 65535:
        return ("Ephemeral", "Dynamic high port — assigned temporarily by Windows")
    if 1024 <= port <= 49151:
        return ("Registered", f"Registered port {port} — check if expected for this app")
    return ("System", f"Well-known system port {port}")

SUSPICIOUS_AUDIO_PROCESSES: Set[str] = {
    "pjsua.exe", "sox.exe", "ffmpeg.exe", "sndrec32.exe", "soundrecorder.exe",
}


def get_ip_geolocation(ip: str) -> Dict[str, str]:
    global _ip_geo_cache
    if is_private_ip(ip):
        return {"country": "Local", "region": "LAN", "city": "Private", "org": "", "trust": "safe"}
    if ip in _ip_geo_cache:
        return _ip_geo_cache[ip]
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query",
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "org": data.get("org", data.get("isp", "Unknown")),
                    "trust": "unknown",
                }
                _ip_geo_cache[ip] = result
                return result
    except Exception:
        pass
    result = {"country": "Unknown", "region": "", "city": "", "org": "", "trust": "unknown"}
    _ip_geo_cache[ip] = result
    return result


def is_private_ip(ip: str) -> bool:
    try:
        ip = ip.strip()

        # ── IPv6 loopback & link-local ──────────────────────────────────────
        if ip in ("::1", "0:0:0:0:0:0:0:1"):   # loopback
            return True
        il = ip.lower()
        if il.startswith("fe80"):               # link-local (fe80::/10)
            return True
        if il.startswith("fc") or il.startswith("fd"):  # unique local (fc00::/7)
            return True
        if il in ("::", "0:0:0:0:0:0:0:0"):    # unspecified
            return True
        # IPv4-mapped IPv6  e.g. ::ffff:192.168.1.1
        if il.startswith("::ffff:"):
            ip = il[7:]                         # strip prefix, fall through to IPv4 check

        # ── IPv4 ────────────────────────────────────────────────────────────
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        first, second = int(parts[0]), int(parts[1])
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first == 127:                        # loopback
            return True
        if first == 169 and second == 254:      # APIPA / link-local
            return True
        return False
    except Exception:
        return False


def extract_remote_ip(raddr: str) -> str:
    """Extract IP from 'ip:port' string — handles both IPv4 and IPv6."""
    if not raddr:
        return raddr
    # IPv6 addresses are stored as plain '::1', not '[::1]:port' by psutil,
    # but the display string is built as f"{ip}:{port}" which could be ambiguous.
    # rsplit on the last ':' works fine for IPv4 (192.168.1.1:80 → 192.168.1.1)
    # and for psutil IPv6 strings (::1:445 → ::1 is wrong; use raddr.ip directly instead).
    # This helper is only used for display parsing, not for psutil objects.
    if ":" in raddr:
        return raddr.rsplit(":", 1)[0]
    return raddr


def classify_connection(ip: str, port: int, org: str, country: str, trusted_ips: Dict) -> str:
    """
    5-level classification.
    Returns: 'safe' | 'known' | 'unknown' | 'suspicious' | 'dangerous'
    """
    if is_private_ip(ip):
        return "safe"

    # Explicit user trust → SAFE
    if ip in trusted_ips:
        return "safe"

    # DANGEROUS: confirmed bad ports (outbound)
    if port in DANGEROUS_PORTS:
        return "dangerous"

    # SUSPICIOUS: Tor relay ports, IRC, SOCKS, backdoor ports
    if port in SUSPICIOUS_PORTS:
        return "suspicious"

    # SUSPICIOUS: geopolitically sensitive country
    if country in SUSPICIOUS_COUNTRIES:
        return "suspicious"

    # KNOWN: well-known organisation
    if org:
        org_lower = org.lower()
        for safe_org in KNOWN_SAFE_ORGS:
            if safe_org.lower() in org_lower:
                return "known"

    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Firewall helper
# ─────────────────────────────────────────────────────────────────────────────

def block_ip_firewall(ip: str, rule_name: str = None) -> bool:
    """Block an IP using Windows Firewall via netsh"""
    rule = rule_name or f"NID_Block_{ip}"
    rc, _out, _err = safe_run(
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule}", "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes",
        ],
        timeout=15,
    )
    return rc == 0


# ─────────────────────────────────────────────────────────────────────────────
# Connection trust manager
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionTrustManager:
    def __init__(self, state_path: str):
        self.state_path = state_path.replace("nid_state.json", "connection_trust.json")
        self.trusted_ips: Dict[str, Dict] = {}
        self.trusted_domains: Dict[str, Dict] = {}
        self._load()

    def _load(self):
        try:
            if os.path.exists(self.state_path):
                with open(self.state_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.trusted_ips = data.get("trusted_ips", {})
                    self.trusted_domains = data.get("trusted_domains", {})
        except Exception:
            pass

    def save(self):
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"trusted_ips": self.trusted_ips, "trusted_domains": self.trusted_domains},
                    f, indent=2, ensure_ascii=False,
                )
        except Exception:
            pass

    def trust_ip(self, ip: str, label: str = "", notes: str = ""):
        self.trusted_ips[ip] = {"label": label or "Trusted", "first_seen": now_ts(), "notes": notes}
        self.save()

    def untrust_ip(self, ip: str):
        if ip in self.trusted_ips:
            del self.trusted_ips[ip]
            self.save()

    def trust_domain(self, domain: str, label: str = ""):
        self.trusted_domains[domain.lower()] = {"label": label or "Trusted", "first_seen": now_ts()}
        self.save()


# ─────────────────────────────────────────────────────────────────────────────
# System helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_admin_windows() -> bool:
    if not sys.platform.startswith("win"):
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def parse_ipconfig_subnet() -> Optional[str]:
    rc, out, _ = safe_run(["ipconfig"])
    if rc != 0:
        return None
    ip = mask = None
    for line in out.splitlines():
        s = line.strip()
        if s.lower().startswith("ipv4 address") or "IPv4 Address" in s:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s)
            if m:
                ip = m.group(1)
        if s.lower().startswith("subnet mask") or "Subnet Mask" in s:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", s)
            if m:
                mask = m.group(1)
        if ip and mask:
            break
    if not ip or not mask:
        return None

    def ip_to_int(x: str) -> int:
        p = [int(v) for v in x.split(".")]
        return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]

    def int_to_ip(v: int) -> str:
        return ".".join(str((v >> s) & 0xFF) for s in (24, 16, 8, 0))

    net_i = ip_to_int(ip) & ip_to_int(mask)
    prefix = bin(ip_to_int(mask)).count("1")
    return f"{int_to_ip(net_i)}/{prefix}"


def get_default_gateway() -> Optional[str]:
    rc, out, _ = safe_run(["route", "print"])
    if rc != 0:
        return None
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("0.0.0.0"):
            parts = re.split(r"\s+", line)
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                gw = parts[2]
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                    return gw
    return None


def arp_table() -> Dict[str, str]:
    rc, out, _ = safe_run(["arp", "-a"])
    if rc != 0:
        return {}
    res: Dict[str, str] = {}
    for line in out.splitlines():
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
        if m:
            res[m.group(1)] = m.group(2).lower().replace("-", ":")
    return res


def ping_sweep(cidr: str, limit: int = 254, timeout_ms: int = 250) -> None:
    if not cidr.endswith("/24"):
        return
    prefix = ".".join(cidr.split("/")[0].split(".")[:3])
    ips = [f"{prefix}.{i}" for i in range(1, 255)]
    random.shuffle(ips)
    for ip in ips[:min(limit, len(ips))]:
        safe_run(["ping", "-n", "1", "-w", str(timeout_ms), ip], timeout=2)


def scapy_arp_scan(cidr: str, timeout_s: int = 2) -> Dict[str, str]:
    if not try_load_scapy():
        return {}
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        ans, _ = srp(pkt, timeout=timeout_s, verbose=False)
        return {str(rcv.psrc): str(rcv.hwsrc).lower() for _, rcv in ans if rcv.psrc and rcv.hwsrc}
    except Exception:
        return {}


def local_ipv4() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# MAC / device intelligence
# ─────────────────────────────────────────────────────────────────────────────

MAC_MANUFACTURERS = {
    "00:1a:2b": "Apple Inc.", "28:cf:e9": "Apple Inc.", "40:a6:d9": "Apple Inc.",
    "00:16:32": "Samsung Electronics", "b4:99:ba": "Samsung Electronics",
    "fc:a1:3e": "Amazon Technologies Inc.", "74:c2:46": "Amazon Technologies Inc.",
    "18:b4:30": "Google Inc.", "44:65:0d": "Google Inc.",
    "00:0d:3a": "Raspberry Pi Foundation", "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd.",
    "00:1b:44": "Roku Inc.", "c8:d7:4d": "Roku Inc.",
    "e8:9f:6d": "Xiaomi Communications", "34:ce:00": "Xiaomi Communications",
    "28:6e:d4": "Huawei Technologies", "00:e0:4c": "Huawei Technologies",
    "ac:5a:be": "LG Electronics", "00:07:f1": "LG Electronics",
    "00:12:fb": "Sony Corporation", "00:02:b3": "Sony Corporation",
    "00:1e:58": "Dell Inc.", "00:14:22": "Dell Inc.",
    "00:1f:29": "HP Inc.", "00:15:5d": "Microsoft Corporation",
    "00:17:c4": "Netgear Inc.", "00:04:ea": "Netgear Inc.",
    "00:90:f5": "TP-Link Technologies", "c8:3a:35": "TP-Link Technologies",
    "f0:b4:29": "ASUSTek Computer Inc.", "00:17:9a": "ASUSTek Computer Inc.",
    "00:0c:f6": "Cisco Systems", "00:1b:1f": "Cisco Systems",
    "00:1d:09": "Intel Corporation", "00:aa:00": "Intel Corporation",
}

DEVICE_PATTERNS = {
    "smartphone": ["apple", "samsung", "xiaomi", "huawei", "oneplus"],
    "tablet": ["apple", "samsung", "microsoft"],
    "smart_tv": ["samsung", "lg", "sony", "tcl", "vizio"],
    "smart_speaker": ["amazon", "google"],
    "iot_device": ["raspberry", "esp", "arduino"],
    "router": ["cisco", "netgear", "tp-link", "asus", "linksys"],
    "computer": ["dell", "hp", "intel", "microsoft"],
}


def get_mac_manufacturer(mac: str) -> str:
    if not mac:
        return "Unknown"
    mac = mac.lower().replace("-", ":")
    prefix = mac[:8]
    if prefix in MAC_MANUFACTURERS:
        return MAC_MANUFACTURERS[prefix]
    try:
        resp = requests.get(f"https://api.macvendors.com/{prefix}", timeout=3)
        if resp.status_code == 200:
            mfr = resp.text.strip()
            MAC_MANUFACTURERS[prefix] = mfr
            return mfr
    except Exception:
        pass
    return "Unknown"


def detect_device_type(manufacturer: str, mac: str) -> str:
    mfr_lower = manufacturer.lower()
    for dtype, keywords in DEVICE_PATTERNS.items():
        if any(k in mfr_lower for k in keywords):
            return dtype.replace("_", " ").title()
    return "Unknown Device"


def analyze_device_behavior(mac: str, ip: str, known_devices: Dict) -> Dict:
    analysis = {"risk_score": 0, "behaviors": [], "recommendations": []}
    if mac not in known_devices:
        analysis["risk_score"] += 20
        analysis["behaviors"].append("New device on network")
        analysis["recommendations"].append("Verify if this is your device")
    device_info = known_devices.get(mac, {})
    if "ip_history" in device_info and len(set(device_info["ip_history"])) > 1:
        analysis["risk_score"] += 40
        analysis["behaviors"].append("Multiple IP addresses detected")
        analysis["recommendations"].append("Possible ARP spoofing - investigate")
    manufacturer = get_mac_manufacturer(mac)
    if manufacturer == "Unknown":
        analysis["risk_score"] += 15
        analysis["behaviors"].append("Unknown manufacturer")
        analysis["recommendations"].append("Investigate unknown device")
    score = analysis["risk_score"]
    analysis["risk_level"] = "HIGH" if score >= 50 else ("MEDIUM" if score >= 25 else "LOW")
    return analysis


def get_device_intelligence(mac: str, ip: str, known_devices: Dict) -> Dict:
    manufacturer = get_mac_manufacturer(mac)
    device_type = detect_device_type(manufacturer, mac)
    behavior = analyze_device_behavior(mac, ip, known_devices)
    return {
        "mac": mac, "ip": ip, "manufacturer": manufacturer, "device_type": device_type,
        "risk_score": behavior["risk_score"], "risk_level": behavior["risk_level"],
        "behaviors": behavior["behaviors"], "recommendations": behavior["recommendations"],
        "first_seen": known_devices.get(mac, {}).get("first_seen", now_ts()),
        "last_seen": known_devices.get(mac, {}).get("last_seen", now_ts()),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Noise filters / alert helpers
# ─────────────────────────────────────────────────────────────────────────────

NOISY_MAC_PREFIXES = ("01:00:5e", "33:33")
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def is_noisy_mac(mac: str) -> bool:
    m = (mac or "").lower()
    if not m:
        return False
    if m == BROADCAST_MAC:
        return True
    return any(m.startswith(p) for p in NOISY_MAC_PREFIXES)


def compact_alert_key(category: str, title: str, details: Dict) -> str:
    d = details or {}
    parts = [f"cat={category}", f"title={title}"]
    for k in ("mac", "ip", "src_ip", "gateway_ip", "old_mac", "new_mac"):
        if k in d and d[k]:
            parts.append(f"{k}={d[k]}")
    return "|".join(parts)


def make_alert(severity: str, category: str, title: str, details: Optional[Dict] = None) -> Dict:
    return {
        "timestamp": now_ts(),
        "severity": severity,   # INFO|WARN|HIGH
        "category": category,   # DEVICE|MITM|SCAN|DNS|OUTBOUND|SYSTEM
        "title": title,
        "details": details or {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Core network monitor
# ─────────────────────────────────────────────────────────────────────────────

class NetworkMonitor:
    def __init__(self, state_path: str):
        self.state_path = state_path

        self.trusted: Dict[str, Dict] = {}
        self.known_devices: Dict[str, Dict] = {}
        self.baseline_gateway_ip: str = ""
        self.baseline_gateway_mac: str = ""
        self.last_arp: Dict[str, str] = {}
        self.last_devices: Dict[str, str] = {}

        self.alerts: List[Dict] = []
        self._alert_index: Dict[str, int] = {}
        self._alert_last_seen: Dict[str, float] = {}
        self._rate_limit: Dict[str, float] = {}

        self.sniff_thread: Optional[threading.Thread] = None
        self.sniff_stop = threading.Event()

        self.syn_tracker: Dict[str, Dict] = {}

        self.dns_queries: Dict[str, List] = {}
        self.suspicious_processes: Set[str] = set()
        self.monitored_files: Dict[str, str] = {}
        self.file_observer = None
        self.process_baseline: Dict[str, Dict] = {}

        self.conn_trust = ConnectionTrustManager(state_path)

        # Advanced scan rate limiter
        self._adv_scan_counter: int = 0
        self._adv_last_ts: float = 0.0

        self._load_state()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_state(self):
        if not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.trusted = data.get("trusted", {}) or {}
            self.known_devices = data.get("known_devices", {}) or {}
            self.baseline_gateway_ip = data.get("baseline_gateway_ip", "") or ""
            self.baseline_gateway_mac = data.get("baseline_gateway_mac", "") or ""
        except Exception:
            pass

    def save_state(self):
        try:
            data = {
                "trusted": self.trusted,
                "known_devices": self.known_devices,
                "baseline_gateway_ip": self.baseline_gateway_ip,
                "baseline_gateway_mac": self.baseline_gateway_mac,
                "saved_at": now_ts(),
            }
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    # ── Alert logging ─────────────────────────────────────────────────────────

    def log(self, severity: str, category: str, title: str, details: Optional[Dict] = None):
        details = details or {}
        key = compact_alert_key(category, title, details)
        now = time.time()

        cooldown = 0.0
        if category == "MITM" and "multiple ip" in title.lower():
            cooldown = 30.0
        if category == "DEVICE" and "discovered" in title.lower():
            cooldown = 10.0
        if category == "OUTBOUND" and "high number" in title.lower():
            cooldown = 30.0

        nxt = self._rate_limit.get(key, 0.0)
        if cooldown > 0 and now < nxt:
            return
        if cooldown > 0:
            self._rate_limit[key] = now + cooldown

        last = self._alert_last_seen.get(key)
        if last is not None and (now - last) <= 45:
            idx = self._alert_index.get(key)
            if idx is not None and 0 <= idx < len(self.alerts):
                a = self.alerts[idx]
                d = a.get("details", {})
                d["_count"] = int(d.get("_count", 1)) + 1
                d["_last_seen_ts"] = now_ts()
                d["_last_details"] = details
                a["details"] = d
                self._alert_last_seen[key] = now
            return

        a = make_alert(severity, category, title, details)
        a["details"]["_count"] = 1
        a["details"]["_first_seen_ts"] = a["timestamp"]
        self.alerts.append(a)
        self._alert_index[key] = len(self.alerts) - 1
        self._alert_last_seen[key] = now

        if len(self.alerts) > 1500:
            self.alerts = self.alerts[-1200:]
            self._alert_index.clear()
            self._alert_last_seen.clear()
            for i, aa in enumerate(self.alerts):
                k = compact_alert_key(aa["category"], aa["title"], aa.get("details", {}))
                self._alert_index[k] = i
                self._alert_last_seen[k] = now

    # ── Trust management ──────────────────────────────────────────────────────

    def trust_mac(self, mac: str, label: str):
        mac = (mac or "").lower()
        if not mac:
            return
        if mac not in self.trusted:
            self.trusted[mac] = {"label": label.strip() or "Trusted", "first_seen": now_ts()}
        else:
            self.trusted[mac]["label"] = label.strip() or self.trusted[mac].get("label", "Trusted")
        self.save_state()

    def untrust_mac(self, mac: str):
        mac = (mac or "").lower()
        if mac in self.trusted:
            del self.trusted[mac]
            self.save_state()

    def set_gateway_baseline(self, gw_ip: str, gw_mac: str):
        self.baseline_gateway_ip = gw_ip
        self.baseline_gateway_mac = gw_mac
        self.save_state()
        self.log("INFO", "SYSTEM", "Gateway baseline updated",
                 {"gateway_ip": gw_ip, "gateway_mac": gw_mac})

    # ── Device discovery / analysis ───────────────────────────────────────────

    def discover_devices(self, cidr: Optional[str], active: bool) -> Dict[str, str]:
        found_ip_mac: Dict[str, str] = {}
        if active and cidr:
            if try_load_scapy():
                found_ip_mac.update(scapy_arp_scan(cidr, timeout_s=2))
            else:
                ping_sweep(cidr)
                found_ip_mac.update(arp_table())
        found_ip_mac.update(arp_table())
        mac_ip: Dict[str, str] = {}
        for ip, mac in found_ip_mac.items():
            if not mac:
                continue
            m = mac.lower()
            if is_noisy_mac(m):
                continue
            mac_ip[m] = ip
        return mac_ip

    def analyze_devices(self, mac_ip: Dict[str, str], gw_ip: Optional[str]):
        if gw_ip:
            arps = arp_table()
            gw_mac = arps.get(gw_ip, "")
            if gw_mac:
                if not self.baseline_gateway_ip:
                    self.set_gateway_baseline(gw_ip, gw_mac)
                elif self.baseline_gateway_ip == gw_ip and self.baseline_gateway_mac and gw_mac != self.baseline_gateway_mac:
                    self.log("HIGH", "MITM",
                             "Gateway MAC changed (possible ARP spoof / MITM)",
                             {"gateway_ip": gw_ip, "old_mac": self.baseline_gateway_mac, "new_mac": gw_mac})

        for mac, ip in mac_ip.items():
            prev = self.known_devices.get(mac)
            if not prev:
                sev = "INFO" if mac in self.trusted else "WARN"
                self.log(sev, "DEVICE",
                         "Trusted device discovered" if mac in self.trusted else "New device discovered",
                         {"mac": mac, "ip": ip, "trusted": mac in self.trusted,
                          "label": self.trusted.get(mac, {}).get("label", "")})
            self.known_devices[mac] = {
                "last_ip": ip, "last_seen": now_ts(),
                "trusted": mac in self.trusted,
                "label": self.trusted.get(mac, {}).get("label", ""),
            }

        ip_to_mac = {ip: mac for mac, ip in mac_ip.items()}
        mac_to_ips: Dict[str, List[str]] = {}
        for mac, ip in mac_ip.items():
            mac_to_ips.setdefault(mac, []).append(ip)

        for mac, ips in mac_to_ips.items():
            if len(set(ips)) >= 2 and mac not in self.trusted:
                self.log("WARN", "MITM", "One MAC claims multiple IPs (possible spoofing)",
                         {"mac": mac, "ips": sorted(set(ips))})

        if self.last_arp:
            for ip, mac in ip_to_mac.items():
                old = self.last_arp.get(ip)
                if old and old != mac:
                    self.log("HIGH", "MITM", "IP-to-MAC mapping changed (ARP spoof indicator)",
                             {"ip": ip, "old_mac": old, "new_mac": mac})

        self.last_devices = dict(mac_ip)
        self.last_arp = {ip: mac for mac, ip in mac_ip.items()}
        self.save_state()

    # ── Outbound connections snapshot ─────────────────────────────────────────

    def snapshot_outbound(self) -> List[Dict]:
        conns_out: List[Dict] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return conns_out

        for c in conns:
            try:
                if not c.raddr:
                    continue
                pid = c.pid or 0
                pname = "?"
                exe_path = ""
                try:
                    if pid:
                        proc = psutil.Process(pid)
                        pname = proc.name()
                        try:
                            exe_path = proc.exe()
                        except Exception:
                            exe_path = ""
                except Exception:
                    pname = "?"

                la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                remote_ip = str(c.raddr.ip)
                remote_port = int(c.raddr.port)

                geo = get_ip_geolocation(remote_ip)
                trust_level = classify_connection(
                    remote_ip, remote_port,
                    geo.get("org", ""),
                    geo.get("country", "Unknown"),
                    self.conn_trust.trusted_ips,
                )

                svc_name, svc_desc = port_service(remote_port)
                # Also check local port for well-known services (e.g. SMB server on 445)
                local_port = int(c.laddr.port) if c.laddr else 0
                if svc_name in ("Ephemeral", "Registered") and local_port in PORT_SERVICES:
                    svc_name, svc_desc = port_service(local_port)

                conns_out.append({
                    "pid": pid,
                    "process": pname,
                    "exe": exe_path,
                    "laddr": la,
                    "raddr": ra,
                    "status": str(c.status),
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "country": geo.get("country", "Unknown"),
                    "region": geo.get("region", ""),
                    "city": geo.get("city", ""),
                    "org": geo.get("org", ""),
                    "trust": trust_level,
                    "service": svc_name,
                    "service_desc": svc_desc,
                })
            except Exception:
                continue

        trust_order = {"safe": 0, "known": 1, "unknown": 2, "suspicious": 3, "dangerous": 4}
        conns_out.sort(
            key=lambda x: (-(trust_order.get(x["trust"], 2)), x.get("process", "")),
        )
        return conns_out

    # ── Advanced threat detection ─────────────────────────────────────────────

    def _detect_advanced_threats(self, conns: List[Dict]):
        """
        Gate-kept: runs at most every 30 seconds or every 5th scan.
        Calls sub-detectors for Flipper Zero, Tor, audio spying, etc.
        """
        self._adv_scan_counter += 1
        now = time.time()
        if self._adv_scan_counter % 5 != 0 and (now - self._adv_last_ts) < 30:
            return
        self._adv_last_ts = now

        self._detect_flipper_zero()
        self._detect_tor_activity(conns)
        self._detect_audio_spying()

    def _detect_flipper_zero(self):
        """Detect Flipper Zero and similar BadUSB devices via WMI"""
        try:
            _rc, out2, _err = safe_run(
                [
                    "wmic", "path", "Win32_PnPEntity", "where",
                    "Caption like '%Flipper%' or Caption like '%BadUSB%' or "
                    "(DeviceID like '%VID_0483%' and DeviceID like '%PID_5741%')",
                    "get", "Caption,DeviceID",
                ],
                timeout=10,
            )
            if out2.strip() and len(out2.strip().splitlines()) > 1:
                self.log(
                    "HIGH", "DEVICE",
                    "Flipper Zero or suspicious USB HID device detected",
                    {"details": out2.strip()[:300], "action": "Physical inspection recommended"},
                )
        except Exception:
            pass

    def _detect_tor_activity(self, conns: List[Dict]):
        """Detect Tor usage and dark web tool activity"""
        tor_ports = {9050, 9150, 9001, 9030, 9040}

        for c in conns:
            port = c.get("remote_port", 0)
            raddr = c.get("raddr", "")
            proc = c.get("process", "").lower()

            if port in tor_ports:
                self.log("HIGH", "OUTBOUND",
                         "Connection to known Tor port detected",
                         {"process": c.get("process"), "raddr": raddr, "port": port})

            if proc in TOR_PROCESSES:
                self.log("WARN", "SYSTEM",
                         "Tor relay process detected running",
                         {"process": proc, "connection": raddr})

        # Check for running Tor processes even without active connections
        try:
            for proc in psutil.process_iter(["name", "exe"]):
                try:
                    name = proc.info["name"].lower()
                    if name in TOR_PROCESSES:
                        self.log("WARN", "SYSTEM",
                                 "Tor process running on system",
                                 {"process": name})
                except Exception:
                    pass
        except Exception:
            pass

    def _detect_audio_spying(self):
        """Detect processes that may be recording audio/microphone"""
        try:
            _rc, out, _err = safe_run(
                [
                    "wmic", "path", "Win32_Process",
                    "where",
                    "Name like '%record%' or Name like '%capture%' or Name like '%listen%'",
                    "get", "Name,ProcessId,ExecutablePath",
                ],
                timeout=8,
            )
            if out.strip() and len(out.strip().splitlines()) > 1:
                self.log("WARN", "SYSTEM",
                         "Possible audio recording process detected via WMI",
                         {"processes": out.strip()[:300]})

            for proc in psutil.process_iter(["name", "exe", "pid"]):
                try:
                    name = proc.info["name"].lower()
                    if name in SUSPICIOUS_AUDIO_PROCESSES:
                        self.log("HIGH", "SYSTEM",
                                 "Suspicious audio-capable process detected",
                                 {"process": name, "pid": proc.info["pid"],
                                  "exe": proc.info.get("exe", "")})
                except Exception:
                    pass
        except Exception:
            pass

    # ── DNS monitoring ────────────────────────────────────────────────────────

    def monitor_dns_queries(self):
        try:
            rc, out, _ = safe_run(["ipconfig", "/displaydns"])
            if rc != 0:
                return
            current_time = time.time()
            suspicious_domains = ["*.tk", "*.ml", "*.ga", "bit.ly", "tinyurl.com", "t.co", "*onion"]
            for line in out.splitlines():
                if "Record Name" in line:
                    match = re.search(r"Record Name:\s*(\S+)", line)
                    if match:
                        domain = match.group(1).lower()
                        self.dns_queries.setdefault(domain, []).append(current_time)
                        if len(self.dns_queries[domain]) > 50:
                            window = 300
                            recent = [t for t in self.dns_queries[domain] if current_time - t <= window]
                            if len(recent) > 20:
                                self.log("WARN", "DNS",
                                         "High frequency DNS queries (possible tunneling/exfiltration)",
                                         {"domain": domain, "query_count": len(recent), "time_window": f"{window}s"})
                        for pattern in suspicious_domains:
                            if fnmatch.fnmatch(domain, pattern):
                                self.log("HIGH", "DNS",
                                         "Query to suspicious domain detected",
                                         {"domain": domain, "pattern": pattern})
                        break
        except Exception as e:
            self.log("WARN", "SYSTEM", "DNS monitoring error", {"error": str(e)})

    # ── Process monitoring ────────────────────────────────────────────────────

    def monitor_suspicious_processes(self):
        try:
            current_processes = {}
            suspicious_indicators = [
                ("keylogger", "log", "record"),
                ("sniffer", "capture", "wireshark", "tshark"),
                ("remote", "teamviewer", "anydesk", "vnc"),
                ("crypt", "encrypt", "ransom"),
                ("miner", "bitcoin", "ethereum"),
                ("hack", "exploit", "payload"),
                ("proxy", "tunnel", "vpn"),
            ]
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
                try:
                    name = proc.info["name"].lower()
                    exe = proc.info.get("exe", "").lower()
                    cmdline = " ".join(proc.info.get("cmdline", [])).lower()
                    current_processes[name] = {"pid": proc.info["pid"], "exe": exe,
                                               "cmdline": cmdline, "first_seen": now_ts()}
                    for grp in suspicious_indicators:
                        if any(ind in name or ind in exe or ind in cmdline for ind in grp):
                            if name not in self.suspicious_processes:
                                self.suspicious_processes.add(name)
                                self.log("HIGH", "SYSTEM", "Suspicious process detected",
                                         {"process": name, "exe": exe, "indicators": grp})
                            break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            for name, info in current_processes.items():
                if name not in self.suspicious_processes:
                    if name not in self.process_baseline:
                        self.process_baseline[name] = {"count": 1, "first_seen": info["first_seen"]}
                    else:
                        self.process_baseline[name]["count"] += 1

            current_time = time.time()
            self.process_baseline = {
                k: v for k, v in self.process_baseline.items()
                if current_time - time.mktime(
                    time.strptime(v["first_seen"], "%Y-%m-%d %H:%M:%S")
                ) <= 3600
            }
        except Exception as e:
            self.log("WARN", "SYSTEM", "Process monitoring error", {"error": str(e)})

    # ── File monitoring ───────────────────────────────────────────────────────

    def start_file_monitoring(self, paths: List[str]):
        if not HAS_WATCHDOG:
            self.log("WARN", "SYSTEM", "File monitoring disabled (watchdog missing)",
                     {"action": "pip install watchdog"})
            return
        try:
            monitor_ref = self

            class SecurityFileHandler(FileSystemEventHandler):
                def on_modified(self, event):
                    if event.is_directory:
                        return
                    filepath = event.src_path
                    try:
                        with open(filepath, "rb") as f:
                            fhash = hashlib.sha256(f.read()).hexdigest()
                        if filepath in monitor_ref.monitored_files:
                            if monitor_ref.monitored_files[filepath] != fhash:
                                monitor_ref.log("HIGH", "SYSTEM", "Critical file modified",
                                               {"file": filepath,
                                                "old_hash": monitor_ref.monitored_files[filepath][:16],
                                                "new_hash": fhash[:16]})
                        monitor_ref.monitored_files[filepath] = fhash
                    except Exception:
                        pass

            critical_paths = [
                os.path.expandvars(r"%SystemRoot%\System32\drivers\etc\hosts"),
                os.path.expandvars(r"%SystemRoot%\System32\config"),
            ] + paths

            self.file_observer = Observer()
            handler = SecurityFileHandler()
            for path in critical_paths:
                if os.path.exists(path):
                    self.file_observer.schedule(handler, path, recursive=True)
                    try:
                        with open(path, "rb") as f:
                            self.monitored_files[path] = hashlib.sha256(f.read()).hexdigest()
                    except Exception:
                        pass
            self.file_observer.start()
            self.log("INFO", "SYSTEM", "File monitoring started", {"paths": len(critical_paths)})
        except Exception as e:
            self.log("WARN", "SYSTEM", "File monitoring setup failed", {"error": str(e)})

    def stop_file_monitoring(self):
        if self.file_observer:
            self.file_observer.stop()
            self.file_observer.join()

    # ── Passive sniff ─────────────────────────────────────────────────────────

    def start_passive_sniff(self):
        if not try_load_scapy():
            self.log("WARN", "SYSTEM", "Passive sniff disabled (scapy missing)",
                     {"action": "pip install scapy"})
            return
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.sniff_stop.clear()
        self.sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.sniff_thread.start()
        self.log("INFO", "SYSTEM", "Passive sniff started",
                 {"requires": "Npcap + Admin for best results"})

    def stop_passive_sniff(self):
        self.sniff_stop.set()
        self.log("INFO", "SYSTEM", "Passive sniff stopping", {})

    def _sniff_loop(self):
        def handler(pkt):
            if self.sniff_stop.is_set():
                return
            try:
                if ARP is not None and pkt.haslayer(ARP):
                    arp = pkt.getlayer(ARP)
                    if getattr(arp, "op", None) == 2:
                        psrc = str(getattr(arp, "psrc", ""))
                        hwsrc = str(getattr(arp, "hwsrc", "")).lower()
                        if (
                            self.baseline_gateway_ip and psrc == self.baseline_gateway_ip
                            and self.baseline_gateway_mac and hwsrc
                            and hwsrc != self.baseline_gateway_mac
                        ):
                            self.log("HIGH", "MITM",
                                     "Observed ARP reply claiming to be gateway with different MAC",
                                     {"gateway_ip": psrc, "claimed_mac": hwsrc,
                                      "baseline_mac": self.baseline_gateway_mac})
            except Exception:
                pass
            try:
                if pkt.haslayer("IP") and pkt.haslayer("TCP"):
                    ip_layer = pkt["IP"]
                    tcp = pkt["TCP"]
                    flags = int(tcp.flags)
                    if (flags & 0x02) and not (flags & 0x10):
                        src = str(ip_layer.src)
                        dport = int(tcp.dport)
                        rec = self.syn_tracker.get(src)
                        t = time.time()
                        if not rec:
                            self.syn_tracker[src] = {"ports": {dport}, "ts": t}
                        else:
                            if t - rec["ts"] > 20:
                                rec["ports"] = {dport}
                                rec["ts"] = t
                            else:
                                rec["ports"].add(dport)
                            if len(rec["ports"]) >= 18:
                                self.log("WARN", "SCAN",
                                         "Possible port scan (many SYNs to multiple ports)",
                                         {"src_ip": src, "ports_count": len(rec["ports"]),
                                          "sample_ports": sorted(list(rec["ports"]))[:25]})
                                rec["ports"].clear()
                                rec["ts"] = t
            except Exception:
                pass

        try:
            sniff(
                filter="arp or tcp",
                prn=handler,
                store=False,
                stop_filter=lambda _p: self.sniff_stop.is_set(),
            )
        except Exception as e:
            self.log("WARN", "SYSTEM",
                     "Passive sniff failed (Npcap/Admin likely missing)", {"error": str(e)})

    # ── Threat level calculation ───────────────────────────────────────────────

    def compute_threat_level(self) -> str:
        """
        Returns 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' based on recent alerts.
        """
        cutoff = time.time() - 3600
        high_count = 0
        warn_count = 0
        for a in self.alerts:
            try:
                ts = time.mktime(time.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if ts < cutoff:
                continue
            sev = a.get("severity", "")
            if sev == "HIGH":
                high_count += 1
            elif sev == "WARN":
                warn_count += 1
        if high_count >= 3:
            return "CRITICAL"
        if high_count >= 1:
            return "HIGH"
        if warn_count >= 5:
            return "MEDIUM"
        return "LOW"

    def get_active_threats(self) -> List[Dict]:
        """Return HIGH-severity alerts from the last hour."""
        cutoff = time.time() - 3600
        threats = []
        for a in self.alerts:
            try:
                ts = time.mktime(time.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                continue
            if ts >= cutoff and a.get("severity") in ("HIGH", "WARN"):
                threats.append(a)
        return list(reversed(threats[-100:]))


# ─────────────────────────────────────────────────────────────────────────────
# GUI helpers
# ─────────────────────────────────────────────────────────────────────────────

def simple_prompt(parent, title: str, label: str, default: str = "") -> Optional[str]:
    win = ctk.CTkToplevel(parent)
    win.title(title)
    win.resizable(False, False)
    win.grab_set()

    ctk.CTkLabel(win, text=label).pack(padx=12, pady=(12, 6))
    var = tk.StringVar(value=default)
    ent = ctk.CTkEntry(win, textvariable=var, width=44)
    ent.pack(padx=12, pady=(0, 12))
    ent.focus_set()

    out: Dict[str, Optional[str]] = {"v": None}
    btns = ctk.CTkFrame(win)
    btns.pack(pady=(0, 12))

    def ok():
        out["v"] = var.get().strip()
        win.destroy()

    def cancel():
        out["v"] = None
        win.destroy()

    ctk.CTkButton(btns, text="OK", command=ok).pack(side="left", padx=6)
    ctk.CTkButton(btns, text="Cancel", command=cancel).pack(side="left", padx=6)
    win.bind("<Return>", lambda _e: ok())
    win.bind("<Escape>", lambda _e: cancel())
    parent.wait_window(win)
    return out["v"]


# Trust/classification display colours
TRUST_COLORS = {
    "safe":       "#90EE90",   # light green
    "known":      "#87CEEB",   # light blue
    "unknown":    "#FFD700",   # gold / yellow
    "suspicious": "#FFA500",   # orange
    "dangerous":  "#FF4444",   # red
}

THREAT_LEVEL_COLORS = {
    "LOW":      "#90EE90",
    "MEDIUM":   "#FFD700",
    "HIGH":     "#FFA500",
    "CRITICAL": "#FF4444",
}


# ─────────────────────────────────────────────────────────────────────────────
# Connection detail popup
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionDetailPopup:
    def __init__(self, parent, conn: Dict, monitor: "NetworkMonitor", on_refresh):
        self.parent = parent
        self.conn = conn
        self.mon = monitor
        self.on_refresh = on_refresh

        self.win = ctk.CTkToplevel(parent)
        self.win.title("Connection Detail")
        self.win.geometry("560x520")
        self.win.resizable(False, False)
        self.win.grab_set()

        self._build()

    def _build(self):
        c = self.conn
        trust = c.get("trust", "unknown")
        color = TRUST_COLORS.get(trust, "white")

        header = ctk.CTkFrame(self.win, fg_color=("#1e1e2e", "#1e1e2e"), corner_radius=8)
        header.pack(fill="x", padx=12, pady=(12, 4))
        ctk.CTkLabel(header, text=f"  {c.get('process', '?')}",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(side="left", pady=8, padx=4)
        ctk.CTkLabel(header, text=f"PID {c.get('pid', '?')}",
                     text_color="gray").pack(side="left", pady=8, padx=4)
        ctk.CTkLabel(header, text=trust.upper(),
                     text_color=color,
                     font=ctk.CTkFont(weight="bold")).pack(side="right", pady=8, padx=12)

        info = ctk.CTkFrame(self.win, corner_radius=8)
        info.pack(fill="x", padx=12, pady=4)

        def row(lbl, val):
            r = ctk.CTkFrame(info, fg_color="transparent")
            r.pack(fill="x", padx=8, pady=2)
            ctk.CTkLabel(r, text=lbl, width=120, anchor="w",
                         font=ctk.CTkFont(weight="bold")).pack(side="left")
            ctk.CTkLabel(r, text=str(val), anchor="w", wraplength=340).pack(side="left", padx=4)

        # Service badge — most important "what is this?" answer
        svc_name = c.get("service", "")
        svc_desc = c.get("service_desc", "")
        if svc_name:
            svc_frame = ctk.CTkFrame(info, fg_color="#1a2a3a", corner_radius=6)
            svc_frame.pack(fill="x", padx=8, pady=(4, 6))
            ctk.CTkLabel(
                svc_frame,
                text=f"  🔌  {svc_name}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#87CEEB",
                anchor="w",
            ).pack(side="left", padx=8, pady=4)
            if svc_desc:
                ctk.CTkLabel(
                    svc_frame,
                    text=svc_desc,
                    text_color="#aaaaaa",
                    anchor="w",
                    wraplength=340,
                ).pack(side="left", padx=4, pady=4)

        row("Remote IP:", c.get("remote_ip", ""))
        row("Remote port:", c.get("remote_port", ""))
        row("Local addr:", c.get("laddr", ""))
        row("Status:", c.get("status", ""))
        row("Country:", c.get("country", ""))
        row("Organization:", c.get("org", ""))
        row("Executable:", c.get("exe", "(unavailable)") or "(unavailable)")

        trust_explanations = {
            "safe":       "Explicitly trusted by you, or private LAN address.",
            "known":      "Belongs to a well-known organisation (Google, Microsoft, etc.).",
            "unknown":    "No geolocation or org data available.",
            "suspicious": "Unusual port, flagged country, or unrecognised service.",
            "dangerous":  "Confirmed bad port (Tor exit, backdoor, etc.).",
        }
        row("Trust reason:", trust_explanations.get(trust, ""))

        exe_path = c.get("exe", "")
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=8)

        if exe_path and os.path.exists(exe_path):
            ctk.CTkButton(
                btn_frame, text="Open Location",
                command=lambda: self._open_location(exe_path),
                fg_color="#3a7ebf", hover_color="#2b6194", width=130,
            ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Block IP",
            command=self._block_ip,
            fg_color="#bf6d3a", hover_color="#944e2b", width=110,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Trust IP",
            command=self._trust_ip,
            fg_color="#3abf6d", hover_color="#2b944e", width=110,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="Kill Process",
            command=self._kill_process,
            fg_color="#bf3a3a", hover_color="#942b2b", width=110,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            self.win, text="Close",
            command=self.win.destroy, width=80,
        ).pack(pady=(4, 12))

    def _open_location(self, exe_path: str):
        try:
            subprocess.Popen(
                ["explorer", "/select,", exe_path],
                creationflags=_CREATE_NO_WINDOW,
            )
        except Exception as e:
            messagebox.showerror("Open Location", str(e), parent=self.win)

    def _block_ip(self):
        ip = self.conn.get("remote_ip", "")
        if not ip:
            return
        if messagebox.askyesno("Block IP",
                               f"Add Windows Firewall outbound block rule for {ip}?",
                               parent=self.win):
            ok = block_ip_firewall(ip)
            if ok:
                messagebox.showinfo("Block IP", f"Outbound rule created for {ip}.", parent=self.win)
                self.mon.log("HIGH", "SYSTEM", "IP blocked via firewall",
                             {"ip": ip, "process": self.conn.get("process")})
            else:
                messagebox.showerror("Block IP",
                                     "netsh failed. Run as Administrator for firewall access.",
                                     parent=self.win)

    def _trust_ip(self):
        ip = self.conn.get("remote_ip", "")
        if not ip:
            return
        self.mon.conn_trust.trust_ip(ip, "Manually trusted")
        messagebox.showinfo("Trust IP", f"{ip} added to trust list.", parent=self.win)
        self.on_refresh()
        self.win.destroy()

    def _kill_process(self):
        pid = self.conn.get("pid", 0)
        pname = self.conn.get("process", "?")
        if not pid:
            messagebox.showerror("Kill Process", "No PID available.", parent=self.win)
            return
        if messagebox.askyesno("Kill Process",
                               f"Terminate {pname} (PID {pid})?\nThis cannot be undone.",
                               parent=self.win):
            try:
                psutil.Process(pid).kill()
                messagebox.showinfo("Kill Process", f"{pname} (PID {pid}) terminated.",
                                    parent=self.win)
                self.mon.log("HIGH", "SYSTEM", "Process killed by user",
                             {"process": pname, "pid": pid})
                self.on_refresh()
                self.win.destroy()
            except Exception as e:
                messagebox.showerror("Kill Process", str(e), parent=self.win)


# ─────────────────────────────────────────────────────────────────────────────
# Main App
# ─────────────────────────────────────────────────────────────────────────────

class App(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent, corner_radius=10)
        self.parent = parent
        parent.title("Network Intrusion Detector Pro")
        parent.geometry("1240x760")
        # Single topmost flash to bring window to front
        parent.attributes("-topmost", True)
        parent.after(100, lambda: parent.attributes("-topmost", False))

        self.state_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "nid_state.json"
        )
        self.mon = NetworkMonitor(self.state_path)

        self.running = True
        self.worker_q: "queue.Queue[str]" = queue.Queue()

        self.active_scan = tk.BooleanVar(value=True)
        self.passive_scan = tk.BooleanVar(value=True)
        self.refresh_ms = tk.IntVar(value=3500)

        self.cidr = tk.StringVar(value=parse_ipconfig_subnet() or "")
        self.gateway = tk.StringVar(value=get_default_gateway() or "")
        self.localip = tk.StringVar(value=local_ipv4() or "")

        self._last_conns: List[Dict] = []
        self._last_scan_ts: str = ""

        self._build_ui()

        threading.Thread(target=self._worker_loop, daemon=True).start()

        self.after(600, self.scan_now)
        self.after(900, self._ensure_passive)
        self.after(700, self._ui_tick)

    # ── Style helper (called ONCE) ────────────────────────────────────────────

    def _apply_tree_style(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure(
            "Treeview",
            background="#2b2b2b", foreground="white",
            fieldbackground="#2b2b2b", borderwidth=0, rowheight=25,
        )
        style.configure(
            "Treeview.Heading",
            background="#565b5e", foreground="white",
            relief="flat", font=("Arial", 10, "bold"),
        )
        style.map("Treeview", background=[("selected", "#1f538d")])

    # ── UI build ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        self._apply_tree_style()

        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=10, pady=8)

        ctk.CTkLabel(top, text=f"Admin: {'YES' if is_admin_windows() else 'NO'}").pack(side="left")
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)
        ctk.CTkLabel(top, text="Local IP").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.localip, width=120).pack(side="left", padx=6)
        ctk.CTkLabel(top, text="Gateway").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.gateway, width=120).pack(side="left", padx=6)
        ctk.CTkLabel(top, text="LAN CIDR").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.cidr, width=140).pack(side="left", padx=6)
        ttk.Separator(top, orient="vertical").pack(side="left", fill="y", padx=10)
        ctk.CTkCheckBox(top, text="Active discovery", variable=self.active_scan).pack(side="left", padx=6)
        ctk.CTkCheckBox(top, text="Passive sniff", variable=self.passive_scan).pack(side="left", padx=6)
        ctk.CTkLabel(top, text="Refresh (ms)").pack(side="left")
        ctk.CTkEntry(top, textvariable=self.refresh_ms, width=80).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Scan now", command=self.scan_now,
                      fg_color="#3a7ebf", hover_color="#2b6194").pack(side="left", padx=6)
        ctk.CTkButton(top, text="Export report", command=self.export_report).pack(side="left", padx=6)
        ctk.CTkButton(top, text="Force stop", command=self.force_stop,
                      fg_color="#bf3a3a", hover_color="#942b2b").pack(side="left", padx=6)

        nb = ctk.CTkTabview(self)
        nb.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.tab_dashboard = nb.add("Summary")
        self.tab_devices = nb.add("Devices")
        self.tab_connections = nb.add("Connections")
        self.tab_alerts = nb.add("Alerts")
        self.tab_trust = nb.add("Trust list")
        self.tab_threats = nb.add("Threats")

        self._build_dashboard()
        self._build_devices()
        self._build_connections()
        self._build_alerts()
        self._build_trust()
        self._build_threats()

        self.pack(fill="both", expand=True)

    # ── Dashboard tab ─────────────────────────────────────────────────────────

    def _build_dashboard(self):
        box = ctk.CTkFrame(self.tab_dashboard, corner_radius=10)
        box.pack(fill="both", expand=True, padx=8, pady=8)
        self.live_text = ctk.CTkTextbox(
            box, wrap="word", font=ctk.CTkFont(family="Consolas", size=13)
        )
        self.live_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.live_text.configure(state="disabled")
        self._update_live_text()

    def _update_live_text(self):
        threat_level = self.mon.compute_threat_level()
        susp_conns = sum(
            1 for c in self._last_conns if c.get("trust") in ("suspicious", "dangerous")
        )
        lines = [
            f"  Threat level : {threat_level}",
            f"  Suspicious connections : {susp_conns}",
            f"  Active connections : {len(self._last_conns)}",
            f"  Last scan : {self._last_scan_ts or '(pending)'}",
            "",
            "What matters most:",
            "  - New/untrusted device on LAN",
            "  - Gateway MAC changes vs baseline (possible MITM)",
            "  - IP->MAC mapping flips (strong ARP spoof indicator)",
            "  - Possible port scan (passive sniff)",
            "  - SUSPICIOUS / DANGEROUS outbound connections",
            "",
            "Noise reduction:",
            "  - Multicast/broadcast MACs filtered",
            "  - Alerts deduped + rate-limited",
            "",
            "Status:",
            f"  scapy={'YES' if HAS_SCAPY else 'NO'} | watchdog={'YES' if HAS_WATCHDOG else 'NO'} | admin={'YES' if is_admin_windows() else 'NO'}",
            f"  active={'ON' if self.active_scan.get() else 'OFF'} | passive={'ON' if self.passive_scan.get() else 'OFF'}",
            f"  Gateway baseline: {self.mon.baseline_gateway_ip or '(not set)'} / {self.mon.baseline_gateway_mac or '(not set)'}",
        ]
        self.live_text.configure(state="normal")
        self.live_text.delete("1.0", "end")
        self.live_text.insert("1.0", "\n".join(lines))
        self.live_text.configure(state="disabled")

    # ── Devices tab ───────────────────────────────────────────────────────────

    def _build_devices(self):
        f = self.tab_devices
        top = ctk.CTkFrame(f)
        top.pack(fill="x", padx=8, pady=6)
        ctk.CTkButton(top, text="Set current gateway as baseline",
                      command=self.set_gateway_baseline).pack(side="left", padx=6)
        self.dev_summary = ctk.CTkLabel(top, text="Devices: 0")
        self.dev_summary.pack(side="right", padx=10)

        cols = ("trusted", "label", "mac", "ip", "last_seen")
        self.dev_tree = ttk.Treeview(f, columns=cols, show="headings", height=22)
        for c in cols:
            self.dev_tree.heading(c, text=c.upper())
            w = 140
            if c == "mac":
                w = 180
            if c == "ip":
                w = 120
            if c == "label":
                w = 220
            self.dev_tree.column(c, width=w, stretch=True)
        self.dev_tree.pack(fill="both", expand=True, padx=8, pady=8)

        act = ctk.CTkFrame(f)
        act.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(act, text="Trust selected", command=self.trust_selected).pack(side="left", padx=6)
        ctk.CTkButton(act, text="Untrust selected", command=self.untrust_selected).pack(side="left", padx=6)
        ctk.CTkButton(act, text="Copy selected", command=self.copy_device_selected).pack(side="left", padx=6)

    # ── Connections tab ───────────────────────────────────────────────────────

    def _build_connections(self):
        f = self.tab_connections
        cols = ("trust", "process", "service", "laddr", "raddr", "country", "org", "status")
        self.conn_tree = ttk.Treeview(f, columns=cols, show="headings", height=26)
        headings = {
            "trust": "TRUST", "process": "PROCESS", "service": "SERVICE",
            "laddr": "LOCAL", "raddr": "REMOTE",
            "country": "COUNTRY", "org": "ORGANIZATION", "status": "STATUS",
        }
        widths = {
            "trust": 90, "process": 140, "service": 110,
            "laddr": 130, "raddr": 130,
            "country": 90, "org": 180, "status": 90,
        }
        for c in cols:
            self.conn_tree.heading(c, text=headings[c])
            self.conn_tree.column(c, width=widths[c], stretch=(c in ("org", "process")))
        self.conn_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Double-click → detail popup (also opens Explorer to executable location)
        self.conn_tree.bind("<Double-1>", self._on_conn_double_click)

        filter_frame = ctk.CTkFrame(f)
        filter_frame.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkLabel(filter_frame, text="Filter:").pack(side="left", padx=(0, 6))
        self.conn_filter = tk.StringVar(value="ALL")
        ttk.Combobox(
            filter_frame, textvariable=self.conn_filter, width=18,
            values=("ALL", "SAFE", "KNOWN", "UNKNOWN", "SUSPICIOUS", "DANGEROUS"),
            state="readonly",
        ).pack(side="left", padx=6)
        ctk.CTkButton(filter_frame, text="Apply", command=self.refresh_connections).pack(side="left", padx=6)
        ctk.CTkButton(filter_frame, text="Trust IP", command=self.trust_connection_ip).pack(side="left", padx=6)
        ctk.CTkButton(filter_frame, text="Untrust IP", command=self.untrust_connection_ip).pack(side="left", padx=6)
        ctk.CTkButton(filter_frame, text="Block IP (Firewall)", command=self.block_selected_ip,
                      fg_color="#bf6d3a", hover_color="#944e2b").pack(side="left", padx=6)

    def _on_conn_double_click(self, _event):
        sel = self.conn_tree.selection()
        if not sel:
            return
        iid = sel[0]
        try:
            idx = int(iid.split("-")[1])
        except Exception:
            return

        # Resolve the index against the currently displayed (filtered) list
        filter_val = self.conn_filter.get()
        filtered = self._filtered_conns(filter_val)
        if idx < 0 or idx >= len(filtered):
            return

        conn = filtered[idx]
        ConnectionDetailPopup(self.parent, conn, self.mon, self.refresh_connections)

    def _filtered_conns(self, filter_val: str) -> List[Dict]:
        result = []
        for c in self._last_conns[:1200]:
            trust = c.get("trust", "unknown")
            if filter_val != "ALL" and trust.upper() != filter_val.upper():
                continue
            result.append(c)
        return result

    # ── Alerts tab ────────────────────────────────────────────────────────────

    def _build_alerts(self):
        f = self.tab_alerts
        bar = ctk.CTkFrame(f)
        bar.pack(fill="x", padx=8, pady=(8, 0))

        self.alert_filter_cat = tk.StringVar(value="ALL")
        self.alert_filter_sev = tk.StringVar(value="ALL")

        ctk.CTkLabel(bar, text="Category").pack(side="left")
        ttk.Combobox(
            bar, textvariable=self.alert_filter_cat, width=10,
            values=("ALL", "DEVICE", "MITM", "SCAN", "DNS", "OUTBOUND", "SYSTEM"),
            state="readonly",
        ).pack(side="left", padx=6)
        ctk.CTkLabel(bar, text="Severity").pack(side="left")
        ttk.Combobox(
            bar, textvariable=self.alert_filter_sev, width=8,
            values=("ALL", "INFO", "WARN", "HIGH"),
            state="readonly",
        ).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Apply", command=self.refresh_alerts).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Clear alerts", command=self.clear_alerts).pack(side="left", padx=6)

        cols = ("time", "severity", "category", "title")
        self.alert_tree = ttk.Treeview(f, columns=cols, show="headings", height=20)
        for c in cols:
            self.alert_tree.heading(c, text=c.upper())
            w = 760 if c == "title" else 180
            self.alert_tree.column(c, width=w, stretch=(c == "title"))
        self.alert_tree.pack(fill="both", expand=True, padx=8, pady=8)
        self.alert_tree.bind("<<TreeviewSelect>>", lambda _e: self.show_alert_details())

        box = ctk.CTkFrame(f, corner_radius=10)
        box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.alert_details = ctk.CTkTextbox(
            box, height=150, wrap="word", font=ctk.CTkFont(family="Consolas", size=13)
        )
        self.alert_details.pack(fill="both", expand=True, padx=10, pady=10)
        self.alert_details.configure(state="disabled")

    # ── Trust list tab ────────────────────────────────────────────────────────

    def _build_trust(self):
        f = self.tab_trust
        cols = ("mac", "label", "first_seen")
        self.trust_tree = ttk.Treeview(f, columns=cols, show="headings", height=24)
        for c in cols:
            self.trust_tree.heading(c, text=c.upper())
            w = 280 if c == "label" else 220
            self.trust_tree.column(c, width=w, stretch=True)
        self.trust_tree.pack(fill="both", expand=True, padx=8, pady=8)

        row = ctk.CTkFrame(f)
        row.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(row, text="Remove selected", command=self.remove_trust_selected).pack(side="left", padx=6)

    # ── Threats tab ───────────────────────────────────────────────────────────

    def _build_threats(self):
        f = self.tab_threats

        # Threat gauge row
        gauge_frame = ctk.CTkFrame(f, corner_radius=8)
        gauge_frame.pack(fill="x", padx=8, pady=(10, 4))

        ctk.CTkLabel(gauge_frame, text="Overall Threat Level:",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left", padx=12, pady=8)
        self.threat_level_label = ctk.CTkLabel(
            gauge_frame, text="LOW",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#90EE90",
        )
        self.threat_level_label.pack(side="left", padx=8, pady=8)

        # Stats row
        stats_frame = ctk.CTkFrame(f, fg_color="transparent")
        stats_frame.pack(fill="x", padx=8, pady=2)
        self.threat_stats_label = ctk.CTkLabel(stats_frame, text="", text_color="gray")
        self.threat_stats_label.pack(side="left", padx=12)

        # Active threats list
        cols = ("time", "severity", "category", "title")
        self.threat_tree = ttk.Treeview(f, columns=cols, show="headings", height=16)
        for c in cols:
            self.threat_tree.heading(c, text=c.upper())
            w = 600 if c == "title" else 150
            self.threat_tree.column(c, width=w, stretch=(c == "title"))
        self.threat_tree.pack(fill="both", expand=True, padx=8, pady=8)

        # Action buttons
        act = ctk.CTkFrame(f, fg_color="transparent")
        act.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(act, text="Kill Process",
                      command=self.threats_kill_process,
                      fg_color="#bf3a3a", hover_color="#942b2b").pack(side="left", padx=6)
        ctk.CTkButton(act, text="Block IP (Firewall)",
                      command=self.threats_block_ip,
                      fg_color="#bf6d3a", hover_color="#944e2b").pack(side="left", padx=6)
        ctk.CTkButton(act, text="Investigate",
                      command=self.threats_investigate).pack(side="left", padx=6)
        ctk.CTkButton(act, text="Refresh",
                      command=self.refresh_threats).pack(side="right", padx=6)

    # ─────────────────────────────────────────────────────────────────────────
    # Actions
    # ─────────────────────────────────────────────────────────────────────────

    def scan_now(self):
        try:
            self.worker_q.put_nowait("scan")
        except Exception:
            pass

    def force_stop(self):
        self.running = False
        self.mon.stop_passive_sniff()
        try:
            self.parent.destroy()
        except Exception:
            pass

    def export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON report", "*.json")],
            title="Save network report",
        )
        if not path:
            return
        report = {
            "generated_at": now_ts(),
            "admin": is_admin_windows(),
            "scapy_available": HAS_SCAPY,
            "cidr": self.cidr.get(),
            "gateway": self.gateway.get(),
            "local_ip": self.localip.get(),
            "trusted": self.mon.trusted,
            "known_devices": self.mon.known_devices,
            "gateway_baseline": {
                "ip": self.mon.baseline_gateway_ip,
                "mac": self.mon.baseline_gateway_mac,
            },
            "alerts": self.mon.alerts,
            "connections_snapshot": self._last_conns,
            "threat_level": self.mon.compute_threat_level(),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export", f"Saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def set_gateway_baseline(self):
        gw = self.gateway.get().strip()
        if not gw:
            messagebox.showerror("Gateway baseline", "Gateway IP is empty.")
            return
        arps = arp_table()
        mac = arps.get(gw, "")
        if not mac:
            messagebox.showerror("Gateway baseline",
                                 "Could not find gateway MAC in ARP table.\nTry Scan now and retry.")
            return
        self.mon.set_gateway_baseline(gw, mac)
        self._update_live_text()

    def trust_selected(self):
        sel = self.dev_tree.selection()
        if not sel:
            return
        iid = sel[0]
        mac = self.dev_tree.set(iid, "mac").lower()
        label = self.dev_tree.set(iid, "label") or "Trusted"
        label = simple_prompt(self.parent, "Trust device", "Label for this device:", default=label)
        if label is None:
            return
        self.mon.trust_mac(mac, label)
        self.mon.log("INFO", "DEVICE", "Device marked as trusted", {"mac": mac, "label": label})
        self.refresh_all()

    def untrust_selected(self):
        sel = self.dev_tree.selection()
        if not sel:
            return
        iid = sel[0]
        mac = self.dev_tree.set(iid, "mac").lower()
        self.mon.untrust_mac(mac)
        self.mon.log("INFO", "DEVICE", "Device removed from trust list", {"mac": mac})
        self.refresh_all()

    def copy_device_selected(self):
        sel = self.dev_tree.selection()
        if not sel:
            return
        iid = sel[0]
        row = {c: self.dev_tree.set(iid, c) for c in ("trusted", "label", "mac", "ip", "last_seen")}
        text = json.dumps(row, indent=2, ensure_ascii=False)
        self.parent.clipboard_clear()
        self.parent.clipboard_append(text)
        self.mon.log("INFO", "SYSTEM", "Copied device to clipboard", row)

    def remove_trust_selected(self):
        sel = self.trust_tree.selection()
        if not sel:
            return
        iid = sel[0]
        mac = self.trust_tree.set(iid, "mac").lower()
        self.mon.untrust_mac(mac)
        self.mon.log("INFO", "DEVICE", "Trust entry removed", {"mac": mac})
        self.refresh_all()

    def clear_alerts(self):
        self.mon.alerts.clear()
        self.mon._alert_index.clear()
        self.mon._alert_last_seen.clear()
        self.mon._rate_limit.clear()
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        self.alert_details.configure(state="normal")
        self.alert_details.delete("1.0", "end")
        self.alert_details.configure(state="disabled")

    def alert_passes_filter(self, a: Dict) -> bool:
        cat = self.alert_filter_cat.get()
        sev = self.alert_filter_sev.get()
        if cat != "ALL" and a.get("category") != cat:
            return False
        if sev != "ALL" and a.get("severity") != sev:
            return False
        return True

    # Connections actions ──────────────────────────────────────────────────────

    def _selected_conn(self) -> Optional[Dict]:
        sel = self.conn_tree.selection()
        if not sel:
            return None
        try:
            idx = int(sel[0].split("-")[1])
        except Exception:
            return None
        filtered = self._filtered_conns(self.conn_filter.get())
        if idx < len(filtered):
            return filtered[idx]
        return None

    def trust_connection_ip(self):
        conn = self._selected_conn()
        if not conn:
            messagebox.showinfo("Trust IP", "Please select a connection first")
            return
        ip = conn.get("remote_ip", "")
        if ip:
            self.mon.conn_trust.trust_ip(ip, "Manually trusted connection")
            messagebox.showinfo("Trust IP", f"IP {ip} added to trust list")
            self.refresh_connections()

    def untrust_connection_ip(self):
        conn = self._selected_conn()
        if not conn:
            messagebox.showinfo("Untrust IP", "Please select a connection first")
            return
        ip = conn.get("remote_ip", "")
        if ip:
            self.mon.conn_trust.untrust_ip(ip)
            messagebox.showinfo("Untrust IP", f"IP {ip} removed from trust list")
            self.refresh_connections()

    def block_selected_ip(self):
        conn = self._selected_conn()
        if not conn:
            messagebox.showinfo("Block IP", "Please select a connection first")
            return
        ip = conn.get("remote_ip", "")
        if not ip:
            return
        if messagebox.askyesno("Block IP", f"Add Windows Firewall outbound block rule for {ip}?"):
            ok = block_ip_firewall(ip)
            if ok:
                messagebox.showinfo("Block IP", f"Outbound block rule created for {ip}.")
                self.mon.log("HIGH", "SYSTEM", "IP blocked via firewall",
                             {"ip": ip, "process": conn.get("process")})
            else:
                messagebox.showerror("Block IP",
                                     "netsh failed. Run as Administrator for firewall access.")

    # Threats tab actions ─────────────────────────────────────────────────────

    def _selected_threat_alert(self) -> Optional[Dict]:
        sel = self.threat_tree.selection()
        if not sel:
            return None
        try:
            idx = int(sel[0].split("-")[1])
        except Exception:
            return None
        threats = self.mon.get_active_threats()
        if idx < len(threats):
            return threats[idx]
        return None

    def threats_kill_process(self):
        alert = self._selected_threat_alert()
        if not alert:
            messagebox.showinfo("Kill Process", "Select a threat first")
            return
        details = alert.get("details", {})
        proc_name = details.get("process", "")
        pid_val = details.get("pid", 0)

        if not pid_val:
            messagebox.showinfo("Kill Process", "No PID in this alert.")
            return
        try:
            pid_val = int(pid_val)
        except Exception:
            messagebox.showinfo("Kill Process", "Invalid PID.")
            return

        if messagebox.askyesno("Kill Process",
                               f"Terminate {proc_name or 'process'} (PID {pid_val})?"):
            try:
                psutil.Process(pid_val).kill()
                messagebox.showinfo("Kill Process", f"PID {pid_val} terminated.")
                self.mon.log("HIGH", "SYSTEM", "Process killed via Threats tab",
                             {"process": proc_name, "pid": pid_val})
                self.refresh_threats()
            except Exception as e:
                messagebox.showerror("Kill Process", str(e))

    def threats_block_ip(self):
        alert = self._selected_threat_alert()
        if not alert:
            messagebox.showinfo("Block IP", "Select a threat first")
            return
        details = alert.get("details", {})
        ip = details.get("remote_ip", details.get("ip", ""))
        if not ip:
            messagebox.showinfo("Block IP", "No IP address found in this alert.")
            return
        if messagebox.askyesno("Block IP", f"Add Windows Firewall outbound block for {ip}?"):
            ok = block_ip_firewall(ip)
            if ok:
                messagebox.showinfo("Block IP", f"Block rule created for {ip}.")
                self.mon.log("HIGH", "SYSTEM", "IP blocked via Threats tab", {"ip": ip})
                self.refresh_threats()
            else:
                messagebox.showerror("Block IP",
                                     "netsh failed. Run as Administrator for firewall access.")

    def threats_investigate(self):
        alert = self._selected_threat_alert()
        if not alert:
            messagebox.showinfo("Investigate", "Select a threat first")
            return
        text = json.dumps(alert, indent=2, ensure_ascii=False)
        win = ctk.CTkToplevel(self.parent)
        win.title("Threat Investigation")
        win.geometry("600x400")
        tb = ctk.CTkTextbox(win, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        tb.pack(fill="both", expand=True, padx=8, pady=8)
        tb.insert("1.0", text)
        tb.configure(state="disabled")
        ctk.CTkButton(win, text="Close", command=win.destroy).pack(pady=8)

    # ─────────────────────────────────────────────────────────────────────────
    # Background worker
    # ─────────────────────────────────────────────────────────────────────────

    def _worker_loop(self):
        while self.running:
            try:
                job = self.worker_q.get(timeout=0.2)
            except queue.Empty:
                continue

            if job == "scan":
                try:
                    cidr = self.cidr.get().strip() or None
                    gw = self.gateway.get().strip() or None
                    active = bool(self.active_scan.get())

                    mac_ip = self.mon.discover_devices(cidr, active=active)
                    self.mon.analyze_devices(mac_ip, gw_ip=gw)

                    conns = self.mon.snapshot_outbound()
                    self._last_conns = conns
                    self._last_scan_ts = now_ts()

                    if len(conns) > 80:
                        self.mon.log("INFO", "OUTBOUND", "High number of active connections",
                                     {"count": len(conns)})

                    # Advanced threat scans (rate-limited internally)
                    self.mon._detect_advanced_threats(conns)

                except Exception as e:
                    self.mon.log("WARN", "SYSTEM", "Scan error", {"error": str(e)})

    def _ensure_passive(self):
        if self.passive_scan.get():
            self.mon.start_passive_sniff()

    def _ui_tick(self):
        if self.running:
            self.scan_now()
        self.refresh_all()
        self._update_live_text()
        self.after(max(1000, int(self.refresh_ms.get())), self._ui_tick)

    # ─────────────────────────────────────────────────────────────────────────
    # View refresh
    # ─────────────────────────────────────────────────────────────────────────

    def refresh_all(self):
        self.refresh_devices()
        self.refresh_connections()
        self.refresh_alerts()
        self.refresh_trust()
        self.refresh_threats()

    def refresh_devices(self):
        for i in self.dev_tree.get_children():
            self.dev_tree.delete(i)
        items = [
            (mac, info)
            for mac, info in (self.mon.known_devices or {}).items()
            if not is_noisy_mac(mac)
        ]
        items.sort(
            key=lambda x: (1 if x[0] in self.mon.trusted else 0, x[1].get("last_seen", "")),
            reverse=True,
        )
        for mac, info in items[:900]:
            trusted = "YES" if mac in self.mon.trusted else ""
            label = self.mon.trusted.get(mac, {}).get("label", "") if mac in self.mon.trusted else ""
            self.dev_tree.insert("", "end", iid=f"dev-{mac}",
                                 values=(trusted, label, mac, info.get("last_ip", ""),
                                         info.get("last_seen", "")))
        self.dev_summary.configure(
            text=f"Devices: {len(items)} (Trusted: {len(self.mon.trusted)})"
        )

    def refresh_connections(self):
        for i in self.conn_tree.get_children():
            self.conn_tree.delete(i)
        filter_val = self.conn_filter.get()
        filtered = self._filtered_conns(filter_val)
        for idx, c in enumerate(filtered[:800]):
            trust = c.get("trust", "unknown")
            org = c.get("org", "")
            if len(org) > 35:
                org = org[:32] + "..."
            iid = f"c-{idx}"
            self.conn_tree.insert(
                "", "end", iid=iid,
                values=(
                    trust.upper(),
                    c.get("process", "?"),
                    c.get("service", ""),
                    c.get("laddr", ""),
                    c.get("raddr", ""),
                    c.get("country", ""),
                    org,
                    c.get("status", ""),
                ),
                tags=(trust,),
            )
            self.conn_tree.tag_configure(trust, foreground=TRUST_COLORS.get(trust, "white"))

    def refresh_alerts(self):
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        recent = list(reversed(self.mon.alerts[-800:]))
        idx = 0
        for a in recent:
            if not self.alert_passes_filter(a):
                continue
            title = a.get("title", "")
            cnt = int(a.get("details", {}).get("_count", 1))
            if cnt > 1:
                title = f"{title}  (x{cnt})"
            self.alert_tree.insert("", "end", iid=f"a-{idx}",
                                   values=(a.get("timestamp", ""), a.get("severity", ""),
                                           a.get("category", ""), title))
            idx += 1

    def show_alert_details(self):
        sel = self.alert_tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0].split("-")[1])
        except Exception:
            return
        recent = list(reversed(self.mon.alerts[-800:]))
        filtered = [a for a in recent if self.alert_passes_filter(a)]
        if idx < 0 or idx >= len(filtered):
            return
        text = json.dumps(filtered[idx], indent=2, ensure_ascii=False)
        self.alert_details.configure(state="normal")
        self.alert_details.delete("1.0", "end")
        self.alert_details.insert("1.0", text)
        self.alert_details.configure(state="disabled")

    def refresh_trust(self):
        for i in self.trust_tree.get_children():
            self.trust_tree.delete(i)
        for mac, info in sorted(self.mon.trusted.items()):
            self.trust_tree.insert("", "end", iid=f"t-{mac}",
                                   values=(mac, info.get("label", ""), info.get("first_seen", "")))

    def refresh_threats(self):
        for i in self.threat_tree.get_children():
            self.threat_tree.delete(i)

        level = self.mon.compute_threat_level()
        color = THREAT_LEVEL_COLORS.get(level, "white")
        self.threat_level_label.configure(text=level, text_color=color)

        susp = sum(1 for c in self._last_conns if c.get("trust") in ("suspicious", "dangerous"))
        high_alerts = sum(1 for a in self.mon.alerts[-200:] if a.get("severity") == "HIGH")
        self.threat_stats_label.configure(
            text=f"Suspicious/Dangerous connections: {susp}  |  "
                 f"HIGH alerts (recent): {high_alerts}  |  "
                 f"Last scan: {self._last_scan_ts or '(pending)'}"
        )

        threats = self.mon.get_active_threats()
        for idx, a in enumerate(threats[:200]):
            self.threat_tree.insert(
                "", "end", iid=f"th-{idx}",
                values=(a.get("timestamp", ""), a.get("severity", ""),
                        a.get("category", ""), a.get("title", "")),
                tags=(a.get("severity", ""),),
            )
        self.threat_tree.tag_configure("HIGH", foreground="#FF4444")
        self.threat_tree.tag_configure("WARN", foreground="#FFA500")
        self.threat_tree.tag_configure("INFO", foreground="#90EE90")


# ─────────────────────────────────────────────────────────────────────────────
# Toolbox entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_tool():
    try:
        if tk._default_root is None:
            root = ctk.CTkToplevel()
            root.withdraw()
            app = App(root)
            root.protocol("WM_DELETE_WINDOW", app.force_stop)
            root.mainloop()
        else:
            win = ctk.CTkToplevel(tk._default_root)
            app = App(win)
            win.protocol("WM_DELETE_WINDOW", app.force_stop)
    except Exception as e:
        try:
            messagebox.showerror("Network Intrusion Detector Pro", f"Startup error:\n{e}")
        except Exception:
            pass


if __name__ == "__main__":
    run_tool()
