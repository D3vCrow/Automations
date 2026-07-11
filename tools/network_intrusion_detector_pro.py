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

from tools._common.threadsafe import BoundedDeque, SnapshotDict
from tools._common.alert_store import AlertStore
from tools._common.atomic_io import atomic_write_json, read_json, sweep_stale_tmp
from tools._common.verdict import (
    Verdict,
    VerdictState,
    arbitrate,
    contrast_text_color,
)
from tools._common import ui_theme

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
    except Exception:  # noqa: BLE001 - boundary: optional scapy dep import (init may raise OSError/RuntimeError on missing libs)
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
    except (subprocess.SubprocessError, OSError, ValueError) as e:
        return 1, "", str(e)


# ─────────────────────────────────────────────────────────────────────────────
# IP Geolocation & 5-level Connection Classification
# ─────────────────────────────────────────────────────────────────────────────

_ip_geo_cache: SnapshotDict = SnapshotDict()

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
    if is_private_ip(ip):
        return {"country": "Local", "region": "LAN", "city": "Private", "org": "", "trust": "safe"}
    cached = _ip_geo_cache.get(ip)
    if cached is not None:
        return cached
    if len(_ip_geo_cache) > 2000:
        _ip_geo_cache.clear()
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
    except (requests.RequestException, ValueError, KeyError):
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
    except (ValueError, AttributeError, IndexError):
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
# IP Reputation Checker  (VirusTotal + AbuseIPDB)
# ─────────────────────────────────────────────────────────────────────────────

_API_KEYS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "nid_api_keys.json")

# Reputation indicators used in the connections table REP column
REP_CLEAN      = "✓"
REP_SUSPICIOUS = "⚠"
REP_DANGEROUS  = "✗"
REP_UNCHECKED  = "—"
REP_PENDING    = "…"

REP_COLORS = {
    REP_CLEAN:      "#90EE90",
    REP_SUSPICIOUS: "#FFA500",
    REP_DANGEROUS:  "#FF4444",
    REP_UNCHECKED:  "#888888",
    REP_PENDING:    "#888888",
}


class IPReputationChecker:
    """Wraps VirusTotal v3 + AbuseIPDB v2 behind a single check_ip() call."""

    # Rate-limit tracking
    VT_MAX_PER_MIN = 4
    ABUSE_MAX_PER_DAY = 1000

    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._vt_key: str = ""
        self._abuse_key: str = ""
        self._vt_timestamps: List[float] = []
        self._abuse_day_count: int = 0
        self._abuse_day_start: float = time.time()
        self._lock = threading.Lock()
        self._load_keys()

    # ── Key management ──────────────────────────────────────────────────────

    def _load_keys(self):
        data = read_json(_API_KEYS_PATH, default={})
        self._vt_key = (data.get("virustotal_key", "") or "").strip()
        self._abuse_key = (data.get("abuseipdb_key", "") or "").strip()

    def save_keys(self, vt_key: str, abuse_key: str):
        self._vt_key = vt_key.strip()
        self._abuse_key = abuse_key.strip()
        try:
            atomic_write_json(
                _API_KEYS_PATH,
                {"virustotal_key": self._vt_key, "abuseipdb_key": self._abuse_key},
            )
        except (OSError, TypeError):
            pass

    @property
    def has_keys(self) -> bool:
        return bool(self._vt_key or self._abuse_key)

    # ── Rate limiting ───────────────────────────────────────────────────────

    def _vt_rate_ok(self) -> bool:
        now = time.time()
        self._vt_timestamps = [t for t in self._vt_timestamps if now - t < 60]
        return len(self._vt_timestamps) < self.VT_MAX_PER_MIN

    def _abuse_rate_ok(self) -> bool:
        now = time.time()
        if now - self._abuse_day_start > 86400:
            self._abuse_day_count = 0
            self._abuse_day_start = now
        return self._abuse_day_count < self.ABUSE_MAX_PER_DAY

    # ── API calls ───────────────────────────────────────────────────────────

    def _query_virustotal(self, ip: str) -> Dict:
        if not self._vt_key or not self._vt_rate_ok():
            return {}
        try:
            resp = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self._vt_key},
                timeout=8,
            )
            self._vt_timestamps.append(time.time())
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                return {
                    "vt_malicious":  int(stats.get("malicious", 0)),
                    "vt_suspicious": int(stats.get("suspicious", 0)),
                    "vt_harmless":   int(stats.get("harmless", 0)),
                    "vt_undetected": int(stats.get("undetected", 0)),
                    "vt_reputation": int(attrs.get("reputation", 0)),
                }
        except (requests.RequestException, ValueError, KeyError, TypeError):
            pass
        return {}

    def _query_abuseipdb(self, ip: str) -> Dict:
        if not self._abuse_key or not self._abuse_rate_ok():
            return {}
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._abuse_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                timeout=8,
            )
            self._abuse_day_count += 1
            if resp.status_code == 200:
                d = resp.json().get("data", {})
                return {
                    "abuse_score":   int(d.get("abuseConfidenceScore", 0)),
                    "abuse_reports": int(d.get("totalReports", 0)),
                    "abuse_is_tor":  bool(d.get("isTor", False)),
                    "abuse_usage":   str(d.get("usageType", "")),
                    "abuse_domain":  str(d.get("domain", "")),
                    "abuse_country": str(d.get("countryCode", "")),
                }
        except (requests.RequestException, ValueError, KeyError, TypeError):
            pass
        return {}

    # ── Main check ──────────────────────────────────────────────────────────

    def check_ip(self, ip: str, force: bool = False) -> Dict:
        """
        Check an IP against VT + AbuseIPDB.  Returns a combined dict.
        Results are cached for the session (unless force=True).
        """
        if is_private_ip(ip):
            return {"rep": REP_CLEAN, "source": "private"}

        with self._lock:
            if not force and ip in self._cache:
                return self._cache[ip]

        vt = self._query_virustotal(ip)
        ab = self._query_abuseipdb(ip)

        result = {**vt, **ab}
        result["source"] = "+".join(filter(None, ["vt" if vt else "", "abuse" if ab else ""]))
        result["checked_at"] = now_ts()

        # Derive reputation indicator
        vt_mal = result.get("vt_malicious", 0)
        abuse  = result.get("abuse_score", 0)

        if vt_mal >= 3 or abuse >= 50:
            result["rep"] = REP_DANGEROUS
        elif vt_mal >= 1 or abuse >= 15:
            result["rep"] = REP_SUSPICIOUS
        else:
            result["rep"] = REP_CLEAN

        with self._lock:
            self._cache[ip] = result
        return result

    def get_cached(self, ip: str) -> Optional[Dict]:
        """Return cached result or None."""
        with self._lock:
            return self._cache.get(ip)

    def reputation_upgrades_trust(self, ip: str, current_trust: str) -> str:
        """
        Given an IP's reputation data, return the same or higher severity trust.
        Never downgrades (e.g. safe → safe, unknown → dangerous).
        """
        cached = self.get_cached(ip)
        if not cached:
            return current_trust

        trust_order = {"safe": 0, "known": 1, "unknown": 2, "suspicious": 3, "dangerous": 4}
        current_level = trust_order.get(current_trust, 2)

        rep = cached.get("rep", REP_UNCHECKED)
        if rep == REP_DANGEROUS:
            new_level = max(current_level, 4)
        elif rep == REP_SUSPICIOUS:
            new_level = max(current_level, 3)
        else:
            # Clean reputation: optionally upgrade unknown → known
            vt_harmless = cached.get("vt_harmless", 0)
            if current_trust == "unknown" and vt_harmless >= 30:
                new_level = max(current_level, 1)  # → known
            else:
                new_level = current_level

        reverse = {v: k for k, v in trust_order.items()}
        return reverse.get(new_level, current_trust)


# Global instance (created once, used by App and NetworkMonitor)
_reputation_checker: Optional[IPReputationChecker] = None


def get_reputation_checker() -> IPReputationChecker:
    global _reputation_checker
    if _reputation_checker is None:
        _reputation_checker = IPReputationChecker()
    return _reputation_checker


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
        data = read_json(self.state_path, default={})
        self.trusted_ips = data.get("trusted_ips", {}) or {}
        self.trusted_domains = data.get("trusted_domains", {}) or {}

    def save(self):
        try:
            atomic_write_json(
                self.state_path,
                {"trusted_ips": self.trusted_ips, "trusted_domains": self.trusted_domains},
            )
        except (OSError, TypeError):
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
    except (ImportError, OSError, AttributeError):
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
    except (OSError, RuntimeError, AttributeError):
        return {}


def local_ipv4() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
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
    except (requests.RequestException, ValueError):
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
# Plain-language verdict adapter
# ─────────────────────────────────────────────────────────────────────────────
# Maps recent alerts onto the shared five-state Verdict vocabulary in
# tools._common.verdict. See plans/2026-07-10-network-tools-audit.md §6 and §8.
#
# The load-bearing rule (plan §6): attack-vs-noise comes from the alert
# CATEGORY, not a raw HIGH count. A burst of "new device" alerts is benign even
# at HIGH severity; a single ARP-spoof (MITM) is an attack. compute_threat_level
# counts severities and so cries wolf on benign bursts — this banner does not.

# A HIGH here is a possible attack (RED); a WARN is worth-a-look (AMBER).
_NID_ATTACK_CATEGORIES = {"MITM", "SCAN", "DNS"}
# Usually benign — worth-a-look (AMBER) at most, never RED on their own.
_NID_BENIGN_CATEGORIES = {"DEVICE", "OUTBOUND"}
# SYSTEM alerts are tool/status noise and carry no threat verdict.

# "Recent" window — matches compute_threat_level()'s one hour.
_NID_RECENT_WINDOW_S = 3600


def _parse_alert_epoch(ts: str) -> Optional[float]:
    """Parse an alert timestamp (``%Y-%m-%d %H:%M:%S``) to epoch seconds or None."""
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S"))
    except (ValueError, KeyError, TypeError):
        return None


def summarize_nid_alerts(alerts: List[Dict], now_epoch: float,
                         window_s: float = _NID_RECENT_WINDOW_S) -> Dict[str, object]:
    """Bucket recent HIGH/WARN alerts into attack vs benign, with dominant category.

    INFO alerts and non-threat categories (``SYSTEM``) are ignored — they don't
    move the verdict.

    Args:
        alerts: Alert dicts (``severity`` / ``category`` / ``timestamp``).
        now_epoch: Current time, epoch seconds — the window anchor.
        window_s: How far back "recent" reaches.

    Returns:
        A dict with ``attack_high`` / ``attack_warn`` / ``benign_high`` /
        ``benign_warn`` counts plus ``dominant_attack`` / ``dominant_benign``
        category labels (``""`` when none).
    """
    cutoff = now_epoch - window_s
    attack_high = attack_warn = benign_high = benign_warn = 0
    attack_cats: Dict[str, int] = {}
    benign_cats: Dict[str, int] = {}
    for a in alerts:
        epoch = _parse_alert_epoch(a.get("timestamp", ""))
        if epoch is None or epoch < cutoff:
            continue
        sev = (a.get("severity") or "").upper()
        if sev not in ("HIGH", "WARN"):
            continue
        cat = (a.get("category") or "").upper()
        if cat in _NID_ATTACK_CATEGORIES:
            attack_cats[cat] = attack_cats.get(cat, 0) + 1
            if sev == "HIGH":
                attack_high += 1
            else:
                attack_warn += 1
        elif cat in _NID_BENIGN_CATEGORIES:
            benign_cats[cat] = benign_cats.get(cat, 0) + 1
            if sev == "HIGH":
                benign_high += 1
            else:
                benign_warn += 1
    return {
        "attack_high": attack_high,
        "attack_warn": attack_warn,
        "benign_high": benign_high,
        "benign_warn": benign_warn,
        "dominant_attack": max(attack_cats, key=attack_cats.get) if attack_cats else "",
        "dominant_benign": max(benign_cats, key=benign_cats.get) if benign_cats else "",
    }


def _nid_attack_red(dominant_cat: str, count: int) -> Verdict:
    """RED verdict for a high-severity attack-shaped alert, phrased by category."""
    wording = {
        "MITM": (
            "Something is impersonating your router or a device — possible attack.",
            "A gateway/MAC change or ARP-spoof pattern was detected.",
            "Disconnect Wi-Fi, switch to mobile data, and verify this network before trusting it.",
        ),
        "SCAN": (
            "A device on your network is scanning the others — possible intruder.",
            "Port-scan or sweep activity was detected on your LAN.",
            "Find the device on the Devices tab, disconnect it, and change your Wi-Fi password.",
        ),
        "DNS": (
            "Suspicious DNS activity — possible data theft or redirection.",
            "Unusual DNS queries were detected.",
            "Disconnect the affected device and check your DNS settings.",
        ),
    }
    headline, evidence, action = wording.get(dominant_cat, (
        "Something on your network looks like an attack.",
        "One or more high-severity threat alerts fired.",
        "Open the Threats tab and disconnect anything you don't recognize.",
    ))
    return Verdict(
        state=VerdictState.RED,
        headline=headline,
        evidence=evidence,
        action=action,
        detail=f"{count} high-severity {dominant_cat or 'threat'} alert(s) in the last hour.",
        confidence=1.0,
    )


def _nid_attack_amber(dominant_cat: str, count: int) -> Verdict:
    """AMBER verdict for lower-severity suspicious (attack-shaped) activity."""
    return Verdict(
        state=VerdictState.AMBER,
        headline="Some suspicious network activity — worth a look.",
        evidence="Lower-severity threat signals fired recently.",
        action="Open the Threats tab to see what triggered it.",
        detail=f"{count} warning-level {dominant_cat or 'threat'} alert(s) in the last hour.",
    )


def _nid_benign_amber(dominant_cat: str, count: int) -> Verdict:
    """AMBER verdict for usually-benign activity (new device / unusual outbound)."""
    wording = {
        "DEVICE": (
            "A new device joined your network — worth a look.",
            "An unrecognized device appeared on the LAN.",
            "Open the Devices tab and confirm you recognize it.",
        ),
        "OUTBOUND": (
            "Unusual outgoing traffic — worth a look.",
            "A device sent more data than usual.",
            "Check which app or device is sending a lot of data.",
        ),
    }
    headline, evidence, action = wording.get(dominant_cat, (
        "Some unusual but likely-benign activity — worth a look.",
        "A low-risk alert fired recently.",
        "Open the Alerts tab for details.",
    ))
    return Verdict(
        state=VerdictState.AMBER,
        headline=headline,
        evidence=evidence,
        action=action,
        detail=f"{count} {dominant_cat or 'benign'} alert(s) in the last hour.",
    )


def _nid_green() -> Verdict:
    """GREEN verdict — no recent threat signals."""
    return Verdict(
        state=VerdictState.GREEN,
        headline="No threats detected — your network looks clean.",
        evidence="No suspicious alerts in the last hour.",
    )


def build_nid_verdict(alerts: List[Dict], now_epoch: float, *,
                      capability_note: str = "",
                      window_s: float = _NID_RECENT_WINDOW_S) -> Verdict:
    """Derive the banner :class:`Verdict` from recent alerts.

    A high-severity attack-shaped alert (MITM/SCAN/DNS) is RED and, via
    :func:`arbitrate`, outranks any benign "worth a look" — the safety rule that
    a possible attack must never be masked by reassuring noise. Benign-category
    alerts (new device / outbound) are AMBER at most, never RED on their own.

    Args:
        alerts: Alert dicts to weigh (the monitor's alert list).
        now_epoch: Current time, epoch seconds.
        capability_note: What the tool currently can't see (no admin / no
            passive capture); surfaced on the winning verdict so GREEN never
            silently means "blind".
        window_s: "Recent" window in seconds.

    Returns:
        The single arbitrated :class:`Verdict` for the banner.
    """
    s = summarize_nid_alerts(alerts, now_epoch, window_s)
    candidates: List[Verdict] = []
    if s["attack_high"]:
        candidates.append(_nid_attack_red(s["dominant_attack"], s["attack_high"]))
    elif s["attack_warn"]:
        candidates.append(_nid_attack_amber(s["dominant_attack"], s["attack_warn"]))
    if s["benign_high"] or s["benign_warn"]:
        candidates.append(
            _nid_benign_amber(s["dominant_benign"], s["benign_high"] + s["benign_warn"])
        )
    if not candidates:
        candidates.append(_nid_green())
    verdict = arbitrate(candidates)
    if capability_note:
        verdict.capability_note = capability_note
    return verdict


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
        self._alert_lock = threading.Lock()

        self.sniff_thread: Optional[threading.Thread] = None
        self.sniff_stop = threading.Event()

        self.syn_tracker: Dict[str, Dict] = {}

        self.dns_queries: Dict[str, List] = {}
        self.suspicious_processes: Set[str] = set()
        self.monitored_files: Dict[str, str] = {}
        self.file_observer = None
        self.process_baseline: Dict[str, Dict] = {}

        self.conn_trust = ConnectionTrustManager(state_path)

        # Durable threat/alert history (survives app close) — own DB file per
        # tool; see plans/2026-07-10-network-tools-audit.md.
        db_dir = os.path.dirname(self.state_path) or "."
        self.alert_store = AlertStore(os.path.join(db_dir, "nid_incidents.db"))

        # Clear any temp files left behind by an atomic write that crashed
        # mid-rename (see tools/_common/atomic_io.py).
        sweep_stale_tmp(db_dir)

        # Advanced scan rate limiter
        self._adv_scan_counter: int = 0
        self._adv_last_ts: float = 0.0

        self._load_state()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load_state(self):
        data = read_json(self.state_path, default=None)
        if not data:
            return
        self.trusted = data.get("trusted", {}) or {}
        self.known_devices = data.get("known_devices", {}) or {}
        self.baseline_gateway_ip = data.get("baseline_gateway_ip", "") or ""
        self.baseline_gateway_mac = data.get("baseline_gateway_mac", "") or ""

    def save_state(self):
        try:
            data = {
                "trusted": self.trusted,
                "known_devices": self.known_devices,
                "baseline_gateway_ip": self.baseline_gateway_ip,
                "baseline_gateway_mac": self.baseline_gateway_mac,
                "saved_at": now_ts(),
            }
            atomic_write_json(self.state_path, data)
        except (OSError, TypeError):
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

        with self._alert_lock:
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
                    self.alert_store.update_seen(a.get("_db_id"), d["_count"], d["_last_seen_ts"])
                    self._alert_last_seen[key] = now
                return

            a = make_alert(severity, category, title, details)
            a["details"]["_count"] = 1
            a["details"]["_first_seen_ts"] = a["timestamp"]
            self.alerts.append(a)
            self._alert_index[key] = len(self.alerts) - 1
            self._alert_last_seen[key] = now
            a["_db_id"] = self.alert_store.insert(a, ts_epoch=now)

            if len(self.alerts) > 1500:
                self.alerts = self.alerts[-1200:]
                self._alert_index.clear()
                self._alert_last_seen.clear()
                for i, aa in enumerate(self.alerts):
                    k = compact_alert_key(aa["category"], aa["title"], aa.get("details", {}))
                    self._alert_index[k] = i
                    self._alert_last_seen[k] = now

    def snapshot_alerts(self) -> List[Dict]:
        """Return a point-in-time copy of the alert list (thread-safe).

        Readers must iterate this snapshot, never ``self.alerts`` directly: the
        worker thread appends (and periodically rebinds) the list under
        ``_alert_lock``, so a bare iteration races with it and raises
        ``RuntimeError: list changed size during iteration`` on busy hosts.

        Returns:
            A shallow copy of the current alerts; the dicts inside are shared
            with the live list, so treat them as read-only.
        """
        with self._alert_lock:
            return list(self.alerts)

    def clear_alerts(self) -> None:
        """Clear the alert list and its dedup bookkeeping (thread-safe).

        Must be used instead of clearing ``self.alerts`` from the UI thread:
        the worker maintains the list and its index/last-seen/rate-limit maps
        together under ``_alert_lock``, so a bare ``.clear()`` from another
        thread races the worker's ``log()``.
        """
        with self._alert_lock:
            self.alerts.clear()
            self._alert_index.clear()
            self._alert_last_seen.clear()
            self._rate_limit.clear()

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
        except psutil.Error:
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
                        except psutil.Error:
                            exe_path = ""
                except psutil.Error:
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

                # Reputation check (hybrid: only for unknown/suspicious/dangerous)
                rep_checker = get_reputation_checker()
                rep_indicator = REP_UNCHECKED
                cached_rep = rep_checker.get_cached(remote_ip)
                if cached_rep:
                    rep_indicator = cached_rep.get("rep", REP_UNCHECKED)
                    trust_level = rep_checker.reputation_upgrades_trust(remote_ip, trust_level)

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
                    "rep": rep_indicator,
                    "service": svc_name,
                    "service_desc": svc_desc,
                })
            except (psutil.Error, AttributeError, ValueError, TypeError):
                continue

        trust_order = {"safe": 0, "known": 1, "unknown": 2, "suspicious": 3, "dangerous": 4}
        conns_out.sort(
            key=lambda x: (-(trust_order.get(x["trust"], 2)), x.get("process", "")),
        )
        return conns_out

    def recent_for_ip(self, ip: str, limit: int = 5) -> list[dict]:
        """Return the last ``limit`` outbound connections to ``ip``.

        Pilot stub: NetworkMonitor does not yet keep per-IP history
        (App holds a ``_conn_history`` dict but with a different key
        schema). AI triage works on the current alert alone for now;
        wire history through here when it earns its keep.
        """
        return []

    # ── Background reputation checks (hybrid auto-check) ─────────────────────

    def check_reputations_background(self, conns: List[Dict]):
        """
        Auto-check IPs classified as unknown/suspicious/dangerous.
        Runs in a background thread to avoid blocking the UI.
        Max 3 checks per cycle to stay within rate limits.
        """
        rep = get_reputation_checker()
        if not rep.has_keys:
            return

        to_check = []
        for c in conns:
            ip = c.get("remote_ip", "")
            trust = c.get("trust", "")
            if trust in ("unknown", "suspicious", "dangerous") and ip and not is_private_ip(ip):
                if rep.get_cached(ip) is None:
                    to_check.append(ip)
            if len(to_check) >= 3:
                break

        if not to_check:
            return

        def _bg():
            for ip in to_check:
                result = rep.check_ip(ip)
                if result.get("rep") in (REP_DANGEROUS, REP_SUSPICIOUS):
                    self.log("WARN", "REPUTATION",
                             f"IP {ip} flagged by reputation services",
                             {"ip": ip, "rep": result.get("rep", ""),
                              "vt_malicious": result.get("vt_malicious", 0),
                              "abuse_score": result.get("abuse_score", 0),
                              "source": result.get("source", "")})

        threading.Thread(target=_bg, daemon=True).start()

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
        except Exception:  # noqa: BLE001 - boundary: sub-detector swallow; must never crash advanced-threat scan loop
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
                except (psutil.Error, AttributeError, KeyError):
                    pass
        except psutil.Error:
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
                except (psutil.Error, AttributeError, KeyError):
                    pass
        except psutil.Error:
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
        except Exception as e:  # noqa: BLE001 - boundary: DNS detector top-level; logs error and keeps scan loop alive
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
        except Exception as e:  # noqa: BLE001 - boundary: process monitor top-level; logs error and keeps scan loop alive
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
                    except OSError:
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
                    except OSError:
                        pass
            self.file_observer.start()
            self.log("INFO", "SYSTEM", "File monitoring started", {"paths": len(critical_paths)})
        except Exception as e:  # noqa: BLE001 - boundary: watchdog setup; logs error and continues without file monitoring
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
            except Exception:  # noqa: BLE001 - boundary: scapy ARP packet handler; must never break the sniff loop
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
            except Exception:  # noqa: BLE001 - boundary: scapy TCP packet handler; must never break the sniff loop
                pass

        try:
            sniff(
                filter="arp or tcp",
                prn=handler,
                store=False,
                stop_filter=lambda _p: self.sniff_stop.is_set(),
            )
        except Exception as e:  # noqa: BLE001 - boundary: scapy sniff() raises broad set (Npcap/permission/runtime); logs and exits sniff thread
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
        for a in self.snapshot_alerts():
            try:
                ts = time.mktime(time.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S"))
            except (ValueError, KeyError, TypeError):
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
        for a in self.snapshot_alerts():
            try:
                ts = time.mktime(time.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S"))
            except (ValueError, KeyError, TypeError):
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
        self.win.geometry("580x720")
        self.win.resizable(True, True)
        self.win.minsize(520, 500)
        self.win.grab_set()

        self._build()

    def _build(self):
        c = self.conn
        trust = c.get("trust", "unknown")
        color = TRUST_COLORS.get(trust, "white")

        # Scrollable container for all content
        scroll = ctk.CTkScrollableFrame(self.win, corner_radius=0)
        scroll.pack(fill="both", expand=True, padx=0, pady=0)
        self._scroll = scroll  # exposed so _render_triage_panel can parent into it

        header = ctk.CTkFrame(scroll, fg_color=("#1e1e2e", "#1e1e2e"), corner_radius=8)
        header.pack(fill="x", padx=12, pady=(12, 4))
        ctk.CTkLabel(header, text=f"  {c.get('process', '?')}",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(side="left", pady=8, padx=4)
        ctk.CTkLabel(header, text=f"PID {c.get('pid', '?')}",
                     text_color="gray").pack(side="left", pady=8, padx=4)
        ctk.CTkLabel(header, text=trust.upper(),
                     text_color=color,
                     font=ctk.CTkFont(weight="bold")).pack(side="right", pady=8, padx=12)

        info = ctk.CTkFrame(scroll, corner_radius=8)
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

        # ── Reputation section ──────────────────────────────────────────────
        rep_frame = ctk.CTkFrame(scroll, corner_radius=8)
        rep_frame.pack(fill="x", padx=12, pady=4)

        rep_header = ctk.CTkFrame(rep_frame, fg_color="transparent")
        rep_header.pack(fill="x", padx=8, pady=(6, 2))
        ctk.CTkLabel(rep_header, text="🛡️  IP Reputation",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(side="left")

        self._rep_content = ctk.CTkFrame(rep_frame, fg_color="transparent")
        self._rep_content.pack(fill="x", padx=8, pady=(0, 6))

        remote_ip = c.get("remote_ip", "")
        rep_checker = get_reputation_checker()
        cached = rep_checker.get_cached(remote_ip)
        if cached:
            self._show_rep_results(cached)
        else:
            ctk.CTkLabel(self._rep_content, text="Not checked yet",
                         text_color="gray").pack(anchor="w")

        rep_btn_row = ctk.CTkFrame(rep_frame, fg_color="transparent")
        rep_btn_row.pack(fill="x", padx=8, pady=(0, 8))
        self._check_rep_btn = ctk.CTkButton(
            rep_btn_row, text="Check Reputation",
            command=lambda: self._check_reputation(remote_ip),
            fg_color="#5865F2", hover_color="#4752C4", width=150,
        )
        self._check_rep_btn.pack(side="left", padx=4)
        self._rep_status_lbl = ctk.CTkLabel(rep_btn_row, text="", text_color="gray")
        self._rep_status_lbl.pack(side="left", padx=8)

        if not rep_checker.has_keys:
            self._check_rep_btn.configure(state="disabled")
            self._rep_status_lbl.configure(text="No API keys configured")

        # ────────────────────────────────────────────────────────────────────
        exe_path = c.get("exe", "")
        btn_frame = ctk.CTkFrame(scroll, fg_color="transparent")
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

        # AI triage button — gated on availability.
        from tools._common import ai_triage as _ai

        ok, reason = _ai.is_available()
        triage_btn = ctk.CTkButton(
            btn_frame,
            text="🤖 Triage" if ok else f"🤖 Triage ({reason})",
            state=("normal" if ok else "disabled"),
            command=self._on_triage,
            width=130,
        )
        triage_btn.pack(side="left", padx=4)
        self._triage_btn = triage_btn
        self._triage_panel: "ctk.CTkFrame | None" = None

        ctk.CTkButton(
            scroll, text="Close",
            command=self.win.destroy, width=80,
        ).pack(pady=(4, 12))

    def _open_location(self, exe_path: str):
        try:
            subprocess.Popen(
                ["explorer", "/select,", exe_path],
                creationflags=_CREATE_NO_WINDOW,
            )
        except OSError as e:
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
            except psutil.Error as e:
                messagebox.showerror("Kill Process", str(e), parent=self.win)

    def _on_triage(self) -> None:
        """Build payload, call AI triage, render result in a side panel."""
        from tools._common import ai_triage as _ai

        payload = {
            "alert": {
                "severity": self.conn.get("severity", "INFO"),
                "category": self.conn.get("category", "outbound"),
                "title": self.conn.get("title") or "Connection detail",
                "details": dict(self.conn.get("details", {})),
            },
            "context": {
                "classification": self.conn.get("trust", "UNKNOWN"),
                "ip": self.conn.get("remote_ip", ""),
                "port": int(self.conn.get("remote_port", 0) or 0),
                "country": self.conn.get("country", ""),
                "org": self.conn.get("org", ""),
                "process_name": self.conn.get("process", ""),
                "geo": dict(self.conn.get("geo", {})),
                "reputation": dict(self.conn.get("reputation", {})),
                "recent_same_ip": list(self.mon.recent_for_ip(
                    self.conn.get("remote_ip", ""), limit=5
                )),
            },
        }

        try:
            result = _ai.triage_alert(payload)
        except _ai.BudgetExhausted:
            self._show_triage_error("AI budget exhausted — resets midnight.")
            return
        except Exception as exc:  # noqa: BLE001 — final defensive boundary
            self._show_triage_error(f"AI triage failed: {type(exc).__name__}")
            return

        self._render_triage_panel(result)

    def _show_triage_error(self, message: str) -> None:
        """Show a small error label in place of the side panel."""
        self._render_triage_panel(None, error=message)

    def _render_triage_panel(
        self, result: "_ai.TriageResult | None", error: "str | None" = None
    ) -> None:
        """Render or refresh the triage side panel inside the scrollable frame."""
        if self._triage_panel is not None:
            self._triage_panel.destroy()
        panel = ctk.CTkFrame(self._scroll)
        panel.pack(fill="x", padx=12, pady=(0, 8))
        self._triage_panel = panel

        if error:
            ctk.CTkLabel(panel, text=error, text_color="#c44").pack(anchor="w", padx=8, pady=4)
            return

        if result is None:
            raise ValueError("_render_triage_panel called with result=None and no error")

        cached = " (cached)" if result.cached else ""
        ctk.CTkLabel(
            panel,
            text=f"AI: {result.severity_human.upper()}{cached}",
            font=ctk.CTkFont(size=11, weight="bold"),
        ).pack(anchor="w", padx=8, pady=(8, 0))
        ctk.CTkLabel(panel, text=result.why_it_matters, wraplength=500, anchor="w").pack(
            anchor="w", padx=8, pady=(4, 8)
        )
        ctk.CTkLabel(
            panel,
            text=f"Suggested: {result.suggested_action} — {result.suggested_action_reason}",
            wraplength=500,
            anchor="w",
        ).pack(anchor="w", padx=8)
        ctk.CTkLabel(
            panel,
            text=f"FP likelihood: {result.false_positive_likelihood:.0%}",
            anchor="w",
        ).pack(anchor="w", padx=8, pady=(8, 0))
        if result.evidence:
            ctk.CTkLabel(panel, text="Evidence:", font=ctk.CTkFont(size=9, weight="bold"), anchor="w").pack(
                anchor="w", padx=8, pady=(8, 0)
            )
            for ev in result.evidence:
                ctk.CTkLabel(panel, text=f"• {ev}", wraplength=500, anchor="w").pack(anchor="w", padx=16)

    def _show_rep_results(self, rep: Dict):
        """Display reputation results in the popup."""
        for w in self._rep_content.winfo_children():
            w.destroy()

        indicator = rep.get("rep", REP_UNCHECKED)
        ind_color = REP_COLORS.get(indicator, "#888888")

        # Indicator badge
        badge_frame = ctk.CTkFrame(self._rep_content, fg_color="#1a2a3a", corner_radius=6)
        badge_frame.pack(fill="x", pady=(2, 4))
        ctk.CTkLabel(badge_frame, text=f"  {indicator}  ",
                     font=ctk.CTkFont(size=16, weight="bold"),
                     text_color=ind_color).pack(side="left", padx=6, pady=4)
        label_map = {REP_CLEAN: "Clean", REP_SUSPICIOUS: "Suspicious", REP_DANGEROUS: "Dangerous"}
        ctk.CTkLabel(badge_frame, text=label_map.get(indicator, "Unknown"),
                     text_color=ind_color,
                     font=ctk.CTkFont(weight="bold")).pack(side="left", pady=4)
        ctk.CTkLabel(badge_frame, text=f"  (via {rep.get('source', '?')})",
                     text_color="gray").pack(side="left", pady=4, padx=4)

        def detail_row(lbl, val, val_color="white"):
            r = ctk.CTkFrame(self._rep_content, fg_color="transparent")
            r.pack(fill="x", pady=1)
            ctk.CTkLabel(r, text=lbl, width=140, anchor="w",
                         text_color="gray").pack(side="left")
            ctk.CTkLabel(r, text=str(val), anchor="w",
                         text_color=val_color).pack(side="left", padx=4)

        # VirusTotal results
        if "vt_malicious" in rep:
            vt_mal = rep["vt_malicious"]
            vt_susp = rep.get("vt_suspicious", 0)
            vt_harm = rep.get("vt_harmless", 0)
            mal_col = "#FF4444" if vt_mal > 0 else "#90EE90"
            detail_row("VT Malicious:", f"{vt_mal}  (suspicious: {vt_susp}, harmless: {vt_harm})", mal_col)
            detail_row("VT Reputation:", rep.get("vt_reputation", "?"))

        # AbuseIPDB results
        if "abuse_score" in rep:
            score = rep["abuse_score"]
            score_col = "#FF4444" if score >= 50 else "#FFA500" if score >= 15 else "#90EE90"
            detail_row("Abuse Score:", f"{score}%  ({rep.get('abuse_reports', 0)} reports)", score_col)
            if rep.get("abuse_is_tor"):
                detail_row("Tor Node:", "YES", "#FF4444")
            if rep.get("abuse_usage"):
                detail_row("Usage Type:", rep.get("abuse_usage", ""))
            if rep.get("abuse_domain"):
                detail_row("Domain:", rep.get("abuse_domain", ""))

        if rep.get("checked_at"):
            detail_row("Checked at:", rep["checked_at"])

    def _check_reputation(self, ip: str):
        """Manual reputation check (runs in background thread, updates UI)."""
        if not ip or is_private_ip(ip):
            self._rep_status_lbl.configure(text="Private IP — no check needed")
            return

        self._check_rep_btn.configure(state="disabled")
        self._rep_status_lbl.configure(text="Checking...")

        def _bg():
            rep = get_reputation_checker()
            result = rep.check_ip(ip, force=True)

            def _update_ui():
                try:
                    if not self.win.winfo_exists():
                        return
                except (tk.TclError, AttributeError):
                    return
                self._show_rep_results(result)
                self._check_rep_btn.configure(state="normal")
                self._rep_status_lbl.configure(text="")

            try:
                self.win.after(0, _update_ui)
            except (tk.TclError, AttributeError):
                pass

        threading.Thread(target=_bg, daemon=True).start()


# ─────────────────────────────────────────────────────────────────────────────
# Main App
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# API Keys Settings dialog
# ─────────────────────────────────────────────────────────────────────────────

class APIKeySettingsDialog:
    def __init__(self, parent):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("API Key Settings")
        self.win.geometry("520x280")
        self.win.resizable(False, False)
        self.win.grab_set()

        rep = get_reputation_checker()

        ctk.CTkLabel(self.win, text="🔑  API Keys for IP Reputation",
                     font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(16, 4))
        ctk.CTkLabel(self.win, text="Keys are stored locally in tools/nid_api_keys.json",
                     text_color="gray", font=ctk.CTkFont(size=11)).pack(pady=(0, 12))

        form = ctk.CTkFrame(self.win)
        form.pack(fill="x", padx=20, pady=4)

        # VirusTotal key
        r1 = ctk.CTkFrame(form, fg_color="transparent")
        r1.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(r1, text="VirusTotal:", width=100, anchor="w",
                     font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.vt_var = tk.StringVar(value=rep._vt_key)
        ctk.CTkEntry(r1, textvariable=self.vt_var, width=340, show="*").pack(side="left", padx=4)

        # AbuseIPDB key
        r2 = ctk.CTkFrame(form, fg_color="transparent")
        r2.pack(fill="x", padx=10, pady=6)
        ctk.CTkLabel(r2, text="AbuseIPDB:", width=100, anchor="w",
                     font=ctk.CTkFont(weight="bold")).pack(side="left")
        self.abuse_var = tk.StringVar(value=rep._abuse_key)
        ctk.CTkEntry(r2, textvariable=self.abuse_var, width=340, show="*").pack(side="left", padx=4)

        # Status
        self.status_lbl = ctk.CTkLabel(self.win, text="", text_color="gray")
        self.status_lbl.pack(pady=4)

        # Buttons
        btns = ctk.CTkFrame(self.win, fg_color="transparent")
        btns.pack(pady=8)
        ctk.CTkButton(btns, text="Save", command=self._save,
                      fg_color="#3abf6d", hover_color="#2b944e", width=100).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Cancel", command=self.win.destroy, width=100).pack(side="left", padx=6)

        # Show current status
        has_vt = "✓" if rep._vt_key else "✗"
        has_ab = "✓" if rep._abuse_key else "✗"
        self.status_lbl.configure(text=f"VT key: {has_vt}  |  AbuseIPDB key: {has_ab}")

    def _save(self):
        rep = get_reputation_checker()
        rep.save_keys(self.vt_var.get(), self.abuse_var.get())
        has_vt = "✓" if rep._vt_key else "✗"
        has_ab = "✓" if rep._abuse_key else "✗"
        self.status_lbl.configure(text=f"Saved!  VT: {has_vt}  |  AbuseIPDB: {has_ab}", text_color="#90EE90")


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

        # Rolling (epoch, active_count, flagged_count) samples for the Summary
        # activity chart. One sample per UI tick; 200 caps ~10 min at the 3.5 s
        # default refresh, so the "last 5 minutes" window is always covered.
        self._activity_history: BoundedDeque = BoundedDeque(maxlen=200)

        # Connection history — accumulates all unknown/suspicious/dangerous IPs.
        # Mutated in place by the scan worker (_update_history) while the UI
        # thread iterates it (refresh_history / export); guard every access with
        # this lock so readers never see a mid-mutation dict.
        self._history_path = self.state_path.replace("nid_state.json", "nid_conn_history.json")
        self._history_lock = threading.Lock()
        self._conn_history: Dict[str, Dict] = {}   # keyed by remote_ip
        # Debounce + cap the 1.5 MB whole-file rewrite: write at most once per
        # interval, keep only the most-recently-seen entries, store compact.
        self._history_dirty = False
        self._history_last_write = 0.0
        self._HISTORY_WRITE_INTERVAL = 30.0   # seconds between disk writes
        self._HISTORY_MAX_ENTRIES = 5000      # cap, pruned by last_seen
        self._load_history()

        self._build_ui()

        threading.Thread(target=self._worker_loop, daemon=True).start()

        self.after(600, self.scan_now)
        self.after(900, self._ensure_passive)
        self.after(700, self._ui_tick)

    # ── Style helper (called ONCE) ────────────────────────────────────────────

    def _apply_tree_style(self):
        style = ttk.Style(self)
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
        style.map("Treeview",
            background=[("selected", "#1f538d")],
            foreground=[("selected", "white")])

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
        ctk.CTkButton(top, text="⚙ API Keys", command=lambda: APIKeySettingsDialog(self.parent),
                      fg_color="#565b5e", hover_color="#6e7377", width=90).pack(side="left", padx=6)

        # --- Plain-language verdict banner (the single top-line answer) ---
        self._build_verdict_banner()

        self.nb = ctk.CTkTabview(self)
        nb = self.nb
        nb.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.tab_dashboard = nb.add("Summary")
        self.tab_devices = nb.add("Devices")
        self.tab_connections = nb.add("Connections")
        self.tab_history = nb.add("History")
        self.tab_alerts = nb.add("Alerts")
        self.tab_trust = nb.add("Trust list")
        self.tab_threats = nb.add("Threats")

        self._build_dashboard()
        self._build_devices()
        self._build_connections()
        self._build_history()
        self._build_alerts()
        self._build_trust()
        self._build_threats()

        self.pack(fill="both", expand=True)

    # ── Plain-language verdict banner ─────────────────────────────────────────

    def _build_verdict_banner(self):
        """Build the top verdict banner — one colour, one line, always visible."""
        banner = ctk.CTkFrame(self, corner_radius=8)
        banner.pack(fill="x", padx=10, pady=(0, 6))
        self.verdict_banner = banner
        self._verdict_detail_visible = False

        head = ctk.CTkFrame(banner, fg_color="transparent")
        head.pack(fill="x", padx=12, pady=(8, 2))

        self.verdict_state_label = ctk.CTkLabel(
            head, text="…  Checking", font=("Segoe UI", 13, "bold"))
        self.verdict_state_label.pack(side="left")

        self.verdict_detail_btn = ctk.CTkButton(
            head, text="Why?", width=54, height=24,
            command=self._toggle_verdict_detail)
        self.verdict_detail_btn.pack(side="right")

        self.verdict_headline_label = ctk.CTkLabel(
            head, text="Checking your network…", font=("Segoe UI", 13),
            anchor="w", justify="left", wraplength=1000)
        self.verdict_headline_label.pack(side="left", padx=(12, 8))

        self.verdict_action_label = ctk.CTkLabel(
            banner, text="", font=("Segoe UI", 11),
            anchor="w", justify="left", wraplength=1180)
        self.verdict_action_label.pack(fill="x", padx=12, pady=(0, 8))

        # Detail row is packed only while toggled open.
        self.verdict_detail_label = ctk.CTkLabel(
            banner, text="", font=("Segoe UI", 10),
            anchor="w", justify="left", wraplength=1180)

    def _toggle_verdict_detail(self):
        """Show or hide the "why we think this" detail row."""
        if self._verdict_detail_visible:
            self.verdict_detail_label.pack_forget()
            self.verdict_detail_btn.configure(text="Why?")
        else:
            self.verdict_detail_label.pack(fill="x", padx=12, pady=(0, 8))
            self.verdict_detail_btn.configure(text="Hide")
        self._verdict_detail_visible = not self._verdict_detail_visible

    def _verdict_capability_note(self) -> str:
        """Describe what the detector currently can't see, for the banner.

        Passive attack detection (ARP-spoof/MITM and scan patterns) needs both
        Administrator rights and a working packet capture (Npcap + scapy). When
        either is missing, say so, so a GREEN "all clear" never over-claims.
        """
        gaps = []
        if not is_admin_windows():
            gaps.append("not running as Administrator")
        if not HAS_SCAPY:
            gaps.append("passive capture off (install Npcap + scapy)")
        if not gaps:
            return ""
        return "Limited visibility — " + "; ".join(gaps) + "."

    def _update_verdict_banner(self):
        """Repaint the banner from the current alerts (state colour + five slots)."""
        verdict = build_nid_verdict(
            self.mon.snapshot_alerts(), time.time(),
            capability_note=self._verdict_capability_note(),
        )
        color = verdict.color
        text_color = contrast_text_color(color)
        self.verdict_banner.configure(fg_color=color)

        self.verdict_state_label.configure(
            text=f"{verdict.icon}  {verdict.short_label}", text_color=text_color)
        self.verdict_headline_label.configure(
            text=verdict.headline, text_color=text_color)

        action = verdict.action
        if verdict.capability_note:
            note = f"Note: {verdict.capability_note}"
            action = f"{action}    {note}" if action else note
        self.verdict_action_label.configure(text=action, text_color=text_color)

        detail_bits = [b for b in (verdict.evidence, verdict.detail) if b]
        self.verdict_detail_label.configure(
            text="\n".join(detail_bits), text_color=text_color)

    # ── Dashboard tab ─────────────────────────────────────────────────────────

    # Plain label first; the technical term rides underneath so a non-technical
    # reader isn't met with jargon. Keys drive _update_dashboard / _paint_card.
    _DASH_CARDS = [
        ("Devices", "on your network", "devices"),
        ("New devices", "not on trust list", "new_devices"),
        ("Router check", "gateway identity", "gateway"),
        ("Connections", "active now", "connections"),
        ("Flagged", "suspicious or dangerous", "flagged"),
        ("Recent alerts", "last hour", "alerts"),
    ]

    def _build_dashboard(self):
        scroll = ctk.CTkScrollableFrame(self.tab_dashboard)
        scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # --- Metric cards (6, spacious 3x2 grid; mirrors the NSM Overview) ---
        grid = ctk.CTkFrame(scroll, fg_color="transparent")
        grid.pack(fill="x", padx=5, pady=(5, 4))

        self.dash_values: Dict[str, ctk.CTkLabel] = {}
        self.dash_pills: Dict[str, ctk.CTkLabel] = {}
        for i, (title, sub, key) in enumerate(self._DASH_CARDS):
            r, c = divmod(i, 3)
            card = ctk.CTkFrame(grid, fg_color=ui_theme.SURFACE, corner_radius=10,
                                border_width=1, border_color=ui_theme.BORDER)
            card.grid(row=r, column=c, padx=6, pady=6, sticky="nsew")
            grid.columnconfigure(c, weight=1)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 0))
            names = ctk.CTkFrame(top, fg_color="transparent")
            names.pack(side="left", anchor="w")
            ctk.CTkLabel(names, text=title, anchor="w", text_color=ui_theme.TEXT,
                         font=(ui_theme.FONT_FAMILY, 13, "bold")).pack(anchor="w")
            ctk.CTkLabel(names, text=sub, anchor="w", text_color=ui_theme.TEXT_FAINT,
                         font=(ui_theme.FONT_FAMILY, 9)).pack(anchor="w")
            pill = ctk.CTkLabel(top, text="", width=110, corner_radius=8,
                                fg_color=ui_theme.SURFACE_ALT,
                                text_color=ui_theme.TEXT_FAINT,
                                font=(ui_theme.FONT_FAMILY, 10, "bold"))
            pill.pack(side="right", anchor="e")
            self.dash_pills[key] = pill

            val_lbl = ctk.CTkLabel(card, text="--", anchor="w",
                                   text_color=ui_theme.TEXT_MUTED,
                                   font=(ui_theme.FONT_FAMILY, 26, "bold"))
            val_lbl.pack(anchor="w", padx=12, pady=(2, 12))
            self.dash_values[key] = val_lbl

        # --- Activity chart (last 5 minutes) ---
        chart_frame = ctk.CTkFrame(scroll)
        chart_frame.pack(fill="x", padx=5, pady=(2, 4))
        ctk.CTkLabel(chart_frame, text="Activity — Last 5 Minutes",
                     font=(ui_theme.FONT_FAMILY, 10, "bold"),
                     text_color=ui_theme.TEXT_MUTED).pack(anchor="w", padx=10, pady=(4, 0))
        self.activity_canvas = tk.Canvas(chart_frame, height=170,
                                         bg=ui_theme.SURFACE_ALT, highlightthickness=0)
        self.activity_canvas.pack(fill="x", padx=8, pady=(2, 6))

        # --- Compact status strip (what the detector can/can't see right now) ---
        info_frame = ctk.CTkFrame(scroll)
        info_frame.pack(fill="x", padx=5, pady=(2, 8))
        self.dash_info = ctk.CTkLabel(info_frame, text="", anchor="w", justify="left",
                                      text_color=ui_theme.TEXT_MUTED,
                                      font=(ui_theme.FONT_FAMILY, 10))
        self.dash_info.pack(anchor="w", padx=10, pady=6)

        self._update_dashboard()

    def _paint_card(self, key: str, value_text: str, state: VerdictState) -> None:
        """Paint one Summary card from a single verdict state.

        Sets the big value's colour and the status pill's word + fill, so the
        card shows its state as colour AND text (never colour alone) and reads
        from the one shared palette the plain-language banner uses.

        Args:
            key: Dashboard card key (e.g. ``"flagged"``).
            value_text: The value string to display (e.g. ``"2"``).
            state: The metric's verdict state.
        """
        style = ui_theme.status_style(state)
        self.dash_values[key].configure(text=value_text, text_color=style.text)
        self.dash_pills[key].configure(
            text=f"{style.icon} {ui_theme.card_word(state)}",
            fg_color=style.fill, text_color=style.ink)

    @staticmethod
    def _threat_status(level: str) -> VerdictState:
        """Threat level string -> verdict state (LOW green, MEDIUM amber, HIGH/CRITICAL red)."""
        return {
            "LOW": VerdictState.GREEN,
            "MEDIUM": VerdictState.AMBER,
            "HIGH": VerdictState.RED,
            "CRITICAL": VerdictState.RED,
        }.get(level, VerdictState.GRAY)

    @staticmethod
    def _flagged_status(suspicious: int, dangerous: int) -> VerdictState:
        """Flagged-connection counts -> verdict state (dangerous red, suspicious amber, else green)."""
        if dangerous > 0:
            return VerdictState.RED
        if suspicious > 0:
            return VerdictState.AMBER
        return VerdictState.GREEN

    @staticmethod
    def _new_devices_status(untrusted: int) -> VerdictState:
        """Untrusted-device count -> verdict state (0 green, otherwise amber)."""
        return VerdictState.AMBER if untrusted > 0 else VerdictState.GREEN

    def _gateway_status(self) -> Tuple[VerdictState, str]:
        """Gateway identity vs baseline -> (state, value word).

        No baseline yet is GRAY "Not set"; a live gateway MAC that differs from
        the baseline is RED "Changed" (possible MITM); anything else is GREEN
        "OK". A missing live MAC (no passive capture) never fabricates "Changed".
        """
        base = self.mon.baseline_gateway_mac
        if not base:
            return VerdictState.GRAY, "Not set"
        current = self.mon.last_arp.get(self.gateway.get(), "")
        if current and current != base:
            return VerdictState.RED, "Changed"
        return VerdictState.GREEN, "OK"

    def _sample_activity(self) -> None:
        """Record one (epoch, active, flagged) point for the activity chart."""
        conns = self._last_conns
        active = len(conns)
        flagged = sum(1 for c in conns if c.get("trust") in ("suspicious", "dangerous"))
        self._activity_history.append((time.time(), active, flagged))

    def _dashboard_info_text(self) -> str:
        """One compact block: capabilities, gateway baseline, reputation keys."""
        rep = get_reputation_checker()
        caps = (f"scapy {'on' if HAS_SCAPY else 'off'}   ·   "
                f"admin {'yes' if is_admin_windows() else 'no'}   ·   "
                f"active scan {'on' if self.active_scan.get() else 'off'}   ·   "
                f"passive sniff {'on' if self.passive_scan.get() else 'off'}")
        base = self.mon.baseline_gateway_mac or "(not set)"
        reput = (f"VirusTotal {'on' if rep._vt_key else 'off'}   ·   "
                 f"AbuseIPDB {'on' if rep._abuse_key else 'off'}   ·   "
                 f"{len(rep._cache)} IPs checked this session")
        last = self._last_scan_ts or "(pending)"
        return (f"Watching:   {caps}\n"
                f"Gateway baseline:   {base}\n"
                f"Reputation:   {reput}\n"
                f"Last scan:   {last}")

    def _update_dashboard(self) -> None:
        """Repaint the six Summary cards, the info strip and the activity chart."""
        known = self.mon.known_devices or {}
        trusted = self.mon.trusted or {}
        conns = self._last_conns
        scanned = bool(self._last_scan_ts)

        dev_count = len(known)
        untrusted = sum(1 for mac in known if mac not in trusted)
        active = len(conns)
        susp = sum(1 for c in conns if c.get("trust") == "suspicious")
        dang = sum(1 for c in conns if c.get("trust") == "dangerous")

        # Devices — informational; grey until something is seen.
        self._paint_card("devices", str(dev_count) if dev_count else "—",
                         VerdictState.GREEN if dev_count else VerdictState.GRAY)
        # New devices — on the LAN but not on the trust list.
        if dev_count:
            self._paint_card("new_devices", str(untrusted),
                             self._new_devices_status(untrusted))
        else:
            self._paint_card("new_devices", "—", VerdictState.GRAY)
        # Router check — gateway identity vs baseline (MITM guard).
        gw_state, gw_text = self._gateway_status()
        self._paint_card("gateway", gw_text, gw_state)
        # Connections — active outbound sockets right now.
        self._paint_card("connections", str(active) if scanned else "—",
                         VerdictState.GREEN if scanned else VerdictState.GRAY)
        # Flagged — suspicious/dangerous outbound.
        self._paint_card("flagged", str(susp + dang) if scanned else "—",
                         self._flagged_status(susp, dang) if scanned else VerdictState.GRAY)
        # Recent alerts — HIGH/WARN in the last hour, coloured by threat level.
        recent_alerts = len(self.mon.get_active_threats())
        self._paint_card("alerts", str(recent_alerts),
                         self._threat_status(self.mon.compute_threat_level()))

        self.dash_info.configure(text=self._dashboard_info_text())
        self._draw_activity_chart()

    def _draw_activity_chart(self) -> None:
        """Redraw the activity chart with the last 5 minutes of samples."""
        canvas = self.activity_canvas
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 100 or h < 40:
            return
        cutoff = time.time() - 300
        recent = [row for row in self._activity_history.snapshot() if row[0] >= cutoff]
        series = [
            {"label": "Active", "axis": "left",
             "color": ui_theme.status_style(VerdictState.BLUE).text,
             "points": [(t, a) for (t, a, _f) in recent]},
            {"label": "Flagged", "axis": "left",
             "color": ui_theme.status_style(VerdictState.AMBER).text,
             "points": [(t, f) for (t, _a, f) in recent]},
        ]
        ui_theme.draw_line_chart(canvas, series, w, h, left_unit="")

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
        cols = ("trust", "rep", "process", "service", "laddr", "raddr", "country", "org", "status")
        self.conn_tree = ttk.Treeview(f, columns=cols, show="headings", height=26)
        headings = {
            "trust": "TRUST", "rep": "REP", "process": "PROCESS", "service": "SERVICE",
            "laddr": "LOCAL", "raddr": "REMOTE",
            "country": "COUNTRY", "org": "ORGANIZATION", "status": "STATUS",
        }
        widths = {
            "trust": 90, "rep": 40, "process": 140, "service": 110,
            "laddr": 130, "raddr": 130,
            "country": 90, "org": 170, "status": 90,
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
        conn_combo = ttk.Combobox(
            filter_frame, textvariable=self.conn_filter, width=18,
            values=("ALL", "SAFE", "KNOWN", "UNKNOWN", "SUSPICIOUS", "DANGEROUS"),
            state="readonly",
        )
        conn_combo.pack(side="left", padx=6)
        conn_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_connections())
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
        except (ValueError, IndexError):
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

    # ── History tab ───────────────────────────────────────────────────────────

    def _build_history(self):
        f = self.tab_history

        info = ctk.CTkLabel(
            f, text="All unknown / suspicious / dangerous connections ever seen (persisted across sessions)",
            text_color="gray", font=ctk.CTkFont(size=12))
        info.pack(anchor="w", padx=10, pady=(8, 2))

        cols = ("trust", "rep", "remote_ip", "process", "service", "raddr",
                "country", "org", "first_seen", "last_seen", "times_seen")
        self.hist_tree = ttk.Treeview(f, columns=cols, show="headings", height=24)
        headings = {
            "trust": "TRUST", "rep": "REP", "remote_ip": "REMOTE IP",
            "process": "PROCESS", "service": "SERVICE", "raddr": "REMOTE ADDR",
            "country": "COUNTRY", "org": "ORGANIZATION",
            "first_seen": "FIRST SEEN", "last_seen": "LAST SEEN", "times_seen": "#",
        }
        widths = {
            "trust": 90, "rep": 40, "remote_ip": 130, "process": 120,
            "service": 90, "raddr": 140, "country": 80, "org": 160,
            "first_seen": 140, "last_seen": 140, "times_seen": 40,
        }
        for c in cols:
            self.hist_tree.heading(c, text=headings[c])
            self.hist_tree.column(c, width=widths[c], stretch=(c in ("org", "process")))
        self.hist_tree.pack(fill="both", expand=True, padx=8, pady=(2, 4))

        self.hist_tree.bind("<Double-1>", self._on_hist_double_click)

        # Filter + buttons
        bar = ctk.CTkFrame(f)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkLabel(bar, text="Filter:").pack(side="left", padx=(0, 6))
        self.hist_filter = tk.StringVar(value="ALL")
        hist_combo = ttk.Combobox(
            bar, textvariable=self.hist_filter, width=18,
            values=("ALL", "UNKNOWN", "SUSPICIOUS", "DANGEROUS"),
            state="readonly",
        )
        hist_combo.pack(side="left", padx=6)
        hist_combo.bind("<<ComboboxSelected>>", lambda _e: self.refresh_history())
        ctk.CTkButton(bar, text="Refresh", command=self.refresh_history, width=80).pack(side="left", padx=6)
        ctk.CTkButton(bar, text="Clear All", command=self._clear_history, width=80,
                      fg_color="#bf3a3a", hover_color="#942b2b").pack(side="right", padx=6)

    def _on_hist_double_click(self, event):
        sel = self.hist_tree.selection()
        if not sel:
            return
        iid = sel[0]
        ip = self.hist_tree.set(iid, "remote_ip")
        # Find matching entry in history and build a fake conn dict for the detail popup
        with self._history_lock:
            entry = self._conn_history.get(ip)
        if not entry:
            return
        conn_data = {
            "remote_ip": ip,
            "remote_port": entry.get("remote_port", 0),
            "trust": entry.get("trust", "unknown"),
            "rep": entry.get("rep", ""),
            "process": entry.get("process", "?"),
            "exe": entry.get("exe", ""),
            "service": entry.get("service", ""),
            "service_desc": entry.get("service_desc", ""),
            "laddr": entry.get("laddr", ""),
            "raddr": entry.get("raddr", ""),
            "country": entry.get("country", ""),
            "org": entry.get("org", ""),
            "status": entry.get("status", ""),
            "pid": 0,
        }
        ConnectionDetailPopup(self.parent, conn_data, self.mon, self.refresh_connections)

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
        self.alert_tree.bind("<Button-3>", self._on_alert_tree_right_click)

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

        # ── Trusted Devices (MAC) ──
        ctk.CTkLabel(f, text="Trusted Devices (MAC)",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(8, 2))
        cols = ("mac", "label", "first_seen")
        self.trust_tree = ttk.Treeview(f, columns=cols, show="headings", height=10)
        for c in cols:
            self.trust_tree.heading(c, text=c.upper())
            w = 280 if c == "label" else 220
            self.trust_tree.column(c, width=w, stretch=True)
        self.trust_tree.pack(fill="both", expand=True, padx=8, pady=(2, 4))

        row = ctk.CTkFrame(f)
        row.pack(fill="x", padx=8, pady=(0, 6))
        ctk.CTkButton(row, text="Remove selected", command=self.remove_trust_selected).pack(side="left", padx=6)

        # ── Trusted IPs (connections) ──
        ctk.CTkLabel(f, text="Trusted IPs (Connections)",
                     font=ctk.CTkFont(size=13, weight="bold")).pack(anchor="w", padx=10, pady=(6, 2))
        ip_cols = ("ip", "label", "first_seen", "notes")
        self.trust_ip_tree = ttk.Treeview(f, columns=ip_cols, show="headings", height=10)
        for c in ip_cols:
            self.trust_ip_tree.heading(c, text=c.upper())
            w = 300 if c == "notes" else 200 if c == "label" else 160
            self.trust_ip_tree.column(c, width=w, stretch=(c == "notes"))
        self.trust_ip_tree.pack(fill="both", expand=True, padx=8, pady=(2, 4))

        row2 = ctk.CTkFrame(f)
        row2.pack(fill="x", padx=8, pady=(0, 8))
        ctk.CTkButton(row2, text="Remove selected IP", command=self._remove_trust_ip_selected).pack(side="left", padx=6)
        ctk.CTkButton(row2, text="Refresh", command=self.refresh_trust).pack(side="right", padx=6)

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
        except queue.Full:
            pass

    def force_stop(self):
        self.running = False
        self.mon.stop_passive_sniff()
        # Flush any history changes deferred by the write debounce.
        self._flush_history()
        try:
            self.parent.destroy()
        except tk.TclError:
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
            "alerts": self.mon.snapshot_alerts(),
            "connections_snapshot": self._last_conns,
            "threat_level": self.mon.compute_threat_level(),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export", f"Saved:\n{path}")
        except (OSError, TypeError) as e:
            messagebox.showerror("Export failed", str(e))

    # ── Connection History persistence ──────────────────────────────────────

    def _load_history(self):
        data = read_json(self._history_path, default={}) or {}
        with self._history_lock:
            self._conn_history = data

    def _save_history(self):
        # Prune to the most-recently-seen entries and copy under the lock, then
        # write compact JSON outside it: slow disk I/O must never block the
        # scan worker's in-memory history updates.
        with self._history_lock:
            if len(self._conn_history) > self._HISTORY_MAX_ENTRIES:
                kept = sorted(
                    self._conn_history.items(),
                    key=lambda kv: kv[1].get("last_seen", ""),
                    reverse=True,
                )[: self._HISTORY_MAX_ENTRIES]
                self._conn_history = dict(kept)
            data = dict(self._conn_history)
        try:
            atomic_write_json(self._history_path, data, indent=None)
            self._history_last_write = time.time()
            self._history_dirty = False
        except (OSError, TypeError):
            pass

    def _save_history_debounced(self):
        """Persist history at most once per ``_HISTORY_WRITE_INTERVAL``.

        The scan worker calls this every scan; without the debounce it rewrites
        the whole (up to ~1.5 MB) file many times a minute. Changes inside the
        window are marked dirty and flushed by the next past-window call, by
        :meth:`_clear_history`, or by :meth:`_flush_history` on close.
        """
        if (time.time() - self._history_last_write) >= self._HISTORY_WRITE_INTERVAL:
            self._save_history()
        else:
            self._history_dirty = True

    def _flush_history(self):
        """Force-write any pending (debounced) history changes."""
        if self._history_dirty:
            self._save_history()

    def _update_history(self, conns: List[Dict]):
        """Add unknown/suspicious/dangerous connections to persistent history."""
        dominated = {"unknown", "suspicious", "dangerous"}
        changed = False
        # Hold the lock for the whole in-memory pass (no I/O here) so a
        # concurrent refresh_history never iterates a mid-mutation dict.
        with self._history_lock:
            for c in conns:
                trust = c.get("trust", "unknown")
                if trust not in dominated:
                    continue
                ip = c.get("remote_ip", "")
                if not ip:
                    continue
                if ip in self._conn_history:
                    entry = self._conn_history[ip]
                    entry["last_seen"] = now_ts()
                    entry["times_seen"] = entry.get("times_seen", 1) + 1
                    # upgrade severity level if worse
                    order = {"unknown": 0, "suspicious": 1, "dangerous": 2}
                    if order.get(trust, 0) > order.get(entry.get("trust", "unknown"), 0):
                        entry["trust"] = trust
                    # update other fields
                    entry["process"] = c.get("process", entry.get("process", "?"))
                    entry["service"] = c.get("service", entry.get("service", ""))
                    entry["country"] = c.get("country", entry.get("country", ""))
                    entry["org"] = c.get("org", entry.get("org", ""))
                    entry["rep"] = c.get("rep", entry.get("rep", ""))
                    entry["raddr"] = c.get("raddr", entry.get("raddr", ""))
                    entry["laddr"] = c.get("laddr", entry.get("laddr", ""))
                    entry["status"] = c.get("status", entry.get("status", ""))
                    changed = True
                else:
                    self._conn_history[ip] = {
                        "remote_ip": ip,
                        "trust": trust,
                        "process": c.get("process", "?"),
                        "service": c.get("service", ""),
                        "laddr": c.get("laddr", ""),
                        "raddr": c.get("raddr", ""),
                        "country": c.get("country", ""),
                        "org": c.get("org", ""),
                        "rep": c.get("rep", ""),
                        "status": c.get("status", ""),
                        "first_seen": now_ts(),
                        "last_seen": now_ts(),
                        "times_seen": 1,
                        "remote_port": c.get("remote_port", 0),
                        "exe": c.get("exe", ""),
                    }
                    changed = True
        if changed:
            self._save_history_debounced()

    def _clear_history(self):
        if not messagebox.askyesno("Clear History",
                                   "Delete all connection history entries?",
                                   parent=self.parent):
            return
        with self._history_lock:
            self._conn_history.clear()
        self._save_history()
        self.refresh_history()

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
        self._update_dashboard()

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

    def _remove_trust_ip_selected(self):
        sel = self.trust_ip_tree.selection()
        if not sel:
            return
        iid = sel[0]
        ip = self.trust_ip_tree.set(iid, "ip")
        self.mon.conn_trust.untrust_ip(ip)
        self.mon.log("INFO", "CONNECTION", "Trusted IP removed", {"ip": ip})
        self.refresh_trust()

    def clear_alerts(self):
        self.mon.clear_alerts()
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
        except (ValueError, IndexError):
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
        except (ValueError, IndexError):
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
        except (ValueError, TypeError):
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
            except psutil.Error as e:
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

                    # Accumulate unknown/suspicious/dangerous to persistent history
                    self._update_history(conns)

                    if len(conns) > 80:
                        self.mon.log("INFO", "OUTBOUND", "High number of active connections",
                                     {"count": len(conns)})

                    # Advanced threat scans (rate-limited internally)
                    self.mon._detect_advanced_threats(conns)

                    # Background reputation checks (hybrid: unknown/suspicious/dangerous)
                    self.mon.check_reputations_background(conns)

                except Exception as e:  # noqa: BLE001 - boundary: scan worker top-level; logs error and keeps daemon thread alive
                    self.mon.log("WARN", "SYSTEM", "Scan error", {"error": str(e)})

    def _ensure_passive(self):
        if self.passive_scan.get():
            self.mon.start_passive_sniff()

    def _ui_tick(self):
        if self.running:
            self.scan_now()
        self._sample_activity()
        self.refresh_all()
        try:
            interval = max(1000, int(self.refresh_ms.get()))
        except ValueError:
            interval = 3500
        self.after(interval, self._ui_tick)

    # ─────────────────────────────────────────────────────────────────────────
    # View refresh
    # ─────────────────────────────────────────────────────────────────────────

    def refresh_all(self, force: bool = False):
        # Always refresh the top verdict banner and the summary dashboard
        self._update_verdict_banner()
        self._update_dashboard()

        if force:
            self.refresh_devices()
            self.refresh_connections()
            self.refresh_history()
            self.refresh_alerts()
            self.refresh_trust()
            self.refresh_threats()
            return

        # Only refresh the currently visible tab for performance
        active = self.nb.get()
        if active == "Devices":
            self.refresh_devices()
        elif active == "Connections":
            self.refresh_connections()
        elif active == "History":
            self.refresh_history()
        elif active == "Alerts":
            self.refresh_alerts()
        elif active == "Trust list":
            self.refresh_trust()
        elif active == "Threats":
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
            rep = c.get("rep", REP_UNCHECKED)
            self.conn_tree.insert(
                "", "end", iid=iid,
                values=(
                    trust.upper(),
                    rep,
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
        recent = list(reversed(self.mon.snapshot_alerts()[-800:]))
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
        except (ValueError, IndexError):
            return
        recent = list(reversed(self.mon.snapshot_alerts()[-800:]))
        filtered = [a for a in recent if self.alert_passes_filter(a)]
        if idx < 0 or idx >= len(filtered):
            return
        text = json.dumps(filtered[idx], indent=2, ensure_ascii=False)
        self.alert_details.configure(state="normal")
        self.alert_details.delete("1.0", "end")
        self.alert_details.insert("1.0", text)
        self.alert_details.configure(state="disabled")

    def refresh_history(self):
        for i in self.hist_tree.get_children():
            self.hist_tree.delete(i)
        filt = self.hist_filter.get().lower()
        trust_order = {"dangerous": 0, "suspicious": 1, "unknown": 2}
        with self._history_lock:
            hist_values = list(self._conn_history.values())
        entries = sorted(
            hist_values,
            key=lambda e: (trust_order.get(e.get("trust", "unknown"), 2), e.get("last_seen", "")),
        )
        for idx, e in enumerate(entries):
            trust = e.get("trust", "unknown")
            if filt != "all" and trust != filt:
                continue
            org = e.get("org", "")
            if len(org) > 35:
                org = org[:32] + "..."
            iid = f"h-{idx}"
            self.hist_tree.insert(
                "", "end", iid=iid,
                values=(
                    trust.upper(),
                    e.get("rep", ""),
                    e.get("remote_ip", ""),
                    e.get("process", "?"),
                    e.get("service", ""),
                    e.get("raddr", ""),
                    e.get("country", ""),
                    org,
                    e.get("first_seen", ""),
                    e.get("last_seen", ""),
                    e.get("times_seen", 1),
                ),
                tags=(trust,),
            )
            self.hist_tree.tag_configure(trust, foreground=TRUST_COLORS.get(trust, "white"))

    def refresh_trust(self):
        # Device trust (MAC)
        for i in self.trust_tree.get_children():
            self.trust_tree.delete(i)
        for mac, info in sorted(self.mon.trusted.items()):
            self.trust_tree.insert("", "end", iid=f"t-{mac}",
                                   values=(mac, info.get("label", ""), info.get("first_seen", "")))
        # Connection trust (IP)
        for i in self.trust_ip_tree.get_children():
            self.trust_ip_tree.delete(i)
        for ip, info in sorted(self.mon.conn_trust.trusted_ips.items()):
            self.trust_ip_tree.insert("", "end", iid=f"tip-{ip}",
                                      values=(ip, info.get("label", ""),
                                              info.get("first_seen", ""),
                                              info.get("notes", "")))

    def refresh_threats(self):
        for i in self.threat_tree.get_children():
            self.threat_tree.delete(i)

        level = self.mon.compute_threat_level()
        color = THREAT_LEVEL_COLORS.get(level, "white")
        self.threat_level_label.configure(text=level, text_color=color)

        susp = sum(1 for c in self._last_conns if c.get("trust") in ("suspicious", "dangerous"))
        high_alerts = sum(1 for a in self.mon.snapshot_alerts()[-200:] if a.get("severity") == "HIGH")
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

    # ── Alert-tree right-click context menu ───────────────────────────────────

    def _on_alert_tree_right_click(self, event: tk.Event) -> None:
        """Show context menu on right-click over the alerts table."""
        iid = self.alert_tree.identify_row(event.y)
        if iid:
            self.alert_tree.selection_set(iid)

        from tools._common import ai_triage as _ai
        ok, _ = _ai.is_available()

        menu = tk.Menu(self, tearoff=0)
        menu.add_command(
            label="🤖 Triage this alert",
            command=self._on_triage_selected_alert,
            state=("normal" if ok else "disabled"),
        )
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _on_triage_selected_alert(self) -> None:
        """Triage the alert under the right-click cursor."""
        from tools._common import ai_triage as _ai

        selection = self.alert_tree.selection()
        if not selection:
            return
        alert = self._alert_for_tree_item(selection[0])
        if alert is None:
            return

        details = alert.get("details", {})
        payload = {
            "alert": {
                "severity": alert.get("severity", "INFO"),
                "category": alert.get("category", ""),
                "title": alert.get("title", ""),
                "details": dict(details),
            },
            "context": {
                "ip": (
                    details.get("ip", "")
                    or details.get("remote_ip", "")
                    or details.get("gateway_ip", "")
                    or details.get("raddr", "")
                ),
                "port": int(details.get("port", details.get("remote_port", 0)) or 0),
                "country": details.get("country", ""),
                "process_name": details.get("process", details.get("process_name", "")),
            },
        }

        try:
            result = _ai.triage_alert(payload)
        except _ai.BudgetExhausted:
            messagebox.showwarning("AI Triage", "Daily token budget exhausted.")
            return
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("AI Triage", f"Failed: {type(exc).__name__}")
            return

        self._show_triage_dialog(alert, result)

    def _alert_for_tree_item(self, item_id: str) -> "dict | None":
        """Look up the alert dict whose tree-row id is ``item_id``.

        Mirrors the index logic in ``show_alert_details``: the tree is
        populated from a filtered slice of ``self.mon.alerts`` (reversed,
        last 800), so we recover the alert by extracting the filtered index
        from the iid (format ``"a-<idx>"``).
        """
        try:
            idx = int(item_id.split("-")[1])
        except (ValueError, IndexError):
            return None
        recent = list(reversed(self.mon.snapshot_alerts()[-800:]))
        filtered = [a for a in recent if self.alert_passes_filter(a)]
        if 0 <= idx < len(filtered):
            return filtered[idx]
        return None

    def _show_triage_dialog(self, alert: dict, result: "_ai.TriageResult") -> None:
        """Render the triage result in a small CTkToplevel dialog."""
        dlg = ctk.CTkToplevel(self.parent)
        dlg.title(f"AI Triage — {alert.get('title', '')}")
        dlg.geometry("480x280")
        dlg.resizable(False, False)
        dlg.attributes("-topmost", True)
        dlg.after(100, lambda: dlg.attributes("-topmost", False))
        dlg.after(100, dlg.focus_set)

        cached_suffix = " (cached)" if result.cached else ""
        ctk.CTkLabel(
            dlg,
            text=f"{result.severity_human.upper()}{cached_suffix}",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(anchor="w", padx=14, pady=(14, 4))
        ctk.CTkLabel(
            dlg, text=result.why_it_matters, wraplength=440, anchor="w"
        ).pack(anchor="w", padx=14, pady=4)
        ctk.CTkLabel(
            dlg,
            text=f"Action: {result.suggested_action} — {result.suggested_action_reason}",
            wraplength=440,
            anchor="w",
        ).pack(anchor="w", padx=14, pady=4)
        ctk.CTkLabel(
            dlg,
            text=f"FP likelihood: {result.false_positive_likelihood:.0%}",
            anchor="w",
        ).pack(anchor="w", padx=14, pady=(4, 0))
        ctk.CTkButton(dlg, text="Close", command=dlg.destroy, width=80).pack(
            pady=(12, 14)
        )


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
    except Exception as e:  # noqa: BLE001 - boundary: tool entry point; surfaces any startup failure to the user via dialog
        try:
            messagebox.showerror("Network Intrusion Detector Pro", f"Startup error:\n{e}")
        except tk.TclError:
            pass


if __name__ == "__main__":
    run_tool()
