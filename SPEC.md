# Python Automations Toolbox — Project Specification

## Overview

A modular Windows desktop automation toolbox built with Python and CustomTkinter. Tools are self-contained `.py` files that are auto-discovered and launched from a central GUI. Dual deployment: integrated toolbox launcher + portable standalone executables.

**Author:** D3vCrow
**Platform:** Windows 10/11
**Python:** 3.11.1
**GUI Framework:** CustomTkinter 5.2.2 (dark theme)

---

## Architecture

```
Automations/
  Main.py              — Toolbox launcher (grid layout, search, favorites)
  tools/               — All tool modules (auto-discovered)
  tools/archived/      — Deprecated tools (not loaded)
  portable/            — Standalone launchers, build specs, EXEs
  portable/build/      — PyInstaller spec files
  portable/dist/       — Built executables
  venv/                — Python virtual environment
  exports/             — JSON reports from monitoring tools
```

### Tool Module Convention

Every tool in `tools/` must expose:
- `TOOL_NAME: str` — Display name in the launcher
- `run_tool()` — Entry point (creates a CTkToplevel window)
- `TOOL_DESCRIPTION: str` (optional) — Tooltip text

### Launcher (Main.py)

- Scans `tools/` for `*.py` files using `importlib`
- Dynamic grid layout (1-4 columns based on window width)
- Search with 300ms debounce, favorites persistence (`favorites.json`)
- Single-instance enforcement — re-clicking focuses existing window
- System stats sidebar (CPU/RAM via psutil)
- Keyboard shortcuts: Ctrl+F (search), Enter (launch first match)

---

## Tools (10 Active)

### Network & Security (5 tools)

| Tool | File | Lines | Purpose |
|------|------|-------|---------|
| Network Stability Monitor Pro | `network_stability_monitor.py` | 3,080 | Live network health monitoring with latency tracking, incident timeline, Wi-Fi analyzer, diagnostics |
| Network Intrusion Detector Pro | `network_intrusion_detector_pro.py` | 3,063 | LAN device discovery, connection classification (5 levels), threat detection (Flipper Zero, Tor, audio spying), firewall blocking |
| Security Audit | `security_audit.py` | 1,836 | One-shot system security scan: startup items, processes, ports, filesystem, DNS, accounts, certificates, event logs |
| Account Activity Monitor | `account_activity_monitor.py` | 2,362 | Windows Event Log monitor: account changes, logon activity, device events, system changes, spy check (camera/mic access, remote tools) |
| Network Pattern Analyzer | `network_pattern_analyzer.py` | 433 | Network traffic pattern analysis |

### System (3 tools)

| Tool | File | Lines | Purpose |
|------|------|-------|---------|
| System Health Monitor | `system_health_monitor.py` | 1,534 | Real-time CPU/RAM/disk/GPU monitoring, process manager, disk analysis, startup management, alerts |
| System Cleaner Pro | `system_cleaner.py` | 1,197 | RAM/disk cleanup utility |
| Folder Size Analyzer Pro | `folder_size_analyzer.py` | 603 | Disk usage visualization |

### Media & Utility (2 tools)

| Tool | File | Lines | Purpose |
|------|------|-------|---------|
| FFmpeg Studio | `ffmpeg_studio.py` | 1,716 | Video recording (GPU encoder auto-detection), screen capture with visual area selector, web-friendly conversion with platform presets |
| Screen Lock (Kid-Safe) | `screen_lock.py` | 683 | Transparent overlay lock with opacity slider, Ctrl+Alt+U unlock |

**Total:** 16,507 lines across 10 tools

---

## Key Technical Details

### Network Stability Monitor Pro
- Polls gateway + 2 internet targets + DNS every 2-5 seconds (dynamic interval)
- 5-minute live chart (CPU-style line graph on tk.Canvas)
- Incident tracking with normalized deduplication (latency/DNS/gateway grouped)
- Wi-Fi Analyzer tab: forces active scan via WlanScan API (ctypes), channel scoring algorithm (1/6/11), visual channel map, interference detection
- BSSID change detection (evil twin attack)
- Signal quality tracking with correlation to incidents
- Auto-export at configurable time
- Event log with category filters (Link, Gateway, ISP, DNS, Degraded, Config, Security)

### Network Intrusion Detector Pro
- 5-level connection classification: SAFE / KNOWN / UNKNOWN / SUSPICIOUS / DANGEROUS
- LAN device discovery: ARP scan (scapy) + ping sweep fallback
- Passive sniffing: ARP spoof/MITM detection (requires Npcap + admin)
- SERVICE column: resolves ports to human names (~50 entries)
- ConnectionDetailPopup: double-click for full details + Open Location / Block IP / Trust IP / Kill Process
- Advanced threat detection (~30s intervals): Flipper Zero (WMI PnP), Tor activity, audio spying
- Threats tab: gauge (LOW→CRITICAL), active threats, Kill/Block/Investigate buttons
- IP geolocation via ip-api.com (cached)
- Trust/baseline persistence: `nid_state.json`, `connection_trust.json`

### Security Audit
- 10 check categories: startup, processes, ports/firewall, filesystem, DNS, accounts, Wi-Fi, USB/devices, browser/certs, event logs
- Smart noise reduction: deduplicates ports (IPv4/IPv6), aggregates firewall rules, filters known-safe patterns (MCP DLLs, VC_redist)
- Hosts file analysis: distinguishes ad-blocking (127.0.0.1 blocks) from hijacking
- Event log analysis with appropriate thresholds (service installs = INFO, not CRITICAL)

### Account Activity Monitor
- 34 event types across 6 categories: Account, Logon, Device, System, Security, Software
- Noise-free: excluded successful logons (490/day), Defender config spam (500/day), service type changes, NTP syncs
- Smart aggregation: repeated events within 5 minutes collapse into one
- Internal Windows noise filter: DWM, UMFD, SYSTEM/LOCAL SERVICE logons excluded
- Spy Check tab: camera/mic access history (registry), remote access detection, log tampering, suspicious scheduled tasks
- User Accounts tab: SID analysis, all-time account event history
- "Fix Log Sizes" button: one-click increase event log retention from 20MB to 200MB

### FFmpeg Studio
- GPU encoder auto-detection: actually runs test encodes (not just `-encoders` list)
- Supported: h264_nvenc, hevc_nvenc (NVIDIA), h264_amf (AMD), h264_qsv (Intel)
- `_FATAL_CONFLICTS` dict: auto-fixes known-bad encoder/codec/bitdepth combos
- Color-correct recording: `scale=in_range=full:out_range={range}:out_color_matrix=bt709`
- Visual area selector: app minimizes → FFmpeg screenshot → tkinter Canvas overlay with spotlight reveal, corner handles, dimension badge, Shift=16:9 snap
- Convert tab: platform presets (YouTube, YouTube 4K, Discord/Web, Twitter/X, Archive)

---

## Dependencies

| Package | Version | Used By |
|---------|---------|---------|
| customtkinter | 5.2.2 | All tools (UI framework) |
| psutil | 7.2.2 | Health monitor, intrusion detector, security audit |
| keyboard | 0.13.5 | Screen lock |
| requests | 2.32.5 | Intrusion detector (IP geolocation) |
| scapy | 2.7.0 | Intrusion detector (ARP scan, packet sniffing) — optional |
| pillow | 11.1.0 | FFmpeg Studio (area selector screenshot) |
| pyinstaller | 6.19.0 | Portable EXE builds |

---

## Portable Deployment

4 tools have portable standalone builds:
- `Network_Stability_Monitor_Pro.exe` (~15 MB)
- `Network_Intrusion_Detector_Pro.exe` (~22 MB)
- `Security_Audit.exe` (~14 MB, UAC admin elevation)
- `Account_Activity_Monitor.exe` (~14 MB, UAC admin elevation)

Each has: PyInstaller spec file (`portable/build/*.spec`), portable
Python launcher (`portable/*_Portable.py`), batch file wrapper
(`portable/run_*.bat`).

Launchers import tool code directly from the canonical `tools/` package
(`from tools.account_activity_monitor import App` etc.). Specs set
`pathex=[repo-root]` so PyInstaller resolves the package from source.
No duplicate `.py` sources live under `portable/` —
`tests/test_no_portable_source_drift.py` guards against drift.

---

## Patterns & Conventions

- **Subprocess safety:** All calls use `creationflags=subprocess.CREATE_NO_WINDOW`
- **Dark theme:** `#2b2b2b` tree background, `#1e1e1e` card background, `#1a1a1a` canvas
- **Threading:** Worker thread + queue pattern (`work_q` → worker → `result_q` → UI via `after()`)
- **Tree style:** `ttk.Style` with clam theme, configured ONCE per app
- **State files:** JSON persistence in `tools/` directory alongside tool files
- **Single-instance:** Toolbox tracks open tool windows, focuses existing on re-launch
