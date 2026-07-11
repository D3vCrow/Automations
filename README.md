# Python Automations Toolbox

A modular Windows desktop automation suite — **12 self-contained tools** behind one
auto-discovering launcher, built with Python and CustomTkinter. Each tool is a single
file dropped into `tools/`; the launcher finds it, no registration needed.

[![tests](https://github.com/D3vCrow/Automations/actions/workflows/test.yml/badge.svg)](https://github.com/D3vCrow/Automations/actions/workflows/test.yml)
![python](https://img.shields.io/badge/python-3.11-blue)
![platform](https://img.shields.io/badge/platform-Windows%2010%2F11-lightgrey)

> **Focus of this repo (for reviewers):** it doubles as a portfolio of practical
> systems programming on Windows — process/network/security tooling, a shared
> architecture layer, a safe optional LLM integration, and a real test suite
> (**482 tests**). Start with the highlights below.

---

## Start here — engineering highlights

| What | Where | Why it's worth a look |
|------|-------|-----------------------|
| **Shared `_common` architecture** | [`tools/_common/`](tools/_common/) | One DRY foundation across every tool: repo paths, `.env` config, hidden-window subprocess helpers, thread-safe primitives (`BoundedDeque`, `SnapshotDict`), a narrow-except decorator, and dark-theme styling. |
| **AI-triage layer** | [`tools/_common/ai_triage.py`](tools/_common/ai_triage.py) · [design writeup](docs/portfolio/ai-triage-demo.md) | Optional LLM triage done safely: a single SDK seam, a PII/credential **sanitizer**, a daily **token-budget gate**, a 24h SQLite cache, and a strict **graceful-fallback** rule — if anything fails, the tool's rule-based behaviour is unchanged. |
| **GPU encoder auto-detection** | [`tools/ffmpeg_studio.py`](tools/ffmpeg_studio.py) | Detects NVENC/AMF/QSV by running *real* test encodes, not by trusting `-encoders`; a conflict table auto-fixes bad encoder/codec/bit-depth combos. |
| **Test suite + CI** | [`tests/`](tests/) | 482 passing tests (pytest), run on every push via GitHub Actions. |

---

## Tools

### 🛡️ Network & Security
- **Network Intrusion Detector Pro** — LAN device discovery (ARP scan + ping-sweep fallback), 5-level connection classification, passive ARP-spoof/MITM detection, threat sweeps (Flipper Zero, Tor, audio-spying), firewall blocking.
- **Network Stability Monitor Pro** — live latency/health monitoring, 5-minute chart, incident timeline, and a Wi-Fi analyzer (active scan via the `WlanScan` API, channel scoring, evil-twin detection).
- **Account Activity Monitor** — Windows Event Log timeline of account/logon/device/system changes, with a spy-check tab (camera/mic registry access, remote-tool and log-tampering detection).
- **Security Audit** — one-shot 10-category system scan (startup, processes, ports, filesystem, DNS, accounts, Wi-Fi, USB, certs, event logs) with heavy noise reduction.
- **Network Pattern Analyzer** — companion to the Stability Monitor: finds time-correlations and frequency patterns in exported incident data.

### 🖥️ System
- **System Health Monitor** — real-time CPU/RAM/disk/GPU, process manager, disk analysis, startup management, threshold alerts.
- **System Cleaner Pro** — safe disk + RAM cleanup with size preview, standby-memory purge, and Explorer restart.
- **Folder Size Analyzer Pro** — recursive disk-usage explorer with progress bars and CSV/JSON export.

### 🎬 Media & Utility
- **FFmpeg Studio** — screen/gameplay recorder, converter, and a visual area-selector overlay, with the GPU auto-detection above.
- **Screen Lock (Kid-Safe)** — transparent keyboard-blocking overlay with an opacity slider and a `Ctrl+Alt+U` unlock.

### 🧰 Developer
- **Claude Usage Monitor** — live cost/token dashboard for Claude Code: parses local JSONL session logs into per-session cost, token, and "waste factor" breakdowns.

### 🎲 Fun / Experimental
- **Decision Dice** — weighted-RNG decision maker with animated dice, custom profiles, and a decision journal. A playground piece, not a serious utility.

---

## Architecture

- **Launcher (`Main.py`)** — scans `tools/` with `importlib`, renders a responsive grid, and enforces single-instance windows. A tool only needs to expose `TOOL_NAME` and `run_tool()`.
- **Threading** — background work uses a worker-thread + queue pattern; the UI is only ever updated from the main thread via `after()`.
- **Subprocess safety** — every external call runs hidden (`CREATE_NO_WINDOW`) through the shared `_common.subprocess` helpers.
- **Portable builds** — four tools ship as standalone PyInstaller executables; launchers import the canonical `tools/` package (no source duplication — a test guards against drift).

## Tech stack

Python 3.11 · CustomTkinter (dark theme) · psutil · scapy (optional, for LAN scanning) ·
pillow · pytest. Optional AI features use the `claude-agent-sdk` and are **off by default**
(enable via `AUTOMATIONS_AI_ENABLED=1`; see [`.env.example`](.env.example)).

## Running it

```bash
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
python Main.py            # launch the toolbox
python tools\system_health_monitor.py   # or run one tool directly
```

## Tests

```bash
pytest -q
```

## License

[MIT](LICENSE) © D3vCrow
