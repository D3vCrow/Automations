# AI Triage Pilot — Network Intrusion Detector

## Problem

The Network Intrusion Detector (NID) classifies every outbound connection
into one of five buckets (SAFE / KNOWN / UNKNOWN / SUSPICIOUS / DANGEROUS)
using IP reputation, geo, and process heuristics. It works, but the user
still has to interpret each `SUSPICIOUS` row themselves: *why* is this
connection flagged, *what* should I do about it, and is this likely a
false positive?

## Solution

Added an opt-in `🤖 Triage` button. Clicking it sends a sanitized payload
(no command-lines, no home paths, no MAC, no SSID) to Claude Haiku 4.5
via the Claude Agent SDK against my Max subscription. The model returns a
structured JSON object the UI renders in a side panel:

- Severity in plain English (low / medium / high / critical)
- One-sentence "why it matters"
- Suggested action (monitor / block / kill_process / investigate / ignore)
- False-positive likelihood (0–100%)
- Evidence bullets

The rule-based classification is unchanged. AI is layered on top, never
replacing it. Default OFF — single env var to enable. Daily token cap of
50k acts as a safety net.

## Before / After

![Before — raw alert detail](img/nid-before.png)

![After — same alert with AI triage panel](img/nid-after.png)

## Architecture

All AI calls go through one shared module: `tools/_common/ai_triage.py`.
That module owns the sanitizer, SQLite cache (24h TTL), daily-token
budget gate, auth detection (Claude Code OAuth or `ANTHROPIC_API_KEY`),
SDK wrapper, and response parser. NID itself does not import the SDK.

This keeps the integration small and re-usable. The same module powers
upcoming AI features in `security_audit`, `system_health_monitor`, and
`account_activity_monitor`.

## Tech

- Python 3.11+, Tkinter
- Claude Agent SDK (subscription-billed via Max)
- SQLite for the response cache
- pytest with mocked SDK calls — zero network in CI

## Source

- Spec: [`docs/superpowers/specs/2026-04-27-ai-triage-pilot-design.md`](../superpowers/specs/2026-04-27-ai-triage-pilot-design.md)
- Module: [`tools/_common/ai_triage.py`](../../tools/_common/ai_triage.py)
- UI hook: `tools/network_intrusion_detector_pro.py`
- Tests: [`tests/test_common_ai_triage.py`](../../tests/test_common_ai_triage.py)
