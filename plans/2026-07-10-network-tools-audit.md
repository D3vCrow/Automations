# Network Tools Deep Audit — NID + NSM

*Date: 2026-07-10 · Branch: feat/ai-triage-pilot · Source: 15-agent ultracode workflow (network-tools-deep-audit) + manual verification*

Two tools, two jobs:
- **NSM** — Network Stability Monitor Pro (`tools/network_stability_monitor.py`, 3,211 LOC) — "is my internet broken, and whose fault?"
- **NID** — Network Intrusion Detector Pro (`tools/network_intrusion_detector_pro.py`, 3,295 LOC) — "is someone attacking me?"

---

## 1. Headline verdict

- **What's good today:** NSM already answers "router or ISP" and keeps durable incident history in SQLite (1,853 rows on disk, back to April). Its plain-English "this is NOT a hacker" explainer is the best layperson content in either tool.
- **The biggest gap:** the verdict never reaches the user. NSM's root-cause engine is dead-code-gated; NID has zero durable threat history plus three detections defined but never called. Both tools show a blank or misleading top-line during a real event.
- **The merge call:** do **not** merge the apps. Extract shared plumbing + the verdict engine into `tools/_common` (half-built already), keep two separate apps and two EXEs. Captures 100% of the duplication win without NID's admin/scapy footprint infecting NSM.
- **Do first:** fix NSM's dead import (one line) and give NID a persisted alerts table. Together they turn on the answer both tools exist to give.

## 2. Three confirmed defects (verified against source)

1. **NSM's root-cause brain is switched off at runtime.** `network_stability_monitor.py:52` `from network_intelligence_engine import ...`, but that module exists only in `tools/archived/` — import fails → `HAS_INTELLIGENCE = False` (line 60) → the smart root-cause verdict behind `if HAS_INTELLIGENCE:` (line 502) never runs. Incident *logging* still works; the plain-English *root-cause explainer* is dark. **One-line-ish fix** (correct the import path / move the module out of `archived/`).
2. **NID never persists its threat log.** `self.alerts` is a plain in-memory list (line 889), trimmed to 1,200 in RAM (985-986), read in a few places, **never written to disk**. The only `json.dumps` of an alert (2890) is a single-row copy for the detail popup. Close the app → the whole threat timeline is gone. There is no query DB.
3. **Three dead detections in NID.** `monitor_dns_queries` (1319), `monitor_suspicious_processes` (1350), `start_file_monitoring` (1398) each appear exactly once — defined, never called. Wire in or delete.

## 3. Merge decision — shared-core, separate UIs (do NOT merge apps)

**One line:** every pro-merge signal is engine-level (same gateway, same ARP table, same MAC baseline) and a shared `tools/_common` captures 100% of it — while merging would infect NSM's zero-privilege binary with NID's admin+scapy+wmi footprint, give it shared fate for NID's crashers, and still leave a ~6,500-line file that must be split anyway.

**Benefits of shared-core:** kills the real duplication drift (`get_default_gateway` has three different guards `>=3`/`>=4`/`>=5`; `CREATE_NO_WINDOW` two spellings; `safe_run`/`now_ts` written twice) — fix lands once; forces NID to finally adopt the `BoundedDeque`/`SnapshotDict` NSM already uses; the shared gateway-MAC-change event feeds both NID's "ARP spoof" and NSM's "config drift" from one computation.

**Costs / caveats:** the unified live "threat + stability" dashboard idea is what you give up. `_common` becomes a coordination point spanning a privilege boundary (elevated NID vs unprivileged NSM) — if a shared incidents DB is built, funnel all DB access through one writer thread; don't share a connection across the boundary. The "it's a subset of B8" framing only holds if B8 is actually scheduled — if it slips, ship a minimal standalone `_common` extraction independently.

**Architecture:** three-layer split, done as the B8 god-file work — no merge step. (1) `tools/_common`: move `safe_run`, `now_ts`/`parse_ts` (store epoch float + display string), single `get_default_gateway`, ARP-table parse, add `net_signals` (gateway-MAC baseline + ARP/config-drift, one function two callers), add `atomic_write(path, data)` (tmp + `os.replace`) and route every JSON save through it. (2) Per-tool `*_engine.py` / `*_store.py` / `*_ui.py`; fix both dead-wiring bugs during the split; give NID a real SQLite alerts table. (3) Two apps, two portable shims (untouched). Move `nid_api_keys.json` to `.env`/keyring.

## 4. Persistence & data-safety

**Is history safe today?** Split. **NSM: yes** — incidents commit to SQLite per-event, survive close, browsable back to April. **NID: no** — the alert log is RAM-only, capped 1,500, gone on every close; a NID user cannot revisit day-N threats at all.

Fixes, in order:
1. **[P0/L]** Give NID a real alerts table (SQLite, mirror NSM's `_db_insert_incident` at 561). INSERT the moment an alert fires. Single biggest persistence gap.
2. **[P0/M]** Atomic writes everywhere — `write tmp → fsync → os.replace`, sweep leftover `.tmp` on startup. Today every save truncates the live file; the 1.5 MB `nid_conn_history.json` (rewritten ~17×/min) self-wipes to `{}` on a mid-write crash (`_load_history` silent reset, 2607-2608). **`fsync` before replace is required** — without it a power-loss still leaves a zero-length file.
3. **[P0/S]** Downgrade silent resets: on decode error rename bad file to `.corrupt` + log, don't discard. The `nid_state.json` (trust/known-devices) reset is **security-critical** — its wipe re-alarms every device AND a re-established baseline may trust a now-compromised gateway.
4. **[P1/M]** Cap + prune + debounce `nid_conn_history.json` (5,000 most-recent by last_seen; write ≤once/30-60s, compact).
5. **[P1/S]** NSM date-range query + pagination in `_db_load_incidents` (601, today severity/category + LIMIT 500 only); index on `start_time`; retention prune; rotate the unbounded `exports/` dir (103 files, 27 MB).
6. **Design-around now:** the connection dossier is a plaintext, permanent, browsing-adjacent log — set a retention default and make "clear history" actually shred. `.env` for API keys is still plaintext — for live VT/AbuseIPDB keys use OS keyring/DPAPI or state the residual risk honestly.

## 5. Performance & consistency — top fixes

1. **[P0/M]** Debounce + cap + atomic-write the 1.5 MB history (one change) — biggest worker stall + top corruption risk together. `_save_history` (2610).
2. **[P0/M]** Put NID `alerts` / `_conn_history` / `_last_conns` behind `BoundedDeque` + `.snapshot()` — **latent crasher**, not just perf: `RuntimeError: list changed size during iteration` surfaces as random `refresh_*` tracebacks on busy hosts (reads as "flaky UI," is a threading bug). Cache one snapshot per refresh, don't call it per reader.
3. **[P1/M]** Move geo (`get_ip_geolocation` 247) + MAC-vendor (`get_mac_manufacturer` 786) lookups off the scan critical path — both do blocking `requests.get` in the worker loop; 20 new IPs = up to 60s frozen (last-scan timestamp stuck). Use the bounded-background pattern NID already has for reputation.
4. **[P1/M]** Throttle NID's `wmic` advanced scans (gate AND, not OR — `_detect_advanced_threats` 1225); hoist the 5 `tag_configure` calls out of the 800-row insert loop (3036).
5. **[P1/M]** NSM: id-index incidents (O(1) `_find_incident` 931), enable WAL + one connection behind a lock, track max-severity O(1), and **close open incidents on shutdown** so DEGRADED-at-exit doesn't leave `end_time=''` forever (919-929).

*Honesty note: the "17×/min" and "multi-hundred-ms freeze" figures are reasoned from poll-rate, not profiled. The fixes are right regardless; profile before trusting the exact severity ordering.*

## 6. The plain-language verdict layer — the single banner

**One banner, one color, one line, at the top of the first screen** — computed live, not buried behind a row-click. This is the highest-leverage UX work and answers the question the tools exist for.

**Five slots, always this order:** traffic-light state · plain meaning · evidence+freshness line · one opinionated action · "why we think this" toggle (JSON hidden behind it).

**Five states:** 🟢 Green "Your network looks healthy" (no button) · 🔵 **Blue (the anti-panic state both tools lack)** "This looks like an internet outage, not your fault" · 🟡 Amber "Worth a look" (benign explanation first, one-tap "it's mine" downgrade) · 🔴 Red reserved for confirmed high-confidence harm (one bright action with reassurance baked in: "Block it — your other devices stay online").

**Build:** NSM — fix the dead import, then promote existing `_get_friendly_explanation` content to a live top banner (content already written, just disconnected). NID — author the banner it never had; derive attack-vs-noise from alert **category** (MITM / DNS-exfil / internal-scan = attack-shaped; new-device / outbound-volume = usually benign), not raw HIGH count. Share the verdict vocabulary through the engine so both speak one language.

**Three arbitration rules the banner MUST have (where a wrong verdict is dangerous):**
- **Precedence when signals conflict:** an ARP-spoof often *presents* as an outage. "Possible attack" must outrank "looks like ISP outage" — define the precedence table explicitly.
- **Confidence bar on the blue state:** the reassuring "it's not you" verdict suppresses vigilance. Never claim "not your fault, not an attacker" below a high confidence threshold.
- **A "what's actually active / can't see" capability line:** passive ARP sniff, port-scan, BadUSB silently degrade without Npcap/admin; turn each unavailable detector into an explicit "not checking this" line, and state "we can only see this PC, not your other devices" — else green means "safe" and "blind" indistinguishably.

## 7. Prioritized backlog

| P | Item | Why | Effort | Tool |
|---|------|-----|--------|------|
| **P0** | Fix NSM dead intelligence import | Root-cause verdict renders blank today — one line turns it on | S | NSM |
| **P0** | Live plain-verdict banner on first screen | The single answer both tools exist to give; nobody reads a table | M | both |
| **P0** | NID persisted alerts table (SQLite) | Threat history is 100% lost on close today | L | NID |
| **P0** | Debounce + cap + atomic-write the 1.5 MB history | Biggest worker stall + top corruption/silent-wipe risk, one change | M | NID |
| **P0** | BoundedDeque + snapshot for alerts/conn state | Latent crasher on busy hosts, reads as "flaky UI" | M | NID |
| **P0** | Banner precedence + blue-state confidence bar | A reassuring wrong verdict is the tool's worst failure mode | M | both |
| **P1** | Baseline-integrity / re-baseline guidance | Trust-on-first-use: a dirty baseline greens every threat check forever | M | NID |
| **P1** | "What's active / can't see" capability + coverage line | Green must not mean "blind"; state IoT + missing-Npcap gaps honestly | M | both |
| **P1** | Gateway-MAC-change (confirmed on recheck) + DNS-answer-integrity vs trusted resolver | Two highest-signal, lowest-FP attack checks; catch the 2026 SOHO campaign | M each | NID |
| **P1** | This-PC-scanning-out (Mirai/botnet) detection | Very high confidence infection signal, fully PC-detectable | M | NID |
| **P1** | Move geo + MAC-vendor lookups off scan path | Kills the "app frozen, timestamp stuck" symptom | M | NID |
| **P1** | NSM: WAL, id-indexed incidents, close-on-shutdown, date-range query | Removes "database is locked," never-closing incidents, enables day-N browse | M | NSM |
| **P1** | Per-finding "what it means / what to do" card; hide JSON | NID dumps raw JSON at users; NSM's good version is JSON-walled | M | both |
| **P1** | Captive-portal detection | Else DNS-integrity check cries "hijack" on every hotel network | M | both |
| **P1** | Traceroute first-hop localization (promote from P3) | The only thing that locates a *degraded* connection's owner | M | NSM |
| **P2** | Bufferbloat / latency-under-load | The most-missed modern home fault ("fast but laggy") | L | NSM |
| **P2** | RSSI/SNR + 5GHz channel scoring (today: signal% + 2.4GHz only) | Real Wi-Fi diagnosis, not a percent bar | M | NSM |
| **P2** | Wire up NID's dead detections (DNS-tunnel, process, file-integrity) or delete | Advertised in docstring, never called — honesty debt | M | NID |
| **P2** | Evil-twin w/ mesh-BSSID whitelist; MAC-randomization-aware new-device | The two biggest false-positive landmines | L / M | both |
| **P2** | Weight threat roll-up by attack-shape, not count; demote country-based SUSPICIOUS | One flaky ARP flip = CRITICAL today; a CDN exit in 8 nations false-flags | M | NID |
| **P2** | Consolidate duplicated helpers into `_common/` | So every fix above lands once, not twice (drift is already live) | M | both |
| **P2** | Retention cap + real "clear history" shred; API keys to keyring/DPAPI | Plaintext permanent browsing-adjacent log + live keys on disk | S / M | NID |
| **P3** | IPv6 (reachability, AAAA, RA-guard); MTU black-hole probe; throughput-vs-plan | Whole missing address family + "big pages hang" fault, dual-stack 2026 net | M-L | NSM |
| **P3** | Non-English-Windows parse-failure honesty | English-only CLI parsing gives confident *wrong* verdicts abroad | S | NSM |
| **P3** | Colorblind audit — color always paired with icon/shape/text | Prescribed but never verified against current tables/cards | S | both |

## 8. The three most dangerous gaps (from the completeness critic)

These are cases where the tool doesn't just miss a threat — it actively tells a non-technical user they're safe when they may not be:

1. **Baseline poisoning.** Gateway-MAC-change, DNS-server-changed, evil-twin all compare to "a saved known-good baseline." Nothing verifies the baseline was captured on a *clean* network. First run on an already-compromised network → the malicious state becomes trusted → those checks read green forever. Needs baseline-integrity + re-baseline-from-known-safe guidance + staleness expiry.
2. **Attack masquerading as outage.** When the gateway is down (ISP-looking) *and* the gateway MAC changed (attack-looking), the banner must arbitrate — "possible attack" outranks "ISP outage." Under-specified today.
3. **The reassuring-but-wrong blue state.** If "it's not you / ISP outage" fires when the real cause is local (or an attack), it tells an attacked user to stand down. Needs a confidence floor before it may claim "not your fault, not an attacker."

## 9. Provenance

- 15 agents, ~1.3M tokens, 15.5 min. Full raw result: session task `wkfguh3ys`.
- Load-bearing claims (dead NSM import, NID no-persistence, 3 dead detections) manually verified against source — see §2.
- Full 45-check catalog with plain-language + traffic-light wording: Appendix (below).

---

## Appendix A — Full check catalog (45 checks)

*Status: have = works today · partial = present but not delivering (dead-gated / never-called / high-FP) · missing = not in either tool. Tool: which tool owns it, or "neither".*

| P | Check | Points to | Status | Tool | What it means (plain) |
|---|-------|-----------|--------|------|------------------------|
| P0 | Ping the router (default gateway reachable?) | My Router | have | NSM | Can your computer even talk to your router (the box that gives you internet)? If not, the problem is right here at home — a cable, the router, or your Wi-Fi connection. |
| P0 | Resolve a hostname (DNS lookup works?) | My ISP | have | NSM | When you type a website name, your PC has to look up its number (like a phone book). If the number-lookup is broken but the internet itself works, this is a name-lookup problem, usually fixable by switching to a different lookup service. |
| P0 | DNS answer integrity vs trusted resolver (hijack check) | Malicious-actor | missing | neither | We check that important sites (like your bank) point to the real address and haven't been secretly redirected to a fake one. A mismatch is a strong sign your router or internet has been tampered with. |
| P0 | This PC scanning the internet on attack ports (Mirai/botnet) | Malicious-actor | missing | neither | Your computer is quietly trying to break into lots of other machines on the internet. That almost always means it's been taken over and is being used in an attack. |
| P0 | Ping a public IP without DNS (8.8.8.8 / 1.1.1.1) | My ISP | have | NSM | Can you reach the wider internet, ignoring website names? If your router answers but this doesn't, your internet provider is the problem — not your gear. |
| P0 | Gateway MAC changed vs clean baseline (ARP-spoof / MITM) | Malicious-actor | partial | NID | Something is pretending to be your router so it can secretly read what you send. This is one of the clearest signs of a real attack on your home network. |
| P0 | Top-line plain verdict banner (is it my network or an attacker?) | External-benign | missing | neither | One clear sentence at the top that tells you if you're fine, if it's just your internet provider, or if something looks like an attack — and what to do about it. No jargon, no reading a table. |
| P0 | Root-cause verdict engine (Router/ISP/DNS/Adapter/Suspicious) | My Router | partial | NSM | The part of the tool that weighs all the clues and names the most likely cause in one word. Right now it's switched off by a wiring bug, so the main answer shows up blank. |
| P1 | Packet loss over a rolling window | My ISP | have | NSM | How many messages get dropped on the way. A little is normal; a lot means your connection is unreliable, and where it drops tells us if it's your router or your provider. |
| P1 | Latency / RTT thresholds with plain grading | My ISP | have | NSM | How long it takes for a message to go out and come back. High numbers mean everything feels slow — we tell you whether it's your router or the internet beyond it. |
| P1 | Outbound beaconing + destination reputation + unsigned process | Malicious-actor | partial | NID | Spyware often 'phones home' on a steady schedule. We watch for a program quietly checking in with the same outside address over and over, especially an unknown one, which is a strong sign of data being stolen. |
| P1 | ISP outage / anti-panic 'it's not you' state | My ISP | partial | NSM | When your internet provider is down, we say so plainly and reassure you it isn't your fault or an attack — instead of leaving you guessing or blaming yourself. |
| P1 | Wired-vs-Wi-Fi + second-device blast-radius scoping | My Device | missing | neither | We check whether the problem happens on just this computer or on everything. If only this one device is affected, the fix is on the device — not your whole network. |
| P1 | Adapter / DHCP health (got a real IP?) | My Device | have | NSM | Your device needs a valid address from the router to get online. If it gave itself a fake one, it never got a proper address — usually a quick reconnect or router restart fixes it. |
| P1 | Per-finding plain 'what it means / what to do' explainer | External-benign | partial | NSM | For every warning, a clear sentence on what it means for you and the single thing to do next — instead of a wall of technical text. |
| P1 | Incident history that survives close (revisit day-N) | External-benign | partial | NSM | A simple day-by-day diary of what happened on your network, so you can look back at last night or last week. One tool keeps this; the security tool currently forgets everything when you close it. |
| P1 | BadUSB / keystroke-injection detection (Flipper/Rubber Ducky) | Malicious-actor | partial | NID | A malicious USB stick can pretend to be a keyboard and type commands faster than any human. We watch for a new 'keyboard' that appears and immediately starts typing — a classic attack gadget. |
| P1 | Bufferbloat / latency under load (fast but laggy) | My Router | missing | neither | Your internet is fast on a speed test but feels laggy during video calls or big uploads. That's usually your router struggling to keep up, and it's fixable in the router settings — not your provider's fault. |
| P1 | Router admin exposed to the internet (WAN posture) | My Router | missing | neither | We check if your router's control panel can be reached from the open internet. If it can, anyone can try to guess your password — you should turn that setting off. |
| P1 | Router DNS setting changed vs expected (hijack posture) | Malicious-actor | partial | both | Your router tells all your devices where to look up website names. If that setting was quietly changed to an unknown service, someone may be steering you to fake sites. |
| P1 | Wi-Fi signal strength RSSI / SNR (radio quality) | My Wi-Fi | partial | NSM | How strong and clean your Wi-Fi signal really is where you're sitting. Weak or noisy signal makes everything slow, and moving closer or changing channel fixes it — it's not your provider. |
| P2 | Jitter (variation in latency) | My ISP | missing | neither | Whether your connection speed is steady or jumpy. Jumpy connections make video calls stutter and games lag even when the average speed looks fine. |
| P2 | IP reputation check (VirusTotal / AbuseIPDB) | Malicious-actor | have | NID | We check the addresses your PC talks to against lists of known-bad ones. A match is a warning sign, but we treat one hit as a clue, not proof. |
| P2 | DNS tunneling / exfiltration pattern | Malicious-actor | partial | NID | Attackers sometimes sneak stolen data out disguised as harmless website-name lookups. We watch for that unusual pattern. (This code exists in the tool but isn't switched on yet.) |
| P2 | Suspicious process detection (keylogger/RAT/miner/ransomware) | Malicious-actor | partial | NID | We look for programs whose names match known spying or ransom tools running on your PC. (This check exists in the tool but isn't currently turned on.) |
| P2 | 5-level outbound connection classification (Safe/Known/Unknown/Suspicious/Dangerous) | External-benign | have | NID | Every outside connection your PC makes gets a plain color rating from safe to dangerous. Some ratings (like flagging a whole country) are noisy, so treat orange as 'worth a look', not proof. |
| P2 | New / unknown device joined (MAC-randomization aware) | External-benign | partial | NID | A device we haven't seen joined your network. Usually it's your own phone, a guest, or a new gadget — modern phones change their ID often, so this is normal. We only worry if it then does something bad. |
| P2 | Device inventory with vendor + type identification | External-benign | have | NID | A list of everything on your network with a friendly name and type (phone, TV, printer) so you can spot anything you don't recognize. |
| P2 | One MAC claims multiple IPs / IP-to-MAC flip | Malicious-actor | have | NID | Odd patterns in how devices identify themselves on your network can hint at impersonation. On their own these are often harmless (phones, virtual machines), so we treat them as 'worth a look'. |
| P2 | Passive ARP-reply sniff for gateway impersonation | Malicious-actor | partial | NID | A background watcher that catches the exact moment something lies about being your router. It needs special permissions to run, so it isn't always on. |
| P2 | Hosts-file / config file integrity monitoring | Malicious-actor | partial | NID | A key system file can be edited to redirect you to fake sites. We watch it for unexpected changes. (Present in the tool but not switched on yet.) |
| P2 | Per-device DNS / hosts / VPN / proxy override check | My Device | partial | NID | Sometimes one computer has its own settings (a VPN, a proxy, or an edited system file) that break things just for it. We check whether that's what's going on here. |
| P2 | Threat level / overall severity roll-up | Malicious-actor | partial | NID | One overall number for how worried to be. Today it just counts alerts, so it can over-react to harmless things — it should weigh real attacks more heavily. |
| P2 | Inbound port-scan that precedes a connection to an open port | Malicious-actor | partial | NID | Someone testing your computer's doors to find one left open. The internet does this to everyone harmlessly all day, so we only alarm when it comes from inside your network or actually gets in. |
| P2 | Evil-twin / rogue access point detection (mesh-whitelisted) | Malicious-actor | partial | NSM | A fake Wi-Fi network can copy your network's name to trick you into connecting. We watch for that — but we first learn your own mesh boxes so we don't cry wolf on them. |
| P2 | Direct-to-modem tie-breaker (router vs ISP) | My Router | missing | neither | A simple test: plug your computer straight into the internet box, skipping your router. If it works that way, your router is the problem. If it still doesn't, it's your provider. |
| P2 | Router instability / reboot-loop detection | My Router | missing | neither | If your router keeps quietly restarting itself, your internet will drop over and over. That's a failing router, and we can spot the pattern. |
| P2 | Wi-Fi channel congestion & recommendation | My Wi-Fi | partial | NSM | Your Wi-Fi shares airwaves with your neighbors. If too many are on the same channel, everyone slows down. We suggest a clearer channel. |
| P2 | Wi-Fi signal correlated with the current problem | My Wi-Fi | have | NSM | We check if your Wi-Fi was weak exactly when the problem started, so we can tell you the weak signal was probably the cause. |
| P3 | Tor connection detection | External-benign | have | NID | We spot when your PC uses Tor, an anonymity tool. That might be you using a privacy browser, or it might be malware hiding its tracks — so it's a heads-up, not an alarm. |
| P3 | Audio-spying / mic-capture process detection | External-benign | have | NID | We look for programs that could be recording your microphone. This one is unreliable — many normal apps trip it — so it's just a heads-up to review. |
| P3 | Traffic throughput vs provisioned plan | My ISP | missing | neither | Whether you're actually getting the internet speed you pay for. Consistently far below it, on every device, points to your provider. |
| P3 | Traceroute first-hop fault localization | My ISP | missing | neither | We trace the path your traffic takes and find the exact point where it slows or drops — which tells us if it's your router or somewhere out on your provider's network. |
| P3 | Credential-stuffing / brute-force on router admin | Malicious-actor | missing | neither | Someone repeatedly guessing your router's password. Your PC can't see this directly — only the router knows — so we instead warn you to close the door that makes it possible. |
| P3 | Local loopback / TCP-IP stack health | My Device | missing | neither | A quick self-test of your computer's own networking software. If this fails, the fault is inside this PC, not your router or internet. |

## Appendix B — Suggested traffic-light wording (P0/P1)

### Suggested traffic-light wording (P0/P1)

- **Ping the router (default gateway reachable?)** — Green: Your router is responding normally. / Red: Your computer can't reach your router — check the cable or Wi-Fi, or restart the router.
- **Resolve a hostname (DNS lookup works?)** — Green: Website names are resolving fine. / Amber: The internet is up but name-lookup is failing — try switching your DNS to 1.1.1.1.
- **DNS answer integrity vs trusted resolver (hijack check)** — Green: Website addresses match the trusted answer. / Red: A site is being redirected somewhere it shouldn't be — possible DNS hijack. Don't log in to banking; check your router's DNS settings.
- **This PC scanning the internet on attack ports (Mirai/botnet)** — Green: No sign your PC is attacking others. / Red: Your PC is scanning the internet like an infected machine — disconnect it and run a malware scan.
- **Ping a public IP without DNS (8.8.8.8 / 1.1.1.1)** — Green: Path to the internet is open. / Red: Your router works but the internet beyond it is down — this looks like your provider.
- **Gateway MAC changed vs clean baseline (ARP-spoof / MITM)** — Green: Your router's identity is unchanged. / Red: Something is impersonating your router (possible attack) — disconnect and check with someone technical.
- **Top-line plain verdict banner (is it my network or an attacker?)** — Green: Your network looks healthy — nothing needs you. / Blue: Looks like an internet outage, not your fault. / Red: Something is impersonating your router — possible attack. See details.
- **Root-cause verdict engine (Router/ISP/DNS/Adapter/Suspicious)** — Fix wiring first: today this shows blank/'Stable' even during a real outage.
- **Packet loss over a rolling window** — Green: Almost no dropped traffic. / Amber: Losing more traffic than normal — connection is unreliable right now.
- **Latency / RTT thresholds with plain grading** — Green: Response times are snappy. / Amber: Responses are slow — pages and calls will lag.
- **Outbound beaconing + destination reputation + unsigned process** — Green: No suspicious phone-home activity. / Red: A program is regularly sending data to an untrusted address — possible spyware.
- **ISP outage / anti-panic 'it's not you' state** — Blue: This looks like an internet outage, not a problem with your network. Your provider seems down.
- **Wired-vs-Wi-Fi + second-device blast-radius scoping** — Amber: This looks like a problem with this one device only. / Amber: All your devices are affected — it's the router or your provider, not this PC.
- **Adapter / DHCP health (got a real IP?)** — Green: Your device has a proper network address. / Amber: Your device didn't get an address from the router — reconnect or restart the router.
- **Per-finding plain 'what it means / what to do' explainer** — Each alert shows: What this means · What to do · (Technical details hidden by default).
- **Incident history that survives close (revisit day-N)** — History: grouped by day, newest first, each line shows what happened and how it ended.
- **BadUSB / keystroke-injection detection (Flipper/Rubber Ducky)** — Green: No suspicious USB input devices. / Red: A device just plugged in and started typing like an attack tool — unplug it now.
- **Bufferbloat / latency under load (fast but laggy)** — Green: Stays responsive even when busy. / Amber: Gets very laggy under load (bufferbloat) — turn on Smart Queue/QoS in your router.
- **Router admin exposed to the internet (WAN posture)** — Green: Your router's admin page is not exposed to the internet. / Amber: Your router can be managed from the internet — turn off remote administration.
- **Router DNS setting changed vs expected (hijack posture)** — Green: Your name-lookup service is the expected one. / Red: Your router's name-lookup was changed to an unknown service — possible hijack.
- **Wi-Fi signal strength RSSI / SNR (radio quality)** — Green: Strong, clean Wi-Fi signal. / Amber: Weak or noisy Wi-Fi — move closer to the router or change channel.
