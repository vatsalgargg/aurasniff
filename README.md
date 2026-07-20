# ⚡ AuraSniff

<p align="center">
  <b>A premium, AI-powered terminal network forensics tool.</b><br/>
  <i>Powered by Gemini, Claude, or both — in Dual-LLM Ensemble Mode.</i>
</p>

<p align="center">
  <a href="https://pypi.org/project/aurasniff/"><img src="https://img.shields.io/pypi/v/aurasniff.svg?style=for-the-badge&color=6C63FF" alt="PyPI version"/></a>
  <a href="https://pypi.org/project/aurasniff/"><img src="https://img.shields.io/pypi/dm/aurasniff?style=for-the-badge&color=00C9A7" alt="PyPI downloads"/></a>
  <img src="https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&color=3776AB" alt="Python Support"/>
  <a href="https://github.com/vatsalgargg/aurasniff/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License: MIT"/></a>
  <a href="https://github.com/vatsalgargg/aurasniff"><img src="https://img.shields.io/github/stars/vatsalgargg/aurasniff.svg?style=for-the-badge&color=FFD700" alt="GitHub stars"/></a>
</p>

---

## 🌟 What is AuraSniff?

**AuraSniff** is a professional-grade, zero-dependency CLI network forensics tool that runs entirely in your terminal. Point it at a `.pcap` or `.pcapng` file and instantly get:

- A rich visual dashboard of all traffic, connections, and protocols
- A full map of every website each device visited
- Extracted cleartext credentials and security anomaly alerts
- A live AI-powered chat shell where you can ask questions in plain English

No Wireshark. No GUI. No heavy installs. Just run `aurasniff <file.pcap>` and you're in.

---

## 🚀 Core Features

| Feature | Description |
|---|---|
| ⚡ **Zero-Dependency Parsing** | Streams PCAP/PCAPNG files locally via Scapy. No Wireshark needed. |
| 🌐 **IP → Website Map** | See which websites every IP visited — from DNS, HTTP, and TLS/SNI combined. |
| 🔑 **Credentials Harvester** | Extracts plaintext logins from HTTP-POST, FTP, SMTP, POP3, and IMAP. |
| 🚨 **Security Anomaly Engine** | Detects port scanning, ARP spoofing, DNS tunneling, and cleartext passwords. |
| 🤖 **Multi-Provider AI** | Works with **Gemini**, **Claude**, or **GPT-4o** out of the box. |
| ⚡ **Dual-LLM Ensemble Mode** | Gemini + Claude chained together — the most powerful analysis mode. |
| 🔍 **Deep Hex Inspection** | Layer-by-layer tree view with colour-coded Hex + ASCII dump for any packet. |
| 🧠 **Offline Fallback** | No API key? Smart keyword routing still answers credential, DNS, and alert queries. |

---

## ⚡ Dual-LLM Ensemble Mode

> **The most powerful way to run AuraSniff.** Configure both a Gemini and a Claude key — the tool activates Ensemble Mode automatically. No flags, no extra commands.

### Why two models?

Each model has a superpower:

| Model | Role in Ensemble | Strength |
|---|---|---|
| **Gemini** | Fast Capture Scanner | Large context window — reads the entire PCAP summary in one shot and generates a precise packet filter |
| **Local Engine** | Packet Retriever | Applies Gemini's filter to the raw packet database with zero latency |
| **Claude** | Forensic Analyst | Receives the exact matched packets — performs deep threat analysis, pattern detection, and structured risk reporting |

### How the pipeline works

```
┌─────────────────────────────────────────────────────────────────────┐
│  You ask: "Is there any suspicious traffic from 10.0.0.15?"         │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
             ╔═════════════▼══════════════╗
             ║  Step 1 — Gemini           ║
             ║  Full PCAP-wide fast scan  ║  → Overview + Smart filter
             ╚═════════════╤══════════════╝
                           │  { "src": "10.0.0.15" }
             ╔═════════════▼══════════════╗
             ║  Local Engine              ║
             ║  Raw packet retrieval      ║  → 37 packets matched
             ╚═════════════╤══════════════╝
                           │  Packet list + metadata
             ╔═════════════▼══════════════╗
             ║  Step 2 — Claude           ║
             ║  Deep forensic analysis    ║  → Risk report in Markdown
             ╚════════════════════════════╝
```

### Output you get

```
┌──────────────── Gemini Overview (Step 1/2) ─────────────────────────────┐
│ Device 10.0.0.15 shows signs of port scanning — 34 unique destination   │
│ ports contacted within 8 seconds. DNS activity is normal. No creds.     │
└──────────────────────────────────────────────────────────────────────────┘
Gemini filter: { "src": "10.0.0.15" }
37 packets matched. Sending to Claude for deep analysis…

┌──────────── ⚡ AuraSniff Ensemble — Claude Forensic Report ─────────────┐
│                                                                          │
│  ## Threat Assessment                                                    │
│  **Severity: HIGH** — Active internal port scan detected.               │
│                                                                          │
│  ### Attack Pattern                                                      │
│  - SYN packets sent to ports 22, 80, 443, 3389, 8080, 8443, 5432…      │
│  - 34 distinct ports contacted in 8.3 seconds                           │
│  - Classic TCP SYN sweep — likely automated scanner (nmap/masscan)      │
│                                                                          │
│  ### Risk Summary                                                        │
│  - 🔴 CRITICAL: Internal reconnaissance — attacker already on LAN       │
│  - 🟡 MEDIUM: No successful connections observed in this capture        │
│  - ✅ SAFE: No credentials or data exfiltration detected                 │
└──────────────────────────────────────────────────────────────────────────┘
```

### Setup (2 commands)

```bash
# 1. Set your Gemini key
aurasniff config set-key <GEMINI_API_KEY>

# 2. Set your Claude key — Ensemble activates automatically
aurasniff config set-key <CLAUDE_API_KEY> --provider claude

# Verify
aurasniff config show
# → Active provider: Gemini ⚡ Claude Ensemble
```

### AI Mode Summary

| Keys Configured | Mode Activated |
|---|---|
| Gemini only | Gemini solo analysis |
| Claude only | Claude solo analysis |
| GPT-4o only | GPT-4o solo analysis |
| **Gemini + Claude** | **⚡ Ensemble Mode (auto)** |
| None | Smart offline fallback |

---

## ⚙️ Installation

```bash
# Base install — includes Gemini + Claude (Ensemble-ready out of the box)
pip install aurasniff

# Add GPT-4o support (optional)
pip install aurasniff[openai]

# Add everything
pip install aurasniff[all]
```

---

## 🛠️ Usage

### Open a file instantly (recommended)
```bash
aurasniff <file.pcap>
```
Automatically parses the file, renders the dashboard, and drops you into the AI shell.

### Specific subcommands

```bash
# Interactive AI shell
aurasniff shell <file.pcap>

# One-shot dashboard
aurasniff analyze <file.pcap>

# Single natural language question (no shell)
aurasniff query <file.pcap> "which IPs are scanning ports?"
```

### Shell commands

Once in the shell, type any of these:

| Command | What it does |
|---|---|
| `websites` | Map of all IPs → websites visited (DNS + HTTP + TLS) |
| `websites <IP>` | Filter to a specific IP or hostname |
| `creds` | Show extracted plaintext credentials |
| `alerts` | Show security anomaly detections |
| `dns` | Full DNS query log |
| `http` | HTTP connections and status codes |
| `detail <N>` | Hex dissection of packet #N |
| `exit` / `q` | Exit the shell |
| *any text* | Ask the AI in plain English |

### Natural language examples

```
Is there any suspicious traffic?
Which websites did the laptop visit?
Show me login credentials found in the capture
Did any device do a port scan?
What did 192.168.1.15 do?
Summarise the top security threats
```

---

## 🔧 AI Configuration

API keys are stored securely in your **OS keychain** (Windows Credential Manager, macOS Keychain, Linux Secret Service). They are never written to disk in plain text. Environment variables (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) are also supported for CI/CD pipelines.

```bash
# Set Gemini key
aurasniff config set-key <GEMINI_KEY>

# Set Claude key  →  Ensemble Mode activates automatically
aurasniff config set-key <CLAUDE_KEY> --provider claude

# Set GPT-4o key (optional)
aurasniff config set-key <OPENAI_KEY> --provider openai

# View active mode and all configured keys
aurasniff config show

# Force a specific provider
aurasniff config set-provider gemini      # Gemini only
aurasniff config set-provider claude      # Claude only
aurasniff config set-provider ensemble    # Force Ensemble
aurasniff config set-provider auto        # Auto-detect (default)
```

---

## 🎨 Visual Preview

### Dashboard
```
┌─────────────────────────────────────────────────────────────────────────────┐
│ ▲ AURA SNIFF PCAP ANALYZER ▲                                               │
│ Premium Command Line Traffic Inspector & AI Security Assistant             │
└─────────────────────────────────────────────────────────────────────────────┘
┌──────────────── Capture Summary ────────────────┐┌──── Protocol Distribution ─────┐
│ File:    capture.pcapng                         ││ TCP    4,821  90.8%  ████████  │
│ Packets: 5,312                                  ││ UDP      391   7.4%  █░░░░░░░  │
│ Size:    3.41 MB  │  Duration: 62.3s            ││ ICMP      78   1.5%  ░░░░░░░░  │
└─────────────────────────────────────────────────┘└────────────────────────────────┘
┌──────────────────── 🔑 Extracted Credentials ────────────────────────────────┐
│  Pkt │ Protocol  │ Source      │ Destination  │ Credentials                  │
│   42 │ HTTP-POST │ 10.0.0.101  │ 203.0.113.10 │ User: john / Pass: p@ssw0rd  │
│   87 │ FTP       │ 10.0.0.101  │ 10.0.0.5     │ User: ftpuser / Pass: secret │
└──────────────────────────────────────────────────────────────────────────────┘
┌──────────────────── 🚨 Security Alerts ──────────────────────────────────────┐
│  Severity │ Type          │ Source      │ Description                        │
│  HIGH     │ PORT SCAN     │ 10.0.0.15   │ 34 ports hit in 8.3s (SYN sweep)  │
│  MEDIUM   │ ARP SPOOFING  │ 10.0.0.7    │ 3 MACs claiming IP 10.0.0.1       │
└──────────────────────────────────────────────────────────────────────────────┘
```

### IP → Website Map (`websites`)
```
┌─────────────────────── 🌐 IP → Website Map ──────────────────────────────────┐
│ Source IP   │ Device       │ DNS Queries          │ TLS / HTTPS              │
│─────────────│──────────────│──────────────────────│──────────────────────────│
│ 10.0.0.101  │ OFFICE-PC    │ google.com           │ github.com               │
│             │              │ stackoverflow.com     │ api.github.com           │
│ 10.0.0.102  │ WORK-LAPTOP  │ youtube.com          │ accounts.google.com      │
└──────────────────────────────────────────────────────────────────────────────┘
```

### Packet Hex Dissection (`detail 42`)
```
Packet #42
├── Ether (dst=aa:bb:cc:dd:ee:01, src=aa:bb:cc:dd:ee:02)
├── IP   (src=10.0.0.101, dst=203.0.113.10, proto=TCP)
├── TCP  (sport=51423, dport=80, flags=PA)
└── Raw  (load=b'POST /login HTTP/1.1\r\nHost: example.com...')

0000  aa bb cc dd ee 01 aa bb  cc dd ee 02 08 00 45 00  |..............E.|
0010  00 df 00 01 00 00 40 06  7c 9a 0a 00 00 65 cb 00  |......@.|....e..|
0030  50 4f 53 54 20 2f 6c 6f  67 69 6e 20 48 54 54 50  |POST /login HTTP|
```

---

## 📋 Changelog

### v0.1.5 — Latest ⚡ Dual-LLM Ensemble Mode
- 🤖 **Auto Ensemble Mode**: Set both Gemini and Claude keys — tool automatically chains them for maximum power
- 🔬 **Gemini → Filter → Claude pipeline**: Gemini scans the capture, Claude deep-dives the matched packets
- 🎨 **Ensemble prompt badge**: Shell shows `[Gemini ⚡ Claude Ensemble]` when active
- 📦 `anthropic` bundled in core install (no extra `pip install` step needed)
- 🔧 `set-provider` now supports `ensemble` and `auto` choices

### v0.1.4
- 🤖 Claude + GPT-4o provider support added
- 🔐 OS keychain key storage via `keyring`
- 🔁 Auto-fallback between providers
- 🎨 Dynamic shell prompt badge

### v0.1.3
- 🌐 IP → Website Map feature + `websites` shell command
- 🐛 7 bug fixes including port filter and text search

### v0.1.2
- Initial public release — dashboard, credentials harvester, anomaly engine, Gemini AI shell

---

## 🔒 Security & Privacy

1. **100% Local Processing** — All packet parsing, filtering, and storage happens on your machine. Raw PCAP data never leaves.
2. **Minified AI Context** — Neither Gemini nor Claude ever receive raw binary packet data. They only receive structured text metadata (IPs, hostnames, domain names, alert titles). In Ensemble Mode, Claude additionally receives a text-formatted list of matched packet headers — never raw payloads.
3. **HTTPS Limitation** — AuraSniff cannot decrypt TLS/HTTPS (port 443) traffic without a session key log. To capture credentials, use HTTP, FTP, SMTP, or local unencrypted services.

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.
