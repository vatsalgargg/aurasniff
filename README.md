# ⚡ AuraSniff


<p align="center">
  <b>A premium, interactive terminal-based network packet capture (PCAP) analyzer with built-in Gemini AI assistance.</b>
</p>

<p align="center">
  <a href="https://pypi.org/project/aurasniff/"><img src="https://img.shields.io/pypi/v/aurasniff.svg?style=for-the-badge&color=blue" alt="PyPI version"/></a>
  <a href="https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&color=green"><img src="https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&color=green" alt="Python Support"/></a>
  <a href="https://github.com/vatsalgargg/aurasniff/blob/master/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License: MIT"/></a>
  <a href="https://github.com/vatsalgargg/aurasniff"><img src="https://img.shields.io/github/stars/vatsalgargg/aurasniff.svg?style=for-the-badge&color=gold" alt="GitHub stars"/></a>
</p>

---

## 🌟 Introduction

**AuraSniff** is a lightweight command-line interface (CLI) that brings advanced network forensics and artificial intelligence to your terminal. It parses `.pcap` and `.pcapng` files locally without relying on Wireshark or `tshark`, computes connection metrics, extracts cleartext login credentials, maps which websites each IP address visited, and features a chat shell where you can query your network captures in natural language using Gemini.

---

## 🚀 Core Features

* **⚡ Zero-Dependency Dissection**: Streams and parses capture files locally using Scapy. No Wireshark needed.
* **🌐 IP → Website Map**: Instantly see which websites every IP address in your capture was visiting — built from DNS queries, HTTP Host headers, and TLS/HTTPS SNI names combined.
* **🔑 Credentials Harvester**: Automatically intercepts and displays cleartext logins across HTTP-POST, FTP, SMTP, POP3, and IMAP payloads.
* **🚨 Security Anomaly Engine**: Identifies network anomalies including:
  * **Port Scanning**: Highlights hosts hitting multiple distinct ports.
  * **ARP Spoofing**: Detects multiple MAC addresses claiming the same IP.
  * **DNS Tunneling**: Flags abnormally long, high-entropy query names (indicative of C2/Exfiltration).
  * **Cleartext passwords**: Warns about insecure login transmissions.
* **💬 Gemini AI Chat REPL**: Launch an interactive shell to ask questions like *"Who is scanning ports?"*, *"What websites did 192.168.1.15 visit?"*, or *"Are there any suspicious hosts?"*. Gemini translates your questions into local search filters and answers in markdown.
* **🔍 Deep Hex Inspection**: Drill into individual packets to view a structured layer tree (Ethernet → IP → TCP → Payload) alongside a color-coded Hex & ASCII dump.
* **🧠 Smart Offline Fallback**: No API key? The tool still intelligently routes natural language queries to the right view — credentials, alerts, websites, DNS, HTTP, or raw packet filter.

---

## 🎨 Visual Preview

AuraSniff's terminal interface is built with `Rich` for a clean, cyber-neon theme:

### The Dashboard (`aurasniff analyze`)
```text
┌─────────────────────────────────────────────────────────────────────────────┐
│ ▲ AURA SNIFF PCAP ANALYZER ▲                                               │
│ Premium Command Line Traffic Inspector & AI Security Assistant             │
└─────────────────────────────────────────────────────────────────────────────┘
┌──────────────── Capture Summary ────────────────┐┌──── Protocol Distribution ────┐
│ File Path:   capture.pcapng                     ││ Protocol  Count  Ratio        │
│ Packets:     5,312                              ││ TCP       4,821  90.8% ██████ │
│ Data Size:   3.41 MB                            ││ UDP         391   7.4% █░░░░░ │
│ Duration:    62.3 s                             │└───────────────────────────────┘
└─────────────────────────────────────────────────┘
┌───────────────────────── 🔑 Extracted Credentials ──────────────────────────┐
│ Pkt # │ Protocol  │ Source      │ Destination  │ Credentials Info            │
│   42  │ HTTP-POST │ 10.0.0.101  │ 203.0.113.10 │ User: john / Pass: p@ssw0rd │
│   87  │ FTP       │ 10.0.0.101  │ 10.0.0.5     │ User: ftpuser / Pass: secret│
└─────────────────────────────────────────────────────────────────────────────┘
```

### IP → Website Map (`websites`)
```text
┌──────────────────────────────────── 🌐 IP → Website Map ────────────────────────────────────┐
│ Source IP    │ Device Name  │ DNS Queries           │ TLS / HTTPS Sites                      │
│──────────────│──────────────│───────────────────────│────────────────────────────────────────│
│ 10.0.0.101   │ OFFICE-PC    │ google.com            │ github.com                             │
│              │              │ stackoverflow.com      │ api.github.com                         │
│ 10.0.0.102   │ WORK-LAPTOP  │ youtube.com           │ accounts.google.com                    │
│              │              │ reddit.com            │ mail.google.com                         │
└──────────────────────────────────────────────────────────────────────────────────────────────┘
  2 IP addresses shown
```

### Deep Packet Hex Dissection (`detail 8`)
```text
Packet #42
├── Ether (dst=aa:bb:cc:dd:ee:01, src=aa:bb:cc:dd:ee:02, type=2048)
├── IP (version=4, ihl=5, proto=6, src=10.0.0.101, dst=203.0.113.10)
├── TCP (sport=51423, dport=80, flags=PA, window=8192)
└── Raw (load=b'POST /login HTTP/1.1\r\nHost: example.com...)

0000  aa bb cc dd ee 01 aa bb  cc dd ee 02 08 00 45 00  |..............E.|
0010  00 df 00 01 00 00 40 06  7c 9a 0a 00 00 65 cb 00  |......@.|....e..|
```

---

## ⚙️ Installation

Install the base package (includes Gemini AI support):
```bash
pip install aurasniff
```

Add Claude (Anthropic) support:
```bash
pip install aurasniff[claude]
```

Add OpenAI GPT-4o support:
```bash
pip install aurasniff[openai]
```

Install everything at once:
```bash
pip install aurasniff[all]
```

---

## 🛠️ Usage Guide

### 1. Interactive AI Chat Shell
Launch the prompt loop to inspect, query, and dissect a capture file:
```bash
aurasniff shell <path_to_file.pcap>
```

#### Shell Commands

| Command | Description |
|---|---|
| `websites` | Show all IPs and every website they visited (DNS + HTTP + TLS) |
| `websites <IP>` | Filter website map to a specific IP or device hostname |
| `dns` | Show full DNS query log |
| `http` | Show HTTP connections and status codes |
| `creds` | Print intercepted credentials |
| `alerts` | View detected security anomalies |
| `detail <N>` | Deep hex dissection of packet #N (e.g. `detail 42`) |
| `exit` / `q` | Exit the shell |
| *any question* | Ask Gemini AI in natural language |

#### Natural Language Examples (with or without Gemini key)
```
Which websites is 10.0.0.101 visiting?
Show me browsing history for the laptop
Is there any suspicious traffic?
Find login credentials
What did the device on 10.0.0.5 do?
Show DNS queries from 10.0.0.102
```

### 2. General Dashboard Scan
Generate a visual summary of the capture:
```bash
aurasniff analyze <path_to_file.pcap>
```

### 3. Quick AI Query
Run a single natural language question directly from your terminal:
```bash
aurasniff query <path_to_file.pcap> "which websites did each IP visit?"
```

### 4. Configure Gemini API Key
To enable AI capabilities, save your API key (stored securely in the OS keychain):
```bash
# Gemini (included by default)
aurasniff config set-key <GEMINI_KEY>

# Claude (requires pip install aurasniff[claude])
aurasniff config set-key <CLAUDE_KEY> --provider claude

# OpenAI GPT-4o (requires pip install aurasniff[openai])
aurasniff config set-key <OPENAI_KEY> --provider openai

# Switch the active provider
aurasniff config set-provider claude

# View all configured keys
aurasniff config show
```
> **Security:** Keys are stored in the **OS keychain** (Windows Credential Manager / macOS Keychain / Linux Secret Service), never written to disk in plain text. Environment variables (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) are also supported for CI/CD use.

---

## 📋 Changelog

### v0.1.4 — Latest
**New Features**
- 🤖 **Multi-provider AI**: Claude (`claude-3-5-haiku`) and GPT-4o (`gpt-4o-mini`) supported alongside Gemini
- 🔐 **Secure key storage**: API keys stored in OS keychain via `keyring` — never written to disk in plain text
- 🔁 **Auto-fallback**: If default provider key is missing, automatically switches to next available provider
- 🎨 **Dynamic shell prompt**: Shows active provider `[Gemini]` / `[Claude]` / `[GPT-4o]` / `[Offline]`
- 📦 **Optional extras**: `pip install aurasniff[claude]`, `[openai]`, `[all]` — lighter default install
- ⚙️ New config commands: `set-key --provider`, `set-provider`, enhanced `show`

### v0.1.3
- 🌐 IP → Website Map, `websites` shell command, 7 bug fixes

### v0.1.2
- Initial public release with dashboard, credentials harvester, anomaly engine, and Gemini AI shell

---

## 🔒 Security & Privacy Disclosures

1. **Local Processing**: AuraSniff performs all packet parsing, dissection, database storage, and filtering **locally on your machine**. 
2. **Minified Context**: When utilizing the Gemini AI features, AuraSniff **does not upload your raw binary PCAP file**. Instead, it generates a minified text-based summary of metadata (hostnames, domain lookups, connection metrics, and alert titles) and sends only this summary alongside your prompt to the Gemini API. Your actual packet payloads remain 100% private.
3. **The HTTPS Limitation**: Like any passive packet sniffer, AuraSniff **cannot decrypt TLS/HTTPS traffic** (Port 443) without session keys. If you log in to a secure website like GitHub, the credentials will be encrypted before hitting the network interface. To test credential sniffing, capture traffic on unencrypted services (e.g., local development servers running HTTP, legacy router dashboards, or raw FTP).

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
