# ⚡ AuraSniff

<p align="center">
  <img src="https://raw.githubusercontent.com/vatsalgargg/aurasniff/master/assets/logo.png" alt="AuraSniff Logo" width="180" onerror="this.style.display='none'"/>
</p>

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

**AuraSniff** is a lightweight, zero-dependency command-line interface (CLI) that brings advanced network forensics and artificial intelligence to your terminal. It parses `.pcap` and `.pcapng` files locally without relying on heavy external software or standard Wireshark installations, computes connection metrics, extracts cleartext login credentials, and features a chat shell where you can query your network captures in natural language using Gemini.

---

## 🚀 Core Features

* **⚡ Zero-Dependency Dissection**: Streams and parses capture files locally using Scapy. You don't need Wireshark or `tshark` installed.
* **🔑 Credentials Harvester**: Automatically intercepts and displays cleartext logins across HTTP-POST, FTP, SMTP, POP3, and IMAP payloads.
* **🚨 Security Anomaly Engine**: Identifies network anomalies in real-time, including:
  * **Port Scanning**: Highlights hosts hitting multiple distinct ports in short intervals.
  * **ARP Spoofing**: Detects multiple MAC addresses claiming the same IP.
  * **DNS Tunneling**: Flagging abnormally long, high-entropy query names (indicative of C2/Exfiltration).
  * **Cleartext passwords**: Warns you about insecure login transmissions.
* **💬 Gemini AI Chat REPL**: Launch an interactive shell to ask questions like *"Who is scanning ports?"* or *"What did the device with IP 192.168.1.15 do?"*. Gemini translates your questions into local database search filters and answers in markdown.
* **🔍 Deep Hex Inspection**: Drill down into individual packets to view a structured tree of layers (Ethernet ➜ IP ➜ TCP ➜ Payload) alongside a color-coded side-by-side Hex & ASCII dump.

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
│ File Path:   home.pcapng                        ││ Protocol  Count  Ratio        │
│ Packets:     46                                 ││ TCP          42  91.3% ██████ │
│ Data Size:   3.2 KB                             ││ UDP           4   8.7% █░░░░░ │
│ Duration:    23.0 s                             │└───────────────────────────────┘
└─────────────────────────────────────────────────┘
┌───────────────────────── 🔑 Extracted Credentials ──────────────────────────┐
│ Pkt # │ Protocol  │ Source       │ Destination   │ Credentials Info         │
│   8   │ HTTP-POST │ 192.168.1.15 │ 93.184.216.34 │ User: admin / Pass: 123  │
│  13   │ FTP       │ 192.168.1.15 │ 192.168.1.5   │ User: admin / Pass: test │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Deep Packet Hexdissection (`detail 8`)
```text
Packet #8
├── Ether (dst=00:11:22:33:44:00, src=00:11:22:33:44:55, type=2048)
├── IP (version=4, ihl=5, proto=6, src=192.168.1.15, dst=93.184.216.34)
├── TCP (sport=49152, dport=80, flags=PA, window=8192)
└── Raw (load=b'POST /login HTTP/1.1\r\nHost: example.com...)

Raw Packet Hex/ASCII Dump:
0000  00 11 22 33 44 00 00 11  22 33 44 55 08 00 45 00  |.."3D..."3DU..E.|
0010  00 df 00 01 00 00 40 06  82 86 c0 a8 01 0f 5d b8  |......@.......].|
0020  d8 22 c0 00 00 50 00 00  00 00 00 00 00 00 50 18  |."...P........P.|
0030  20 00 f4 73 00 00 50 4f  53 54 20 2f 6c 6f 67 69  | ..s..POST /logi|
0040  n  20 48 54 54 50 2f 31  2e 31 0d 0a 48 6f 73 74  |n HTTP/1.1..Host|
0050  3a 20 65 78 61 6d 70 6c  65 2e 63 6f 6d 0d 0a 75  |: example.com..u|
```

---

## ⚙️ Installation

Install the package globally via pip:
```bash
pip install aurasniff
```

---

## 🛠️ Usage Guide

### 1. Interactive AI Chat Shell
Launch the prompt loop to inspect, query, and dissect the capture file:
```bash
aurasniff shell <path_to_file.pcap>
```
*   Type `dns` to show DNS lookup history.
*   Type `http` to see HTTP connections.
*   Type `creds` to print extracted credentials.
*   Type `alerts` to view detected threats.
*   Type `detail <pkt_index>` (e.g. `detail 8`) to run deep dissection and hex dumps.
*   Ask questions like: *"Did any local laptop connect to standard DNS servers?"* or *"Which host triggered the port scanning alert?"*

### 2. General Dashboard Scan
Generate a visual summary of the packet capture:
```bash
aurasniff analyze <path_to_file.pcap>
```

### 3. Quick AI Query
Run a single natural language question directly from your system command line:
```bash
aurasniff query <path_to_file.pcap> "explain the security alerts found"
```

### 4. Configure Gemini API Key
To enable the AI capabilities, save your Gemini API Key locally:
```bash
aurasniff config set-key <YOUR_GEMINI_API_KEY>
```
*Note: If no API key is saved, the tool falls back to a local offline keyword routing parser.*

---

## 🔒 Security & Privacy Disclosures

1. **Local Processing**: AuraSniff performs all packet parsing, dissection, database storage, and filtering **locally on your machine**. 
2. **Minified Context**: When utilizing the Gemini AI features, AuraSniff **does not upload your raw binary PCAP file**. Instead, it generates a minified text-based summary of metadata (hostnames, domain lookups, connection metrics, and alert titles) and sends only this summary alongside your prompt to the Gemini API. Your actual packet payloads remain 100% private.
3. **The HTTPS Limitation**: Like any passive packet sniffer, AuraSniff **cannot decrypt TLS/HTTPS traffic** (Port 443) without session keys. If you log in to a secure website like GitHub, the credentials will be encrypted before hitting the network interface. To test credential sniffing, capture traffic on unencrypted services (e.g., local development servers running HTTP, legacy router dashboards, or raw FTP).

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](file:///V:/VG/websites/packet-analyzer/LICENSE) file for details.
