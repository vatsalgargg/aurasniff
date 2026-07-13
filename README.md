# AuraSniff

[![PyPI version](https://img.shields.io/pypi/v/aurasniff.svg)](https://pypi.org/project/aurasniff/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Repository](https://img.shields.io/badge/GitHub-Repository-blue.svg)](https://github.com/vatsalgargg/aurasniff)

**AuraSniff** is a premium, interactive terminal-based network packet capture (PCAP) analyzer. It extracts key protocol features, automatically hunts down cleartext credentials, scans for security anomalies (like port scans, ARP spoofing, and DNS tunneling), and lets you query your network capture files in natural language using the Gemini AI API.

---

## Features

* **⚡ Offline PCAP parsing**: Streams and parses `.pcap` and `.pcapng` files locally without relying on external servers or a local Wireshark installation.
* **🔑 Automatic Credentials Harvester**: Instantly pulls cleartext logins from SMTP, POP3, IMAP, FTP, and HTTP POST forms.
* **🚨 Threat & Anomaly Engine**: Detects port scanning, ARP anomalies, and DNS tunneling indicators right from the dashboard.
* **💻 Interactive AI Chat Shell**: Connect your Gemini API Key to talk with your PCAP file. Type questions like *"Find traffic from John's iPad"* or *"Is there any suspicious port scanning?"* and let Gemini build search filters to query the packet log.
* **🔍 Deep Packet Inspection**: Explores packet layer hierarchies and side-by-side colorized hex-ASCII payload dumps directly in the terminal.

---

## Installation

AuraSniff can be installed directly from PyPI:

```bash
pip install aurasniff
```

---

## Quick Start

### 1. Run Complete Dashboard Analysis
To parse a PCAP file and output a comprehensive console dashboard:
```bash
aurasniff analyze <path_to_file.pcap>
```

### 2. Configure Gemini API Key (Optional)
To use natural language queries, configure your Gemini API key:
```bash
aurasniff config set-key <YOUR_GEMINI_API_KEY>
```
*Note: If no key is set, AuraSniff defaults to a local keyword/rule-based search fallback.*

### 3. Open Interactive AI Prompt Shell
Launch the shell REPL:
```bash
aurasniff shell <path_to_file.pcap>
```
**Example Commands Inside Shell:**
* `creds` - Show all captured passwords.
* `dns` - View DNS lookups.
* `detail 45` - Deep inspect packet #45.
* *"Which website did the device with IP 192.168.1.15 contact?"*
* *"Who is scanning ports?"*

### 4. Single-Query Command
Ask a quick question from standard command line:
```bash
aurasniff query <path_to_file.pcap> "what HTTP log-ins did you find?"
```

---

## License

Distributed under the MIT License. See `LICENSE` for more information.
