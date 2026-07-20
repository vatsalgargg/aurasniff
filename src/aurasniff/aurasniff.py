import os
import sys
import json
import argparse
import re
from pathlib import Path

# Force standard streams to use UTF-8 to prevent charmap codec errors on Windows console
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt

# Import local modules (relative package imports)
from .pcap_parser import PCAPParser
from . import terminal_ui

console = Console()
CONFIG_FILE = Path.home() / ".aurasniff.json"

def load_config():
    """Loads non-sensitive config (provider preference) from ~/.aurasniff.json."""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(config):
    """Saves non-sensitive config to ~/.aurasniff.json."""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        console.print(f"[bold red]Error saving config:[/] {e}")
        return False

# ── Secure Key Storage ─────────────────────────────────────────────────────────
# API keys are stored in the OS keychain (Windows Credential Manager / macOS
# Keychain / Linux Secret Service) via the `keyring` library.  The JSON config
# file is only used as a fallback for headless / server environments where no
# keychain daemon is available.  Keys are NEVER logged or printed in full.

KEYRING_SERVICE = "aurasniff"

_PROVIDER_ENV_VARS = {
    "gemini": "GEMINI_API_KEY",
    "claude": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
}

_PROVIDER_DISPLAY = {
    "gemini": "Gemini",
    "claude": "Claude",
    "openai": "GPT-4o",
}

_PROVIDER_COLORS = {
    "gemini": "green",
    "claude": "yellow",
    "openai": "cyan",
}

def _store_key_secure(provider, api_key):
    """
    Store an API key securely.
    Tries OS keychain first (keyring), falls back to JSON config file.
    """
    try:
        import keyring
        keyring.set_password(KEYRING_SERVICE, provider, api_key)
        return True
    except Exception:
        pass
    # Fallback: plain JSON file (works on headless servers / CI)
    config = load_config()
    config[f"{provider}_api_key"] = api_key
    return save_config(config)

def _get_key_secure(provider):
    """
    Retrieve an API key for the given provider.
    Priority: environment variable -> OS keychain -> JSON config file.
    Keys are never stored in module-level globals or logged in plain text.
    """
    # 1. Environment variable — highest priority, ideal for CI/CD pipelines
    env_key = os.environ.get(_PROVIDER_ENV_VARS.get(provider, ""))
    if env_key:
        return env_key

    # 2. OS keychain — most secure for interactive desktop use
    try:
        import keyring
        key = keyring.get_password(KEYRING_SERVICE, provider)
        if key:
            return key
    except Exception:
        pass

    # 3. Fallback: plain JSON config file
    config = load_config()
    return config.get(f"{provider}_api_key") or None

def get_active_provider():
    """
    Returns (provider_name, api_key) for the configured default provider.
    
    Special case: if both 'gemini' and 'claude' keys are present and the
    configured provider is not explicitly a single provider, returns
    ('ensemble', None) to signal the dual-LLM collaborative mode.
    
    Returns (None, None) when no key is configured anywhere.
    """
    config  = load_config()
    default = config.get("default_provider", "auto")

    # Explicit ensemble request
    if default == "ensemble":
        gemini_key = _get_key_secure("gemini")
        claude_key = _get_key_secure("claude")
        if gemini_key and claude_key:
            return "ensemble", None
        # Degrade gracefully if only one key is available
        if gemini_key:
            console.print("[bold yellow]Ensemble mode selected but Claude key not found — using Gemini only.[/]")
            return "gemini", gemini_key
        if claude_key:
            console.print("[bold yellow]Ensemble mode selected but Gemini key not found — using Claude only.[/]")
            return "claude", claude_key
        return None, None

    # Auto-detect ensemble: if both Gemini & Claude are configured and no
    # explicit single-provider preference is set, activate ensemble automatically.
    if default == "auto":
        gemini_key = _get_key_secure("gemini")
        claude_key = _get_key_secure("claude")
        if gemini_key and claude_key:
            return "ensemble", None
        if gemini_key:
            return "gemini", gemini_key
        if claude_key:
            return "claude", claude_key
        # Try OpenAI as last resort
        openai_key = _get_key_secure("openai")
        if openai_key:
            return "openai", openai_key
        return None, None

    # Explicit single-provider
    key = _get_key_secure(default)
    if key:
        return default, key

    # Auto-fallback to the next available provider
    for provider in ("gemini", "claude", "openai"):
        if provider == default:
            continue
        key = _get_key_secure(provider)
        if key:
            console.print(f"[dim]Note: '{default}' key not found — using '{provider}' instead.[/]")
            return provider, key

    return None, None

def run_parser_with_progress(filepath):
    """
    Parses a PCAP file while displaying a beautiful Rich progress bar.
    """
    if not os.path.exists(filepath):
        console.print(f"[bold red]Error:[/] PCAP file not found at '{filepath}'")
        sys.exit(1)

    parser = PCAPParser(filepath)
    
    console.print(f"[bold blue]Opening:[/] {os.path.basename(filepath)}")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Parsing packets...", total=None)
        
        def update_progress(count):
            progress.update(task, description=f"[cyan]Parsed {count:,} packets...", advance=500)

        parser.parse(progress_callback=update_progress)
        progress.update(task, description=f"[green]Successfully parsed {parser.total_packets:,} packets!")

    return parser

def filter_packets_locally(parser, query_dict):
    """
    Filters packets based on a structured query dictionary.
    Keys can be: src, dst, proto, port, text
    """
    filtered = []
    src   = query_dict.get("src")
    dst   = query_dict.get("dst")
    proto = query_dict.get("proto")
    port  = query_dict.get("port")
    text  = query_dict.get("text")

    for pkt in parser.packets_summary:
        if src:
            src_ip_match   = (src.lower() in pkt["src"].lower())
            src_host_match = False
            if pkt["src"] in parser.ip_to_hostname:
                src_host_match = (src.lower() in parser.ip_to_hostname[pkt["src"]].lower())
            if not (src_ip_match or src_host_match):
                continue

        if dst:
            dst_ip_match   = (dst.lower() in pkt["dst"].lower())
            dst_host_match = False
            if pkt["dst"] in parser.ip_to_hostname:
                dst_host_match = (dst.lower() in parser.ip_to_hostname[pkt["dst"]].lower())
            if not (dst_ip_match or dst_host_match):
                continue

        if proto and proto.lower() != pkt["proto"].lower():
            continue

        if port:
            # BUG FIX: info format is "TCP: <sport> -> <dport> [flags]" or "UDP: <sport> -> <dport>"
            # The old ":port" pattern never matched this format.
            # Correct patterns: port as source (" <port> ->") or as destination ("-> <port>" or "-> <port> [").
            port_s  = str(port)
            info    = pkt["info"]
            sport_match = f" {port_s} ->" in info
            dport_match = (f"-> {port_s} " in info or info.endswith(f"-> {port_s}") or f"-> {port_s}[" in info)
            if not (sport_match or dport_match):
                continue

        # BUG FIX: only search info field for text, not proto — proto is too short and causes
        # false negatives (e.g. searching "github" skips all TCP packets not matching "github" in "TCP")
        if text and text.lower() not in pkt["info"].lower():
            continue

        filtered.append(pkt)

    return filtered

def run_local_fallback_query(parser, query):
    """
    If no API key is available, run basic keyword-based matching rules.
    """
    query_lower = query.lower()

    # BUG FIX: "user" alone was too broad (matched "issue", etc.).
    # Now check for more specific credential-related terms.
    if ("cred" in query_lower or "password" in query_lower or "passwd" in query_lower
            or "login" in query_lower or "username" in query_lower
            or ("pass" in query_lower and "passive" not in query_lower)):
        console.print("[bold yellow]Running Local Fallback: Displaying extracted credentials...[/]")
        if parser.credentials:
            cred_table = terminal_ui.Table(show_header=True, header_style="bold green")
            cred_table.add_column("Pkt #")
            cred_table.add_column("Proto")
            cred_table.add_column("Source")
            cred_table.add_column("Destination")
            cred_table.add_column("Details")
            for c in parser.credentials:
                cred_table.add_row(str(c["index"]), c["protocol"], c["src"], c["dst"], c["info"])
            console.print(cred_table)
        else:
            console.print("No credentials found in packet payloads.")
        return

    if ("suspect" in query_lower or "suspicious" in query_lower or "alert" in query_lower
            or "threat" in query_lower or "attack" in query_lower or "anomaly" in query_lower
            or "malicious" in query_lower or "intrusion" in query_lower):
        console.print("[bold yellow]Running Local Fallback: Displaying security alerts...[/]")
        if parser.alerts:
            alert_table = terminal_ui.Table(show_header=True, header_style="bold red")
            alert_table.add_column("Severity")
            alert_table.add_column("Anomalous Activity")
            alert_table.add_column("Source IP")
            alert_table.add_column("Details")
            for alert in parser.alerts:
                alert_table.add_row(alert["severity"], alert["type"], alert["source"], alert["description"])
            console.print(alert_table)
        else:
            console.print("No alerts or security anomalies detected.")
        return

    # NEW: website/browsing queries — route to IP→website map
    website_keywords = (
        "website", "sites", "browsing", "browse", "visited", "visiting",
        "internet", "domain", "domains", "surf", "browsed", "what is",
        "which site", "history"
    )
    if any(kw in query_lower for kw in website_keywords):
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query)
        target_ip = ip_match.group(0) if ip_match else None
        msg = f"IP {target_ip}" if target_ip else "all IPs"
        console.print(f"[bold yellow]Running Local Fallback: Showing websites visited by {msg}...[/]")
        ip_website_map = parser.get_ip_website_map()
        terminal_ui.render_ip_websites_table(ip_website_map, target_ip=target_ip)
        return

    if "dns" in query_lower or "lookup" in query_lower or "nslookup" in query_lower:
        console.print("[bold yellow]Running Local Fallback: Displaying DNS log...[/]")
        terminal_ui.render_dns_table(parser.dns_queries[:40])
        return

    if "http" in query_lower or "url" in query_lower:
        console.print("[bold yellow]Running Local Fallback: Displaying HTTP log...[/]")
        terminal_ui.render_http_table(parser.http_traffic[:40])
        return

    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query)
    if ip_match:
        ip = ip_match.group(0)
        console.print(f"[bold yellow]Running Local Fallback: Filtering for IP {ip}...[/]")
        filtered = filter_packets_locally(parser, {"src": ip}) + filter_packets_locally(parser, {"dst": ip})
        seen = set()
        unique_filtered = []
        for p in filtered:
            if p["index"] not in seen:
                seen.add(p["index"])
                unique_filtered.append(p)
        terminal_ui.render_packets_list(unique_filtered[:50], parser)
        return

    console.print(f"[bold yellow]Running Local Fallback: Searching packets for '{query}'...[/]")
    filtered = filter_packets_locally(parser, {"text": query})
    if filtered:
        terminal_ui.render_packets_list(filtered[:50], parser)
    else:
        console.print("No matching packets found. (Set a Gemini API key for advanced natural language query support!)")

# ── Shared AI helpers ─────────────────────────────────────────────────────────

def _build_system_prompt(parser):
    """Build the structured PCAP context sent to every AI provider."""
    stats         = parser.get_summary_statistics()
    dhcp_summary  = [f"{ip} -> {name}" for ip, name in parser.ip_to_hostname.items()]
    alerts_sum    = [f"[{a['severity']}] {a['type']}: {a['description']}" for a in parser.alerts]
    sorted_convs  = sorted(parser.connections.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
    convs_sum     = [f"{s} -> {d} via {p} ({c['packets']} pkts, {terminal_ui.format_size(c['bytes'])})" for (s, d, p), c in sorted_convs]
    creds_sum     = [f"{c['protocol']} creds at {c['src']}->{c['dst']}: {c['username']} / {c['password']}" for c in parser.credentials]
    dns_sum       = [f"{d['src']} lookup '{d['qname']}' -> '{d['answers']}'" for d in parser.dns_queries[:25]]
    http_sum      = [f"{h['src']} -> {h['host']} {h['method']} {h['path']} [{h['status']}]" for h in parser.http_traffic[:25]]
    tls_sum       = [f"{t['src']} -> SNI: {t['host']}" for t in parser.tls_traffic[:25]]

    ip_map = parser.get_ip_website_map()
    ip_web_sum = []
    for ip, data in list(ip_map.items())[:20]:
        name_part = f" ({data['hostname']})" if data.get("hostname") else ""
        sites = list(dict.fromkeys(
            data.get("dns", [])[:6] + data.get("tls", [])[:6] + data.get("http", [])[:4]
        ))[:10]
        if sites:
            ip_web_sum.append(f"{ip}{name_part} visited: {', '.join(sites)}")

    return f"""You are AuraSniff AI, a premium network security analysis assistant.
You are helping the user inspect a packet capture (PCAP/PCAPNG) file.
Analyze the following structured capture summary and answer the user's question.

CRITICAL INSTRUCTIONS:
1. Provide a clear, expert, and concise explanation in Markdown format.
2. If the user's question implies filtering or showing matching packets, you MUST output a structured filter JSON block at the very end of your response, strictly inside a code block marked with ```json.
The JSON must follow this schema:
{{
  "filter": {{
    "src": "optional source IP or hostname",
    "dst": "optional destination IP or hostname",
    "proto": "optional protocol name e.g. TCP, UDP, DNS, HTTP, ICMP",
    "port": optional_port_integer,
    "text": "optional text search keyword"
  }}
}}
Do not write anything else in that JSON block. Omit it entirely if no packet list needs to be shown.

Capture Summary:
- File: {os.path.basename(parser.filepath)}
- Total Packets: {stats['total_packets']:,}
- Total Bytes: {terminal_ui.format_size(stats['total_bytes'])}
- Duration: {stats['duration']} s
- Protocols: {stats['protocols_count']}
- Security Alerts: {alerts_sum}
- Credentials: {creds_sum}
- DHCP Hostnames: {dhcp_summary}
- Top Conversations: {convs_sum}
- IP -> Website Map: {ip_web_sum}
- DNS Queries (recent 25): {dns_sum}
- HTTP Requests (recent 25): {http_sum}
- TLS SNI (recent 25): {tls_sum}
"""

def _extract_json_filter(text_response):
    """Parse optional JSON filter block from AI response. Returns (clean_text, filter_dict)."""
    json_filter = None
    json_match  = re.search(r'```json\s*(\{.*?\})\s*```', text_response, re.DOTALL)
    if json_match:
        try:
            json_filter   = json.loads(json_match.group(1))
            text_response = text_response.replace(json_match.group(0), "").strip()
        except Exception:
            pass
    return text_response, json_filter

# ── Per-provider query functions ───────────────────────────────────────────────

def query_gemini(api_key, parser, user_prompt):
    """Query Google Gemini (gemini-2.5-flash)."""
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        console.print("[bold red]Error:[/] google-genai missing. Run: pip install google-genai")
        return None, None

    client = genai.Client(api_key=api_key)
    try:
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=_build_system_prompt(parser),
                temperature=0.2
            )
        )
    except Exception as e:
        console.print(f"[bold red]Gemini API Error:[/] {e}")
        return None, None

    return _extract_json_filter(response.text)

def query_claude(api_key, parser, user_prompt):
    """Query Anthropic Claude (claude-3-5-haiku-20241022)."""
    try:
        import anthropic
    except ImportError:
        console.print("[bold red]Error:[/] anthropic missing. Run: pip install anthropic")
        return None, None

    client = anthropic.Anthropic(api_key=api_key)
    try:
        message = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=2048,
            temperature=0.2,
            system=_build_system_prompt(parser),
            messages=[{"role": "user", "content": user_prompt}]
        )
        text_response = message.content[0].text
    except Exception as e:
        console.print(f"[bold red]Claude API Error:[/] {e}")
        return None, None

    return _extract_json_filter(text_response)

def query_openai(api_key, parser, user_prompt):
    """Query OpenAI (gpt-4o-mini)."""
    try:
        from openai import OpenAI
    except ImportError:
        console.print("[bold red]Error:[/] openai missing. Run: pip install openai")
        return None, None

    client = OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": _build_system_prompt(parser)},
                {"role": "user",   "content": user_prompt}
            ]
        )
        text_response = response.choices[0].message.content
    except Exception as e:
        console.print(f"[bold red]OpenAI API Error:[/] {e}")
        return None, None

    return _extract_json_filter(text_response)

_PROVIDER_QUERY_FN = {
    "gemini": query_gemini,
    "claude": query_claude,
    "openai": query_openai,
}

_PROVIDER_DISPLAY["ensemble"] = "Gemini ⚡ Claude Ensemble"
_PROVIDER_COLORS["ensemble"]  = "magenta"

def _format_packets_for_claude(packets, parser, max_packets=30):
    """
    Build a compact human-readable text representation of filtered packets
    to send to Claude for deep forensic analysis.
    """
    lines = []
    for pkt in packets[:max_packets]:
        line = (
            f"[#{pkt['index']}] {pkt['proto']} | "
            f"{pkt['src']} → {pkt['dst']} | "
            f"{pkt['length']}B | {pkt['info']}"
        )
        # Attach DHCP hostname if available
        src_host = parser.ip_to_hostname.get(pkt["src"])
        dst_host = parser.ip_to_hostname.get(pkt["dst"])
        if src_host or dst_host:
            line += f" | hosts: {src_host or '?'} → {dst_host or '?'}"
        lines.append(line)
    return "\n".join(lines)

def handle_ensemble_query(parser, query):
    """
    Collaborative Dual-LLM query pipeline:
      1. Gemini  → fast PCAP-wide analysis + extract a packet filter
      2. Local   → apply filter, retrieve exact matching packets
      3. Claude  → deep forensic analysis on the matched packets + Gemini's overview
    """
    gemini_key = _get_key_secure("gemini")
    claude_key = _get_key_secure("claude")

    # ── Step 1: Gemini fast scan ──────────────────────────────────────────────
    console.print(Panel(
        "[bold green]Step 1/2[/] — [cyan]Gemini[/] scanning the full capture for relevant traffic…",
        border_style="green", expand=False
    ))
    with console.status("[cyan]Gemini analysing capture…", spinner="dots"):
        gemini_text, filter_dict = query_gemini(gemini_key, parser, query)

    if not gemini_text:
        console.print("[bold red]Gemini failed.[/] Falling back to Claude-only mode…")
        explanation, filter_dict = query_claude(claude_key, parser, query)
        if explanation:
            console.print(Panel(explanation, title="AuraSniff AI  [Claude]", border_style="yellow"))
        else:
            run_local_fallback_query(parser, query)
        return

    # Show Gemini's overview briefly
    console.print(Panel(
        gemini_text,
        title="[green]Gemini Overview[/] (Step 1/2)",
        border_style="dim green"
    ))

    # ── Step 2: Apply Gemini's filter locally ─────────────────────────────────
    matched_packets = []
    if filter_dict and "filter" in filter_dict:
        criteria = filter_dict["filter"]
        console.print(f"[bold blue]Gemini filter:[/] {criteria}")
        matched_packets = filter_packets_locally(parser, criteria)
        if matched_packets:
            console.print(
                f"[green]{len(matched_packets)} packets matched.[/] Sending to Claude for deep analysis…"
            )
        else:
            console.print("[yellow]No packets matched the filter — Claude will analyse the full capture summary.[/]")

    # ── Step 3: Claude deep forensic analysis ────────────────────────────────
    console.print(Panel(
        "[bold yellow]Step 2/2[/] — [yellow]Claude[/] performing deep forensic analysis on matched packets…",
        border_style="yellow", expand=False
    ))

    packet_context = ""
    if matched_packets:
        packet_context = (
            f"\n\nThe following {len(matched_packets)} packets were retrieved by Gemini's filter "
            f"and are the focus of your deep analysis:\n"
            f"{_format_packets_for_claude(matched_packets, parser)}\n"
        )

    claude_prompt = (
        f"The user asked: {query}\n\n"
        f"Gemini's initial overview:\n{gemini_text}\n"
        f"{packet_context}\n"
        "Based on the above, provide a detailed expert forensic security analysis. "
        "Identify any malicious patterns, credential exposure, anomalous behaviours, "
        "attack vectors, or data exfiltration indicators. Use structured Markdown with "
        "clear headings, bullet points, and a final risk summary."
    )

    with console.status("[yellow]Claude performing forensic deep-dive…", spinner="dots"):
        claude_text, _ = query_claude(claude_key, parser, claude_prompt)

    if claude_text:
        console.print(Panel(
            claude_text,
            title="[magenta]⚡ AuraSniff Ensemble — Claude Forensic Report[/]",
            border_style="magenta"
        ))
    else:
        console.print("[bold red]Claude analysis failed.[/] Gemini overview above is your final result.")

    # Still show the filtered packet list for reference
    if matched_packets:
        console.print(f"[dim]Matched packets ({min(50, len(matched_packets))} of {len(matched_packets)}):[/]")
        terminal_ui.render_packets_list(matched_packets[:50], parser)

def handle_query(parser, query):
    provider, api_key = get_active_provider()

    if not provider:
        run_local_fallback_query(parser, query)
        return

    # Route to ensemble pipeline if both keys are available
    if provider == "ensemble":
        handle_ensemble_query(parser, query)
        return

    p_display = _PROVIDER_DISPLAY.get(provider, provider.title())
    query_fn  = _PROVIDER_QUERY_FN.get(provider, query_gemini)

    with console.status(f"[cyan]Asking {p_display}…", spinner="dots"):
        explanation, filter_dict = query_fn(api_key, parser, query)

    if explanation:
        console.print(Panel(explanation, title=f"AuraSniff AI  [{p_display}]", border_style="green"))

        if filter_dict and "filter" in filter_dict:
            criteria = filter_dict["filter"]
            console.print(f"[bold blue]AI Recommended Filter:[/] {criteria}")
            filtered = filter_packets_locally(parser, criteria)
            if filtered:
                console.print(f"[green]Showing {min(50, len(filtered))} of {len(filtered)} matching packets:[/]")
                terminal_ui.render_packets_list(filtered[:50], parser)
            else:
                console.print("[yellow]No packets matched the AI-recommended filter criteria.[/]")
    else:
        console.print(f"[bold red]Failed to get a response from {p_display}.[/] Running local fallback…")
        run_local_fallback_query(parser, query)


def run_shell(parser):
    # Render dashboard first for context
    stats = parser.get_summary_statistics()
    terminal_ui.render_dashboard(stats, parser)
    
    terminal_ui.render_shell_banner()
    active_provider, _ = get_active_provider()

    if active_provider:
        p_color   = _PROVIDER_COLORS.get(active_provider, "green")
        p_display = _PROVIDER_DISPLAY.get(active_provider, active_provider.title())
        prompt_str = f"\n[bold green]AuraSniff[/] [bold {p_color}]\\[{p_display}][/] "
    else:
        console.print("[bold yellow]Warning:[/] No AI provider key found. Running in offline mode.")
        console.print(
            "Set a key with: [cyan]aurasniff config set-key <KEY> --provider gemini|claude|openai[/]\n"
        )
        prompt_str = "\n[bold green]AuraSniff[/] [dim]\\[Offline][/] "

    while True:
        try:
            user_input = Prompt.ask(prompt_str).strip()
            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q"):
                console.print("[blue]Exiting AuraSniff AI Chat Shell. Goodbye![/]")
                break
            
            if user_input.lower() == "help":
                console.print("[bold white]Available Commands:[/]")
                console.print("  [cyan]exit/quit/q[/]        - Exit the interactive shell")
                console.print("  [cyan]detail <index>[/]     - Inspect layers and hexdump of packet #index (e.g. `detail 45`)")
                console.print("  [cyan]dns[/]                - Show parsed DNS log")
                console.print("  [cyan]http[/]               - Show parsed HTTP log")
                console.print("  [cyan]creds[/]              - Show extracted credentials")
                console.print("  [cyan]alerts[/]             - Show detected anomalies")
                console.print("  [cyan]websites[/]           - Show all IPs and the websites they visited")
                console.print("  [cyan]websites <IP>[/]      - Show websites visited by a specific IP or hostname")
                console.print("  [cyan]<any text>[/]         - Ask AuraSniff AI a question about the capture")
                continue

            detail_match = re.match(r'^detail\s+(\d+)$', user_input, re.IGNORECASE)
            if detail_match:
                index = int(detail_match.group(1))
                terminal_ui.render_packet_detail(index, parser.filepath)
                continue

            if user_input.lower() == "dns":
                terminal_ui.render_dns_table(parser.dns_queries[:50])
                continue
            if user_input.lower() == "http":
                terminal_ui.render_http_table(parser.http_traffic[:50])
                continue

            # NEW: websites command — show IP->website map
            websites_match = re.match(r'^websites(?:\s+(.+))?$', user_input, re.IGNORECASE)
            if websites_match:
                target_ip = (websites_match.group(1) or "").strip() or None
                ip_website_map = parser.get_ip_website_map()
                if not ip_website_map:
                    console.print("[yellow]No website activity (DNS/HTTP/TLS) found in this capture.[/]")
                else:
                    terminal_ui.render_ip_websites_table(ip_website_map, target_ip=target_ip)
                continue

            if user_input.lower() == "creds":
                if parser.credentials:
                    cred_table = terminal_ui.Table(show_header=True, header_style="bold green")
                    cred_table.add_column("Pkt #")
                    cred_table.add_column("Proto")
                    cred_table.add_column("Source")
                    cred_table.add_column("Destination")
                    cred_table.add_column("Details")
                    for c in parser.credentials:
                        cred_table.add_row(str(c["index"]), c["protocol"], c["src"], c["dst"], c["info"])
                    console.print(cred_table)
                else:
                    console.print("No credentials found.")
                continue
            if user_input.lower() == "alerts":
                if parser.alerts:
                    alert_table = terminal_ui.Table(show_header=True, header_style="bold red")
                    alert_table.add_column("Severity")
                    alert_table.add_column("Type")
                    alert_table.add_column("Source")
                    alert_table.add_column("Description")
                    for a in parser.alerts:
                        alert_table.add_row(a["severity"], a["type"], a["source"], a["description"])
                    console.print(alert_table)
                else:
                    console.print("No alerts found.")
                continue

            handle_query(parser, user_input)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[blue]Exiting shell.[/]")
            break

def main():
    # If the first argument looks like a pcap file or exists, default to 'shell' subcommand
    if len(sys.argv) > 1 and sys.argv[1] not in ("-h", "--help", "config", "analyze", "query", "shell"):
        arg = sys.argv[1]
        if arg.endswith((".pcap", ".pcapng", ".cap")) or os.path.exists(arg):
            sys.argv.insert(1, "shell")

    parser = argparse.ArgumentParser(
        description="AuraSniff: Interactive Command-Line PCAP Traffic & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    config_parser = subparsers.add_parser("config", help="Manage AI provider configuration")
    config_sub    = config_parser.add_subparsers(dest="config_action", help="Actions")

    set_key_parser = config_sub.add_parser("set-key", help="Save an API key (stored in OS keychain)")
    set_key_parser.add_argument("key", help="API key value")
    set_key_parser.add_argument(
        "--provider", "-p",
        choices=["gemini", "claude", "openai"],
        default="gemini",
        help="AI provider the key belongs to (default: gemini)"
    )

    set_prov_parser = config_sub.add_parser("set-provider", help="Set the default AI provider")
    set_prov_parser.add_argument(
        "provider",
        choices=["gemini", "claude", "openai", "ensemble", "auto"],
        help="Provider to use by default. 'ensemble' chains Gemini+Claude. 'auto' picks the best available."
    )

    config_sub.add_parser("show", help="Show all configured keys and the active provider")

    analyze_parser = subparsers.add_parser("analyze", help="Scan capture and show dashboard")
    analyze_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")

    query_parser = subparsers.add_parser("query", help="Ask a single question about the capture")
    query_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")
    query_parser.add_argument("question", help="Natural language question")

    shell_parser = subparsers.add_parser("shell", help="Launch interactive AI prompt shell")
    shell_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "config":
        if args.config_action == "set-key":
            provider = args.provider
            if _store_key_secure(provider, args.key):
                console.print(
                    f"[bold green]{_PROVIDER_DISPLAY.get(provider, provider.title())} API key saved![/]"
                    " [dim](stored in OS keychain — never written to disk in plain text)[/]"
                )
            else:
                console.print(f"[bold red]Failed to save {provider} API key.[/]")

        elif args.config_action == "set-provider":
            config = load_config()
            config["default_provider"] = args.provider
            if save_config(config):
                display = _PROVIDER_DISPLAY.get(args.provider, args.provider.title())
                console.print(f"[bold green]Default provider set to:[/] {display}")
            else:
                console.print("[bold red]Failed to save provider setting.[/]")

        elif args.config_action == "show":
            config          = load_config()
            active_prov, _  = get_active_provider()
            default_prov    = config.get("default_provider", "gemini")
            console.print(f"\n[bold cyan]AuraSniff — AI Provider Config[/]")
            console.print(
                f"  Active provider : [bold green]{_PROVIDER_DISPLAY.get(active_prov, 'None (Offline)') if active_prov else 'None (Offline)'}[/]"
            )
            console.print(f"  Default setting : [cyan]{default_prov}[/]\n")
            for prov, env_var in _PROVIDER_ENV_VARS.items():
                key = _get_key_secure(prov)
                if key:
                    masked = key[:6] + "•••" + key[-4:] if len(key) > 10 else "•" * 8
                    src    = "env var" if os.environ.get(env_var) else "keychain/config"
                    console.print(
                        f"  {prov.ljust(8)}: [green]{masked}[/] [dim]({src})[/]"
                    )
                else:
                    console.print(f"  {prov.ljust(8)}: [red]not configured[/]")
            console.print()

        else:
            config_parser.print_help()
        sys.exit(0)

    pcap_path = getattr(args, "pcap_file", None)
    if not pcap_path:
        console.print("[bold red]Error:[/] PCAP file path is required.")
        sys.exit(1)

    if not os.path.exists(pcap_path):
        console.print(f"[bold red]Error:[/] PCAP file not found at '{pcap_path}'")
        sys.exit(1)

    pcap_parser_inst = run_parser_with_progress(pcap_path)

    if args.command == "analyze":
        stats = pcap_parser_inst.get_summary_statistics()
        terminal_ui.render_dashboard(stats, pcap_parser_inst)
    elif args.command == "query":
        handle_query(pcap_parser_inst, args.question)
    elif args.command == "shell":
        run_shell(pcap_parser_inst)

if __name__ == "__main__":
    main()
