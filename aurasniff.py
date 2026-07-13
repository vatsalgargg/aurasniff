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

# Import local modules
from pcap_parser import PCAPParser
import terminal_ui

console = Console()
CONFIG_FILE = Path.home() / ".aurasniff.json"

def load_config():
    """
    Loads configuration (specifically the Gemini API key) from ~/.aurasniff.json
    """
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(config):
    """
    Saves configuration to ~/.aurasniff.json
    """
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        console.print(f"[bold red]Error saving config:[/] {e}")
        return False

def get_api_key():
    """
    Retrieves the Gemini API Key from environment or configuration
    """
    # 1. Check environment
    env_key = os.environ.get("GEMINI_API_KEY")
    if env_key:
        return env_key
    # 2. Check config file
    config = load_config()
    return config.get("gemini_api_key")

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
        # Since we don't know the exact packet count, we display a spinner and increment count
        task = progress.add_task("[cyan]Parsing packets...", total=None)
        
        def update_progress(count):
            progress.update(task, description=f"[cyan]Parsed {count:,} packets...", advance=500)

        parser.parse(progress_callback=update_progress)
        # Final update
        progress.update(task, description=f"[green]Successfully parsed {parser.total_packets:,} packets!")

    return parser

def filter_packets_locally(parser, query_dict):
    """
    Filters packets based on a structured query dictionary.
    Keys can be: src, dst, proto, port, text
    """
    filtered = []
    src = query_dict.get("src")
    dst = query_dict.get("dst")
    proto = query_dict.get("proto")
    port = query_dict.get("port")
    text = query_dict.get("text")

    for pkt in parser.packets_summary:
        # Match source IP / Hostname
        if src:
            src_ip_match = (src.lower() in pkt["src"].lower())
            src_host_match = False
            if pkt["src"] in parser.ip_to_hostname:
                src_host_match = (src.lower() in parser.ip_to_hostname[pkt["src"]].lower())
            if not (src_ip_match or src_host_match):
                continue

        # Match destination IP / Hostname
        if dst:
            dst_ip_match = (dst.lower() in pkt["dst"].lower())
            dst_host_match = False
            if pkt["dst"] in parser.ip_to_hostname:
                dst_host_match = (dst.lower() in parser.ip_to_hostname[pkt["dst"]].lower())
            if not (dst_ip_match or dst_host_match):
                continue

        # Match protocol
        if proto and proto.lower() != pkt["proto"].lower():
            continue

        # Match port
        if port:
            # Check info field or details for port numbers (a rough CLI filter)
            port_str = f":{port}"
            sport_str = f" {port} ->"
            dport_str = f"-> {port}"
            if not (port_str in pkt["info"] or sport_str in pkt["info"] or dport_str in pkt["info"]):
                continue

        # Match text in summary info
        if text and text.lower() not in pkt["info"].lower() and text.lower() not in pkt["proto"].lower():
            continue

        filtered.append(pkt)

    return filtered

def run_local_fallback_query(parser, query):
    """
    If no API key is available, run basic keyword-based matching rules.
    """
    query_lower = query.lower()
    
    # 1. Credentials
    if "cred" in query_lower or "pass" in query_lower or "login" in query_lower or "user" in query_lower:
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

    # 2. Suspicious Traffic / Alerts
    if "suspect" in query_lower or "suspicious" in query_lower or "alert" in query_lower or "threat" in query_lower or "attack" in query_lower or "anomaly" in query_lower:
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

    # 3. DNS
    if "dns" in query_lower or "domain" in query_lower or "lookup" in query_lower:
        console.print("[bold yellow]Running Local Fallback: Displaying DNS log...[/]")
        terminal_ui.render_dns_table(parser.dns_queries[:40])
        return

    # 4. HTTP
    if "http" in query_lower or "web" in query_lower or "url" in query_lower:
        console.print("[bold yellow]Running Local Fallback: Displaying HTTP log...[/]")
        terminal_ui.render_http_table(parser.http_traffic[:40])
        return

    # 5. IP Address search
    ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', query)
    if ip_match:
        ip = ip_match.group(0)
        console.print(f"[bold yellow]Running Local Fallback: Filtering for IP {ip}...[/]")
        filtered = filter_packets_locally(parser, {"src": ip}) + filter_packets_locally(parser, {"dst": ip})
        # Remove duplicates preserving order
        seen = set()
        unique_filtered = []
        for p in filtered:
            if p["index"] not in seen:
                seen.add(p["index"])
                unique_filtered.append(p)
        terminal_ui.render_packets_list(unique_filtered[:50], parser)
        return

    # 6. Generic Text Search on Info field
    console.print(f"[bold yellow]Running Local Fallback: Searching packets for '{query}'...[/]")
    filtered = filter_packets_locally(parser, {"text": query})
    if filtered:
        terminal_ui.render_packets_list(filtered[:50], parser)
    else:
        console.print("No matching packets found. (Set a Gemini API key for advanced natural language query support!)")

def query_gemini(api_key, parser, user_prompt):
    """
    Connects to the Gemini API using google-genai SDK, feeds structured PCAP details,
    and returns the text explanation + optional search filter.
    """
    try:
        from google import genai
        from google.genai import types
    except ImportError:
        console.print("[bold red]Error:[/] The google-genai library is missing. Install it using `pip install google-genai`.")
        return None, None

    # Compile a structured summary of the PCAP data to fit into the context window
    stats = parser.get_summary_statistics()
    
    # DHCP Map
    dhcp_summary = [f"{ip} -> {name}" for ip, name in parser.ip_to_hostname.items()]
    
    # Alerts
    alerts_summary = [f"[{a['severity']}] {a['type']}: {a['description']}" for a in parser.alerts]
    
    # Top Conversations
    sorted_convs = sorted(parser.connections.items(), key=lambda x: x[1]["bytes"], reverse=True)[:10]
    convs_summary = [f"{s} -> {d} via {p} ({c['packets']} pkts, {format_size(c['bytes'])})" for (s, d, p), c in sorted_convs]

    # Credentials
    creds_summary = [f"{c['protocol']} creds found at {c['src']} -> {c['dst']}: User: {c['username']} / Pass: {c['password']}" for c in parser.credentials]

    # DNS Logs (sample top or recent)
    dns_summary = [f"{dns['src']} lookup '{dns['qname']}' -> '{dns['answers']}'" for dns in parser.dns_queries[:25]]

    # HTTP Logs (sample recent)
    http_summary = [f"{http['src']} -> {http['host']} HTTP {http['method']} {http['path']} [Status: {http['status']}]" for http in parser.http_traffic[:25]]

    # TLS SNI Logs (sample recent)
    tls_summary = [f"{tls['src']} -> TLS Client Hello SNI: {tls['host']}" for tls in parser.tls_traffic[:25]]

    system_instruction = f"""You are AuraSniff AI, a premium network security analysis assistant.
You are helping the user inspect a packet capture (PCAP/PCAPNG) file.
Analyze the following structured capture summary and answer the user's question.

CRITICAL INSTRUCTIONS:
1. Provide a clear, expert, and concise explanation in Markdown format.
2. If the user's question implies filtering or showing matching packets (e.g. "show me DNS queries from 192.168.1.15", "list credentials", "what did the laptop talk to?"), you MUST output a structured filter JSON block at the very end of your response, strictly inside a code block marked with ```json.
The JSON must follow this schema:
{{
  "filter": {{
    "src": "optional source IP or hostname",
    "dst": "optional destination IP or hostname",
    "proto": "optional protocol name e.g. TCP, UDP, DNS, HTTP, ICMP",
    "port": optional_port_integer,
    "text": "optional text search keyword matching info summary"
  }}
}}
Do not write anything else in that JSON block. If no packet list needs to be shown, do not output the JSON filter.

Capture Summary details:
- File Name: {os.path.basename(parser.filepath)}
- Total Packets: {stats['total_packets']:,}
- Total Bytes: {format_size(stats['total_bytes'])}
- Duration: {stats['duration']} seconds
- Protocol Distribution: {stats['protocols_count']}
- Security Alerts: {alerts_summary}
- Extracted Credentials: {creds_summary}
- Hostname Resolution (DHCP): {dhcp_summary}
- Top Conversations: {convs_summary}
- Recent DNS queries: {dns_summary}
- Recent HTTP requests: {http_summary}
- Recent TLS SNI queries: {tls_summary}
"""

    client = genai.Client(api_key=api_key)
    
    try:
        # Use gemini-2.5-flash as the standard model (fast, high capabilities, low latency)
        # Note: the user's environment has google-genai installed, so this works out-of-the-box.
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=user_prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                temperature=0.2
            )
        )
    except Exception as e:
        console.print(f"[bold red]API Error:[/] {e}")
        return None, None

    text_response = response.text
    
    # Extract JSON filter block
    json_filter = None
    json_match = re.search(r'```json\s*(\{.*?\})\s*```', text_response, re.DOTALL)
    if json_match:
        try:
            json_filter = json.loads(json_match.group(1))
            # Remove the JSON code block from the user-facing text response to clean it up
            text_response = text_response.replace(json_match.group(0), "").strip()
        except Exception:
            pass

    return text_response, json_filter

def handle_query(parser, query):
    """
    Handles a query (either AI or local fallback).
    """
    api_key = get_api_key()
    
    if not api_key:
        run_local_fallback_query(parser, query)
        return

    # Query with Gemini
    with console.status("[cyan]Asking AuraSniff AI...", spinner="dots"):
        explanation, filter_dict = query_gemini(api_key, parser, query)

    if explanation:
        console.print(Panel(explanation, title="AuraSniff AI Assistant", border_style="green"))
        
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
        console.print("[bold red]Failed to get response from Gemini API.[/] Running local fallback...")
        run_local_fallback_query(parser, query)

def run_shell(parser):
    """
    Interactive shell mode.
    """
    terminal_ui.render_shell_banner()
    api_key = get_api_key()
    if not api_key:
        console.print("[bold yellow]Warning:[/] No Gemini API key configured. Commands will run in local rule-based fallback mode.")
        console.print("To unlock full AI capabilities, exit and run: `python aurasniff.py config set-key <API_KEY>`\n")

    while True:
        try:
            user_input = Prompt.ask("\n[bold green]AuraSniff[/] ").strip()
            if not user_input:
                continue

            if user_input.lower() in ("exit", "quit", "q"):
                console.print("[blue]Exiting AuraSniff AI Chat Shell. Goodbye![/]")
                break
            
            if user_input.lower() == "help":
                console.print("[bold white]Available Commands:[/]")
                console.print("  [cyan]exit/quit/q[/]      - Exit the interactive shell")
                console.print("  [cyan]detail <index>[/]   - Inspect layers and hexdump of packet #index (e.g. `detail 45`)")
                console.print("  [cyan]dns[/]              - Show parsed DNS log")
                console.print("  [cyan]http[/]             - Show parsed HTTP log")
                console.print("  [cyan]creds[/]            - Show extracted credentials")
                console.print("  [cyan]alerts[/]           - Show detected anomalies")
                console.print("  [cyan]<any text>[/]       - Ask AuraSniff AI a question about the capture")
                continue

            # Check for direct detail packet command
            detail_match = re.match(r'^detail\s+(\d+)$', user_input, re.IGNORECASE)
            if detail_match:
                index = int(detail_match.group(1))
                terminal_ui.render_packet_detail(index, parser.filepath)
                continue

            # Short command shortcuts
            if user_input.lower() == "dns":
                terminal_ui.render_dns_table(parser.dns_queries[:50])
                continue
            if user_input.lower() == "http":
                terminal_ui.render_http_table(parser.http_traffic[:50])
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

            # Pass generic questions to query handler
            handle_query(parser, user_input)

        except (KeyboardInterrupt, EOFError):
            console.print("\n[blue]Exiting shell.[/]")
            break

def main():
    parser = argparse.ArgumentParser(
        description="AuraSniff: Interactive Command-Line PCAP Traffic & Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # config command
    config_parser = subparsers.add_parser("config", help="Manage API key configuration")
    config_sub = config_parser.add_subparsers(dest="config_action", help="Actions")
    
    set_key_parser = config_sub.add_parser("set-key", help="Set Gemini API Key")
    set_key_parser.add_argument("key", help="Gemini API Key")
    
    config_sub.add_parser("show", help="Show current configuration")

    # analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Scan capture and show dashboard")
    analyze_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")

    # query command
    query_parser = subparsers.add_parser("query", help="Ask a single question about the capture")
    query_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")
    query_parser.add_argument("question", help="Natural language question")

    # shell command
    shell_parser = subparsers.add_parser("shell", help="Launch interactive AI prompt shell")
    shell_parser.add_argument("pcap_file", help="Path to PCAP/PCAPNG file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Handle Config
    if args.command == "config":
        if args.config_action == "set-key":
            config = load_config()
            config["gemini_api_key"] = args.key
            if save_config(config):
                console.print("[bold green]Gemini API Key saved successfully![/]")
            else:
                console.print("[bold red]Failed to save API key.[/]")
        elif args.config_action == "show":
            config = load_config()
            key = config.get("gemini_api_key")
            if key:
                masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "..."
                console.print(f"Gemini API Key: [green]{masked}[/]")
            else:
                console.print("Gemini API Key: [red]Not Set[/] (Use `python aurasniff.py config set-key <KEY>`)")
        else:
            config_parser.print_help()
        sys.exit(0)

    # All other commands require a PCAP file
    pcap_path = getattr(args, "pcap_file", None)
    if not pcap_path:
        console.print("[bold red]Error:[/] PCAP file path is required.")
        sys.exit(1)

    # Check file exists
    if not os.path.exists(pcap_path):
        console.print(f"[bold red]Error:[/] PCAP file not found at '{pcap_path}'")
        sys.exit(1)

    # Run parsing
    pcap_parser_inst = run_parser_with_progress(pcap_path)

    # Route Subcommands
    if args.command == "analyze":
        stats = pcap_parser_inst.get_summary_statistics()
        terminal_ui.render_dashboard(stats, pcap_parser_inst)
    elif args.command == "query":
        handle_query(pcap_parser_inst, args.question)
    elif args.command == "shell":
        run_shell(pcap_parser_inst)

if __name__ == "__main__":
    main()
