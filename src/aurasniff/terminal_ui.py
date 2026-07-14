import math
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text
from rich.tree import Tree
from rich.align import Align
import scapy.all as scapy

console = Console()

def get_severity_style(severity):
    severity = severity.lower()
    if severity == "critical":
        return "bold red"
    elif severity == "high":
        return "bold red"
    elif severity == "medium":
        return "bold yellow"
    return "bold cyan"

def format_size(bytes_size):
    if bytes_size == 0:
        return "0 B"
    size_name = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(bytes_size, 1024)))
    p = math.pow(1024, i)
    s = round(bytes_size / p, 2)
    return f"{s} {size_name[i]}"

def format_bps(bps):
    if bps == 0:
        return "0 bps"
    size_name = ("bps", "Kbps", "Mbps", "Gbps")
    i = int(math.floor(math.log(bps, 1024)))
    p = math.pow(1024, i)
    s = round(bps / p, 2)
    return f"{s} {size_name[i]}"

def make_horizontal_bar(val, max_val, width=15):
    if max_val <= 0:
        return ""
    filled = int(round((val / max_val) * width))
    filled = min(width, max(0, filled))
    bar = "█" * filled + "░" * (width - filled)
    return bar

def render_dashboard(stats, parser):
    # Header
    console.print(Panel(
        Align.center(
            Text.assemble(
                ("▲ ", "bold green"),
                ("AURA SNIFF PCAP ANALYZER ", "bold white"),
                ("▲", "bold green"),
                ("\nPremium Command Line Traffic Inspector & AI Security Assistant", "dim italic")
            )
        ),
        border_style="green",
        padding=(1, 2)
    ))

    # Column 1: General Stats
    stats_text = Text()
    stats_text.append("File Path:   ", style="bold cyan").append(f"{parser.filepath}\n")
    stats_text.append("Packets:     ", style="bold cyan").append(f"{stats['total_packets']:,}\n")
    stats_text.append("Data Size:   ", style="bold cyan").append(f"{format_size(stats['total_bytes'])}\n")
    stats_text.append("Duration:    ", style="bold cyan").append(f"{stats['duration']} s\n")
    stats_text.append("Start Time:  ", style="bold cyan").append(f"{stats['start_time']}\n")
    stats_text.append("End Time:    ", style="bold cyan").append(f"{stats['end_time']}\n")
    stats_text.append("Avg Rate:    ", style="bold cyan").append(f"{format_bps(stats['avg_bandwidth_bps'])}\n")

    stats_panel = Panel(stats_text, title="Capture Summary", border_style="blue", expand=True)

    # Column 2: Protocol Breakdown
    proto_table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 1))
    proto_table.add_column("Protocol")
    proto_table.add_column("Count", justify="right")
    proto_table.add_column("Ratio")

    total_pkts = stats["total_packets"] or 1
    sorted_protos = sorted(stats["protocols_count"].items(), key=lambda x: x[1], reverse=True)
    max_proto_count = sorted_protos[0][1] if sorted_protos else 1

    for proto, count in sorted_protos[:6]:
        pct = (count / total_pkts) * 100
        bar = make_horizontal_bar(count, max_proto_count, width=10)
        proto_table.add_row(
            Text(proto, style="bold white"),
            Text(f"{count:,}", style="cyan"),
            Text(f"{pct:.1f}% ", style="dim").append(bar, style="green")
        )

    proto_panel = Panel(proto_table, title="Protocol Distribution", border_style="magenta", expand=True)

    # Display columns side by side
    console.print(Columns([stats_panel, proto_panel], equal=True))

    # Top Conversations
    conv_table = Table(show_header=True, header_style="bold cyan", expand=True)
    conv_table.add_column("Source IP", ratio=3)
    conv_table.add_column("→", justify="center", ratio=1)
    conv_table.add_column("Destination IP", ratio=3)
    conv_table.add_column("Proto", ratio=1)
    conv_table.add_column("Packets", justify="right", ratio=1.5)
    conv_table.add_column("Bytes", justify="right", ratio=1.5)
    conv_table.add_column("Volume Bar", ratio=2)

    sorted_convs = sorted(parser.connections.items(), key=lambda x: x[1]["bytes"], reverse=True)
    max_bytes = sorted_convs[0][1]["bytes"] if sorted_convs else 1

    for flow, data in sorted_convs[:5]:
        src, dst, proto = flow
        src_name = f"{src} ({parser.ip_to_hostname[src]})" if src in parser.ip_to_hostname else src
        dst_name = f"{dst} ({parser.ip_to_hostname[dst]})" if dst in parser.ip_to_hostname else dst
        
        bar = make_horizontal_bar(data["bytes"], max_bytes, width=12)
        conv_table.add_row(
            src_name,
            "→",
            dst_name,
            proto,
            f"{data['packets']:,}",
            format_size(data["bytes"]),
            Text(bar, style="yellow")
        )

    console.print(Panel(conv_table, title="Top Conversations (by volume)", border_style="yellow"))

    # Credentials
    if parser.credentials:
        cred_table = Table(show_header=True, header_style="bold green", expand=True)
        cred_table.add_column("Pkt #", justify="right")
        cred_table.add_column("Protocol")
        cred_table.add_column("Source")
        cred_table.add_column("Destination")
        cred_table.add_column("Credentials Info")

        for cred in parser.credentials[:5]:
            cred_table.add_row(
                str(cred["index"]),
                cred["protocol"],
                cred["src"],
                cred["dst"],
                Text(cred["info"], style="bold green")
            )
        console.print(Panel(cred_table, title="🔑 Extracted Credentials", border_style="green"))
    else:
        console.print(Panel(Text("No plain text credentials intercepted (this is good!).", style="italic green"), title="🔑 Extracted Credentials", border_style="green"))

    # Alerts / Anomalies
    if parser.alerts:
        alert_table = Table(show_header=True, header_style="bold red", expand=True)
        alert_table.add_column("Severity", justify="center")
        alert_table.add_column("Anomalous Activity", justify="left")
        alert_table.add_column("Source IP", justify="left")
        alert_table.add_column("Details", justify="left", ratio=3)

        for alert in parser.alerts:
            sev = alert["severity"]
            alert_table.add_row(
                Text(sev, style=get_severity_style(sev)),
                Text(alert["type"], style="bold white"),
                alert["source"],
                alert["description"]
            )
        console.print(Panel(alert_table, title="🚨 Security Alerts & Anomalies Detected", border_style="red"))
    else:
        console.print(Panel(Text("Zero network anomalies or potential threats detected.", style="italic green"), title="🚨 Security Alerts & Anomalies Detected", border_style="green"))

def render_packets_list(packets, parser):
    table = Table(show_header=True, header_style="bold blue", expand=True)
    table.add_column("#", justify="right", ratio=0.8)
    table.add_column("Time", ratio=1.2)
    table.add_column("Source IP", ratio=2.5)
    table.add_column("Destination IP", ratio=2.5)
    table.add_column("Protocol", ratio=1.2, justify="center")
    table.add_column("Length", justify="right", ratio=1)
    table.add_column("Info Summary", ratio=5)

    for pkt in packets:
        idx = pkt["index"]
        src = pkt["src"]
        dst = pkt["dst"]
        
        if src in parser.ip_to_hostname:
            src = f"{src} ({parser.ip_to_hostname[src]})"
        if dst in parser.ip_to_hostname:
            dst = f"{dst} ({parser.ip_to_hostname[dst]})"

        time_str = f"{pkt['time'] - parser.start_time:.4f}" if parser.start_time is not None else "N/A"

        proto = pkt["proto"]
        proto_style = "bold white"
        if proto == "TCP":
            proto_style = "bold cyan"
        elif proto == "UDP":
            proto_style = "bold blue"
        elif proto == "DNS":
            proto_style = "bold magenta"
        elif proto in ("HTTP", "HTTP-POST"):
            proto_style = "bold green"
        elif proto == "ARP":
            proto_style = "bold yellow"

        table.add_row(
            str(idx),
            time_str,
            src,
            dst,
            Text(proto, style=proto_style),
            str(pkt["len"]),
            pkt["info"]
        )

    console.print(table)

def render_dns_table(dns_queries):
    table = Table(show_header=True, header_style="bold magenta", expand=True)
    table.add_column("Pkt #", justify="right")
    table.add_column("Queried Domain")
    table.add_column("Type", justify="center")
    table.add_column("Source IP")
    table.add_column("Answers / Resolved IP")

    for dns in dns_queries:
        table.add_row(
            str(dns["index"]),
            Text(dns["qname"], style="bold white"),
            dns["type"],
            dns["src"],
            Text(dns["answers"], style="green" if dns["answers"] != "N/A" else "dim")
        )
    console.print(Panel(table, title="🔍 DNS Queries Log", border_style="magenta"))

def render_http_table(http_traffic):
    table = Table(show_header=True, header_style="bold green", expand=True)
    table.add_column("Pkt #", justify="right")
    table.add_column("Method", justify="center")
    table.add_column("Host")
    table.add_column("Path", ratio=3)
    table.add_column("Status", justify="center")
    table.add_column("Source IP")

    for http in http_traffic:
        status = http["status"]
        status_style = "bold green" if status.startswith("2") else "bold yellow" if status.startswith("3") else "bold red" if status != "N/A" else "dim"
        
        table.add_row(
            str(http["index"]),
            Text(http["method"], style="bold cyan"),
            Text(http["host"], style="bold white"),
            http["path"],
            Text(status, style=status_style),
            http["src"]
        )
    console.print(Panel(table, title="🌐 HTTP Traffic Log", border_style="green"))

def render_hexdump(data):
    if not data:
        return Text("No payload data.", style="dim italic")

    result = Text()
    length = len(data)
    
    for i in range(0, length, 16):
        offset = f"{i:04x}  "
        result.append(offset, style="dim white")
        
        hex_part = []
        ascii_part = []
        for j in range(16):
            if i + j < length:
                val = data[i+j]
                hex_part.append(f"{val:02x}")
                if 32 <= val <= 126:
                    ascii_part.append((chr(val), "cyan"))
                elif val == 0:
                    ascii_part.append((".", "dim white"))
                else:
                    ascii_part.append((".", "dim red"))
            else:
                hex_part.append("  ")
                ascii_part.append((" ", "default"))
        
        hex_str = " ".join(hex_part[:8]) + "  " + " ".join(hex_part[8:])
        result.append(hex_str.ljust(48) + "  |", style="bold white")
        
        for char, style in ascii_part:
            result.append(char, style=style)
            
        result.append("|\n", style="bold white")
        
    return result

def render_packet_detail(index, filepath):
    packet = None
    curr_idx = 0
    with scapy.PcapReader(filepath) as pcap_reader:
        for p in pcap_reader:
            curr_idx += 1
            if curr_idx == index:
                packet = p
                break

    if not packet:
        console.print(f"[bold red]Error:[/] Packet #{index} not found in capture file.")
        return

    console.print(Panel(
        Text(f"Detailed Packet Dissection: Packet #{index} (Size: {len(packet)} bytes)", style="bold white"),
        border_style="cyan"
    ))

    tree = Tree(f"[bold green]Packet #{index}[/]")
    
    temp_pkt = packet
    while temp_pkt:
        layer_name = temp_pkt.__class__.__name__
        layer_info = []
        
        for field in temp_pkt.fields_desc:
            val = temp_pkt.getfieldval(field.name)
            if val is not None:
                layer_info.append(f"{field.name}={val}")
        
        field_str = ", ".join(layer_info)
        if len(field_str) > 100:
            field_str = field_str[:97] + "..."
            
        tree.add(f"[bold blue]{layer_name}[/] ({field_str})")
        temp_pkt = temp_pkt.payload if not isinstance(temp_pkt.payload, scapy.NoPayload) else None

    console.print(tree)
    console.print()

    raw_bytes = bytes(packet)
    payload_bytes = None
    if packet.haslayer(scapy.TCP):
        payload_bytes = bytes(packet[scapy.TCP].payload)
    elif packet.haslayer(scapy.UDP):
        payload_bytes = bytes(packet[scapy.UDP].payload)

    console.print("[bold yellow]Raw Packet Hex/ASCII Dump:[/]")
    console.print(render_hexdump(raw_bytes))
    
    if payload_bytes:
        console.print()
        console.print("[bold yellow]Application Payload Hex/ASCII Dump:[/]")
        console.print(render_hexdump(payload_bytes))

def render_shell_banner():
    console.print(Panel(
        Align.center(
            Text.assemble(
                ("💬 ", "green"),
                ("AuraSniff AI Chat Shell ", "bold white"),
                ("💬", "green"),
                ("\nAsk Gemini about your PCAP file. Type your question in natural language.\n", "italic dim"),
                ("Examples: 'Is there any suspicious traffic?', 'Find credentials', 'Who did 192.168.1.15 talk to?'\n", "cyan"),
                ("Special commands: 'exit' to quit shell, 'help' for options, 'detail <#>' to inspect packet layers.", "dim"),
                ("\n'websites' to see all IP→website maps, 'websites <IP>' to filter by IP.", "dim")
            )
        ),
        border_style="green"
    ))


def render_ip_websites_table(ip_website_map, target_ip=None):
    """
    Renders a Rich table showing which websites each IP has visited,
    broken down by DNS queries, HTTP Host headers, and TLS/HTTPS SNI.
    If target_ip is provided, only that IP's activity is shown.
    """
    # Filter by target IP or hostname if specified
    if target_ip:
        filtered = {
            ip: data for ip, data in ip_website_map.items()
            if target_ip.lower() in ip.lower()
            or (data.get("hostname") and target_ip.lower() in data["hostname"].lower())
        }
    else:
        filtered = ip_website_map

    if not filtered:
        console.print(Panel(
            Text(
                f"No website activity found{f' for: {target_ip}' if target_ip else ''}.",
                style="italic yellow"
            ),
            title="🌐 IP → Website Map",
            border_style="cyan"
        ))
        return

    table = Table(
        show_header=True,
        header_style="bold cyan",
        expand=True,
        show_lines=True
    )
    table.add_column("Source IP", ratio=2, style="bold white")
    table.add_column("Device Name", ratio=2)
    table.add_column("DNS Queries", ratio=4)
    table.add_column("HTTP Sites", ratio=3)
    table.add_column("TLS / HTTPS Sites", ratio=4)

    for ip in sorted(filtered.keys()):
        data = filtered[ip]
        hostname = data.get("hostname") or "—"
        dns_list  = data.get("dns",  [])
        http_list = data.get("http", [])
        tls_list  = data.get("tls",  [])

        def _fmt_list(lst, limit=12):
            if not lst:
                return Text("None", style="dim")
            lines = lst[:limit]
            suffix = f"\n  … +{len(lst) - limit} more" if len(lst) > limit else ""
            return Text("\n".join(lines) + suffix)

        table.add_row(
            ip,
            Text(hostname, style="bold yellow" if hostname != "—" else "dim"),
            Text(_fmt_list(dns_list).plain,  style="cyan"),
            Text(_fmt_list(http_list).plain, style="green"),
            Text(_fmt_list(tls_list).plain,  style="magenta"),
        )

    title = f"🌐 IP → Website Map{f'  (filter: {target_ip})' if target_ip else ''}"
    total_ips = len(filtered)
    subtitle = f"{total_ips} IP address{'es' if total_ips != 1 else ''} shown"
    console.print(Panel(table, title=title, subtitle=subtitle, border_style="cyan"))
