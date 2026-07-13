import os
import re
import socket
from datetime import datetime
from collections import defaultdict
import scapy.all as scapy

# Attempt to load TLS dissection from Scapy if available
try:
    scapy.load_layer("tls")
except Exception:
    pass

class PCAPParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.packets_summary = []
        self.connections = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.ip_to_hostname = {}  # DHCP mappings: IP -> hostname
        self.mac_to_hostname = {} # MAC -> hostname
        self.dns_queries = []     # List of dicts
        self.http_traffic = []    # List of dicts
        self.tls_traffic = []     # List of dicts
        self.credentials = []     # List of dicts (user, pass, protocol, packet_index, src, dst)
        self.alerts = []          # List of security anomaly dicts
        self.protocols_count = defaultdict(int)
        self.total_bytes = 0
        self.start_time = None
        self.end_time = None
        self.duration = 0.0
        self.total_packets = 0

        # Heuristic trackers for port scanning
        # src_ip -> set of (dst_ip, dst_port)
        self.port_scan_tracker = defaultdict(set)
        # ip -> set of mac addresses
        self.arp_tracker = defaultdict(set)

    def parse(self, progress_callback=None):
        """
        Parses the PCAP/PCAPNG file packet by packet using PcapReader.
        Calls progress_callback(current_packet_count) if provided.
        """
        if not os.path.exists(self.filepath):
            raise FileNotFoundError(f"PCAP file not found: {self.filepath}")

        packet_count = 0
        
        # Open the file using Scapy's PcapReader for memory efficiency
        with scapy.PcapReader(self.filepath) as pcap_reader:
            for packet in pcap_reader:
                packet_count += 1
                self.total_packets = packet_count
                
                if progress_callback and packet_count % 500 == 0:
                    progress_callback(packet_count)
                
                try:
                    self._process_packet(packet, packet_count)
                except Exception:
                    # Ignore malformed packets but continue parsing
                    pass

        # Calculate summary statistics
        if self.start_time and self.end_time:
            self.duration = max(0.1, float(self.end_time - self.start_time))
        else:
            self.duration = 0.0

        # Post-process security alerts
        self._analyze_anomalies()

    def _process_packet(self, packet, index):
        # 1. Timestamps & Basic Length
        time_float = float(packet.time)
        if self.start_time is None or time_float < self.start_time:
            self.start_time = time_float
        if self.end_time is None or time_float > self.end_time:
            self.end_time = time_float

        pkt_len = len(packet)
        self.total_bytes += pkt_len

        # 2. Extract Protocol Layer Information
        src_ip = "N/A"
        dst_ip = "N/A"
        src_mac = "N/A"
        dst_mac = "N/A"
        proto_name = "Ethernet"
        info = "Raw Link Layer"

        # Check Ethernet / MAC layers
        if packet.haslayer(scapy.Ether):
            src_mac = packet[scapy.Ether].src
            dst_mac = packet[scapy.Ether].dst

        # Check IP layer
        has_ip = False
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto_name = "IPv4"
            has_ip = True
        elif packet.haslayer(scapy.IPv6):
            src_ip = packet[scapy.IPv6].src
            dst_ip = packet[scapy.IPv6].dst
            proto_name = "IPv6"
            has_ip = True

        # Track ARP for spoofing
        if packet.haslayer(scapy.ARP):
            arp = packet[scapy.ARP]
            proto_name = "ARP"
            if arp.op == 2:
                self.arp_tracker[arp.psrc].add(arp.hwsrc)
            info = f"ARP - {arp.psrc} is at {arp.hwsrc}"

        # Track connection flows
        proto_str = "IP"
        sport = 0
        dport = 0

        # Layer 4 (TCP / UDP)
        if packet.haslayer(scapy.TCP):
            tcp = packet[scapy.TCP]
            proto_name = "TCP"
            proto_str = "TCP"
            sport = tcp.sport
            dport = tcp.dport
            info = f"TCP: {sport} -> {dport} [{tcp.flags}]"
            
            # Port scanning heuristics
            if has_ip:
                self.port_scan_tracker[src_ip].add((dst_ip, dport))
                
            self._process_tcp_payload(packet, index, src_ip, dst_ip, sport, dport)
            
        elif packet.haslayer(scapy.UDP):
            udp = packet[scapy.UDP]
            proto_name = "UDP"
            proto_str = "UDP"
            sport = udp.sport
            dport = udp.dport
            info = f"UDP: {sport} -> {dport}"

            # Port scanning heuristics
            if has_ip:
                self.port_scan_tracker[src_ip].add((dst_ip, dport))

            self._process_udp_payload(packet, index, src_ip, dst_ip, sport, dport)

        elif packet.haslayer(scapy.ICMP):
            proto_name = "ICMP"
            info = "ICMP Echo Request" if packet[scapy.ICMP].type == 8 else "ICMP Echo Reply" if packet[scapy.ICMP].type == 0 else f"ICMP Type {packet[scapy.ICMP].type}"

        # Update protocol statistics
        self.protocols_count[proto_name] += 1

        # Track connection counts
        if has_ip:
            flow_key = (src_ip, dst_ip, proto_str)
            self.connections[flow_key]["packets"] += 1
            self.connections[flow_key]["bytes"] += pkt_len

        # Store basic packet summary
        self.packets_summary.append({
            "index": index,
            "time": time_float,
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto_name,
            "len": pkt_len,
            "info": info
        })

    def _process_tcp_payload(self, packet, index, src_ip, dst_ip, sport, dport):
        tcp = packet[scapy.TCP]
        payload = bytes(tcp.payload)
        if not payload:
            return

        is_http = False
        try:
            if payload.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")):
                is_http = True
                self._parse_http_request(payload, index, src_ip, dst_ip, sport, dport)
            elif payload.startswith(b"HTTP/"):
                is_http = True
                self._parse_http_response(payload, index, src_ip, dst_ip, sport, dport)
        except Exception:
            pass

        # Robust fallback: scan raw payload of any TCP packet (excluding encrypted HTTPS ports 443/8443)
        if dport not in (443, 8443) and sport not in (443, 8443):
            try:
                self._scan_raw_payload_for_creds(payload, index, src_ip, dst_ip, sport, dport)
            except Exception:
                pass

        if not is_http and (dport == 443 or sport == 443 or dport == 8443):
            self._extract_tls_sni(payload, index, src_ip, dst_ip)

        if dport == 21 or sport == 21:
            try:
                line = payload.decode("utf-8", errors="ignore").strip()
                if line.startswith("USER "):
                    username = line[5:]
                    self.credentials.append({
                        "username": username,
                        "password": "<WAITING FOR PASS>",
                        "protocol": "FTP",
                        "index": index,
                        "src": src_ip,
                        "dst": dst_ip,
                        "info": f"FTP User: {username}"
                    })
                elif line.startswith("PASS "):
                    password = line[5:]
                    for cred in reversed(self.credentials):
                        if cred["protocol"] == "FTP" and cred["src"] == src_ip and cred["password"] == "<WAITING FOR PASS>":
                            cred["password"] = password
                            cred["info"] = f"FTP User: {cred['username']} / Pass: {password}"
                            break
            except Exception:
                pass

        if dport in (25, 587, 110, 143):
            try:
                line = payload.decode("utf-8", errors="ignore").strip()
                if dport in (25, 587) and "AUTH LOGIN" in line:
                    self.credentials.append({
                        "username": "<BASE64 ENCODED>",
                        "password": "<BASE64 ENCODED>",
                        "protocol": "SMTP",
                        "index": index,
                        "src": src_ip,
                        "dst": dst_ip,
                        "info": "SMTP Auth Login initiated"
                    })
                elif dport == 110:
                    if line.upper().startswith("USER "):
                        self.credentials.append({
                            "username": line[5:],
                            "password": "<WAITING FOR PASS>",
                            "protocol": "POP3",
                            "index": index,
                            "src": src_ip,
                            "dst": dst_ip,
                            "info": f"POP3 User: {line[5:]}"
                        })
                    elif line.upper().startswith("PASS "):
                        password = line[5:]
                        for cred in reversed(self.credentials):
                            if cred["protocol"] == "POP3" and cred["src"] == src_ip and cred["password"] == "<WAITING FOR PASS>":
                                cred["password"] = password
                                cred["info"] = f"POP3 User: {cred['username']} / Pass: {password}"
                                break
                elif dport == 143:
                    match = re.search(r'\bLOGIN\s+"?([^"\s]+)"?\s+"?([^"\s]+)"?', line, re.IGNORECASE)
                    if match:
                        user, password = match.group(1), match.group(2)
                        self.credentials.append({
                            "username": user,
                            "password": password,
                            "protocol": "IMAP",
                            "index": index,
                            "src": src_ip,
                            "dst": dst_ip,
                            "info": f"IMAP Login User: {user} / Pass: {password}"
                        })
            except Exception:
                pass

    def _process_udp_payload(self, packet, index, src_ip, dst_ip, sport, dport):
        udp = packet[scapy.UDP]
        payload = bytes(udp.payload)
        if not payload:
            return

        if packet.haslayer(scapy.DNS):
            dns = packet[scapy.DNS]
            if dns.qd:
                qname = dns.qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = dns.qd.qtype
                qtype_name = scapy.dnstypes.get(qtype, f"TYPE{qtype}")
                
                answers = []
                if dns.an:
                    for i in range(dns.ancount):
                        ans = dns.an[i]
                        if ans.type == 1:
                            answers.append(ans.rdata)
                        elif ans.type == 28:
                            answers.append(ans.rdata)
                        elif ans.type == 5:
                            answers.append(ans.rdata.decode("utf-8", errors="ignore").rstrip("."))

                self.dns_queries.append({
                    "index": index,
                    "qname": qname,
                    "type": qtype_name,
                    "src": src_ip,
                    "dst": dst_ip,
                    "answers": ", ".join(answers) if answers else "N/A"
                })

        if packet.haslayer(scapy.DHCP) or (sport in (67, 68) and dport in (67, 68)):
            try:
                dhcp_options = packet[scapy.DHCP].options if packet.haslayer(scapy.DHCP) else []
                if not dhcp_options and packet.haslayer(scapy.BOOTP):
                    bootp = packet[scapy.BOOTP]
                    if bootp.haslayer(scapy.DHCP):
                        dhcp_options = bootp[scapy.DHCP].options

                hostname = None
                req_ip = None
                client_mac = packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else None

                for opt in dhcp_options:
                    if isinstance(opt, tuple) and len(opt) >= 2:
                        opt_name = opt[0]
                        opt_val = opt[1]
                        if opt_name == "hostname":
                            if isinstance(opt_val, bytes):
                                hostname = opt_val.decode("utf-8", errors="ignore")
                            else:
                                hostname = str(opt_val)
                        elif opt_name == "requested_addr":
                            req_ip = str(opt_val)

                if hostname:
                    hostname = hostname.strip().rstrip("\x00")
                    if req_ip:
                        self.ip_to_hostname[req_ip] = hostname
                    if client_mac:
                        self.mac_to_hostname[client_mac] = hostname
            except Exception:
                pass

    def _parse_http_request(self, payload, index, src_ip, dst_ip, sport, dport):
        try:
            req_text = payload.decode("utf-8", errors="ignore")
            lines = req_text.split("\r\n")
            if not lines:
                return

            req_line = lines[0].split(" ")
            if len(req_line) < 2:
                return
            method, path = req_line[0], req_line[1]

            headers = {}
            body_start_idx = -1
            for i, line in enumerate(lines[1:]):
                if line == "":
                    body_start_idx = i + 2
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            host = headers.get("host", dst_ip)
            user_agent = headers.get("user-agent", "N/A")
            content_type = headers.get("content-type", "")

            self.http_traffic.append({
                "index": index,
                "method": method,
                "host": host,
                "path": path,
                "src": src_ip,
                "dst": dst_ip,
                "user_agent": user_agent,
                "status": "N/A"
            })

            if method == "POST" and body_start_idx != -1 and body_start_idx < len(lines):
                body = "\r\n".join(lines[body_start_idx:])
                self._scan_http_body_for_creds(body, index, src_ip, dst_ip, host, path)
        except Exception:
            pass

    def _parse_http_response(self, payload, index, src_ip, dst_ip, sport, dport):
        try:
            res_text = payload.decode("utf-8", errors="ignore")
            lines = res_text.split("\r\n")
            if not lines:
                return

            res_line = lines[0].split(" ")
            if len(res_line) < 2:
                return
            status_code = res_line[1]

            for http_req in reversed(self.http_traffic):
                if http_req["src"] == dst_ip and http_req["dst"] == src_ip and http_req["status"] == "N/A":
                    http_req["status"] = status_code
                    break
        except Exception:
            pass

    def _extract_tls_sni(self, payload, index, src_ip, dst_ip):
        try:
            if len(payload) > 43 and payload[0] == 0x16 and payload[1] == 0x03 and payload[5] == 0x01:
                pos = 43
                if pos < len(payload):
                    session_id_len = payload[pos]
                    pos += 1 + session_id_len
                
                if pos + 2 < len(payload):
                    cipher_len = int.from_bytes(payload[pos:pos+2], byteorder="big")
                    pos += 2 + cipher_len

                if pos < len(payload):
                    comp_len = payload[pos]
                    pos += 1 + comp_len

                if pos + 2 < len(payload):
                    ext_len = int.from_bytes(payload[pos:pos+2], byteorder="big")
                    pos += 2
                    end_pos = pos + ext_len
                    
                    while pos + 4 < len(payload) and pos < end_pos:
                        ext_type = int.from_bytes(payload[pos:pos+2], byteorder="big")
                        ext_data_len = int.from_bytes(payload[pos+2:pos+4], byteorder="big")
                        pos += 4
                        
                        if ext_type == 0:
                            if pos + 2 < len(payload):
                                sni_list_len = int.from_bytes(payload[pos:pos+2], byteorder="big")
                                name_type = payload[pos+2]
                                if name_type == 0:
                                    name_len = int.from_bytes(payload[pos+3:pos+5], byteorder="big")
                                    sni = payload[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
                                    
                                    self.tls_traffic.append({
                                        "index": index,
                                        "host": sni,
                                        "src": src_ip,
                                        "dst": dst_ip
                                    })
                                    return
                        pos += ext_data_len
        except Exception:
            pass

    def _scan_http_body_for_creds(self, body, index, src_ip, dst_ip, host, path):
        username_patterns = [r'(?:user|username|login|email|usr|uname)\b' ]
        password_patterns = [r'(?:password|passwd|pass|pwd)\b' ]

        pairs = []
        if "=" in body:
            pairs = [p.split("=", 1) for p in body.split("&") if "=" in p]
        elif "{" in body:
            matches = re.findall(r'"([^"]+)":\s*"([^"]+)"', body)
            pairs = list(matches)

        username = None
        password = None

        for k, v in pairs:
            k_clean = k.strip().lower()
            v_clean = v.strip()
            
            if any(re.search(pat, k_clean) for pat in username_patterns):
                username = v_clean
            elif any(re.search(pat, k_clean) for pat in password_patterns):
                password = v_clean

        if username or password:
            self.credentials.append({
                "username": username or "<NOT FOUND>",
                "password": password or "<NOT FOUND>",
                "protocol": "HTTP-POST",
                "index": index,
                "src": src_ip,
                "dst": dst_ip,
                "info": f"HTTP POST Form at {host}{path} - User: {username or '<N/A>'} / Pass: {password or '<N/A>'}"
            })

    def _scan_raw_payload_for_creds(self, payload, index, src_ip, dst_ip, sport, dport):
        import urllib.parse
        
        try:
            payload_str = payload.decode("utf-8", errors="ignore")
        except Exception:
            try:
                payload_str = payload.decode("latin1", errors="ignore")
            except Exception:
                return

        if not payload_str:
            return

        pwd_keywords = ("password", "passwd", "pwd", "pass", "secret")
        if not any(k in payload_str.lower() for k in pwd_keywords):
            return

        username_patterns = [r'(?:user|username|login|email|usr|uname|mail|log)\b']
        password_patterns = [r'(?:password|passwd|pass|pwd)\b']

        pairs = []
        if "{" in payload_str and ":" in payload_str:
            json_matches = re.findall(r'"([^"]+)"\s*:\s*"([^"]+)"', payload_str)
            if json_matches:
                pairs.extend(json_matches)
        
        if "=" in payload_str and ("&" in payload_str or len(payload_str) < 500):
            body = payload_str
            if "\r\n\r\n" in payload_str:
                body = payload_str.split("\r\n\r\n", 1)[1]
            
            url_pairs = []
            for p in body.split("&"):
                if "=" in p:
                    parts = p.split("=", 1)
                    try:
                        k = urllib.parse.unquote(parts[0].strip())
                        v = urllib.parse.unquote(parts[1].strip())
                        url_pairs.append((k, v))
                    except Exception:
                        pass
            if url_pairs:
                pairs.extend(url_pairs)

        username = None
        password = None

        for k, v in pairs:
            k_clean = k.strip().lower()
            v_clean = v.strip()
            
            if any(re.search(pat, k_clean) for pat in username_patterns):
                username = v_clean
            elif any(re.search(pat, k_clean) for pat in password_patterns):
                password = v_clean

        if password:
            is_dup = False
            for c in self.credentials:
                if c["src"] == src_ip and c["dst"] == dst_ip and c["password"] == password:
                    is_dup = True
                    break

            if not is_dup:
                self.credentials.append({
                    "username": username or "<NOT FOUND>",
                    "password": password,
                    "protocol": f"TCP:{dport}",
                    "index": index,
                    "src": src_ip,
                    "dst": dst_ip,
                    "info": f"Cleartext credentials intercepted (Port {dport}) - User: {username or '<N/A>'} / Pass: {password}"
                })

    def _analyze_anomalies(self):
        # 1. Port scan detection
        for src_ip, targeted in self.port_scan_tracker.items():
            if len(targeted) > 20:
                dest_ports = defaultdict(set)
                for dst_ip, port in targeted:
                    dest_ports[dst_ip].add(port)
                
                for dst_ip, ports in dest_ports.items():
                    if len(ports) > 15:
                        self.alerts.append({
                            "type": "Port Scan",
                            "severity": "High",
                            "source": src_ip,
                            "destination": dst_ip,
                            "description": f"IP {src_ip} scanned {len(ports)} different ports on {dst_ip}."
                        })

        # 2. ARP Spoofing
        for ip, macs in self.arp_tracker.items():
            if len(macs) > 1:
                mac_list = ", ".join(list(macs))
                self.alerts.append({
                    "type": "ARP Spoofing",
                    "severity": "Critical",
                    "source": ip,
                    "destination": "N/A",
                    "description": f"IP {ip} resolved to multiple MAC addresses: {mac_list}."
                })

        # 3. Cleartext Credentials
        for cred in self.credentials:
            if cred["password"] not in ("<WAITING FOR PASS>", "<BASE64 ENCODED>"):
                self.alerts.append({
                    "type": "Cleartext Credentials",
                    "severity": "Medium",
                    "source": cred["src"],
                    "destination": cred["dst"],
                    "description": f"Transmitted cleartext credentials over {cred['protocol']}. User: {cred['username']} / Pass: {cred['password']} (Packet #{cred['index']})."
                })

        # 4. DNS Tunneling
        for dns in self.dns_queries:
            qname = dns["qname"]
            if len(qname) > 65 and not qname.endswith("in-addr.arpa") and not qname.endswith("ip6.arpa"):
                subdomains = qname.split(".")
                longest_sub = max(subdomains, key=len)
                if len(longest_sub) > 40:
                    self.alerts.append({
                        "type": "DNS Tunneling",
                        "severity": "High",
                        "source": dns["src"],
                        "destination": dns["dst"],
                        "description": f"Suspiciously long DNS query: '{qname[:50]}...' (Length: {len(qname)}, Packet #{dns['index']})."
                    })

    def get_summary_statistics(self):
        avg_bandwidth = 0.0
        if self.duration > 0:
            avg_bandwidth = (self.total_bytes * 8) / self.duration

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "duration": round(self.duration, 2),
            "start_time": datetime.fromtimestamp(self.start_time).strftime('%Y-%m-%d %H:%M:%S.%f') if self.start_time else "N/A",
            "end_time": datetime.fromtimestamp(self.end_time).strftime('%Y-%m-%d %H:%M:%S.%f') if self.end_time else "N/A",
            "avg_bandwidth_bps": round(avg_bandwidth, 2),
            "protocols_count": dict(self.protocols_count),
            "alerts_count": len(self.alerts),
            "credentials_count": len([c for c in self.credentials if c["password"] not in ("<WAITING FOR PASS>", "<BASE64 ENCODED>")]),
            "dns_count": len(self.dns_queries),
            "http_count": len(self.http_traffic),
            "tls_count": len(self.tls_traffic)
        }
