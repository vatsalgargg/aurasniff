import time
import scapy.all as scapy

def generate():
    print("Generating mock packets...")
    pkts = []
    t = time.time() - 60  # Start 60 seconds ago

    # Helper to add ether/ip wrapper
    def wrap_ip_udp(src, dst, sport, dport, payload_layer, t_offset):
        return scapy.Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:00") / \
               scapy.IP(src=src, dst=dst) / \
               scapy.UDP(sport=sport, dport=dport) / \
               payload_layer

    # Helper for TCP wrapper
    def wrap_ip_tcp(src, dst, sport, dport, flags, payload_str, t_offset):
        p = scapy.Ether(src="00:11:22:33:44:55", dst="00:11:22:33:44:00") / \
            scapy.IP(src=src, dst=dst) / \
            scapy.TCP(sport=sport, dport=dport, flags=flags)
        if payload_str:
            p = p / scapy.Raw(load=payload_str.encode('utf-8'))
        p.time = t + t_offset
        return p

    # 1. DHCP Discover & Request (IP: 192.168.1.15, Hostname: Johns-MacBook)
    # Option 12: Hostname, Option 50: Requested IP
    dhcp_opts = [
        ("message-type", "request"),
        ("requested_addr", "192.168.1.15"),
        ("hostname", b"Johns-MacBook"),
        "end"
    ]
    dhcp_pkt = scapy.Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / \
               scapy.IP(src="0.0.0.0", dst="255.255.255.255") / \
               scapy.UDP(sport=68, dport=67) / \
               scapy.BOOTP(op=1, chaddr=b"\x00\x11\x22\x33\x44\x55") / \
               scapy.DHCP(options=dhcp_opts)
    dhcp_pkt.time = t
    pkts.append(dhcp_pkt)

    # 2. DNS Lookups
    # Normal query
    dns_q1 = wrap_ip_udp("192.168.1.15", "8.8.8.8", 53535, 53, 
                         scapy.DNS(rd=1, qd=scapy.DNSQR(qname="google.com")), 1)
    dns_q1.time = t + 1
    pkts.append(dns_q1)

    dns_r1 = wrap_ip_udp("8.8.8.8", "192.168.1.15", 53, 53535, 
                         scapy.DNS(qr=1, rd=1, qd=scapy.DNSQR(qname="google.com"), 
                                   ancount=1, an=scapy.DNSRR(rrname="google.com", rdata="142.250.190.46")), 1.1)
    dns_r1.time = t + 1.1
    pkts.append(dns_r1)

    # Suspiciously long DNS tunnel query
    tunnel_qname = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.malicious-domain-control-panel-dns-tunnel-exfil.com"
    dns_q2 = wrap_ip_udp("192.168.1.15", "8.8.8.8", 53536, 53, 
                         scapy.DNS(rd=1, qd=scapy.DNSQR(qname=tunnel_qname)), 2)
    dns_q2.time = t + 2
    pkts.append(dns_q2)

    # 3. HTTP Traffic (HTTP POST Credentials)
    # Handshake
    pkts.append(wrap_ip_tcp("192.168.1.15", "93.184.216.34", 49152, 80, "S", None, 5))
    pkts.append(wrap_ip_tcp("93.184.216.34", "192.168.1.15", 80, 49152, "SA", None, 5.1))
    pkts.append(wrap_ip_tcp("192.168.1.15", "93.184.216.34", 49152, 80, "A", None, 5.2))

    # HTTP POST Request with logins
    post_payload = (
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 37\r\n"
        "\r\n"
        "username=admin&password=SuperSecretPassword123"
    )
    pkts.append(wrap_ip_tcp("192.168.1.15", "93.184.216.34", 49152, 80, "PA", post_payload, 5.3))

    # HTTP 200 OK Response
    res_payload = (
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 20\r\n"
        "\r\n"
        "<h1>Logged In</h1>"
    )
    pkts.append(wrap_ip_tcp("93.184.216.34", "192.168.1.15", 80, 49152, "PA", res_payload, 5.4))

    # 4. FTP Plaintext Login
    # Handshake
    pkts.append(wrap_ip_tcp("192.168.1.15", "192.168.1.5", 49153, 21, "S", None, 10))
    pkts.append(wrap_ip_tcp("192.168.1.5", "192.168.1.15", 21, 49153, "SA", None, 10.1))
    pkts.append(wrap_ip_tcp("192.168.1.15", "192.168.1.5", 49153, 21, "A", None, 10.2))

    # FTP USER command
    pkts.append(wrap_ip_tcp("192.168.1.15", "192.168.1.5", 49153, 21, "PA", "USER administrator\r\n", 10.3))
    pkts.append(wrap_ip_tcp("192.168.1.5", "192.168.1.15", 21, 49153, "PA", "331 Username okay, need password.\r\n", 10.4))
    
    # FTP PASS command
    pkts.append(wrap_ip_tcp("192.168.1.15", "192.168.1.5", 49153, 21, "PA", "PASS FtpSecret55!\r\n", 10.5))
    pkts.append(wrap_ip_tcp("192.168.1.5", "192.168.1.15", 21, 49153, "PA", "230 User logged in, proceed.\r\n", 10.6))

    # 5. Port Scan Anomaly (IP 192.168.1.99 scanning ports 1 to 30 on IP 192.168.1.1)
    for port in range(1, 31):
        scan_pkt = scapy.Ether(src="00:11:22:33:44:99", dst="00:11:22:33:44:00") / \
                   scapy.IP(src="192.168.1.99", dst="192.168.1.1") / \
                   scapy.TCP(sport=60000, dport=port, flags="S")
        scan_pkt.time = t + 20 + (port * 0.1)
        pkts.append(scan_pkt)

    # Write to PCAP file
    filename = "test_capture.pcap"
    print(f"Writing {len(pkts)} packets to {filename}...")
    scapy.wrpcap(filename, pkts)
    print("Generation complete!")

if __name__ == "__main__":
    generate()
