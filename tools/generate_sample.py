#!/usr/bin/env python3
"""
Generate synthetic pcap files for testing and demonstration.

Creates two captures:
  samples/normal_traffic.pcap  — baseline web/DNS/ICMP traffic
  samples/attack_traffic.pcap  — port scan, SYN flood, DNS exfil, ARP spoof

Usage:
    python tools/generate_sample.py
    python tools/generate_sample.py --out samples/custom.pcap --scenario mixed
"""

import argparse
import random
import struct
import sys
import os

# Allow running from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.pcap_writer import (
    PcapWriter, eth_frame, ip_packet, tcp_segment, udp_datagram,
    icmp_echo, arp_packet, dns_query, dns_response,
    ETHERTYPE_IPV4, ETHERTYPE_ARP, PROTO_TCP, PROTO_UDP, PROTO_ICMP,
)
from src.core.pcap_reader import TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST

# ── Network topology ───────────────────────────────────────────────────────────

GATEWAY_MAC = "00:50:56:c0:00:01"
GATEWAY_IP  = "192.168.1.1"

HOSTS = [
    {"mac": "00:0c:29:aa:bb:01", "ip": "192.168.1.10", "name": "workstation-1"},
    {"mac": "00:0c:29:aa:bb:02", "ip": "192.168.1.11", "name": "workstation-2"},
    {"mac": "00:0c:29:aa:bb:03", "ip": "192.168.1.20", "name": "server-web"},
    {"mac": "00:0c:29:aa:bb:04", "ip": "192.168.1.30", "name": "server-db"},
    {"mac": "00:0c:29:aa:bb:05", "ip": "192.168.1.99", "name": "attacker"},
]

DNS_SERVER_IP = "8.8.8.8"
EXTERNAL_IPS  = ["93.184.216.34", "151.101.65.121", "172.217.5.68",
                  "104.244.42.65", "185.60.216.35"]

DOMAINS = [
    ("example.com",       "93.184.216.34"),
    ("github.com",        "140.82.113.4"),
    ("stackoverflow.com", "151.101.65.121"),
    ("google.com",        "172.217.5.68"),
    ("twitter.com",       "104.244.42.65"),
    ("reddit.com",        "151.101.193.140"),
]

HTTP_GETS = [
    b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
    b"GET /index.html HTTP/1.1\r\nHost: github.com\r\nUser-Agent: curl/7.68.0\r\n\r\n",
    b"GET /questions/1234 HTTP/1.1\r\nHost: stackoverflow.com\r\nAccept: text/html\r\n\r\n",
    b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{\"key\": \"value\", \"timestamp\": 1700000000}",
]

HTTP_RESPONSES = [
    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1024\r\nServer: nginx/1.18\r\n\r\n" + b"A" * 512,
    b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.com/\r\nContent-Length: 0\r\n\r\n",
    b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: 128\r\n\r\n" + b"<html>Not Found</html>",
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 256\r\n\r\n" + b'{"status":"ok"}',
]


class ScenarioBuilder:
    """Helper that wraps PcapWriter with a running timestamp."""

    def __init__(self, writer: PcapWriter, base_ts: float = 1_700_000_000.0):
        self.w  = writer
        self.ts = base_ts

    def tick(self, delta: float = None) -> float:
        if delta is None:
            delta = random.uniform(0.001, 0.05)
        self.ts += delta
        return self.ts

    # ── Helpers ────────────────────────────────────────────────────────────────

    def tcp_handshake(self, src_mac, src_ip, dst_mac, dst_ip,
                      sport, dport, seq=None):
        seq = seq or random.randint(1000, 0xFFFFFF)
        # SYN
        self.w.write_tcp(self.tick(), dst_mac, src_mac, src_ip, dst_ip,
                         sport, dport, flags=TCP_SYN, seq=seq)
        # SYN-ACK
        sseq = random.randint(1000, 0xFFFFFF)
        self.w.write_tcp(self.tick(0.002), src_mac, dst_mac, dst_ip, src_ip,
                         dport, sport, flags=TCP_SYN | TCP_ACK, seq=sseq, ack=seq + 1)
        # ACK
        self.w.write_tcp(self.tick(0.001), dst_mac, src_mac, src_ip, dst_ip,
                         sport, dport, flags=TCP_ACK, seq=seq + 1, ack=sseq + 1)
        return seq + 1, sseq + 1

    def tcp_teardown(self, src_mac, src_ip, dst_mac, dst_ip, sport, dport,
                     seq, ack):
        self.w.write_tcp(self.tick(), dst_mac, src_mac, src_ip, dst_ip,
                         sport, dport, flags=TCP_FIN | TCP_ACK, seq=seq, ack=ack)
        self.w.write_tcp(self.tick(0.002), src_mac, dst_mac, dst_ip, src_ip,
                         dport, sport, flags=TCP_FIN | TCP_ACK, seq=ack, ack=seq + 1)
        self.w.write_tcp(self.tick(0.001), dst_mac, src_mac, src_ip, dst_ip,
                         sport, dport, flags=TCP_ACK, seq=seq + 1, ack=ack + 1)

    def arp_request(self, sender, target_ip):
        self.w.write_arp(self.tick(0.001),
                         "ff:ff:ff:ff:ff:ff", sender["mac"],
                         op=1, sender_mac=sender["mac"], sender_ip=sender["ip"],
                         target_mac="00:00:00:00:00:00", target_ip=target_ip)

    def arp_reply(self, sender, target):
        self.w.write_arp(self.tick(0.001),
                         target["mac"], sender["mac"],
                         op=2, sender_mac=sender["mac"], sender_ip=sender["ip"],
                         target_mac=target["mac"], target_ip=target["ip"])

    def dns_exchange(self, client, server_ip, domain, resolved):
        txid = random.randint(1, 0xFFFF)
        sport = random.randint(1024, 65535)
        self.w.write_dns_query(self.tick(), GATEWAY_MAC, client["mac"],
                               client["ip"], server_ip, sport, txid, domain)
        self.w.write_dns_response(self.tick(0.015), client["mac"], GATEWAY_MAC,
                                  server_ip, client["ip"], sport, txid,
                                  domain, resolved)

    def http_exchange(self, client, server_ip, request, response, dport=80):
        sport = random.randint(1024, 65535)
        seq, ack = self.tcp_handshake(
            client["mac"], client["ip"],
            GATEWAY_MAC, server_ip, sport, dport)
        # Request
        self.w.write_tcp(self.tick(0.005),
                         GATEWAY_MAC, client["mac"],
                         client["ip"], server_ip,
                         sport, dport, payload=request,
                         flags=TCP_ACK | 0x08, seq=seq, ack=ack)
        # Response
        self.w.write_tcp(self.tick(0.020),
                         client["mac"], GATEWAY_MAC,
                         server_ip, client["ip"],
                         dport, sport, payload=response,
                         flags=TCP_ACK | 0x08, seq=ack, ack=seq + len(request))
        self.tcp_teardown(client["mac"], client["ip"],
                          GATEWAY_MAC, server_ip, sport, dport,
                          seq + len(request), ack + len(response))

    def icmp_ping(self, src, dst_ip, count=3):
        for i in range(count):
            self.w.write_icmp(self.tick(), GATEWAY_MAC, src["mac"],
                              src["ip"], dst_ip,
                              icmp_type=8, code=0,
                              identifier=random.randint(1, 0xFFFF),
                              sequence=i + 1,
                              payload=b"abcdefghijklmnop")
            self.w.write_icmp(self.tick(0.005), src["mac"], GATEWAY_MAC,
                              dst_ip, src["ip"],
                              icmp_type=0, code=0,
                              identifier=i + 1, sequence=i + 1,
                              payload=b"abcdefghijklmnop")


# ══════════════════════════════════════════════════════════════════════════════
# Scenarios
# ══════════════════════════════════════════════════════════════════════════════

def build_normal(path: str) -> int:
    """Normal web-browsing, DNS, ICMP traffic. No anomalies."""
    ws1, ws2, web, db, att = HOSTS
    count = 0

    with PcapWriter(path) as w:
        b = ScenarioBuilder(w)

        # ── ARP discovery ─────────────────────────────────────────────────────
        for host in [ws1, ws2]:
            b.arp_request(host, GATEWAY_IP)
            b.arp_reply({"mac": GATEWAY_MAC, "ip": GATEWAY_IP}, host)
            count += 2

        # ── DNS lookups ───────────────────────────────────────────────────────
        for _ in range(6):
            client = random.choice([ws1, ws2])
            domain, ip = random.choice(DOMAINS)
            b.dns_exchange(client, DNS_SERVER_IP, domain, ip)
            count += 2

        # ── HTTP browsing ─────────────────────────────────────────────────────
        for _ in range(8):
            client = random.choice([ws1, ws2])
            _, ext_ip = random.choice(DOMAINS)
            req  = random.choice(HTTP_GETS)
            resp = random.choice(HTTP_RESPONSES)
            b.http_exchange(client, ext_ip, req, resp)
            count += 9   # approx (handshake + data + teardown)

        # ── ICMP pings ────────────────────────────────────────────────────────
        for host in [ws1, ws2]:
            b.icmp_ping(host, GATEWAY_IP, count=4)
            count += 8

        # ── Internal server traffic ───────────────────────────────────────────
        for _ in range(5):
            sport = random.randint(1024, 65535)
            b.tcp_handshake(ws1["mac"], ws1["ip"], web["mac"], web["ip"],
                            sport, 80)
            count += 3

    return count


def build_attack(path: str) -> int:
    """Mixed normal + injected attacks."""
    ws1, ws2, web, db, att = HOSTS
    count = 0

    with PcapWriter(path) as w:
        b = ScenarioBuilder(w)

        # ── Normal baseline (brief) ────────────────────────────────────────────
        for domain, ip in DOMAINS[:3]:
            b.dns_exchange(ws1, DNS_SERVER_IP, domain, ip)
        b.http_exchange(ws1, "93.184.216.34",
                        HTTP_GETS[0], HTTP_RESPONSES[0])
        b.icmp_ping(ws1, GATEWAY_IP, 2)
        count += 20

        # ── [ATTACK 1] Vertical port scan ─────────────────────────────────────
        # attacker → web server, scanning 30 TCP ports
        scan_ports = list(range(20, 25)) + [22, 23, 25, 53, 80, 110, 135,
                          139, 143, 443, 445, 993, 3389, 5900, 6379,
                          8080, 8443, 8888, 9200, 27017, 3306, 5432]
        random.shuffle(scan_ports)
        for port in scan_ports:
            seq = random.randint(1000, 0xFFFFFF)
            w.write_tcp(b.tick(0.02), web["mac"], att["mac"],
                        att["ip"], web["ip"], random.randint(40000, 60000), port,
                        flags=TCP_SYN, seq=seq)
            # Closed port → RST
            w.write_tcp(b.tick(0.002), att["mac"], web["mac"],
                        web["ip"], att["ip"], port, random.randint(40000, 60000),
                        flags=TCP_RST | TCP_ACK, seq=0, ack=seq + 1)
            count += 2

        # ── [ATTACK 2] SYN flood against web server ────────────────────────────
        flood_src_ips = [f"10.0.0.{i}" for i in range(1, 80)]
        for i in range(70):
            spoof_ip = random.choice(flood_src_ips)
            w.write_tcp(b.tick(0.005), web["mac"], att["mac"],
                        spoof_ip, web["ip"],
                        random.randint(1024, 65535), 80,
                        flags=TCP_SYN, seq=random.randint(0, 0xFFFFFFFF))
            count += 1

        # ── [ATTACK 3] DNS exfiltration ────────────────────────────────────────
        # Long subdomain labels carrying encoded data
        secret_chunks = [
            "dGhpcyBpcyBzZWNyZXQgZGF0YQ",        # base64-ish labels
            "c2Vuc2l0aXZlLWluZm9ybWF0aW9u",
            "cGFzc3dvcmQxMjM0NTY3OA",
            "Y3JlZGl0Y2FyZC0xMjM0LTU2NzgtOTAxMg",
            "aW50ZXJuYWwtc2VjcmV0LXRva2VuLXZhbHVl",
        ]
        exfil_domain = "c2.evil-domain.net"
        for chunk in secret_chunks:
            txid = random.randint(1, 0xFFFF)
            exfil_name = f"{chunk}.{exfil_domain}"
            w.write_dns_query(b.tick(0.1), GATEWAY_MAC, att["mac"],
                              att["ip"], DNS_SERVER_IP,
                              random.randint(1024, 65535), txid, exfil_name)
            count += 1

        # ── [ATTACK 4] ARP poisoning ───────────────────────────────────────────
        # Attacker claims to be the gateway — gratuitous ARP replies
        for _ in range(5):
            w.write_arp(b.tick(0.05),
                        "ff:ff:ff:ff:ff:ff", att["mac"],
                        op=2,
                        sender_mac=att["mac"],
                        sender_ip=GATEWAY_IP,          # ← spoofed IP!
                        target_mac="00:00:00:00:00:00",
                        target_ip=ws1["ip"])
            count += 1
        # Later — legitimate gateway responds (triggers multi-MAC alert)
        w.write_arp(b.tick(0.1),
                    "ff:ff:ff:ff:ff:ff", GATEWAY_MAC,
                    op=2,
                    sender_mac=GATEWAY_MAC,
                    sender_ip=GATEWAY_IP,
                    target_mac="00:00:00:00:00:00",
                    target_ip=ws1["ip"])
        count += 1

        # ── [ATTACK 5] Connection to suspicious port (C2 beacon) ──────────────
        w.write_tcp(b.tick(0.3), GATEWAY_MAC, att["mac"],
                    att["ip"], "185.220.101.1",
                    random.randint(40000, 60000), 4444,
                    flags=TCP_SYN, seq=random.randint(0, 0xFFFFFF))
        count += 1

        # ── [ATTACK 6] Horizontal scan (same port, many hosts) ─────────────────
        subnet_hosts = [f"192.168.1.{i}" for i in range(1, 25)]
        for target_ip in subnet_hosts:
            w.write_tcp(b.tick(0.015), GATEWAY_MAC, att["mac"],
                        att["ip"], target_ip,
                        random.randint(40000, 60000), 445,
                        flags=TCP_SYN, seq=random.randint(0, 0xFFFFFF))
            count += 1

        # ── Normal traffic continues (to build realistic baseline) ─────────────
        for domain, ip in DOMAINS:
            b.dns_exchange(ws2, DNS_SERVER_IP, domain, ip)
        b.http_exchange(ws2, "151.101.65.121",
                        HTTP_GETS[2], HTTP_RESPONSES[0])
        count += 14

    return count


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Generate sample .pcap files for Network Analysis Lab"
    )
    parser.add_argument(
        "--scenario",
        choices=["normal", "attack", "both"],
        default="both",
        help="Which scenario(s) to generate (default: both)",
    )
    parser.add_argument(
        "--outdir",
        default="samples",
        help="Output directory (default: samples/)",
    )
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    print(f"\n{BOLD}{CYAN}Network Analysis Lab — Sample Generator{RESET}")
    print("─" * 44)

    if args.scenario in ("normal", "both"):
        path = os.path.join(args.outdir, "normal_traffic.pcap")
        n = build_normal(path)
        size = os.path.getsize(path)
        print(f"{GREEN}✓{RESET} {path:<40}  ~{n} packets  ({size:,} bytes)")

    if args.scenario in ("attack", "both"):
        path = os.path.join(args.outdir, "attack_traffic.pcap")
        n = build_attack(path)
        size = os.path.getsize(path)
        print(f"{GREEN}✓{RESET} {path:<40}  ~{n} packets  ({size:,} bytes)")

    print(f"\n{YELLOW}Run the analyzer:{RESET}")
    print(f"  python analyze.py samples/normal_traffic.pcap")
    print(f"  python analyze.py samples/attack_traffic.pcap --dashboard\n")


if __name__ == "__main__":
    main()
