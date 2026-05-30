"""
Test suite for Network Analysis Lab.

Run with:  python -m unittest discover tests/ -v
           OR: pytest tests/ -v  (if pytest is installed)
"""

import os, sys, struct, socket, tempfile, unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.pcap_reader import (
    PcapReader, parse_packet, Packet,
    ETHERTYPE_IPV4, ETHERTYPE_ARP, PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    TCP_SYN, TCP_ACK, TCP_FIN, TCP_RST,
)
from src.core.pcap_writer import (
    PcapWriter, ip_packet, tcp_segment, udp_datagram,
    icmp_echo, arp_packet, dns_query,
    ETHERTYPE_IPV4 as EV4, PROTO_TCP as PT, PROTO_UDP as PU, PROTO_ICMP as PI,
)
from src.analysis.analyzer import TrafficStats, FlowTracker, AnomalyDetector, Alert

# ── Test constants ─────────────────────────────────────────────────────────────
MAC_A = "00:11:22:33:44:01"
MAC_B = "00:11:22:33:44:02"
MAC_C = "00:11:22:33:44:03"
IP_A  = "192.168.1.10"
IP_B  = "192.168.1.20"
IP_C  = "10.0.0.1"
GW_IP = "192.168.1.1"

# ── Helpers ────────────────────────────────────────────────────────────────────

def _mac_b(s):
    return bytes(int(x, 16) for x in s.split(":"))

def _make_pcap(packets):
    f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for ts, raw in packets:
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        f.write(struct.pack("<IIII", ts_sec, ts_usec, len(raw), len(raw)))
        f.write(raw)
    f.close()
    return f.name

def _eth(dst, src, payload, ethertype=EV4):
    return _mac_b(dst) + _mac_b(src) + struct.pack("!H", ethertype) + payload

def _tcp(sport, dport, flags, seq=100, ack=0, payload=b""):
    return tcp_segment(sport, dport, payload, seq=seq, ack=ack, flags=flags)

def _udp(sport, dport, payload=b""):
    return udp_datagram(sport, dport, payload)

def _ip(src, dst, proto, payload, ttl=64):
    return ip_packet(src, dst, proto, payload, ttl=ttl)


# ══════════════════════════════════════════════════════════════════════════════
# PcapReader
# ══════════════════════════════════════════════════════════════════════════════
class TestPcapReader(unittest.TestCase):

    def test_reads_global_header(self):
        path = _make_pcap([])
        try:
            with PcapReader(path) as r:
                self.assertEqual(r.version,   (2, 4))
                self.assertEqual(r.link_type, 1)
        finally:
            os.unlink(path)

    def test_empty_file_yields_no_packets(self):
        path = _make_pcap([])
        try:
            with PcapReader(path) as r:
                self.assertEqual(list(r.packets()), [])
        finally:
            os.unlink(path)

    def test_tcp_syn_dissection(self):
        raw = _eth(MAC_B, MAC_A, _ip(IP_A, IP_B, PT, _tcp(1234, 80, TCP_SYN)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                pkts = list(r.packets())
            self.assertEqual(len(pkts), 1)
            p = pkts[0]
            self.assertEqual(p.ip_src,    IP_A)
            self.assertEqual(p.ip_dst,    IP_B)
            self.assertEqual(p.tcp_sport, 1234)
            self.assertEqual(p.tcp_dport, 80)
            self.assertTrue(p.tcp_flags & TCP_SYN)
            self.assertFalse(p.tcp_flags & TCP_ACK)
        finally:
            os.unlink(path)

    def test_reads_50_packets(self):
        packets = [
            (float(i) * 0.01,
             _eth(MAC_B, MAC_A, _ip(IP_A, IP_B, PT, _tcp(i+1024, 443, TCP_ACK))))
            for i in range(50)
        ]
        path = _make_pcap(packets)
        try:
            with PcapReader(path) as r:
                self.assertEqual(len(list(r.packets())), 50)
        finally:
            os.unlink(path)

    def test_udp_dns_dissection(self):
        payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        raw = _eth(MAC_B, MAC_A,
                   _ip(IP_A, "8.8.8.8", PU, _udp(54321, 53, payload)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.udp_sport, 54321)
            self.assertEqual(p.udp_dport, 53)
            self.assertEqual(p.protocol,  "DNS")
        finally:
            os.unlink(path)

    def test_icmp_dissection(self):
        raw = _eth(MAC_B, MAC_A,
                   _ip(IP_A, IP_B, PI,
                       icmp_echo(icmp_type=8, code=0, identifier=1, sequence=1)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.ip_proto,  PROTO_ICMP)
            self.assertEqual(p.icmp_type, 8)
            self.assertEqual(p.protocol,  "ICMP")
        finally:
            os.unlink(path)

    def test_arp_dissection(self):
        arp = arp_packet(1, MAC_A, IP_A, "00:00:00:00:00:00", GW_IP)
        raw = _eth("ff:ff:ff:ff:ff:ff", MAC_A, arp, 0x0806)
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.ethertype,     ETHERTYPE_ARP)
            self.assertEqual(p.arp_op,        1)
            self.assertEqual(p.arp_sender_ip, IP_A)
            self.assertEqual(p.protocol,      "ARP")
        finally:
            os.unlink(path)

    def test_http_detection(self):
        http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        raw = _eth(MAC_B, MAC_A,
                   _ip(IP_A, IP_B, PT,
                       _tcp(50001, 80, TCP_ACK | 0x08, payload=http_req)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.protocol, "HTTP")
            self.assertIsNotNone(p.http)
            self.assertEqual(p.http["type"],   "request")
            self.assertEqual(p.http["method"], "GET")
            self.assertEqual(p.http["uri"],    "/index.html")
        finally:
            os.unlink(path)

    def test_dns_query_parse(self):
        qpayload = dns_query(0xABCD, "example.com", 1)
        raw = _eth(MAC_B, MAC_A,
                   _ip(IP_A, "8.8.8.8", PU, _udp(12345, 53, qpayload)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertIsNotNone(p.dns)
            self.assertEqual(p.dns["qr"],   "query")
            self.assertEqual(p.dns["txid"], 0xABCD)
            self.assertEqual(len(p.dns["questions"]), 1)
            self.assertIn("example.com", p.dns["questions"][0]["name"])
        finally:
            os.unlink(path)

    def test_tcp_flags_str(self):
        raw = _eth(MAC_B, MAC_A,
                   _ip(IP_A, IP_B, PT, _tcp(1234, 80, TCP_SYN | TCP_ACK)))
        path = _make_pcap([(1.0, raw)])
        try:
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertIn("SYN", p.tcp_flags_str)
            self.assertIn("ACK", p.tcp_flags_str)
        finally:
            os.unlink(path)

    def test_flow_key_bidirectional(self):
        raw_fwd = _eth(MAC_B, MAC_A, _ip(IP_A, IP_B, PT, _tcp(1111, 80, TCP_SYN)))
        raw_rev = _eth(MAC_A, MAC_B, _ip(IP_B, IP_A, PT, _tcp(80, 1111, TCP_SYN | TCP_ACK)))
        path = _make_pcap([(1.0, raw_fwd), (1.001, raw_rev)])
        try:
            with PcapReader(path) as r:
                pkts = list(r.packets())
            self.assertEqual(pkts[0].flow_key, pkts[1].flow_key)
        finally:
            os.unlink(path)

    def test_ttl_parsing(self):
        for ttl in [1, 64, 128, 255]:
            raw = _eth(MAC_B, MAC_A, _ip(IP_A, IP_B, PI,
                       icmp_echo(icmp_type=8), ttl=ttl))
            path = _make_pcap([(1.0, raw)])
            try:
                with PcapReader(path) as r:
                    p = list(r.packets())[0]
                self.assertEqual(p.ip_ttl, ttl)
            finally:
                os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# TrafficStats
# ══════════════════════════════════════════════════════════════════════════════
class TestTrafficStats(unittest.TestCase):

    def _make_pkt(self, src=IP_A, dst=IP_B, proto=PT,
                  sport=1234, dport=80, size=100, ts=1.0):
        p = Packet(ts_sec=int(ts), ts_usec=int((ts%1)*1e6),
                   raw=b"\x00"*size, size=size)
        p.ip_src    = src;  p.ip_dst    = dst
        p.ip_proto  = proto; p.ip_ttl    = 64
        p.tcp_sport = sport; p.tcp_dport = dport
        return p

    def test_counts_packets_and_bytes(self):
        stats = TrafficStats()
        for i in range(10):
            stats.ingest(self._make_pkt(size=100, ts=float(i)))
        self.assertEqual(stats.total_packets, 10)
        self.assertEqual(stats.total_bytes,   1000)

    def test_top_talkers_ordered(self):
        stats = TrafficStats()
        for _ in range(10): stats.ingest(self._make_pkt(src=IP_A))
        for _ in range(3):  stats.ingest(self._make_pkt(src=IP_C))
        self.assertEqual(stats.top_talkers(5)[0]["ip"], IP_A)

    def test_duration(self):
        stats = TrafficStats()
        stats.ingest(self._make_pkt(ts=0.0))
        stats.ingest(self._make_pkt(ts=5.5))
        self.assertAlmostEqual(stats.duration, 5.5, places=2)

    def test_timeline_bins(self):
        stats = TrafficStats()
        for i in range(100):
            stats.ingest(self._make_pkt(ts=float(i) * 0.1))
        bins = stats.timeline_bins(10)
        self.assertLessEqual(len(bins), 10)
        self.assertEqual(sum(b["packets"] for b in bins), 100)

    def test_protocol_summary_nonempty(self):
        stats = TrafficStats()
        for _ in range(5): stats.ingest(self._make_pkt(proto=PT, dport=80))
        self.assertGreater(len(stats.protocol_summary()), 0)


# ══════════════════════════════════════════════════════════════════════════════
# FlowTracker
# ══════════════════════════════════════════════════════════════════════════════
class TestFlowTracker(unittest.TestCase):

    def _pkt(self, src, dst, sport, dport, proto=PT, flags=TCP_ACK, ts=1.0, size=60):
        p = Packet(ts_sec=int(ts), ts_usec=0, raw=b"\x00"*size, size=size)
        p.ip_src = src;  p.ip_dst  = dst;  p.ip_proto  = proto
        p.tcp_sport = sport; p.tcp_dport = dport; p.tcp_flags = flags
        return p

    def test_creates_flow(self):
        ft = FlowTracker()
        f  = ft.update(self._pkt(IP_A, IP_B, 1111, 80, flags=TCP_SYN))
        self.assertIsNotNone(f)
        self.assertEqual(f.packets, 1)

    def test_bidirectional_single_flow(self):
        ft = FlowTracker()
        ft.update(self._pkt(IP_A, IP_B, 1111, 80, flags=TCP_SYN))
        ft.update(self._pkt(IP_B, IP_A, 80, 1111, flags=TCP_SYN | TCP_ACK))
        ft.update(self._pkt(IP_A, IP_B, 1111, 80, flags=TCP_ACK))
        self.assertEqual(len(ft.flows), 1)
        self.assertEqual(list(ft.flows.values())[0].packets, 3)

    def test_multiple_distinct_flows(self):
        ft = FlowTracker()
        ft.update(self._pkt(IP_A, IP_B, 1111, 80))
        ft.update(self._pkt(IP_A, IP_B, 2222, 443))
        ft.update(self._pkt(IP_C, IP_B, 3333, 80))
        self.assertEqual(len(ft.flows), 3)

    def test_bytes_accumulate(self):
        ft = FlowTracker()
        for _ in range(5):
            ft.update(self._pkt(IP_A, IP_B, 1111, 80, size=200))
        self.assertEqual(list(ft.flows.values())[0].bytes, 1000)

    def test_tcp_state_machine_established(self):
        ft = FlowTracker()
        ft.update(self._pkt(IP_A, IP_B, 1111, 80, flags=TCP_SYN, ts=1.0))
        ft.update(self._pkt(IP_B, IP_A, 80, 1111, flags=TCP_SYN | TCP_ACK, ts=1.001))
        ft.update(self._pkt(IP_A, IP_B, 1111, 80, flags=TCP_ACK, ts=1.002))
        self.assertEqual(list(ft.flows.values())[0].state, "ESTABLISHED")

    def test_sorted_flows_by_bytes(self):
        ft = FlowTracker()
        for sport, size in [(1111, 100), (2222, 500), (3333, 50)]:
            for _ in range(3):
                ft.update(self._pkt(IP_A, IP_B, sport, 80, size=size))
        sf = ft.sorted_flows("bytes")
        self.assertGreaterEqual(sf[0].bytes, sf[1].bytes)


# ══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector
# ══════════════════════════════════════════════════════════════════════════════
class TestAnomalyDetector(unittest.TestCase):

    def _syn(self, src, dst, dport, ts=1.0):
        p = Packet(ts_sec=int(ts), ts_usec=0, raw=b"\x00"*60, size=60)
        p.ip_src = src;  p.ip_dst = dst;  p.ip_proto = PT
        p.tcp_sport = 45000; p.tcp_dport = dport; p.tcp_flags = TCP_SYN
        return p

    def _arp_reply(self, sender_mac, sender_ip, target_ip, ts=1.0):
        p = Packet(ts_sec=int(ts), ts_usec=0, raw=b"\x00"*60, size=60)
        p.ethertype = ETHERTYPE_ARP; p.arp_op = 2
        p.arp_sender_mac = sender_mac; p.arp_sender_ip = sender_ip
        p.arp_target_ip  = target_ip;  p.eth_src = sender_mac
        p.eth_dst = "ff:ff:ff:ff:ff:ff"
        return p

    def _dns_pkt(self, src, name, ts=1.0):
        qpayload = dns_query(0x1234, name)
        p = Packet(ts_sec=int(ts), ts_usec=0, raw=b"\x00"*80, size=80)
        p.ip_src = src; p.ip_dst = "8.8.8.8"; p.ip_proto = PU
        p.udp_sport = 54321; p.udp_dport = 53
        from src.core.pcap_reader import _parse_dns
        p.dns = _parse_dns(qpayload)
        return p

    def test_vertical_port_scan_detected(self):
        det = AnomalyDetector(); det.PORT_SCAN_V_THRESHOLD = 5
        alerts = []
        for port in range(20, 30):
            alerts += det.update(self._syn(IP_A, IP_B, port, ts=float(port)*0.01))
        self.assertTrue(any(a.category == "port_scan_vertical" for a in alerts))

    def test_no_scan_below_threshold(self):
        det = AnomalyDetector(); det.PORT_SCAN_V_THRESHOLD = 20
        for port in range(80, 85):
            det.update(self._syn(IP_A, IP_B, port))
        self.assertFalse(any("port_scan" in a.category for a in det.alerts))

    def test_horizontal_scan_on_finalize(self):
        det = AnomalyDetector(); det.PORT_SCAN_H_THRESHOLD = 5
        for i in range(10):
            det.update(self._syn(IP_A, f"192.168.1.{i+1}", 445))
        det.finalize([])
        self.assertTrue(any("horizontal" in a.category for a in det.alerts))

    def test_syn_flood_critical(self):
        det = AnomalyDetector(); det.SYN_FLOOD_THRESHOLD = 10; det.TIME_WINDOW = 5.0
        for i in range(15):
            p = Packet(ts_sec=1, ts_usec=i*100000, raw=b"\x00"*60, size=60)
            p.ip_src = IP_A; p.ip_dst = IP_B; p.ip_proto = PT
            p.tcp_sport = 10000+i; p.tcp_dport = 80; p.tcp_flags = TCP_SYN
            det.update(p)
        floods = [a for a in det.alerts if a.category == "syn_flood"]
        self.assertGreater(len(floods), 0)
        self.assertEqual(floods[0].severity, "CRITICAL")

    def test_arp_spoofing_two_macs(self):
        det = AnomalyDetector()
        det.update(self._arp_reply(MAC_A, GW_IP, IP_A, ts=1.0))
        det.update(self._arp_reply(MAC_B, GW_IP, IP_A, ts=1.1))
        spoof = [a for a in det.alerts if a.category == "arp_spoofing"]
        self.assertEqual(len(spoof), 1)
        self.assertEqual(spoof[0].severity, "HIGH")

    def test_no_arp_alert_single_mac(self):
        det = AnomalyDetector()
        for i in range(5):
            det.update(self._arp_reply(MAC_A, GW_IP, IP_A, ts=float(i)))
        self.assertFalse(any(a.category == "arp_spoofing" for a in det.alerts))

    def test_dns_exfil_long_label(self):
        det = AnomalyDetector()
        det.update(self._dns_pkt(IP_A, "a" * 50 + ".evil.com"))
        self.assertTrue(any(a.category == "dns_exfiltration" for a in det.alerts))

    def test_dns_high_rate(self):
        det = AnomalyDetector(); det.DNS_RATE_THRESHOLD = 5; det.TIME_WINDOW = 10.0
        for i in range(8):
            det.update(self._dns_pkt(IP_A, f"q{i}.example.com", ts=float(i)*0.1))
        self.assertTrue(any(a.category == "dns_high_query_rate" for a in det.alerts))

    def test_suspicious_port_4444(self):
        det = AnomalyDetector()
        p = Packet(ts_sec=1, ts_usec=0, raw=b"\x00"*60, size=60)
        p.ip_src = IP_A; p.ip_dst = "185.220.101.1"; p.ip_proto = PT
        p.tcp_sport = 50000; p.tcp_dport = 4444; p.tcp_flags = TCP_SYN
        det.update(p)
        self.assertTrue(any(a.category == "suspicious_port" for a in det.alerts))

    def test_alert_deduplication(self):
        det = AnomalyDetector(); det.PORT_SCAN_V_THRESHOLD = 3
        for port in range(80, 90):
            det.update(self._syn(IP_A, IP_B, port))
        scans = [a for a in det.alerts if a.category == "port_scan_vertical"]
        self.assertEqual(len(scans), 1)

    def test_summary_structure(self):
        det = AnomalyDetector()
        det.alerts = [
            Alert(severity="CRITICAL", category="t", description="c"),
            Alert(severity="HIGH",     category="t", description="h"),
            Alert(severity="MEDIUM",   category="t", description="m"),
        ]
        s = det.summary()
        self.assertEqual(s["total"],    3)
        self.assertEqual(s["critical"], 1)
        self.assertEqual(s["high"],     1)


# ══════════════════════════════════════════════════════════════════════════════
# PcapWriter round-trip
# ══════════════════════════════════════════════════════════════════════════════
class TestPcapWriterRoundTrip(unittest.TestCase):

    def _tmp(self):
        f = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        f.close()
        return f.name

    def test_tcp_roundtrip(self):
        path = self._tmp()
        try:
            with PcapWriter(path) as w:
                w.write_tcp(1.5, MAC_B, MAC_A, IP_A, IP_B,
                            sport=54321, dport=443, flags=TCP_SYN, seq=42)
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.ip_src,    IP_A)
            self.assertEqual(p.tcp_sport, 54321)
            self.assertEqual(p.tcp_dport, 443)
            self.assertTrue(p.tcp_flags & TCP_SYN)
        finally:
            os.unlink(path)

    def test_udp_roundtrip(self):
        path = self._tmp()
        try:
            with PcapWriter(path) as w:
                w.write_udp(2.0, MAC_B, MAC_A, IP_A, "8.8.8.8", 12345, 53, b"test")
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.udp_dport,   53)
            self.assertEqual(p.udp_payload, b"test")
        finally:
            os.unlink(path)

    def test_icmp_roundtrip(self):
        path = self._tmp()
        try:
            with PcapWriter(path) as w:
                w.write_icmp(1.0, MAC_B, MAC_A, IP_A, IP_B,
                             icmp_type=8, code=0, identifier=99, sequence=1)
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.icmp_type, 8)
        finally:
            os.unlink(path)

    def test_arp_roundtrip(self):
        path = self._tmp()
        try:
            with PcapWriter(path) as w:
                w.write_arp(1.0, "ff:ff:ff:ff:ff:ff", MAC_A,
                            op=1, sender_mac=MAC_A, sender_ip=IP_A,
                            target_mac="00:00:00:00:00:00", target_ip=GW_IP)
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertEqual(p.arp_sender_ip, IP_A)
            self.assertEqual(p.arp_target_ip, GW_IP)
            self.assertEqual(p.arp_op,        1)
        finally:
            os.unlink(path)

    def test_timestamp_precision(self):
        path = self._tmp()
        try:
            with PcapWriter(path) as w:
                w.write_tcp(1234567.891, MAC_B, MAC_A, IP_A, IP_B, 1234, 80, flags=TCP_ACK)
            with PcapReader(path) as r:
                p = list(r.packets())[0]
            self.assertAlmostEqual(p.timestamp, 1234567.891, places=2)
        finally:
            os.unlink(path)


# ══════════════════════════════════════════════════════════════════════════════
# Integration tests
# ══════════════════════════════════════════════════════════════════════════════
class TestIntegration(unittest.TestCase):

    def test_normal_traffic_no_critical_alerts(self):
        from tools.generate_sample import build_normal
        td   = tempfile.mkdtemp()
        path = os.path.join(td, "normal.pcap")
        build_normal(path)
        self.assertGreater(os.path.getsize(path), 0)

        stats = TrafficStats(); flows = FlowTracker(); det = AnomalyDetector()
        with PcapReader(path) as r:
            for pkt in r.packets():
                stats.ingest(pkt); flows.update(pkt); det.update(pkt)
        det.finalize(flows.sorted_flows())

        self.assertGreater(stats.total_packets, 0)
        self.assertEqual(len([a for a in det.alerts if a.severity == "CRITICAL"]), 0)

    def test_attack_traffic_fires_expected_alerts(self):
        from tools.generate_sample import build_attack
        td   = tempfile.mkdtemp()
        path = os.path.join(td, "attack.pcap")
        build_attack(path)

        stats = TrafficStats(); flows = FlowTracker(); det = AnomalyDetector()
        with PcapReader(path) as r:
            for pkt in r.packets():
                stats.ingest(pkt); flows.update(pkt); det.update(pkt)
        det.finalize(flows.sorted_flows())

        cats = {a.category for a in det.alerts}
        self.assertTrue(
            "port_scan_vertical" in cats or "port_scan_horizontal" in cats,
            f"Expected port scan alert, got: {cats}"
        )
        self.assertIn("dns_exfiltration", cats)
        self.assertIn("arp_spoofing",     cats)
        self.assertIn("suspicious_port",  cats)

    def test_protocol_variety_in_normal_traffic(self):
        from tools.generate_sample import build_normal
        td   = tempfile.mkdtemp()
        path = os.path.join(td, "proto_test.pcap")
        build_normal(path)

        stats = TrafficStats()
        with PcapReader(path) as r:
            for pkt in r.packets():
                stats.ingest(pkt)

        names = {p["protocol"] for p in stats.protocol_summary()}
        self.assertTrue(names & {"ARP", "DNS", "HTTP", "ICMP"},
                        f"Expected varied protocols, got: {names}")
        self.assertGreater(stats.duration, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
