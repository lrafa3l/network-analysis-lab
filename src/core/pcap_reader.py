"""
Pure-Python pcap file reader and multi-layer protocol dissector.

No external dependencies required.

Supported layers
----------------
  Link     : Ethernet (802.3), 802.1Q VLAN, Raw IP
  Network  : IPv4, ARP
  Transport: TCP, UDP, ICMP
  Application: DNS, HTTP (cleartext)
"""

from __future__ import annotations

import struct
import socket
from dataclasses import dataclass, field
from typing import Iterator, Optional

# ── EtherType constants ────────────────────────────────────────────────────────
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100

# ── IP protocol numbers ────────────────────────────────────────────────────────
PROTO_ICMP = 1
PROTO_TCP  = 6
PROTO_UDP  = 17

# ── TCP flag bitmasks ──────────────────────────────────────────────────────────
TCP_FIN = 0x001
TCP_SYN = 0x002
TCP_RST = 0x004
TCP_PSH = 0x008
TCP_ACK = 0x010
TCP_URG = 0x020
TCP_ECE = 0x040
TCP_CWR = 0x080

# ── Well-known port sets ───────────────────────────────────────────────────────
HTTP_PORTS  = frozenset({80, 8080, 8000, 8888})
HTTPS_PORTS = frozenset({443, 8443})
DNS_PORTS   = frozenset({53})
DHCP_PORTS  = frozenset({67, 68})
SSH_PORTS   = frozenset({22})
FTP_PORTS   = frozenset({20, 21})
SMTP_PORTS  = frozenset({25, 465, 587})
RDP_PORTS   = frozenset({3389})
SMB_PORTS   = frozenset({139, 445})
TELNET_PORTS= frozenset({23})

# ── ICMP type names ────────────────────────────────────────────────────────────
ICMP_TYPES = {
    0: "Echo Reply",      3: "Dest Unreachable", 5: "Redirect",
    8: "Echo Request",   11: "Time Exceeded",   12: "Parameter Problem",
}

# ── ARP operation names ────────────────────────────────────────────────────────
ARP_OPS = {1: "Request", 2: "Reply", 3: "RARP Request", 4: "RARP Reply"}


# ══════════════════════════════════════════════════════════════════════════════
# Packet dataclass
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Packet:
    ts_sec:  int
    ts_usec: int
    raw:     bytes
    size:    int = 0

    # ── Ethernet ──────────────────────────────────────────────────────────────
    eth_dst:   str = ""
    eth_src:   str = ""
    ethertype: int = 0
    vlan_id:   int = 0

    # ── IPv4 ──────────────────────────────────────────────────────────────────
    ip_version:     int = 0
    ip_src:         str = ""
    ip_dst:         str = ""
    ip_proto:       int = 0
    ip_ttl:         int = 0
    ip_total_len:   int = 0
    ip_id:          int = 0
    ip_flags:       int = 0        # DF=2, MF=1
    ip_frag_offset: int = 0
    ip_dscp:        int = 0

    # ── TCP ───────────────────────────────────────────────────────────────────
    tcp_sport:   int   = 0
    tcp_dport:   int   = 0
    tcp_seq:     int   = 0
    tcp_ack:     int   = 0
    tcp_flags:   int   = 0
    tcp_window:  int   = 0
    tcp_payload: bytes = b""
    tcp_options: bytes = b""

    # ── UDP ───────────────────────────────────────────────────────────────────
    udp_sport:   int   = 0
    udp_dport:   int   = 0
    udp_len:     int   = 0
    udp_payload: bytes = b""

    # ── ICMP ──────────────────────────────────────────────────────────────────
    icmp_type: int = 0
    icmp_code: int = 0

    # ── ARP ───────────────────────────────────────────────────────────────────
    arp_op:         int = 0
    arp_sender_mac: str = ""
    arp_sender_ip:  str = ""
    arp_target_mac: str = ""
    arp_target_ip:  str = ""

    # ── Application ───────────────────────────────────────────────────────────
    dns:  Optional[dict] = None
    http: Optional[dict] = None

    # ── Computed properties ───────────────────────────────────────────────────

    @property
    def timestamp(self) -> float:
        return self.ts_sec + self.ts_usec / 1_000_000

    @property
    def protocol(self) -> str:
        if self.ethertype == ETHERTYPE_ARP:
            return "ARP"
        if self.ethertype == ETHERTYPE_IPV6:
            return "IPv6"
        if self.ip_proto == PROTO_ICMP:
            return "ICMP"
        if self.ip_proto == PROTO_TCP:
            p = {self.tcp_sport, self.tcp_dport}
            if p & HTTP_PORTS:   return "HTTP"
            if p & HTTPS_PORTS:  return "HTTPS"
            if p & SSH_PORTS:    return "SSH"
            if p & FTP_PORTS:    return "FTP"
            if p & SMTP_PORTS:   return "SMTP"
            if p & RDP_PORTS:    return "RDP"
            if p & SMB_PORTS:    return "SMB"
            if p & TELNET_PORTS: return "Telnet"
            return "TCP"
        if self.ip_proto == PROTO_UDP:
            p = {self.udp_sport, self.udp_dport}
            if p & DNS_PORTS:  return "DNS"
            if p & DHCP_PORTS: return "DHCP"
            return "UDP"
        return "UNKNOWN"

    @property
    def sport(self) -> int:
        return self.tcp_sport or self.udp_sport

    @property
    def dport(self) -> int:
        return self.tcp_dport or self.udp_dport

    @property
    def tcp_flags_str(self) -> str:
        bits = [(TCP_SYN,"SYN"),(TCP_ACK,"ACK"),(TCP_FIN,"FIN"),
                (TCP_RST,"RST"),(TCP_PSH,"PSH"),(TCP_URG,"URG"),
                (TCP_ECE,"ECE"),(TCP_CWR,"CWR")]
        return "|".join(n for b, n in bits if self.tcp_flags & b) or "NONE"

    @property
    def icmp_type_name(self) -> str:
        return ICMP_TYPES.get(self.icmp_type, f"type={self.icmp_type}")

    @property
    def arp_op_name(self) -> str:
        return ARP_OPS.get(self.arp_op, str(self.arp_op))

    @property
    def flow_key(self) -> tuple:
        """Canonical (sorted) 5-tuple for bidirectional flow identification."""
        a = (self.ip_src, self.ip_dst, self.ip_proto, self.sport, self.dport)
        b = (self.ip_dst, self.ip_src, self.ip_proto, self.dport, self.sport)
        return min(a, b)

    @property
    def is_fragment(self) -> bool:
        return bool(self.ip_frag_offset or (self.ip_flags & 1))

    def summary(self) -> str:
        src = f"{self.ip_src}:{self.sport}" if self.sport else (self.ip_src or self.eth_src)
        dst = f"{self.ip_dst}:{self.dport}" if self.dport else (self.ip_dst or self.eth_dst)
        flags = f" [{self.tcp_flags_str}]" if self.ip_proto == PROTO_TCP else ""
        return (f"{self.timestamp:>15.6f}  {self.protocol:<7}  "
                f"{src:<23} → {dst:<23}{flags}  {self.size} B")


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)

def _ip4(b: bytes) -> str:
    return socket.inet_ntoa(b)


# ══════════════════════════════════════════════════════════════════════════════
# DNS parser
# ══════════════════════════════════════════════════════════════════════════════

_DNS_TYPES = {
    1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR",
    15:"MX", 16:"TXT", 28:"AAAA", 33:"SRV", 255:"ANY",
}

def _dns_type_name(t: int) -> str:
    return _DNS_TYPES.get(t, str(t))


def _parse_dns_name(data: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    if depth > 12:
        return "", offset
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            rest, _ = _parse_dns_name(data, ptr, depth + 1)
            labels.append(rest)
            break
        offset += 1
        labels.append(data[offset: offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _parse_dns(data: bytes) -> Optional[dict]:
    if len(data) < 12:
        return None
    try:
        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
        result = {
            "txid":       txid,
            "qr":         "response" if (flags >> 15) & 1 else "query",
            "opcode":     (flags >> 11) & 0xF,
            "aa":         bool((flags >> 10) & 1),
            "tc":         bool((flags >> 9) & 1),
            "rd":         bool((flags >> 8) & 1),
            "rcode":      flags & 0xF,
            "questions":  [],
            "answers":    [],
        }
        offset = 12
        for _ in range(qdcount):
            name, offset = _parse_dns_name(data, offset)
            if offset + 4 > len(data):
                break
            qtype, qclass = struct.unpack("!HH", data[offset: offset + 4])
            offset += 4
            result["questions"].append({"name": name, "type": _dns_type_name(qtype), "class": qclass})
        for _ in range(ancount):
            if offset >= len(data):
                break
            name, offset = _parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, ttl, rdlen = struct.unpack("!HHIH", data[offset: offset + 10])
            offset += 10
            rdata = data[offset: offset + rdlen]
            offset += rdlen
            ans = {"name": name, "type": _dns_type_name(rtype), "ttl": ttl, "data": ""}
            if   rtype == 1  and rdlen == 4:  ans["data"] = _ip4(rdata)
            elif rtype == 28 and rdlen == 16:
                try: ans["data"] = socket.inet_ntop(socket.AF_INET6, rdata)
                except Exception: ans["data"] = rdata.hex()
            elif rtype in (2, 5, 12): ans["data"], _ = _parse_dns_name(data, offset - rdlen)
            else: ans["data"] = rdata.hex()
            result["answers"].append(ans)
        return result
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# HTTP parser
# ══════════════════════════════════════════════════════════════════════════════

_HTTP_METHODS = frozenset({"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH","CONNECT","TRACE"})


def _parse_http(data: bytes) -> Optional[dict]:
    if not data:
        return None
    try:
        text = data.decode("iso-8859-1", errors="replace")
        head = text.split("\r\n\r\n", 1)[0]
        lines = head.split("\r\n")
        if not lines:
            return None
        first = lines[0]
        result: dict = {"headers": {}}
        if first.startswith("HTTP/"):
            parts = first.split(" ", 2)
            result.update(type="response", version=parts[0],
                          status_code=int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
                          reason=parts[2] if len(parts) > 2 else "")
        else:
            method = first.split(" ", 1)[0]
            if method not in _HTTP_METHODS:
                return None
            parts = first.split(" ", 2)
            result.update(type="request", method=parts[0],
                          uri=parts[1] if len(parts) > 1 else "",
                          version=parts[2] if len(parts) > 2 else "")
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                result["headers"][k.lower()] = v
        return result
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# Layer parsers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_arp(pkt: Packet, data: bytes) -> None:
    if len(data) < 28:
        return
    pkt.arp_op         = struct.unpack("!H", data[6:8])[0]
    pkt.arp_sender_mac = _mac(data[8:14])
    pkt.arp_sender_ip  = _ip4(data[14:18])
    pkt.arp_target_mac = _mac(data[18:24])
    pkt.arp_target_ip  = _ip4(data[24:28])


def _parse_icmp(pkt: Packet, data: bytes) -> None:
    if len(data) < 4:
        return
    pkt.icmp_type = data[0]
    pkt.icmp_code = data[1]


def _parse_udp(pkt: Packet, data: bytes) -> None:
    if len(data) < 8:
        return
    pkt.udp_sport   = struct.unpack("!H", data[0:2])[0]
    pkt.udp_dport   = struct.unpack("!H", data[2:4])[0]
    pkt.udp_len     = struct.unpack("!H", data[4:6])[0]
    pkt.udp_payload = data[8:]
    if pkt.udp_sport in DNS_PORTS or pkt.udp_dport in DNS_PORTS:
        pkt.dns = _parse_dns(pkt.udp_payload)


def _parse_tcp(pkt: Packet, data: bytes) -> None:
    if len(data) < 20:
        return
    pkt.tcp_sport  = struct.unpack("!H", data[0:2])[0]
    pkt.tcp_dport  = struct.unpack("!H", data[2:4])[0]
    pkt.tcp_seq    = struct.unpack("!I", data[4:8])[0]
    pkt.tcp_ack    = struct.unpack("!I", data[8:12])[0]
    data_offset    = ((data[12] >> 4) & 0xF) * 4
    pkt.tcp_flags  = struct.unpack("!H", data[12:14])[0] & 0x1FF
    pkt.tcp_window = struct.unpack("!H", data[14:16])[0]
    if data_offset > 20:
        pkt.tcp_options = data[20:data_offset]
    pkt.tcp_payload = data[data_offset:]
    ports = {pkt.tcp_sport, pkt.tcp_dport}
    if pkt.tcp_payload and ports & HTTP_PORTS:
        pkt.http = _parse_http(pkt.tcp_payload)


def _parse_ipv4(pkt: Packet, data: bytes) -> None:
    if len(data) < 20:
        return
    pkt.ip_version    = (data[0] >> 4) & 0xF
    ihl               = (data[0] & 0xF) * 4
    pkt.ip_dscp       = (data[1] >> 2) & 0x3F
    pkt.ip_total_len  = struct.unpack("!H", data[2:4])[0]
    pkt.ip_id         = struct.unpack("!H", data[4:6])[0]
    flags_frag        = struct.unpack("!H", data[6:8])[0]
    pkt.ip_flags      = (flags_frag >> 13) & 0x7
    pkt.ip_frag_offset = (flags_frag & 0x1FFF) * 8
    pkt.ip_ttl        = data[8]
    pkt.ip_proto      = data[9]
    pkt.ip_src        = _ip4(data[12:16])
    pkt.ip_dst        = _ip4(data[16:20])
    ip_payload = data[ihl:]
    if   pkt.ip_proto == PROTO_TCP:  _parse_tcp(pkt, ip_payload)
    elif pkt.ip_proto == PROTO_UDP:  _parse_udp(pkt, ip_payload)
    elif pkt.ip_proto == PROTO_ICMP: _parse_icmp(pkt, ip_payload)


def parse_packet(ts_sec: int, ts_usec: int, raw: bytes) -> Packet:
    pkt = Packet(ts_sec=ts_sec, ts_usec=ts_usec, raw=raw, size=len(raw))
    if len(raw) < 14:
        return pkt
    pkt.eth_dst   = _mac(raw[0:6])
    pkt.eth_src   = _mac(raw[6:12])
    pkt.ethertype = struct.unpack("!H", raw[12:14])[0]
    payload = raw[14:]
    if pkt.ethertype == ETHERTYPE_VLAN and len(payload) >= 4:
        pkt.vlan_id   = struct.unpack("!H", payload[0:2])[0] & 0x0FFF
        pkt.ethertype = struct.unpack("!H", payload[2:4])[0]
        payload = payload[4:]
    if   pkt.ethertype == ETHERTYPE_IPV4: _parse_ipv4(pkt, payload)
    elif pkt.ethertype == ETHERTYPE_ARP:  _parse_arp(pkt, payload)
    return pkt


# ══════════════════════════════════════════════════════════════════════════════
# PcapReader
# ══════════════════════════════════════════════════════════════════════════════

class PcapReader:
    """
    Streaming reader for libpcap (.pcap) files.

    Usage
    -----
    >>> with PcapReader("capture.pcap") as r:
    ...     for pkt in r.packets():
    ...         print(pkt.summary())
    """

    MAGIC_LE    = 0xa1b2c3d4   # little-endian, microseconds
    MAGIC_BE    = 0xd4c3b2a1   # big-endian, microseconds
    MAGIC_NS_LE = 0xa1b23c4d   # little-endian, nanoseconds

    def __init__(self, path: str):
        self.path      = path
        self._f        = None
        self._endian   = "<"
        self._ns       = False
        self.link_type = 1
        self.version   = (2, 4)

    def __enter__(self):
        self._f = open(self.path, "rb")
        self._read_global_header()
        return self

    def __exit__(self, *_):
        if self._f:
            self._f.close()

    def _read_global_header(self) -> None:
        hdr = self._f.read(24)
        if len(hdr) < 24:
            raise ValueError("File too short — not a valid pcap")
        magic = struct.unpack("<I", hdr[:4])[0]
        if   magic == self.MAGIC_LE:    self._endian = "<"
        elif magic == self.MAGIC_BE:    self._endian = ">"
        elif magic == self.MAGIC_NS_LE: self._endian = "<"; self._ns = True
        else: raise ValueError(f"Not a pcap file (magic={magic:#010x})")
        e = self._endian
        _, v_maj, v_min, _, _, snaplen, self.link_type = struct.unpack(f"{e}IHHiIII", hdr)
        self.version = (v_maj, v_min)

    def packets(self) -> Iterator[Packet]:
        e = self._endian
        while True:
            rec = self._f.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_frac, cap_len, _ = struct.unpack(f"{e}IIII", rec)
            raw = self._f.read(cap_len)
            if len(raw) < cap_len:
                return
            ts_usec = ts_frac // 1000 if self._ns else ts_frac
            if self.link_type == 1:        # Ethernet
                yield parse_packet(ts_sec, ts_usec, raw)
            elif self.link_type == 101:    # Raw IPv4
                pkt = Packet(ts_sec=ts_sec, ts_usec=ts_usec, raw=raw, size=len(raw))
                _parse_ipv4(pkt, raw)
                yield pkt
