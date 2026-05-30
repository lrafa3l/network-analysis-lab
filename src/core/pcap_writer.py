"""
Pure-Python pcap writer. No external dependencies.

Lets you construct synthetic packet captures programmatically
for testing, demos, and sample traffic generation.
"""

from __future__ import annotations

import struct
import socket
import time
import random
from typing import BinaryIO

# ── Protocol constants ─────────────────────────────────────────────────────────
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806
PROTO_TCP  = 6
PROTO_UDP  = 17
PROTO_ICMP = 1


def _ip4(s: str) -> bytes:
    return socket.inet_aton(s)

def _mac_bytes(s: str) -> bytes:
    return bytes(int(x, 16) for x in s.split(":"))

def _checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data)//2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


# ── Frame builders ─────────────────────────────────────────────────────────────

def eth_frame(dst: str, src: str, ethertype: int, payload: bytes) -> bytes:
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack("!H", ethertype) + payload


def ip_packet(src: str, dst: str, proto: int, payload: bytes,
              ttl: int = 64, ip_id: int = None, flags: int = 0x02) -> bytes:
    if ip_id is None:
        ip_id = random.randint(0, 0xFFFF)
    total_len = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
        0x45,            # version=4, IHL=5
        0x00,            # DSCP/ECN
        total_len,
        ip_id,
        (flags << 13),   # flags + frag offset
        ttl,
        proto,
        0,               # checksum placeholder
        _ip4(src),
        _ip4(dst),
    )
    csum = _checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", csum) + hdr[12:]
    return hdr + payload


def tcp_segment(sport: int, dport: int, payload: bytes = b"",
                seq: int = None, ack: int = 0,
                flags: int = 0x02, window: int = 65535) -> bytes:
    if seq is None:
        seq = random.randint(0, 0xFFFFFFFF)
    data_offset = 5  # 20 bytes, no options
    hdr = struct.pack("!HHIIBBHHH",
        sport, dport, seq, ack,
        (data_offset << 4), flags,
        window,
        0,   # checksum placeholder
        0,   # urgent
    )
    return hdr + payload


def udp_datagram(sport: int, dport: int, payload: bytes = b"") -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def icmp_echo(icmp_type: int = 8, code: int = 0,
              identifier: int = 1, sequence: int = 1,
              payload: bytes = b"") -> bytes:
    data = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence) + payload
    csum = _checksum(data)
    return data[:2] + struct.pack("!H", csum) + data[4:]


def arp_packet(op: int, sender_mac: str, sender_ip: str,
               target_mac: str, target_ip: str) -> bytes:
    target_mac_b = _mac_bytes(target_mac) if target_mac != "00:00:00:00:00:00" \
                   else b"\x00" * 6
    return struct.pack("!HHBBH",
        1,     # HTYPE: Ethernet
        0x0800, # PTYPE: IPv4
        6,     # HLEN
        4,     # PLEN
        op,
    ) + _mac_bytes(sender_mac) + _ip4(sender_ip) + target_mac_b + _ip4(target_ip)


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS query packet."""
    flags = 0x0100  # QR=0, RD=1
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    labels = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"
    question = labels + struct.pack("!HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def dns_response(txid: int, name: str, ip: str, qtype: int = 1) -> bytes:
    """Build a minimal DNS A-record response."""
    flags = 0x8180  # QR=1, AA=1, RD=1, RA=1, RCODE=0
    header = struct.pack("!HHHHHH", txid, flags, 1, 1, 0, 0)
    labels = b""
    for label in name.rstrip(".").split("."):
        enc = label.encode("ascii")
        labels += bytes([len(enc)]) + enc
    labels += b"\x00"
    question = labels + struct.pack("!HH", qtype, 1)
    # Answer with compression pointer back to question
    answer = struct.pack("!HHIHH", 0xC00C, qtype, 1, 300, 4) + _ip4(ip)
    return header + question + answer


# ── PcapWriter ─────────────────────────────────────────────────────────────────

class PcapWriter:
    """
    Write packets to a .pcap file.

    Usage
    -----
    >>> with PcapWriter("out.pcap") as w:
    ...     w.write_eth(ts, dst_mac, src_mac, ETHERTYPE_IPV4, ip_bytes)
    """

    PCAP_GLOBAL_HDR = struct.pack("<IHHiIII",
        0xa1b2c3d4,  # magic
        2, 4,        # version 2.4
        0,           # UTC offset
        0,           # timestamp accuracy
        65535,       # snaplen
        1,           # link type: Ethernet
    )

    def __init__(self, path: str):
        self.path = path
        self._f: Optional[BinaryIO] = None

    def __enter__(self):
        self._f = open(self.path, "wb")
        self._f.write(self.PCAP_GLOBAL_HDR)
        return self

    def __exit__(self, *_):
        if self._f:
            self._f.close()

    def write_raw(self, ts: float, raw: bytes) -> None:
        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        self._f.write(struct.pack("<IIII",
            ts_sec, ts_usec, len(raw), len(raw)))
        self._f.write(raw)

    def write_eth(self, ts: float, dst: str, src: str,
                  ethertype: int, payload: bytes) -> None:
        self.write_raw(ts, eth_frame(dst, src, ethertype, payload))

    def write_ip(self, ts: float,
                 eth_dst: str, eth_src: str,
                 ip_src: str, ip_dst: str,
                 proto: int, payload: bytes, **ip_kw) -> None:
        ip = ip_packet(ip_src, ip_dst, proto, payload, **ip_kw)
        self.write_eth(ts, eth_dst, eth_src, ETHERTYPE_IPV4, ip)

    def write_tcp(self, ts: float,
                  eth_dst: str, eth_src: str,
                  ip_src: str, ip_dst: str,
                  sport: int, dport: int,
                  payload: bytes = b"", **tcp_kw) -> None:
        seg = tcp_segment(sport, dport, payload, **tcp_kw)
        self.write_ip(ts, eth_dst, eth_src, ip_src, ip_dst, PROTO_TCP, seg)

    def write_udp(self, ts: float,
                  eth_dst: str, eth_src: str,
                  ip_src: str, ip_dst: str,
                  sport: int, dport: int,
                  payload: bytes = b"") -> None:
        seg = udp_datagram(sport, dport, payload)
        self.write_ip(ts, eth_dst, eth_src, ip_src, ip_dst, PROTO_UDP, seg)

    def write_icmp(self, ts: float,
                   eth_dst: str, eth_src: str,
                   ip_src: str, ip_dst: str, **icmp_kw) -> None:
        pkt = icmp_echo(**icmp_kw)
        self.write_ip(ts, eth_dst, eth_src, ip_src, ip_dst, PROTO_ICMP, pkt)

    def write_arp(self, ts: float, eth_dst: str, eth_src: str,
                  op: int, sender_mac: str, sender_ip: str,
                  target_mac: str, target_ip: str) -> None:
        pkt = arp_packet(op, sender_mac, sender_ip, target_mac, target_ip)
        self.write_eth(ts, eth_dst, eth_src, ETHERTYPE_ARP, pkt)

    def write_dns_query(self, ts: float,
                        eth_dst: str, eth_src: str,
                        src_ip: str, dst_ip: str,
                        sport: int, txid: int, name: str, qtype: int = 1) -> None:
        payload = dns_query(txid, name, qtype)
        self.write_udp(ts, eth_dst, eth_src, src_ip, dst_ip, sport, 53, payload)

    def write_dns_response(self, ts: float,
                           eth_dst: str, eth_src: str,
                           src_ip: str, dst_ip: str,
                           dport: int, txid: int,
                           name: str, resolved_ip: str) -> None:
        payload = dns_response(txid, name, resolved_ip)
        self.write_udp(ts, eth_dst, eth_src, src_ip, dst_ip, 53, dport, payload)
