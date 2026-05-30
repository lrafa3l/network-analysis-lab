"""
Network traffic analysis engine.

Classes
-------
TrafficStats     — aggregate counters, protocol breakdown, top talkers
FlowTracker      — bidirectional TCP/UDP flow reconstruction
AnomalyDetector  — rule-based threat detection
"""

from __future__ import annotations

from collections import defaultdict, Counter
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

from src.core.pcap_reader import (
    Packet, PROTO_TCP, PROTO_UDP, PROTO_ICMP,
    ETHERTYPE_ARP, TCP_SYN, TCP_ACK, TCP_RST, TCP_FIN,
)


# ══════════════════════════════════════════════════════════════════════════════
# TrafficStats
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class TrafficStats:
    """Aggregate statistics gathered over a packet stream."""

    total_packets: int = 0
    total_bytes:   int = 0

    proto_counts: Counter = field(default_factory=Counter)
    proto_bytes:  Counter = field(default_factory=Counter)

    src_ip_packets: Counter = field(default_factory=Counter)
    src_ip_bytes:   Counter = field(default_factory=Counter)
    dst_ip_packets: Counter = field(default_factory=Counter)
    dst_ip_bytes:   Counter = field(default_factory=Counter)

    dst_port_counts: Counter = field(default_factory=Counter)

    pair_bytes: Counter = field(default_factory=Counter)

    first_ts: float = -1.0
    last_ts:  float = 0.0

    dns_queries:    List[dict] = field(default_factory=list)
    http_requests:  List[dict] = field(default_factory=list)
    http_responses: List[dict] = field(default_factory=list)

    ttl_distribution: Counter = field(default_factory=Counter)
    size_buckets:     Counter = field(default_factory=Counter)

    # Timeline: list of (ts, bytes) for graphing
    timeline: List[tuple] = field(default_factory=list)

    def ingest(self, pkt: Packet) -> None:
        self.total_packets += 1
        self.total_bytes   += pkt.size

        ts = pkt.timestamp
        if self.first_ts < 0:
            self.first_ts = ts
        self.last_ts = ts
        self.timeline.append((ts, pkt.size))

        proto = pkt.protocol
        self.proto_counts[proto] += 1
        self.proto_bytes[proto]  += pkt.size

        if pkt.ip_src:
            self.src_ip_packets[pkt.ip_src] += 1
            self.src_ip_bytes[pkt.ip_src]   += pkt.size
        if pkt.ip_dst:
            self.dst_ip_packets[pkt.ip_dst] += 1
            self.dst_ip_bytes[pkt.ip_dst]   += pkt.size
        if pkt.ip_src and pkt.ip_dst:
            self.pair_bytes[(pkt.ip_src, pkt.ip_dst)] += pkt.size
        if pkt.dport:
            self.dst_port_counts[pkt.dport] += 1
        if pkt.ip_ttl:
            self.ttl_distribution[pkt.ip_ttl] += 1

        self.size_buckets[_size_bucket(pkt.size)] += 1

        if pkt.dns and pkt.dns.get("qr") == "query":
            for q in pkt.dns.get("questions", []):
                self.dns_queries.append({
                    "ts": ts, "src": pkt.ip_src,
                    "name": q.get("name", ""), "type": q.get("type", ""),
                })

        if pkt.http:
            h = pkt.http
            if h.get("type") == "request":
                self.http_requests.append({
                    "ts": ts, "src": pkt.ip_src, "dst": pkt.ip_dst,
                    "method": h.get("method", ""), "uri": h.get("uri", ""),
                    "host": h.get("headers", {}).get("host", ""),
                })
            else:
                self.http_responses.append({
                    "ts": ts, "src": pkt.ip_src,
                    "status": h.get("status_code", 0),
                    "reason": h.get("reason", ""),
                })

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def avg_pps(self) -> float:
        return self.total_packets / self.duration if self.duration else 0.0

    @property
    def avg_bps(self) -> float:
        return self.total_bytes * 8 / self.duration if self.duration else 0.0

    def top_talkers(self, n: int = 10) -> List[dict]:
        return [
            {"ip": ip, "packets": self.src_ip_packets[ip], "bytes": self.src_ip_bytes[ip]}
            for ip, _ in self.src_ip_packets.most_common(n)
        ]

    def top_destinations(self, n: int = 10) -> List[dict]:
        return [
            {"ip": ip, "packets": self.dst_ip_packets[ip], "bytes": self.dst_ip_bytes[ip]}
            for ip, _ in self.dst_ip_packets.most_common(n)
        ]

    def top_ports(self, n: int = 10) -> List[dict]:
        return [{"port": p, "count": c} for p, c in self.dst_port_counts.most_common(n)]

    def protocol_summary(self) -> List[dict]:
        total = max(self.total_packets, 1)
        return [
            {"protocol": p, "packets": c, "bytes": self.proto_bytes[p],
             "pct": round(c / total * 100, 1)}
            for p, c in self.proto_counts.most_common()
        ]

    def timeline_bins(self, num_bins: int = 60) -> List[dict]:
        """Aggregate timeline into fixed-width time bins for charting."""
        if not self.timeline or self.duration < 0.001:
            return []
        bin_size = self.duration / num_bins
        bins: Dict[int, dict] = {}
        for ts, size in self.timeline:
            idx = min(int((ts - self.first_ts) / bin_size), num_bins - 1)
            if idx not in bins:
                bins[idx] = {"t": round(self.first_ts + idx * bin_size, 3),
                             "packets": 0, "bytes": 0}
            bins[idx]["packets"] += 1
            bins[idx]["bytes"]   += size
        return [bins[i] for i in sorted(bins)]


def _size_bucket(n: int) -> str:
    if n < 64:   return "< 64 B"
    if n < 128:  return "64–127 B"
    if n < 256:  return "128–255 B"
    if n < 512:  return "256–511 B"
    if n < 1024: return "512–1023 B"
    return "≥ 1024 B"


# ══════════════════════════════════════════════════════════════════════════════
# FlowTracker
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Flow:
    key:      tuple
    src:      str
    dst:      str
    sport:    int
    dport:    int
    proto:    int
    protocol: str
    start_ts: float
    last_ts:  float = 0.0
    packets:  int   = 0
    bytes:    int   = 0
    syn_count: int  = 0
    ack_count: int  = 0
    fin_count: int  = 0
    rst_count: int  = 0
    state:    str   = "NEW"

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.start_ts)

    @property
    def bps(self) -> float:
        return self.bytes * 8 / self.duration if self.duration else 0.0

    def to_dict(self) -> dict:
        return {
            "src": self.src, "dst": self.dst,
            "sport": self.sport, "dport": self.dport,
            "protocol": self.protocol,
            "packets": self.packets, "bytes": self.bytes,
            "duration": round(self.duration, 3),
            "bps": round(self.bps),
            "state": self.state,
            "start_ts": round(self.start_ts, 3),
        }


class FlowTracker:
    """Reconstruct bidirectional network flows from a packet stream."""

    def __init__(self):
        self.flows: Dict[tuple, Flow] = {}

    def update(self, pkt: Packet) -> Optional[Flow]:
        if not pkt.ip_src:
            return None
        key = pkt.flow_key
        if key not in self.flows:
            self.flows[key] = Flow(
                key=key, src=pkt.ip_src, dst=pkt.ip_dst,
                sport=pkt.sport, dport=pkt.dport,
                proto=pkt.ip_proto, protocol=pkt.protocol,
                start_ts=pkt.timestamp,
            )
        f = self.flows[key]
        f.packets += 1
        f.bytes   += pkt.size
        f.last_ts  = pkt.timestamp
        if pkt.ip_proto == PROTO_TCP:
            fl = pkt.tcp_flags
            if fl & TCP_SYN: f.syn_count += 1
            if fl & TCP_ACK: f.ack_count += 1
            if fl & TCP_FIN: f.fin_count += 1
            if fl & TCP_RST: f.rst_count += 1
            if   fl & TCP_SYN and not (fl & TCP_ACK): f.state = "SYN"
            elif fl & TCP_SYN and     (fl & TCP_ACK): f.state = "SYN-ACK"
            elif fl & TCP_ACK and f.state == "SYN-ACK": f.state = "ESTABLISHED"
            elif fl & TCP_FIN: f.state = "FIN"
            elif fl & TCP_RST: f.state = "RESET"
        return f

    def sorted_flows(self, by: str = "bytes") -> List[Flow]:
        return sorted(self.flows.values(), key=lambda f: getattr(f, by), reverse=True)


# ══════════════════════════════════════════════════════════════════════════════
# AnomalyDetector
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PORTS = frozenset({
    4444, 1337, 31337, 12345, 54321,   # common RAT / reverse-shell ports
    6667, 6668, 6669,                   # IRC (botnet C2)
    23,                                 # Telnet (cleartext auth)
    135, 139, 445,                      # SMB / MS-RPC (exploitation target)
    1433, 3306, 5432,                   # Databases exposed externally
    9200, 6379, 27017,                  # Elasticsearch, Redis, MongoDB
    5900,                               # VNC (often unpatched)
})


@dataclass
class Alert:
    severity:    str
    category:    str
    description: str
    src:         str  = ""
    dst:         str  = ""
    detail:      dict = field(default_factory=dict)
    ts:          float = 0.0

    SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def to_dict(self) -> dict:
        return {
            "severity": self.severity, "category": self.category,
            "description": self.description, "src": self.src, "dst": self.dst,
            "detail": self.detail, "ts": round(self.ts, 3),
        }

    def __str__(self) -> str:
        return (f"[{self.severity:<8}] {self.category:<25}  "
                f"{self.src or '?':<18} → {self.dst or '?':<18}  {self.description}")


class AnomalyDetector:
    """
    Rule-based network anomaly and intrusion detector.

    Detection rules
    ---------------
    1.  Vertical port scan      — one src → many dports on a single dst
    2.  Horizontal port scan    — one src → same dport on many dsts
    3.  SYN flood               — high SYN rate, low ACK ratio
    4.  ARP spoofing            — same IP claimed by multiple MACs
    5.  DNS exfiltration        — long subdomains / high query rate
    6.  Suspicious ports        — connections to known bad/C2 ports
    7.  Large data transfer     — single flow exceeds threshold
    8.  ICMP flood              — high ICMP rate from one source
    9.  TCP RST storm           — many RSTs (scan tool fingerprint)
    10. Cleartext protocol use  — Telnet/FTP credentials at risk
    """

    # ── Thresholds ─────────────────────────────────────────────────────────────
    PORT_SCAN_V_THRESHOLD    = 15     # distinct dports → vertical scan
    PORT_SCAN_H_THRESHOLD    = 10     # distinct dsts on same port → horizontal scan
    SYN_FLOOD_THRESHOLD      = 50     # SYNs/src in time window
    DNS_RATE_THRESHOLD       = 20     # DNS queries/src in time window
    DNS_LABEL_LEN_THRESHOLD  = 30     # max chars in one label → exfil heuristic
    DNS_LABEL_COUNT_THRESHOLD= 5      # max dot-segments
    LARGE_FLOW_MB            = 10     # megabytes before large-flow alert
    ICMP_FLOOD_THRESHOLD     = 30     # ICMP packets/src in time window
    RST_STORM_THRESHOLD      = 30     # RST packets/src in time window
    TIME_WINDOW              = 5.0    # seconds for rate-based checks

    def __init__(self):
        self.alerts: List[Alert] = []
        self._arp_ip_mac:  Dict[str, set]              = defaultdict(set)
        self._syn_ts:      Dict[str, list]             = defaultdict(list)
        self._vscan:       Dict[str, Dict[str, set]]   = defaultdict(lambda: defaultdict(set))
        self._hscan:       Dict[Tuple[str,int], set]   = defaultdict(set)
        self._dns_ts:      Dict[str, list]             = defaultdict(list)
        self._icmp_ts:     Dict[str, list]             = defaultdict(list)
        self._rst_ts:      Dict[str, list]             = defaultdict(list)
        self._seen:        set                         = set()   # dedup keys

    def update(self, pkt: Packet) -> List[Alert]:
        new: List[Alert] = []
        ts = pkt.timestamp
        new += self._check_arp(pkt, ts)
        new += self._check_port_scan(pkt, ts)
        new += self._check_syn_flood(pkt, ts)
        new += self._check_dns(pkt, ts)
        new += self._check_suspicious_ports(pkt, ts)
        new += self._check_icmp(pkt, ts)
        new += self._check_rst(pkt, ts)
        new += self._check_cleartext_proto(pkt, ts)
        self.alerts.extend(new)
        return new

    def finalize(self, flows: List[Flow]) -> List[Alert]:
        new  = self._check_large_flows(flows)
        new += self._flush_hscan()
        self.alerts.extend(new)
        return new

    def summary(self) -> dict:
        by_sev = Counter(a.severity  for a in self.alerts)
        by_cat = Counter(a.category  for a in self.alerts)
        return {
            "total":       len(self.alerts),
            "critical":    by_sev["CRITICAL"],
            "high":        by_sev["HIGH"],
            "medium":      by_sev["MEDIUM"],
            "low":         by_sev["LOW"],
            "info":        by_sev["INFO"],
            "by_category": dict(by_cat.most_common()),
        }

    # ── Rule implementations ───────────────────────────────────────────────────

    def _emit(self, key, alert: Alert) -> List[Alert]:
        if key in self._seen:
            return []
        self._seen.add(key)
        return [alert]

    def _prune(self, lst: list, ts: float) -> list:
        cutoff = ts - self.TIME_WINDOW
        return [t for t in lst if t >= cutoff]

    def _check_arp(self, pkt: Packet, ts: float) -> List[Alert]:
        if pkt.ethertype != ETHERTYPE_ARP or pkt.arp_op != 2:
            return []
        ip, mac = pkt.arp_sender_ip, pkt.arp_sender_mac
        if not ip or not mac:
            return []
        self._arp_ip_mac[ip].add(mac)
        if len(self._arp_ip_mac[ip]) > 1:
            macs = ", ".join(sorted(self._arp_ip_mac[ip]))
            return self._emit(("arp", ip), Alert(
                severity="HIGH", category="arp_spoofing",
                description=f"IP {ip} claimed by {len(self._arp_ip_mac[ip])} MACs — possible ARP cache poisoning",
                src=pkt.eth_src, dst=pkt.eth_dst,
                detail={"ip": ip, "macs": list(self._arp_ip_mac[ip])}, ts=ts,
            ))
        return []

    def _check_port_scan(self, pkt: Packet, ts: float) -> List[Alert]:
        if pkt.ip_proto != PROTO_TCP:
            return []
        if not (pkt.tcp_flags & TCP_SYN) or (pkt.tcp_flags & TCP_ACK):
            return []
        src, dst, dport = pkt.ip_src, pkt.ip_dst, pkt.tcp_dport
        if not src or not dst:
            return []
        self._vscan[src][dst].add(dport)
        self._hscan[(src, dport)].add(dst)
        alerts = []
        n = len(self._vscan[src][dst])
        if n == self.PORT_SCAN_V_THRESHOLD:
            alerts += self._emit(("vscan", src, dst), Alert(
                severity="HIGH", category="port_scan_vertical",
                description=f"{src} scanned {n}+ ports on {dst} — vertical port scan",
                src=src, dst=dst,
                detail={"ports_sampled": sorted(self._vscan[src][dst])[:20], "count": n},
                ts=ts,
            ))
        return alerts

    def _check_syn_flood(self, pkt: Packet, ts: float) -> List[Alert]:
        if pkt.ip_proto != PROTO_TCP:
            return []
        src = pkt.ip_src
        if not src:
            return []
        if pkt.tcp_flags & TCP_SYN and not (pkt.tcp_flags & TCP_ACK):
            self._syn_ts[src].append(ts)
            self._syn_ts[src] = self._prune(self._syn_ts[src], ts)
            if len(self._syn_ts[src]) >= self.SYN_FLOOD_THRESHOLD:
                return self._emit(("synflood", src), Alert(
                    severity="CRITICAL", category="syn_flood",
                    description=(f"{src} sent {len(self._syn_ts[src])} SYNs in "
                                 f"{self.TIME_WINDOW}s — likely SYN flood"),
                    src=src, dst=pkt.ip_dst,
                    detail={"syn_count": len(self._syn_ts[src]),
                            "window_s": self.TIME_WINDOW}, ts=ts,
                ))
        return []

    def _check_dns(self, pkt: Packet, ts: float) -> List[Alert]:
        if not pkt.dns:
            return []
        alerts = []
        src = pkt.ip_src
        self._dns_ts[src].append(ts)
        self._dns_ts[src] = self._prune(self._dns_ts[src], ts)
        if len(self._dns_ts[src]) >= self.DNS_RATE_THRESHOLD:
            alerts += self._emit(("dnsrate", src), Alert(
                severity="MEDIUM", category="dns_high_query_rate",
                description=(f"{src} issued {len(self._dns_ts[src])} DNS queries "
                             f"in {self.TIME_WINDOW}s"),
                src=src, dst=pkt.ip_dst,
                detail={"count": len(self._dns_ts[src])}, ts=ts,
            ))
        for q in pkt.dns.get("questions", []):
            name   = q.get("name", "")
            labels = name.split(".")
            max_lbl = max((len(l) for l in labels), default=0)
            if max_lbl > self.DNS_LABEL_LEN_THRESHOLD or len(labels) > self.DNS_LABEL_COUNT_THRESHOLD:
                alerts += self._emit(("dnsexfil", src, name), Alert(
                    severity="HIGH", category="dns_exfiltration",
                    description=(f"Anomalous DNS query from {src}: {name!r} "
                                 f"({max_lbl}-char label, {len(labels)} labels)"),
                    src=src, dst=pkt.ip_dst,
                    detail={"name": name, "max_label_len": max_lbl,
                            "label_count": len(labels)}, ts=ts,
                ))
        return alerts

    def _check_suspicious_ports(self, pkt: Packet, ts: float) -> List[Alert]:
        if not pkt.ip_src:
            return []
        dport = pkt.dport
        if dport not in SUSPICIOUS_PORTS:
            return []
        return self._emit(("sport", pkt.ip_src, pkt.ip_dst, dport), Alert(
            severity="HIGH", category="suspicious_port",
            description=(f"Traffic to suspicious port {dport} "
                         f"({pkt.ip_src} → {pkt.ip_dst}) — possible C2 or exploit"),
            src=pkt.ip_src, dst=pkt.ip_dst,
            detail={"port": dport}, ts=ts,
        ))

    def _check_icmp(self, pkt: Packet, ts: float) -> List[Alert]:
        if pkt.ip_proto != PROTO_ICMP:
            return []
        src = pkt.ip_src
        if not src:
            return []
        self._icmp_ts[src].append(ts)
        self._icmp_ts[src] = self._prune(self._icmp_ts[src], ts)
        if len(self._icmp_ts[src]) >= self.ICMP_FLOOD_THRESHOLD:
            return self._emit(("icmp", src), Alert(
                severity="MEDIUM", category="icmp_flood",
                description=(f"{src} sent {len(self._icmp_ts[src])} ICMP packets "
                             f"in {self.TIME_WINDOW}s"),
                src=src, dst=pkt.ip_dst,
                detail={"count": len(self._icmp_ts[src])}, ts=ts,
            ))
        return []

    def _check_rst(self, pkt: Packet, ts: float) -> List[Alert]:
        if pkt.ip_proto != PROTO_TCP or not (pkt.tcp_flags & TCP_RST):
            return []
        src = pkt.ip_src
        if not src:
            return []
        self._rst_ts[src].append(ts)
        self._rst_ts[src] = self._prune(self._rst_ts[src], ts)
        if len(self._rst_ts[src]) >= self.RST_STORM_THRESHOLD:
            return self._emit(("rst", src), Alert(
                severity="MEDIUM", category="tcp_rst_storm",
                description=(f"{src} sent {len(self._rst_ts[src])} TCP RSTs in "
                             f"{self.TIME_WINDOW}s — scanner fingerprint"),
                src=src, dst=pkt.ip_dst,
                detail={"count": len(self._rst_ts[src])}, ts=ts,
            ))
        return []

    def _check_cleartext_proto(self, pkt: Packet, ts: float) -> List[Alert]:
        from src.core.pcap_reader import TELNET_PORTS, FTP_PORTS
        if pkt.ip_proto != PROTO_TCP:
            return []
        ports = {pkt.tcp_sport, pkt.tcp_dport}
        if ports & TELNET_PORTS:
            return self._emit(("telnet", pkt.ip_src, pkt.ip_dst), Alert(
                severity="MEDIUM", category="cleartext_protocol",
                description=f"Telnet session detected ({pkt.ip_src} → {pkt.ip_dst}) — credentials sent in cleartext",
                src=pkt.ip_src, dst=pkt.ip_dst,
                detail={"protocol": "Telnet", "port": 23}, ts=ts,
            ))
        return []

    def _check_large_flows(self, flows: List[Flow]) -> List[Alert]:
        alerts = []
        threshold = self.LARGE_FLOW_MB * 1024 * 1024
        for f in flows:
            if f.bytes >= threshold:
                mb = f.bytes / (1024 * 1024)
                alerts += self._emit(("largeflow", f.key), Alert(
                    severity="LOW", category="large_data_transfer",
                    description=(f"{f.src}:{f.sport} → {f.dst}:{f.dport} "
                                 f"transferred {mb:.1f} MB over {f.duration:.1f}s"),
                    src=f.src, dst=f.dst,
                    detail={"bytes": f.bytes, "mb": round(mb, 2),
                            "duration_s": round(f.duration, 2),
                            "protocol": f.protocol}, ts=f.start_ts,
                ))
        return alerts

    def _flush_hscan(self) -> List[Alert]:
        alerts = []
        threshold = max(self.PORT_SCAN_H_THRESHOLD // 2, 3)
        for (src, dport), dsts in self._hscan.items():
            if len(dsts) >= threshold:
                alerts += self._emit(("hflush", src, dport), Alert(
                    severity="HIGH", category="port_scan_horizontal",
                    description=(f"{src} probed port {dport} on {len(dsts)} distinct hosts — horizontal scan"),
                    src=src, dst="<multiple>",
                    detail={"port": dport, "host_count": len(dsts),
                            "hosts_sample": sorted(dsts)[:10]},
                    ts=0.0,
                ))
        return alerts
