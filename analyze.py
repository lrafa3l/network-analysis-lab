#!/usr/bin/env python3
"""
Network Analysis Lab — CLI Analyzer

Usage
-----
    python analyze.py <capture.pcap> [OPTIONS]

Options
-------
    --top N          Show top N talkers/ports (default: 10)
    --filter PROTO   Only show packets matching protocol (TCP/UDP/DNS/HTTP…)
    --dump N         Print first N packet summaries
    --alerts-only    Only print anomaly alerts
    --json           Output full report as JSON to stdout
    --report FILE    Write HTML report to FILE
    --dashboard      Launch interactive web dashboard
    --port PORT      Dashboard port (default: 5000)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List

# Project root on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.pcap_reader   import PcapReader
from src.analysis.analyzer  import TrafficStats, FlowTracker, AnomalyDetector

# ── ANSI colour helpers ────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RED    = "\033[91m"
ORANGE = "\033[38;5;214m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"

SEV_COLOUR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     DIM,
}

PROTO_COLOUR = {
    "HTTP": GREEN, "HTTPS": CYAN, "DNS": MAGENTA,
    "TCP": WHITE,  "UDP": BLUE,   "ICMP": YELLOW,
    "ARP": DIM,    "SSH": GREEN,
}


def _c(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"

def _header(title: str) -> None:
    width = 60
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")

def _row(label: str, value: str, width: int = 26) -> None:
    print(f"  {DIM}{label:<{width}}{RESET}{value}")

def _bytes_human(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"

def _bps_human(bps: float) -> str:
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000:
            return f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbps"

def _bar(value: float, total: float, width: int = 20) -> str:
    filled = int(round(value / total * width)) if total else 0
    filled = min(filled, width)
    return f"{CYAN}{'█' * filled}{DIM}{'░' * (width - filled)}{RESET}"


# ══════════════════════════════════════════════════════════════════════════════
# Core analysis function
# ══════════════════════════════════════════════════════════════════════════════

def analyse(path: str, top_n: int = 10, proto_filter: str = None,
            dump_n: int = 0) -> tuple:
    """
    Read a pcap file and return (stats, flow_tracker, anomaly_detector).
    Prints a live progress counter.
    """
    stats    = TrafficStats()
    flows    = FlowTracker()
    detector = AnomalyDetector()
    packets_dumped = 0

    print(f"\n{BOLD}Reading:{RESET} {_c(path, CYAN)}")

    if dump_n:
        _header(f"Packet Dump (first {dump_n})")
        print(f"  {DIM}{'Timestamp':>15}  {'Protocol':<7}  {'Source':<23}  {'Destination':<23}  Flags / Size{RESET}")
        print(f"  {'─'*90}")

    t0 = time.perf_counter()

    with PcapReader(path) as reader:
        for pkt in reader.packets():
            # Optional filter
            if proto_filter and pkt.protocol.upper() != proto_filter.upper():
                continue

            stats.ingest(pkt)
            flows.update(pkt)
            detector.update(pkt)

            if dump_n and packets_dumped < dump_n:
                # Colour the protocol
                proto_col = PROTO_COLOUR.get(pkt.protocol, WHITE)
                src = f"{pkt.ip_src}:{pkt.sport}" if pkt.sport else (pkt.ip_src or pkt.eth_src)
                dst = f"{pkt.ip_dst}:{pkt.dport}" if pkt.dport else (pkt.ip_dst or pkt.eth_dst)
                flags_str = f" [{pkt.tcp_flags_str}]" if pkt.ip_proto == 6 else ""
                print(f"  {DIM}{pkt.timestamp:>15.6f}{RESET}  "
                      f"{proto_col}{pkt.protocol:<7}{RESET}  "
                      f"{src:<23}  {dst:<23}  "
                      f"{DIM}{flags_str or '':<20}{RESET}  {pkt.size} B")
                packets_dumped += 1

    elapsed = time.perf_counter() - t0
    detector.finalize(flows.sorted_flows())

    print(f"\n  {GREEN}✓{RESET} Processed {_c(f'{stats.total_packets:,}', BOLD)} packets "
          f"in {elapsed:.2f}s  "
          f"({_c(f'{stats.total_packets/elapsed:,.0f}', CYAN)} pkt/s)")

    return stats, flows, detector


# ══════════════════════════════════════════════════════════════════════════════
# Report printing
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(stats: TrafficStats) -> None:
    _header("Capture Summary")
    _row("File duration",     f"{stats.duration:.3f} s")
    _row("Total packets",     f"{stats.total_packets:,}")
    _row("Total bytes",       _bytes_human(stats.total_bytes))
    _row("Avg packet rate",   f"{stats.avg_pps:.1f} pkt/s")
    _row("Avg throughput",    _bps_human(stats.avg_bps))
    _row("Unique src IPs",    str(len(stats.src_ip_packets)))
    _row("Unique dst IPs",    str(len(stats.dst_ip_packets)))
    _row("DNS queries",       str(len(stats.dns_queries)))
    _row("HTTP requests",     str(len(stats.http_requests)))


def print_protocols(stats: TrafficStats) -> None:
    _header("Protocol Distribution")
    proto_data = stats.protocol_summary()
    total_pkts = max(stats.total_packets, 1)
    for row in proto_data[:12]:
        proto = row["protocol"]
        col   = PROTO_COLOUR.get(proto, WHITE)
        bar   = _bar(row["packets"], total_pkts)
        print(f"  {col}{proto:<8}{RESET}  {bar}  "
              f"{row['packets']:>6,} pkts  "
              f"{_bytes_human(row['bytes']):>10}  "
              f"{DIM}{row['pct']:>5.1f}%{RESET}")


def print_top_talkers(stats: TrafficStats, n: int) -> None:
    _header(f"Top {n} Source IP Addresses")
    talkers = stats.top_talkers(n)
    if not talkers:
        print("  (no IP traffic)")
        return
    max_b = max(t["bytes"] for t in talkers) or 1
    for i, t in enumerate(talkers, 1):
        bar = _bar(t["bytes"], max_b, 16)
        print(f"  {DIM}{i:>2}.{RESET}  {CYAN}{t['ip']:<18}{RESET}  {bar}  "
              f"{t['packets']:>6,} pkts  {_bytes_human(t['bytes']):>10}")


def print_top_ports(stats: TrafficStats, n: int) -> None:
    _header(f"Top {n} Destination Ports")
    ports = stats.top_ports(n)
    if not ports:
        print("  (no port data)")
        return
    max_c = max(p["count"] for p in ports) or 1
    PORT_NAMES = {
        80:"HTTP", 443:"HTTPS", 53:"DNS", 22:"SSH", 21:"FTP",
        25:"SMTP", 3389:"RDP", 445:"SMB", 23:"Telnet",
        3306:"MySQL", 5432:"PostgreSQL", 8080:"HTTP-alt",
        4444:"!!RAT", 6667:"IRC/C2", 31337:"!!Elite",
    }
    for p in ports:
        name = PORT_NAMES.get(p["port"], "")
        bar  = _bar(p["count"], max_c, 20)
        flag = _c(f"  ⚠ {name}", ORANGE) if name.startswith("!!") else (f"  {DIM}{name}{RESET}" if name else "")
        print(f"  {CYAN}{p['port']:<7}{RESET}  {bar}  {p['count']:>6,}{flag}")


def print_flows(flows: FlowTracker, n: int = 10) -> None:
    _header(f"Top {n} Network Flows (by bytes)")
    top = flows.sorted_flows("bytes")[:n]
    if not top:
        print("  (no flows)")
        return
    print(f"  {DIM}{'Source':<22} {'Destination':<22} {'Proto':<7} "
          f"{'Pkts':>6} {'Bytes':>10} {'Duration':>10} {'State':<12}{RESET}")
    print(f"  {'─'*90}")
    for f in top:
        src = f"{f.src}:{f.sport}"
        dst = f"{f.dst}:{f.dport}"
        col = PROTO_COLOUR.get(f.protocol, WHITE)
        print(f"  {src:<22} {dst:<22} {col}{f.protocol:<7}{RESET} "
              f"{f.packets:>6,} {_bytes_human(f.bytes):>10} "
              f"{f.duration:>9.3f}s {DIM}{f.state:<12}{RESET}")


def print_alerts(detector: AnomalyDetector) -> None:
    _header("Anomaly Alerts")
    summ = detector.summary()
    if summ["total"] == 0:
        print(f"  {GREEN}✓ No anomalies detected{RESET}")
        return

    # Summary counts
    counts = [
        (summ["critical"], "CRITICAL", RED),
        (summ["high"],     "HIGH",     ORANGE),
        (summ["medium"],   "MEDIUM",   YELLOW),
        (summ["low"],      "LOW",      BLUE),
        (summ["info"],     "INFO",     DIM),
    ]
    parts = "  " + "  ".join(
        f"{col}{n} {sev}{RESET}" for n, sev, col in counts if n
    )
    print(parts)
    print()

    for alert in sorted(detector.alerts,
                        key=lambda a: a.SEV_ORDER.get(a.severity, 99)):
        col   = SEV_COLOUR.get(alert.severity, "")
        badge = f"{col}[{alert.severity:<8}]{RESET}"
        cat   = f"{CYAN}{alert.category}{RESET}"
        print(f"  {badge}  {cat}")
        print(f"  {'':>12}  {alert.description}")
        if alert.src or alert.dst:
            print(f"  {'':>12}  {DIM}src={alert.src or '?'}  dst={alert.dst or '?'}{RESET}")
        print()


def print_dns(stats: TrafficStats, n: int = 15) -> None:
    if not stats.dns_queries:
        return
    _header(f"DNS Queries (first {n})")
    print(f"  {DIM}{'Source':<18} {'Type':<6} {'Name'}{RESET}")
    print(f"  {'─'*60}")
    for q in stats.dns_queries[:n]:
        print(f"  {CYAN}{q['src']:<18}{RESET} {DIM}{q['type']:<6}{RESET} {q['name']}")
    if len(stats.dns_queries) > n:
        print(f"  {DIM}… and {len(stats.dns_queries) - n} more{RESET}")


def print_http(stats: TrafficStats, n: int = 10) -> None:
    if not stats.http_requests:
        return
    _header(f"HTTP Requests (first {n})")
    print(f"  {DIM}{'Source':<18} {'Method':<7} {'Host':<25} URI{RESET}")
    print(f"  {'─'*80}")
    for r in stats.http_requests[:n]:
        host = r.get("host") or r.get("dst", "")
        uri  = r.get("uri", "")
        if len(uri) > 40:
            uri = uri[:37] + "…"
        print(f"  {CYAN}{r['src']:<18}{RESET} {GREEN}{r['method']:<7}{RESET} "
              f"{host:<25} {DIM}{uri}{RESET}")


# ══════════════════════════════════════════════════════════════════════════════
# JSON / HTML report
# ══════════════════════════════════════════════════════════════════════════════

def build_report_dict(path: str, stats: TrafficStats,
                      flows: FlowTracker,
                      detector: AnomalyDetector) -> dict:
    return {
        "file":        os.path.basename(path),
        "generated":   time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "total_packets": stats.total_packets,
            "total_bytes":   stats.total_bytes,
            "duration_s":    round(stats.duration, 3),
            "avg_pps":       round(stats.avg_pps, 2),
            "avg_bps":       round(stats.avg_bps, 2),
            "first_ts":      round(stats.first_ts, 3),
            "last_ts":       round(stats.last_ts, 3),
        },
        "protocols":    stats.protocol_summary(),
        "top_talkers":  stats.top_talkers(20),
        "top_ports":    stats.top_ports(20),
        "flows":        [f.to_dict() for f in flows.sorted_flows("bytes")[:50]],
        "alerts":       [a.to_dict() for a in detector.alerts],
        "alert_summary": detector.summary(),
        "dns_queries":  stats.dns_queries[:100],
        "http_requests":stats.http_requests[:100],
        "timeline":     stats.timeline_bins(60),
        "size_buckets": dict(stats.size_buckets),
        "ttl_distribution": {str(k): v for k, v in
                             sorted(stats.ttl_distribution.items())},
    }


# ══════════════════════════════════════════════════════════════════════════════
# Entry point
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="analyze",
        description="Network Analysis Lab — pcap analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("pcap", help="Path to .pcap file")
    parser.add_argument("--top",       type=int, default=10,
                        help="Number of top entries to show (default: 10)")
    parser.add_argument("--filter",    metavar="PROTO",
                        help="Filter to a protocol (TCP, UDP, DNS, HTTP, …)")
    parser.add_argument("--dump",      type=int, default=0, metavar="N",
                        help="Print first N packet summaries")
    parser.add_argument("--alerts-only", action="store_true",
                        help="Only print anomaly alerts")
    parser.add_argument("--json",      action="store_true",
                        help="Output full JSON report to stdout")
    parser.add_argument("--report",    metavar="FILE",
                        help="Write HTML report to FILE")
    parser.add_argument("--dashboard", action="store_true",
                        help="Launch interactive web dashboard after analysis")
    parser.add_argument("--port",      type=int, default=5000,
                        help="Dashboard port (default: 5000)")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f"{RED}Error:{RESET} File not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    # ── Banner ─────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{CYAN}"
          f"┌──────────────────────────────────────────┐\n"
          f"│     Network Analysis Lab  v1.0           │\n"
          f"│     Packet Forensics & Threat Detection  │\n"
          f"└──────────────────────────────────────────┘"
          f"{RESET}")

    stats, flows, detector = analyse(
        args.pcap,
        top_n=args.top,
        proto_filter=args.filter,
        dump_n=args.dump,
    )

    if args.json:
        report = build_report_dict(args.pcap, stats, flows, detector)
        print(json.dumps(report, indent=2))
        return

    if args.alerts_only:
        print_alerts(detector)
        return

    # ── Full report ────────────────────────────────────────────────────────────
    print_summary(stats)
    print_protocols(stats)
    print_top_talkers(stats, args.top)
    print_top_ports(stats, args.top)
    print_flows(flows, args.top)
    print_alerts(detector)
    print_dns(stats)
    print_http(stats)

    # ── Optional outputs ───────────────────────────────────────────────────────
    if args.report:
        report = build_report_dict(args.pcap, stats, flows, detector)
        _write_html_report(args.report, report)
        print(f"\n{GREEN}✓{RESET} HTML report saved → {_c(args.report, CYAN)}")

    if args.dashboard:
        report = build_report_dict(args.pcap, stats, flows, detector)
        _launch_dashboard(report, args.port)


def _write_html_report(path: str, report: dict) -> None:
    """Minimal standalone HTML report."""
    data_json = json.dumps(report)
    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<title>NAL Report — {report['file']}</title>
<style>
  body{{background:#070B12;color:#D8E4F2;font-family:monospace;padding:32px}}
  h1{{color:#0FCEAB}}pre{{background:#0C1421;padding:16px;border-radius:4px;overflow:auto}}
</style>
</head>
<body>
<h1>Network Analysis Lab — {report['file']}</h1>
<p>Generated: {report['generated']}</p>
<pre>{json.dumps(report, indent=2)}</pre>
</body>
</html>"""
    with open(path, "w") as f:
        f.write(html)


def _launch_dashboard(report: dict, port: int) -> None:
    try:
        from dashboard.app import create_app
        app = create_app(report)
        print(f"\n{GREEN}✓{RESET} Dashboard running at "
              f"{_c(f'http://localhost:{port}', CYAN)}\n"
              f"  {DIM}Press Ctrl+C to stop{RESET}\n")
        app.run(host="0.0.0.0", port=port, debug=False)
    except ImportError as e:
        print(f"\n{YELLOW}⚠{RESET} Could not start dashboard: {e}")
        print(f"  Run:  {CYAN}python dashboard/app.py --data <report.json>{RESET}")


if __name__ == "__main__":
    main()
