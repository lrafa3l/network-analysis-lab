# Network Analysis Lab

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/tests-42%20passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Zero Dependencies](https://img.shields.io/badge/core-zero%20dependencies-success)
![Protocols](https://img.shields.io/badge/protocols-Ethernet%20%7C%20IPv4%20%7C%20TCP%20%7C%20UDP%20%7C%20DNS%20%7C%20HTTP%20%7C%20ARP%20%7C%20ICMP-informational)

A hands-on **network forensics laboratory** built for packet capture analysis, multi-layer protocol dissection, and real-time traffic anomaly detection.

Built from scratch in pure Python — no Scapy, no libpcap bindings, no external parsing libraries. Every byte of every header parsed by hand against the relevant RFCs.

---

## Features

| Category | Capability |
|---|---|
| **Dissection** | Ethernet → IPv4 → TCP/UDP/ICMP → HTTP/DNS/ARP, full flag parsing |
| **Flow tracking** | Bidirectional 5-tuple flow reconstruction, TCP state machine |
| **Anomaly detection** | 10 detection rules (port scans, SYN flood, ARP spoof, DNS exfil, C2 beacons…) |
| **Traffic stats** | Protocol distribution, top talkers, packet-size histogram, timeline |
| **Web dashboard** | Interactive Flask UI with Chart.js — timeline, donut, bar charts |
| **CLI analyzer** | Coloured terminal output, protocol filter, packet dump, JSON export |
| **Sample generator** | Synthetic pcap builder — normal traffic + injected attack scenarios |
| **Test suite** | 42 unit + integration tests, zero external test dependencies |

---

## Architecture

```
network-analysis-lab/
├── src/
│   ├── core/
│   │   ├── pcap_reader.py      # Pure-Python pcap parser + full protocol stack
│   │   └── pcap_writer.py      # pcap builder (for sample generation & testing)
│   └── analysis/
│       └── analyzer.py         # TrafficStats · FlowTracker · AnomalyDetector
├── dashboard/
│   ├── app.py                  # Flask REST API + page routes
│   └── templates/index.html    # Chart.js dark-theme dashboard
├── tools/
│   └── generate_sample.py      # Synthetic traffic generator
├── tests/
│   └── test_core.py            # 42 unit + integration tests
└── analyze.py                  # Main CLI entry point
```

---

## Quick Start

```bash
# Clone and enter the project
git clone https://github.com/yourusername/network-analysis-lab.git
cd network-analysis-lab

# Install dependencies (Flask + display helpers only — core has zero deps)
pip install -r requirements.txt

# Generate sample captures
python tools/generate_sample.py
# → samples/normal_traffic.pcap  (clean web browsing)
# → samples/attack_traffic.pcap  (port scan + SYN flood + DNS exfil + ARP spoof)

# Analyse normal traffic
python analyze.py samples/normal_traffic.pcap

# Analyse attack traffic (alerts only)
python analyze.py samples/attack_traffic.pcap --alerts-only

# Full analysis with packet dump
python analyze.py samples/attack_traffic.pcap --dump 20 --top 15

# Launch interactive dashboard
python analyze.py samples/attack_traffic.pcap --dashboard
# → open http://localhost:5000

# Export JSON report
python analyze.py samples/attack_traffic.pcap --json > report.json
```

---

## CLI Output

```
┌──────────────────────────────────────────┐
│     Network Analysis Lab  v1.0           │
│     Packet Forensics & Threat Detection  │
└──────────────────────────────────────────┘

Reading: samples/attack_traffic.pcap
  ✓ Processed 198 packets in 0.01s  (23,744 pkt/s)

──────────────────────── Capture Summary ──
  File duration              2.953 s
  Total packets              198
  Total bytes                12.4 KB
  Unique src IPs             52

──────────────────── Protocol Distribution ──
  HTTP     ████████████░░░░░░░░   92 pkts   6.2 KB  46.5%
  SMB      ████░░░░░░░░░░░░░░░░   28 pkts   1.5 KB  14.1%
  DNS      ███░░░░░░░░░░░░░░░░░   23 pkts   1.9 KB  11.6%

──────────────────────── Anomaly Alerts ──
  1 CRITICAL  37 HIGH  2 MEDIUM

  [CRITICAL]  syn_flood
               192.168.1.99 sent 50 SYNs in 5.0s — likely SYN flood
               src=192.168.1.99  dst=192.168.1.20

  [HIGH    ]  port_scan_vertical
               192.168.1.99 scanned 15+ ports on 192.168.1.20 — vertical port scan

  [HIGH    ]  arp_spoofing
               IP 192.168.1.1 claimed by 2 MACs — possible ARP cache poisoning

  [HIGH    ]  dns_exfiltration
               Anomalous DNS query: "aW50ZXJuYWwtc2VjcmV0LXRva2VuLXZhbHVl.c2.evil-domain.net"
```

---

## Web Dashboard

Launch with `python analyze.py capture.pcap --dashboard` or run the standalone server:

```bash
python analyze.py capture.pcap --json > report.json
python dashboard/app.py --data report.json --port 5000
```

**Dashboard sections:**
- **Overview** — summary stats, traffic timeline (packets + bytes), protocol donut chart, size histogram
- **Protocols** — full breakdown table with visual percentage bars
- **Top Talkers** — horizontal bar chart + table, sorted by bytes
- **Flows** — bidirectional flow table with state, duration, throughput
- **Alerts** — colour-coded anomaly list (CRITICAL → INFO) with source/dest context
- **DNS** — query log with automatic anomaly highlighting for suspicious labels
- **HTTP** — request log with method colour coding

---

## Anomaly Detection Rules

| ID | Rule | Severity | Trigger |
|---|---|---|---|
| 1 | Vertical port scan | HIGH | ≥15 distinct dports from one src to one dst |
| 2 | Horizontal port scan | HIGH | Same port probed on ≥10 distinct hosts |
| 3 | SYN flood | CRITICAL | ≥50 SYNs from one src within 5 s |
| 4 | ARP spoofing | HIGH | Same IP announced by 2+ different MACs |
| 5 | DNS exfiltration | HIGH | Label > 30 chars or > 5 dot-segments |
| 6 | DNS high query rate | MEDIUM | ≥20 queries/src within 5 s |
| 7 | Suspicious port | HIGH | Connection to known C2/exploit ports (4444, 6379, 31337…) |
| 8 | Large data transfer | LOW | Single flow exceeds 10 MB |
| 9 | ICMP flood | MEDIUM | ≥30 ICMP packets/src within 5 s |
| 10 | Cleartext protocol | MEDIUM | Telnet session detected |

Thresholds are tunable — pass custom values when instantiating `AnomalyDetector`.

---

## Running Tests

```bash
# Standard library only (no pytest required)
python -m unittest tests/test_core.py -v

# With pytest (if installed)
pytest tests/ -v

# What's covered (42 tests across 5 suites)
#   TestPcapReader        — dissection of TCP, UDP, ICMP, ARP, HTTP, DNS; timestamps
#   TestTrafficStats      — counters, top talkers, duration, timeline bins
#   TestFlowTracker       — flow creation, bidirectionality, state machine, sorting
#   TestAnomalyDetector   — all 10 detection rules + deduplication + summary
#   TestPcapWriterRoundTrip — write→read round-trip integrity for all frame types
#   TestIntegration       — end-to-end: generate → analyse → assert alerts
```

---

## Protocol Support

**Parsed layers:**

| Layer | Protocols |
|---|---|
| Link | Ethernet II, 802.1Q VLAN |
| Network | IPv4 (all flags, fragmentation), ARP (request/reply) |
| Transport | TCP (full option parsing, state machine), UDP, ICMP |
| Application | HTTP/1.x (request + response), DNS (A/AAAA/CNAME/MX/NS/PTR) |

**Protocol detection heuristics:**
- Port-based: SSH (22), FTP (20-21), SMTP (25/465/587), RDP (3389), SMB (139/445), Telnet (23)
- Content-based: HTTP method/status-line parsing, DNS header magic validation

---

## Analysing Real Captures

The tool reads any standard `.pcap` file — including those captured with **Wireshark**, **tcpdump**, or **tshark**:

```bash
# From Wireshark: File → Export Specified Packets → pcap format
python analyze.py ~/Downloads/my_capture.pcap

# From tcpdump
sudo tcpdump -i eth0 -w capture.pcap -c 5000
python analyze.py capture.pcap --dashboard

# Filter to a specific protocol
python analyze.py capture.pcap --filter DNS

# Analyse just the alerts from a capture
python analyze.py capture.pcap --alerts-only
```

> **Note:** Live capture requires OS-level packet capture permissions. This tool analyses existing `.pcap` files.

---

## Code Quality

- **Zero core dependencies** — packet parsing uses Python `struct`, `socket`, and `dataclasses` only
- **Type-annotated** throughout (`from __future__ import annotations`)
- **Streaming architecture** — O(1) memory for arbitrarily large captures (one packet in memory at a time)
- **RFC-aligned** — headers parsed against RFC 791 (IPv4), RFC 793 (TCP), RFC 768 (UDP), RFC 1035 (DNS)
- **42 tests** with 100% pass rate, covering unit, integration, and round-trip scenarios

---

## Skills Demonstrated

- **Network fundamentals** — deep understanding of the TCP/IP stack across all OSI layers
- **Binary protocol parsing** — manual struct unpacking, bit manipulation, endianness handling
- **Security analysis** — SOC Level 1 methodology: capture → filter → identify → classify → document
- **Threat detection** — stateful rule engine with time-windowed rate checks and deduplication
- **Python engineering** — clean module design, dataclasses, generators, context managers
- **Full-stack tooling** — CLI (click + ANSI), REST API (Flask), interactive UI (Chart.js)

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built as a portfolio project demonstrating hands-on network forensics skills.*
*All packet parsing written from first principles — no Scapy, no Wireshark bindings.*
