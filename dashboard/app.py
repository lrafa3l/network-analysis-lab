#!/usr/bin/env python3
"""
Network Analysis Lab — Web Dashboard

Serves an interactive dark-theme dashboard showing protocol distribution,
traffic timeline, top talkers, anomaly alerts, flows, and DNS queries.

Usage (standalone):
    python dashboard/app.py --data report.json [--port 5000]

Usage (via analyze.py):
    python analyze.py capture.pcap --dashboard
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, jsonify, render_template_string, abort

# ── HTML template (inline to keep project self-contained) ─────────────────────

_TEMPLATE = open(
    os.path.join(os.path.dirname(__file__), "templates", "index.html")
).read()


def create_app(report: dict) -> Flask:
    """Factory: create a Flask app pre-loaded with a report dict."""
    app = Flask(__name__, template_folder="templates")
    app.config["REPORT"] = report

    @app.route("/")
    def index():
        r = app.config["REPORT"]
        return render_template_string(_TEMPLATE, report=r)

    @app.route("/api/report")
    def api_report():
        return jsonify(app.config["REPORT"])

    @app.route("/api/alerts")
    def api_alerts():
        return jsonify(app.config["REPORT"].get("alerts", []))

    @app.route("/api/flows")
    def api_flows():
        return jsonify(app.config["REPORT"].get("flows", []))

    @app.route("/api/timeline")
    def api_timeline():
        return jsonify(app.config["REPORT"].get("timeline", []))

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="Network Analysis Lab Dashboard")
    parser.add_argument("--data", required=True, help="Path to JSON report file")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    with open(args.data) as f:
        report = json.load(f)

    app = create_app(report)
    print(f"\n  Dashboard → http://localhost:{args.port}\n"
          f"  Press Ctrl+C to stop\n")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
