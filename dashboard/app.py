"""
Flask dashboard — serves the HTML UI and a small REST API.
"""
from __future__ import annotations
from flask import Flask, jsonify, render_template
from storage.database import (
    query_protocol_counts,
    query_traffic_timeline,
    query_top_ips,
    query_recent_alerts,
    query_recent_packets,
)

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


# ── HTML ───────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── API ────────────────────────────────────────────────────────────────────────

@app.route("/api/protocols")
def api_protocols():
    rows = query_protocol_counts()
    return jsonify([{"protocol": r["protocol"], "count": r["cnt"]} for r in rows])


@app.route("/api/timeline")
def api_timeline():
    rows = query_traffic_timeline(minutes=10)
    return jsonify([{"minute": r["minute"], "count": r["cnt"]} for r in rows])


@app.route("/api/top-ips")
def api_top_ips():
    rows = query_top_ips(10)
    return jsonify([{"ip": r["src_ip"], "count": r["cnt"]} for r in rows])


@app.route("/api/alerts")
def api_alerts():
    rows = query_recent_alerts(20)
    return jsonify([dict(r) for r in rows])


@app.route("/api/packets")
def api_packets():
    rows = query_recent_packets(50)
    return jsonify([dict(r) for r in rows])