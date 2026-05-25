"""Flask dashboard — 3 JSON endpoints + 1 HTML page."""

from flask import Flask, jsonify, render_template
from storage.database import query_packet_stats, query_recent_alerts

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/stats")
def api_stats():
    return jsonify(query_packet_stats())


@app.get("/api/alerts")
def api_alerts():
    rows = query_recent_alerts(50)
    return jsonify([dict(r) for r in rows])


