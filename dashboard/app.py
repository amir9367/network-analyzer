from flask import Flask, jsonify, render_template
from storage.database import query_recent_packets, query_recent_alerts
from collections import Counter

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stats")
def stats():
    packets = query_recent_packets(500)
    alerts  = query_recent_alerts(20)

    # Protocol breakdown
    protocol_counts = Counter(p["protocol"] for p in packets)

    # Top source IPs
    top_ips = Counter(p["src_ip"] for p in packets).most_common(5)

    # Traffic over time (group by minute)
    timeline = Counter()
    for p in packets:
        minute = p["timestamp"][:16]   # "2024-01-01T12:34"
        timeline[minute] += p["size"]
    timeline_sorted = sorted(timeline.items())

    return jsonify({
        "total_packets":  len(packets),
        "protocols":      dict(protocol_counts),
        "top_ips":        top_ips,
        "timeline":       timeline_sorted,
        "alerts":         alerts,
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)