from collections import defaultdict
from datetime import datetime, timedelta
from storage.database import insert_alert

# In-memory state (resets on restart — good enough for now)
_port_tracker = defaultdict(set) 
_traffic_bytes = defaultdict(int)
_window_start = datetime.utcnow()

PORT_SCAN_THRESHOLD = 15  # Unique ports per IP in time window
TRAFFIC_SPIKE_BYTES = 5_000_000  # 5 MB in time window
WINDOW_SECONDS = 60  # Time window in seconds

def analyze(packet_data: dict):
    global _window_start

    src = packet_data["src_ip"]
    now = datetime.utcnow()

    # Reset window every WINDOW_SECONDS
    if (now - _window_start).seconds >= WINDOW_SECONDS:
        _port_tracker.clear()
        _traffic_bytes.clear()
        _window_start = now

    # --- Port scan detection ---
    if packet_data.get("dst_port"):
        _port_tracker[src].add(packet_data["dst_port"])
        if len(_port_tracker[src]) >= PORT_SCAN_THRESHOLD:
            insert_alert(
                alert_type="PORT_SCAN",
                src_ip=src,
                detail=f"Hit {len(_port_tracker[src])} unique ports in {WINDOW_SECONDS}s"
            )
            _port_tracker[src].clear()   # Reset so we don't spam alerts

    # --- Traffic spike detection ---
    _traffic_bytes[src] += packet_data["size"]
    if _traffic_bytes[src] >= TRAFFIC_SPIKE_BYTES:
        insert_alert(
            alert_type="TRAFFIC_SPIKE",
            src_ip=src,
            detail=f"Sent {_traffic_bytes[src]:,} bytes in {WINDOW_SECONDS}s"
        )
        _traffic_bytes[src] = 0