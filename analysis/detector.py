"""
Anomaly detection — port-scan and traffic-spike detection
using rolling time windows per source IP.

Thread-safe: all state is protected by a single lock.
"""
from __future__ import annotations
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone

# ── tuneable thresholds ────────────────────────────────────────────────────────
PORT_SCAN_THRESHOLD  = 15          # unique dst ports per IP in WINDOW_SECONDS
TRAFFIC_SPIKE_BYTES  = 5_000_000   # bytes per IP in WINDOW_SECONDS (5 MB)
WINDOW_SECONDS       = 60
CLEANUP_INTERVAL     = 120         # prune stale entries every 2 min
# ──────────────────────────────────────────────────────────────────────────────

_lock = threading.Lock()

# src_ip → list of (timestamp_float, dst_port)
_port_events: dict[str, list[tuple[float, int]]] = defaultdict(list)
# src_ip → list of (timestamp_float, byte_count)
_byte_events:  dict[str, list[tuple[float, int]]] = defaultdict(list)

_last_cleanup = time.monotonic()


def _now() -> float:
    return time.monotonic()


def _prune(events: dict[str, list], cutoff: float) -> None:
    for ip in list(events):
        events[ip] = [e for e in events[ip] if e[0] >= cutoff]
        if not events[ip]:
            del events[ip]


def _maybe_cleanup() -> None:
    global _last_cleanup
    now = _now()
    if now - _last_cleanup > CLEANUP_INTERVAL:
        cutoff = now - WINDOW_SECONDS
        _prune(_port_events, cutoff)
        _prune(_byte_events, cutoff)
        _last_cleanup = now


def check(packet: dict) -> list[dict]:
    """
    Feed a parsed packet dict (from analysis.parser) into the detector.
    Returns a (possibly empty) list of alert dicts with keys:
        timestamp, alert_type, src_ip, detail
    """
    src_ip   = packet.get("src_ip")
    dst_port = packet.get("dst_port")
    length   = packet.get("length", 0)

    if not src_ip:
        return []

    alerts = []
    ts     = datetime.now(timezone.utc).isoformat(timespec="seconds")
    now    = _now()
    cutoff = now - WINDOW_SECONDS

    with _lock:
        _maybe_cleanup()

        # ── byte-spike tracking ────────────────────────────────────────────
        _byte_events[src_ip].append((now, length))
        window_bytes = sum(
            b for t, b in _byte_events[src_ip] if t >= cutoff
        )
        if window_bytes >= TRAFFIC_SPIKE_BYTES:
            alerts.append({
                "timestamp":  ts,
                "alert_type": "TRAFFIC_SPIKE",
                "src_ip":     src_ip,
                "detail": (
                    f"Sent {window_bytes:,} bytes in {WINDOW_SECONDS}s"
                ),
            })
            # reset to avoid alert storm
            _byte_events[src_ip].clear()

        # ── port-scan tracking ────────────────────────────────────────────
        if dst_port is not None:
            _port_events[src_ip].append((now, dst_port))
            recent_ports = {
                p for t, p in _port_events[src_ip] if t >= cutoff
            }
            if len(recent_ports) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "timestamp":  ts,
                    "alert_type": "PORT_SCAN",
                    "src_ip":     src_ip,
                    "detail": (
                        f"Hit {len(recent_ports)} unique ports in {WINDOW_SECONDS}s"
                    ),
                })
                _port_events[src_ip].clear()

    return alerts