"""Anomaly detection: port-scan and traffic-spike, using rolling time windows."""

import threading
from collections import defaultdict
from datetime import datetime, timezone

# ── Configurable thresholds ──────────────────────────────────────────────────
PORT_SCAN_THRESHOLD  = 15          # unique dst ports per window before alert
TRAFFIC_SPIKE_BYTES  = 5_000_000   # bytes per window before alert (5 MB)
WINDOW_SECONDS       = 60
# ─────────────────────────────────────────────────────────────────────────────

_lock = threading.Lock()

# {src_ip: {dst_port: first_seen_ts}}
_port_map: dict[str, dict[int, datetime]] = defaultdict(dict)
# {src_ip: (bytes_total, window_start_ts)}
_byte_map: dict[str, tuple[int, datetime]] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _evict_old(src_ip: str, now: datetime) -> None:
    """Remove stale entries outside the rolling window (called under lock)."""
    cutoff = (now.timestamp() - WINDOW_SECONDS)

    # Evict old ports
    ports = _port_map.get(src_ip, {})
    stale = [p for p, ts in ports.items() if ts.timestamp() < cutoff]
    for p in stale:
        del ports[p]

    # Evict old byte counter
    entry = _byte_map.get(src_ip)
    if entry and entry[1].timestamp() < cutoff:
        del _byte_map[src_ip]


def observe(src_ip: str, dst_port: int | None,
            length: int) -> list[dict]:
    """
    Update internal state for one packet.
    Returns a (possibly empty) list of alert dicts if thresholds were crossed.
    """
    now = alerts = None
    fired: list[dict] = []

    with _lock:
        now = _now()
        _evict_old(src_ip, now)

        # ── Port-scan detection ──────────────────────────────────────────────
        if dst_port is not None:
            ports = _port_map[src_ip]
            if dst_port not in ports:
                ports[dst_port] = now
            if len(ports) >= PORT_SCAN_THRESHOLD:
                fired.append({
                    "alert_type": "PORT_SCAN",
                    "src_ip":     src_ip,
                    "detail":     f"Hit {len(ports)} unique ports in {WINDOW_SECONDS}s",
                    "timestamp":  now.strftime("%Y-%m-%dT%H:%M:%S"),
                })
                _port_map[src_ip].clear()   # reset so we don't spam

        # ── Traffic-spike detection ──────────────────────────────────────────
        if src_ip in _byte_map:
            total, start = _byte_map[src_ip]
            total += length
            _byte_map[src_ip] = (total, start)
        else:
            total = length
            _byte_map[src_ip] = (total, now)

        if total >= TRAFFIC_SPIKE_BYTES:
            fired.append({
                "alert_type": "TRAFFIC_SPIKE",
                "src_ip":     src_ip,
                "detail":     f"Sent {total:,} bytes in {WINDOW_SECONDS}s",
                "timestamp":  now.strftime("%Y-%m-%dT%H:%M:%S"),
            })
            del _byte_map[src_ip]           # reset so we don't spam

    return fired