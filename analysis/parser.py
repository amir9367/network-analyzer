"""
Packet field extraction — converts a raw Scapy packet into a plain dict.
"""
from __future__ import annotations
from datetime import datetime, timezone


def parse_packet(pkt) -> dict | None:
    """
    Return a dict with timestamp, src_ip, dst_ip, protocol, length,
    src_port, dst_port.  Returns None for packets that carry no IP layer.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP
    except ImportError:
        return None

    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    protocol = "OTHER"
    src_port = dst_port = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif ip.proto == 1:
        protocol = "ICMP"

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "protocol": protocol,
        "length": len(pkt),
        "src_port": src_port,
        "dst_port": dst_port,
    }