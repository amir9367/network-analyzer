"""
Packet capture using Scapy.
Auto-detects the active non-loopback interface when none is specified.
"""
from __future__ import annotations
import sys

from analysis.parser import parse_packet
from analysis import detector
from storage.database import init_db, insert_packet, insert_alert


def _auto_interface() -> str:
    """Return the first non-loopback interface that has an IP."""
    try:
        from scapy.all import conf, get_if_list, get_if_addr
    except ImportError:
        print("[!] Scapy is not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)

    for iface in get_if_list():
        if iface in ("lo", "lo0"):
            continue
        try:
            addr = get_if_addr(iface)
            if addr and addr != "0.0.0.0":
                return iface
        except Exception:
            continue

    # fallback to scapy's default
    return conf.iface


def _handle(pkt) -> None:
    data = parse_packet(pkt)
    if data is None:
        return

    insert_packet(
        timestamp=data["timestamp"],
        src_ip=data["src_ip"],
        dst_ip=data["dst_ip"],
        protocol=data["protocol"],
        length=data["length"],
    )

    for alert in detector.check(data):
        insert_alert(**alert)
        print(
            f"[ALERT] {alert['timestamp']}  {alert['alert_type']:<15} "
            f"{alert['src_ip']:<18} {alert['detail']}"
        )


def start_capture(interface: str | None = None, count: int = 0) -> None:
    """
    Capture live packets on *interface* (auto-detected when None).
    *count* = 0 means unlimited; any positive value stops after that many packets.
    """
    try:
        from scapy.all import sniff
    except ImportError:
        print("[!] Scapy is not installed. Run: pip install scapy", file=sys.stderr)
        sys.exit(1)

    init_db()
    iface = interface or _auto_interface()

    print(f"[*] Capturing on interface: {iface}")
    print(f"[*] Packet limit: {'unlimited' if count == 0 else count}")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        sniff(
            iface=iface,
            prn=_handle,
            count=count or 0,
            store=False,    # don't accumulate packets in memory
        )
    except KeyboardInterrupt:
        print("\n[*] Capture stopped.")
    except PermissionError:
        print(
            "[!] Permission denied. Run with sudo (Linux/macOS) "
            "or as Administrator (Windows).",
            file=sys.stderr,
        )
        sys.exit(1)