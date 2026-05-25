"""Live packet capture using Scapy."""

import sys
import signal
from datetime import datetime, timezone

from scapy.all import sniff, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP

from analysis.detector import observe
from storage.database import init_db, insert_packet, insert_alert


def _pick_interface() -> str | None:
    """Return the first non-loopback interface, or None to let Scapy decide."""
    for iface in get_if_list():
        if iface not in ("lo", "lo0", "localhost"):
            return iface
    return None


def _protocol(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "OTHER"


def _handle(pkt) -> None:
    if not pkt.haslayer(IP):
        return

    ip    = pkt[IP]
    proto = _protocol(pkt)
    ts    = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    dport = None

    if pkt.haslayer(TCP):
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        dport = pkt[UDP].dport

    insert_packet(ts, ip.src, ip.dst, proto, len(pkt))

    alerts = observe(ip.src, dport, len(pkt))
    for a in alerts:
        insert_alert(a["timestamp"], a["alert_type"], a["src_ip"], a["detail"])
        print(f"  \033[91m[ALERT]\033[0m {a['alert_type']:15s} | "
              f"{a['src_ip']:<18} {a['detail']}")


def start_capture(interface: str | None = None, count: int = 0) -> None:
    init_db()

    iface = interface or _pick_interface()
    label = iface or "default"
    limit = f"{count} packets" if count else "unlimited"

    print(f"  Capturing on \033[96m{label}\033[0m  ({limit})  — Ctrl+C to stop\n")
    conf.verb = 0   # silence Scapy's own output

    # Allow Ctrl-C to stop sniff cleanly
    def _stop(*_):
        print("\n  Capture stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, _stop)

    sniff(
        iface=iface or None,
        prn=_handle,
        count=count or 0,
        store=False,      # don't accumulate packets in RAM
    )