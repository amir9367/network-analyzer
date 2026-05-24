from scapy.all import sniff, IP, TCP, UDP, conf
from datetime import datetime
from storage.database import init_db, insert_packet
from analysis.detector import analyze

def packet_callback(packet):
    if IP not in packet:
        return  # Skip non-IP traffic (ARP, etc.)

    data = {
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip":    packet[IP].src,
        "dst_ip":    packet[IP].dst,
        "protocol":  packet[IP].proto,
        "size":      len(packet),
        "src_port":  None,
        "dst_port":  None,
    }

    if TCP in packet:
        data["src_port"] = packet[TCP].sport
        data["dst_port"] = packet[TCP].dport
        data["protocol"] = "TCP"
    elif UDP in packet:
        data["src_port"] = packet[UDP].sport
        data["dst_port"] = packet[UDP].dport
        data["protocol"] = "UDP"

    insert_packet(data)
    analyze(data)
    print(f"[{data['timestamp']}] {data['protocol']} {data['src_ip']}:{data['src_port']} → {data['dst_ip']}:{data['dst_port']} ({data['size']} bytes)")


def start_capture(interface=None, count=0, filter_str="ip"):
    """
    Start sniffing packets.
    interface=None auto-selects your active network interface.
    count=0 means capture indefinitely.
    """
    init_db()

    if interface is None:
        interface = conf.iface
        print(f"[*] Auto-selected interface: {interface}")

    print(f"[*] Starting capture on {interface}...")
    sniff(
        iface=interface,
        prn=packet_callback,
        count=count,
        filter=filter_str,
        store=False
    )