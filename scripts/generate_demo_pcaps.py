"""Create harmless, synthetic PCAPs for the NetAudit classroom demonstration.

Run only in an authorized lab. These files contain crafted packets only; they do not
send any network traffic.
"""
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "sample_pcaps"
BASE_TIME = 1_700_000_000.0


def packet(source, destination, transport, offset, payload=b""):
    """Build a timestamped Ethernet/IP packet for offline PCAP writing."""
    frame = Ether() / IP(src=source, dst=destination) / transport
    if payload:
        frame /= Raw(load=payload)
    frame.time = BASE_TIME + offset
    return frame


def write_normal():
    """Make ordinary low-volume DNS, HTTP-like TCP, and UDP packets."""
    frames = []
    for index in range(18):
        offset = index * 2
        frames.append(packet("10.0.0.10", "8.8.8.8", UDP(sport=53000 + index, dport=53), offset, b"normal-dns"))
        frames.append(packet("10.0.0.10", "93.184.216.34", TCP(sport=50000 + index, dport=80, flags="PA"), offset + .2, b"GET / HTTP/1.1"))
    wrpcap(str(OUTPUT_DIR / "normal_traffic.pcap"), frames)


def write_port_scan():
    """Make one source contact many ports within a 10-second window."""
    frames = [packet("192.168.56.50", "192.168.56.10", TCP(sport=40000, dport=port, flags="S"), index * .25) for index, port in enumerate(range(20, 45))]
    wrpcap(str(OUTPUT_DIR / "port_scan.pcap"), frames)


def write_brute_force():
    """Make repeated TCP SYN attempts to SSH; no connection is made or sent."""
    frames = [packet("192.168.56.60", "192.168.56.10", TCP(sport=41000 + index, dport=22, flags="S"), index * .4) for index in range(10)]
    wrpcap(str(OUTPUT_DIR / "brute_force.pcap"), frames)


def write_abnormal_volume():
    """Make three calm windows followed by a large offline traffic burst."""
    frames = []
    for window in range(3):
        for index in range(3):
            frames.append(packet("10.1.1.10", "10.1.1.20", UDP(sport=5000 + index, dport=5001), window * 10 + index, b"small"))
    for index in range(40):
        frames.append(packet("10.1.1.10", "10.1.1.20", UDP(sport=6000 + index, dport=5001), 30 + index * .1, b"X" * 1400))
    wrpcap(str(OUTPUT_DIR / "abnormal_traffic.pcap"), frames)


if __name__ == "__main__":
    OUTPUT_DIR.mkdir(exist_ok=True)
    write_normal(); write_port_scan(); write_brute_force(); write_abnormal_volume()
    print(f"Created demo PCAPs in {OUTPUT_DIR}")
