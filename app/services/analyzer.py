"""Explainable time-window traffic statistics and anomaly rules for NetAudit."""
from collections import Counter, defaultdict
from datetime import timedelta
from statistics import median
from app.config import AUTHENTICATION_PORTS, BRUTE_FORCE_ATTEMPTS, PORT_SCAN_UNIQUE_PORTS, TIME_WINDOW_SECONDS, VOLUME_MULTIPLIER
from app.services.threat_scoring import score_alerts


def _windowed_packets(packets):
    """Group timestamped packet records into fixed 10-second investigation windows."""
    valid = [packet for packet in packets if packet.timestamp]
    if not valid:
        return []
    start = min(packet.timestamp for packet in valid)
    windows = defaultdict(list)
    for packet in valid:
        index = int((packet.timestamp - start).total_seconds() // TIME_WINDOW_SECONDS)
        windows[index].append(packet)
    return [(start + timedelta(seconds=index * TIME_WINDOW_SECONDS), values) for index, values in sorted(windows.items())]


def _alert(alert_type, severity, source, destination, timestamp, evidence, score):
    return {"alert_type": alert_type, "severity": severity, "src_ip": source, "dst_ip": destination,
            "timestamp": timestamp, "description": f"{alert_type}: {evidence}", "evidence": evidence, "score": score}


def detect_port_scans(windows):
    """Flag a source that contacts unusually many destination ports in one window."""
    alerts = []
    for timestamp, packets in windows:
        port_sets = defaultdict(set)
        for packet in packets:
            if packet.src_ip and packet.dst_port is not None:
                port_sets[packet.src_ip].add(packet.dst_port)
        for source, ports in port_sets.items():
            if len(ports) >= PORT_SCAN_UNIQUE_PORTS:
                evidence = f"{len(ports)} distinct destination ports contacted within {TIME_WINDOW_SECONDS} seconds (threshold: {PORT_SCAN_UNIQUE_PORTS})."
                alerts.append(_alert("Possible Port Scan", "High", source, None, timestamp, evidence, 40))
    return alerts


def detect_brute_force(windows):
    """Flag repeated TCP connection attempts to common authentication service ports."""
    alerts = []
    for timestamp, packets in windows:
        attempts = Counter((packet.src_ip, packet.dst_ip, packet.dst_port) for packet in packets
                           if packet.protocol == "TCP" and packet.src_ip and packet.dst_ip and packet.dst_port in AUTHENTICATION_PORTS)
        for (source, destination, port), count in attempts.items():
            if count >= BRUTE_FORCE_ATTEMPTS:
                evidence = f"{count} TCP attempts to {destination}:{port} within {TIME_WINDOW_SECONDS} seconds (threshold: {BRUTE_FORCE_ATTEMPTS})."
                alerts.append(_alert("Possible Brute-Force Activity", "High", source, destination, timestamp, evidence, 40))
    return alerts


def detect_abnormal_volume(windows):
    """Compare each window's byte count against a simple median-based baseline."""
    if len(windows) < 3:
        return []
    bytes_per_window = [sum(packet.packet_length for packet in packets) for _, packets in windows]
    baseline = median(bytes_per_window)
    if baseline <= 0:
        return []
    alerts = []
    for (timestamp, packets), byte_count in zip(windows, bytes_per_window):
        if byte_count > baseline * VOLUME_MULTIPLIER:
            evidence = f"{byte_count} bytes in {TIME_WINDOW_SECONDS} seconds versus {baseline:.0f}-byte median baseline (multiplier: {VOLUME_MULTIPLIER:g}x)."
            alerts.append(_alert("Abnormal Traffic Volume", "Medium", None, None, timestamp, evidence, 30))
    return alerts


def traffic_statistics(packets):
    """Produce dashboard-ready traffic counts from the SQLite packet records."""
    total_bytes = sum(packet.packet_length for packet in packets)
    timestamps = [packet.timestamp for packet in packets if packet.timestamp]
    duration = max((max(timestamps) - min(timestamps)).total_seconds(), 0) if len(timestamps) > 1 else 0
    protocol_counts = Counter(packet.protocol for packet in packets)
    time_windows = _windowed_packets(packets)
    traffic_over_time = [(timestamp.isoformat(), len(window_packets)) for timestamp, window_packets in time_windows]
    window_statistics = [{
        "start": timestamp.isoformat(), "total_packets": len(window_packets),
        "total_bytes": sum(packet.packet_length for packet in window_packets),
        "tcp_packets": sum(packet.protocol == "TCP" for packet in window_packets),
        "udp_packets": sum(packet.protocol == "UDP" for packet in window_packets),
        "icmp_packets": sum(packet.protocol == "ICMP" for packet in window_packets),
        "unique_source_ips": len({packet.src_ip for packet in window_packets if packet.src_ip}),
        "unique_destination_ips": len({packet.dst_ip for packet in window_packets if packet.dst_ip}),
        "unique_destination_ports": len({packet.dst_port for packet in window_packets if packet.dst_port is not None}),
    } for timestamp, window_packets in time_windows]
    return {
        "total_packets": len(packets), "total_bytes": total_bytes, "duration": round(duration, 3),
        "packets_per_second": round(len(packets) / duration, 2) if duration else 0,
        "protocol_distribution": dict(protocol_counts),
        "top_sources": Counter(packet.src_ip for packet in packets if packet.src_ip).most_common(10),
        "top_destinations": Counter(packet.dst_ip for packet in packets if packet.dst_ip).most_common(10),
        "top_ports": [(str(port), count) for port, count in Counter(packet.dst_port for packet in packets if packet.dst_port is not None).most_common(10)],
        "traffic_over_time": traffic_over_time, "window_statistics": window_statistics,
        "tcp_count": protocol_counts["TCP"], "udp_count": protocol_counts["UDP"], "icmp_count": protocol_counts["ICMP"],
        "dns_query_count": sum(bool(packet.dns_query) for packet in packets),
        "http_request_count": sum(bool(packet.http_method) for packet in packets),
        "unique_source_ips": len({packet.src_ip for packet in packets if packet.src_ip}),
        "unique_destination_ips": len({packet.dst_ip for packet in packets if packet.dst_ip}),
        "unique_destination_ports": len({packet.dst_port for packet in packets if packet.dst_port is not None}),
    }


def analyze_packets(packets):
    """Run all required rules and return stats, alerts, score, and severity."""
    windows = _windowed_packets(packets)
    alerts = detect_port_scans(windows) + detect_brute_force(windows) + detect_abnormal_volume(windows)
    score, severity, reasons = score_alerts(alerts)
    return traffic_statistics(packets), alerts, score, severity, reasons
