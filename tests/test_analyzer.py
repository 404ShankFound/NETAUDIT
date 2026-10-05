"""Unit tests for NetAudit's explainable detection rules and score bands."""
from datetime import datetime, timedelta
from types import SimpleNamespace
from app.services.analyzer import analyze_packets, detect_abnormal_volume, detect_brute_force, detect_port_scans
from app.services.threat_scoring import score_alerts


def make_packet(seconds=0, source="10.0.0.1", destination="10.0.0.2", protocol="TCP", destination_port=80, length=60):
    return SimpleNamespace(timestamp=datetime(2025, 1, 1) + timedelta(seconds=seconds), src_ip=source, dst_ip=destination, protocol=protocol, dst_port=destination_port, packet_length=length)


def test_port_scan_detection_flags_many_unique_ports():
    _, alerts, _, _, _ = analyze_packets([make_packet(destination_port=port) for port in range(20, 36)])
    assert any(alert["alert_type"] == "Possible Port Scan" for alert in alerts)


def test_brute_force_detection_flags_repeated_ssh_attempts():
    _, alerts, _, _, _ = analyze_packets([make_packet(destination_port=22) for _ in range(8)])
    assert any(alert["alert_type"] == "Possible Brute-Force Activity" for alert in alerts)


def test_abnormal_volume_detection_uses_window_baseline():
    windows = [(datetime(2025, 1, 1) + timedelta(seconds=index * 10), [make_packet(seconds=index * 10, length=100)] if index < 3 else [make_packet(seconds=index * 10, length=1000)]) for index in range(4)]
    assert len(detect_abnormal_volume(windows)) == 1


def test_score_is_clamped_and_has_severity_band():
    score, severity, reasons = score_alerts([{"alert_type": "Possible Port Scan", "score": 40}, {"alert_type": "Possible Brute-Force Activity", "score": 40}, {"alert_type": "Abnormal Traffic Volume", "score": 30}])
    assert (score, severity) == (100, "Critical")
    assert len(reasons) == 3
