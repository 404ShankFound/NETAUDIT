"""End-to-end API test: upload -> parse -> SQLite -> analysis result."""
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.database.database import Base, get_db
from app.main import app
import app.api.routes_upload as upload_routes


def test_upload_runs_persistence_and_detection(monkeypatch, tmp_path):
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", connect_args={"check_same_thread": False})
    TestSession = sessionmaker(bind=test_engine)
    Base.metadata.create_all(test_engine)
    def override_database():
        database = TestSession()
        try: yield database
        finally: database.close()
    start = datetime(2025, 1, 1)
    def fake_parser(_):
        for index, port in enumerate(range(20, 36)):
            yield {"timestamp": start + timedelta(seconds=index / 10), "packet_number": index + 1, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.2", "protocol": "TCP", "src_port": 40000, "dst_port": port, "packet_length": 60, "tcp_flags": "0x0002", "dns_query": None, "http_host": None, "http_method": None, "http_uri": None}
    monkeypatch.setattr(upload_routes, "parse_pcap", fake_parser)
    app.dependency_overrides[get_db] = override_database
    try:
        response = TestClient(app).post("/upload", files={"file": ("scan.pcap", b"pcap-test", "application/octet-stream")})
        assert response.status_code == 200
        analysis = TestClient(app).get(f"/analyses/{response.json()['analysis_id']}").json()
        assert analysis["packet_count"] == 16
        assert analysis["statistics"]["total_packets"] == 16
        assert any(alert["alert_type"] == "Possible Port Scan" for alert in analysis["alerts"])
    finally:
        app.dependency_overrides.clear()
