"""Validation and PyShark parser unit tests without requiring a TShark binary."""
from types import SimpleNamespace
from io import BytesIO
from fastapi import HTTPException
from starlette.datastructures import UploadFile
from app.services.pcap_parser import parse_pcap
import app.services.pcap_parser as parser
from app.utils.validators import validate_pcap_upload


def test_rejects_non_pcap_filename():
    upload = UploadFile(filename="not-a-capture.txt", file=BytesIO())
    try:
        validate_pcap_upload(upload)
    except HTTPException as error:
        assert error.status_code == 400
    else:
        raise AssertionError("A non-PCAP filename should be rejected")


def test_parser_uses_pyshark_filecapture(monkeypatch, tmp_path):
    fake_packet = SimpleNamespace(number="1", sniff_timestamp="1700000000", length="60", ip=SimpleNamespace(src="10.0.0.1", dst="10.0.0.2"), udp=SimpleNamespace(srcport="53", dstport="53000"))
    class FakeCapture:
        def __init__(self, path, keep_packets):
            assert path.endswith("demo.pcap")
            assert keep_packets is False
        def __iter__(self): return iter([fake_packet])
        def close(self): pass
    monkeypatch.setattr(parser.pyshark, "FileCapture", FakeCapture)
    telemetry = list(parse_pcap(tmp_path / "demo.pcap"))
    assert telemetry[0]["protocol"] == "UDP"
    assert telemetry[0]["src_ip"] == "10.0.0.1"
