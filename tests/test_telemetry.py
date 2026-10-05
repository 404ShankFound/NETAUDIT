"""Tests for defensive PyShark-style telemetry extraction."""
from app.services.telemetry import packet_to_telemetry


class Layer:
    def __init__(self, **fields): self.__dict__.update(fields)


class FakePacket:
    number = "7"; sniff_timestamp = "1700000000"; length = "74"
    ip = Layer(src="10.0.0.1", dst="10.0.0.2")
    tcp = Layer(srcport="51515", dstport="443", flags="0x0002")
    dns = Layer(qry_name="example.test")


def test_extracts_available_layers_without_requiring_http():
    telemetry = packet_to_telemetry(FakePacket())
    assert telemetry["protocol"] == "TCP"
    assert telemetry["src_port"] == 51515
    assert telemetry["dns_query"] == "example.test"
    assert telemetry["http_method"] is None
