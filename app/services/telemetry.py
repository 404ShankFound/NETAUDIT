"""Convert a PyShark packet into the compact telemetry stored in SQLite."""
from datetime import datetime, timezone


def _field(layer, name: str):
    """Safely read an optional PyShark field; packets rarely share all layers."""
    try:
        return getattr(layer, name, None)
    except (AttributeError, KeyError):
        return None


def packet_to_telemetry(packet) -> dict:
    """Extract IP, transport, DNS, and HTTP metadata without retaining packet payloads."""
    timestamp = None
    try:
        timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc).replace(tzinfo=None)
    except (AttributeError, TypeError, ValueError):
        pass

    telemetry = {
        "timestamp": timestamp,
        "packet_number": int(_field(packet, "number") or 0),
        "src_ip": None, "dst_ip": None, "protocol": "OTHER", "src_port": None,
        "dst_port": None, "packet_length": int(_field(packet, "length") or 0),
        "tcp_flags": None, "dns_query": None, "http_host": None,
        "http_method": None, "http_uri": None,
    }
    if hasattr(packet, "ip"):
        telemetry["src_ip"] = _field(packet.ip, "src")
        telemetry["dst_ip"] = _field(packet.ip, "dst")
    elif hasattr(packet, "ipv6"):
        telemetry["src_ip"] = _field(packet.ipv6, "src")
        telemetry["dst_ip"] = _field(packet.ipv6, "dst")
    if hasattr(packet, "tcp"):
        telemetry.update(protocol="TCP", src_port=_to_int(_field(packet.tcp, "srcport")),
                         dst_port=_to_int(_field(packet.tcp, "dstport")), tcp_flags=_field(packet.tcp, "flags"))
    elif hasattr(packet, "udp"):
        telemetry.update(protocol="UDP", src_port=_to_int(_field(packet.udp, "srcport")),
                         dst_port=_to_int(_field(packet.udp, "dstport")))
    elif hasattr(packet, "icmp") or hasattr(packet, "icmpv6"):
        telemetry["protocol"] = "ICMP"
    if hasattr(packet, "dns"):
        telemetry["dns_query"] = _field(packet.dns, "qry_name")
    if hasattr(packet, "http"):
        telemetry["http_host"] = _field(packet.http, "host")
        telemetry["http_method"] = _field(packet.http, "request_method")
        telemetry["http_uri"] = _field(packet.http, "request_uri")
    return telemetry


def _to_int(value):
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
