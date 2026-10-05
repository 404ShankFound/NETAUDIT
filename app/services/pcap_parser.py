"""PyShark FileCapture parser used for genuine TShark-backed PCAP processing."""
from pathlib import Path
import pyshark
from app.services.telemetry import packet_to_telemetry


class PcapParseError(Exception):
    """A safe message for corrupt captures or unavailable TShark."""


def parse_pcap(file_path: Path):
    """Yield extracted telemetry one packet at a time to avoid loading a whole PCAP."""
    capture = None
    try:
        capture = pyshark.FileCapture(str(file_path), keep_packets=False)
        for packet in capture:
            yield packet_to_telemetry(packet)
    except FileNotFoundError as error:
        raise PcapParseError("TShark is not installed or not available on PATH.") from error
    except Exception as error:
        message = str(error).lower()
        if "tshark" in message or "wireshark" in message:
            raise PcapParseError("TShark is unavailable. Install Wireshark/TShark and try again.") from error
        raise PcapParseError("Unable to parse this PCAP. It may be empty, corrupt, or unsupported.") from error
    finally:
        if capture is not None:
            capture.close()
