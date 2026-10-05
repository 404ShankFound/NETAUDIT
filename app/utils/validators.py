"""Upload validation protects the application from unsuitable input files."""
from pathlib import Path
from fastapi import HTTPException, UploadFile
from app.config import MAX_UPLOAD_BYTES


def validate_pcap_upload(upload: UploadFile) -> None:
    """Reject absent or non-PCAP file names before storing user input."""
    if not upload.filename:
        raise HTTPException(status_code=400, detail="Choose a PCAP file before uploading.")
    if Path(upload.filename).suffix.lower() != ".pcap":
        raise HTTPException(status_code=400, detail="Only .pcap files are accepted.")


def validate_upload_size(size: int) -> None:
    """Enforce a predictable limit while streaming an uploaded PCAP to disk."""
    if size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"PCAP exceeds the {MAX_UPLOAD_BYTES // 1024 // 1024} MB upload limit.")
