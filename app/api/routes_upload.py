"""PCAP upload endpoint that executes the simple, reliable demo pipeline."""
import json
import logging
from pathlib import Path
from uuid import uuid4
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from app.config import UPLOAD_DIR
from app.database.database import get_db
from app.database.models import Alert, Analysis, Packet
from app.services.analyzer import analyze_packets
from app.services.pcap_parser import PcapParseError, parse_pcap
from app.utils.validators import validate_pcap_upload, validate_upload_size

router = APIRouter(tags=["upload"])
logger = logging.getLogger(__name__)


@router.post("/upload")
def upload_pcap(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Store a validated PCAP, parse it with PyShark, persist it, and run rules."""
    validate_pcap_upload(file)
    stored_name = f"{uuid4().hex}.pcap"
    stored_path = UPLOAD_DIR / stored_name
    size = 0
    try:
        with stored_path.open("wb") as destination:
            while content := file.file.read(1024 * 1024):
                size += len(content)
                validate_upload_size(size)
                destination.write(content)
        if size == 0:
            raise HTTPException(status_code=400, detail="The uploaded PCAP is empty.")
        analysis = Analysis(filename=Path(file.filename).name, status="processing")
        db.add(analysis)
        db.flush()
        packet_count = 0
        for telemetry in parse_pcap(stored_path):
            db.add(Packet(analysis_id=analysis.id, **telemetry))
            packet_count += 1
            if packet_count % 500 == 0:
                db.flush()
        if packet_count == 0:
            raise HTTPException(status_code=400, detail="No readable packets were found in this PCAP.")
        db.flush()
        packets = db.query(Packet).filter(Packet.analysis_id == analysis.id).order_by(Packet.packet_number).all()
        statistics, found_alerts, score, severity, reasons = analyze_packets(packets)
        for alert in found_alerts:
            db.add(Alert(analysis_id=analysis.id, **alert))
        analysis.packet_count = packet_count
        analysis.duration = statistics["duration"]
        analysis.threat_score = score
        analysis.severity = severity
        analysis.statistics_json = json.dumps(statistics)
        analysis.threat_reasons_json = json.dumps(reasons)
        analysis.status = "complete"
        db.commit()
        return {"analysis_id": analysis.id, "status": analysis.status, "packet_count": packet_count, "threat_score": score, "severity": severity}
    except HTTPException:
        db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise
    except PcapParseError as error:
        db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(error)) from error
    except Exception:
        logger.exception("PCAP analysis failed for uploaded file")
        db.rollback()
        if stored_path.exists():
            stored_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail="Analysis could not be completed. Check server logs for details.")
    finally:
        file.file.close()
