"""PDF route creates a report from persisted data, not dashboard-only state."""
import json
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from app.database.database import get_db
from app.database.models import Alert, Analysis
from app.services.report_generator import generate_report

router = APIRouter(prefix="/analyses", tags=["reports"])
logger = logging.getLogger(__name__)


@router.get("/{analysis_id}/report")
def download_report(analysis_id: int, db: Session = Depends(get_db)):
    """Generate and download the analysis PDF on demand."""
    analysis = db.get(Analysis, analysis_id)
    if not analysis or analysis.status != "complete":
        raise HTTPException(status_code=404, detail="A completed analysis was not found.")
    try:
        alerts = db.query(Alert).filter(Alert.analysis_id == analysis.id).all()
        report = generate_report(analysis, alerts, json.loads(analysis.statistics_json))
        return FileResponse(report, media_type="application/pdf", filename=f"NetAudit_{analysis.id}_report.pdf")
    except Exception:
        logger.exception("PDF report generation failed for analysis %s", analysis_id)
        raise HTTPException(status_code=500, detail="PDF report generation failed.")
