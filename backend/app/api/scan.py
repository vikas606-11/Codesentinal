from fastapi import APIRouter, File, HTTPException, UploadFile

from app.models.schemas import ScanResult
from app.services.scan_service import ScanFailedError, run_scan
from app.services.workspace import UploadError

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("", response_model=ScanResult)
def create_scan(file: UploadFile = File(..., description="A .py file or a .zip of a project")) -> ScanResult:
    """Upload source code, run the scanners, and return normalized findings."""
    try:
        return run_scan(file)
    except UploadError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except ScanFailedError as exc:
        raise HTTPException(
            status_code=503,
            detail={"message": "No scanner could run.", "scanner_errors": [i.model_dump() for i in exc.issues]},
        )
