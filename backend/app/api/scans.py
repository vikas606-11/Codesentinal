from fastapi import APIRouter, HTTPException, Query

from app import db
from app.models.schemas import Category, Finding, FindingDetail, ScanListItem, ScanResult, Severity

router = APIRouter(tags=["scans"])


@router.get("/scans", response_model=list[ScanListItem])
def list_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> list[ScanListItem]:
    """Scan history, newest first."""
    return db.list_scans(limit, offset)


@router.get("/scans/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    """One scan with its score, gate result, and all findings."""
    result = db.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@router.get("/scans/{scan_id}/findings", response_model=list[Finding])
def get_scan_findings(
    scan_id: str,
    severity: Severity | None = None,
    category: Category | None = None,
    tool: str | None = None,
) -> list[Finding]:
    """Findings of a scan, optionally filtered by severity, category, or tool."""
    if not db.scan_exists(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return db.get_findings(scan_id, severity, category, tool)


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: str) -> dict:
    finding = db.get_finding(finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding
