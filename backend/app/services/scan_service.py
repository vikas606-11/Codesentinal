import sqlite3
import time
import uuid
from datetime import datetime, timezone

from fastapi import UploadFile

from app import db, scoring
from app.config import get_settings
from app.models.schemas import ScanResult, ScannerIssue, ScanSummary
from app.scanners.base import SEVERITY_ORDER, Scanner, ScannerError
from app.scanners.gitleaks import GitleaksScanner
from app.scanners.semgrep import SemgrepScanner
from app.scanners.trivy import TrivyScanner
from app.services import workspace


class ScanFailedError(Exception):
    def __init__(self, issues: list[ScannerIssue]) -> None:
        super().__init__("No scanner could run")
        self.issues = issues


def get_scanners() -> list[Scanner]:
    return [SemgrepScanner(), GitleaksScanner(), TrivyScanner()]


def _dedupe(findings: list) -> list:
    """Gitleaks is more precise for secrets: drop Semgrep's generic duplicate on the same line."""
    secret_spots = {(f.file, f.line) for f in findings if f.category == "Secret"}
    return [
        f for f in findings
        if not (f.rule_id == "hardcoded-credential" and (f.file, f.line) in secret_spots)
    ]


def run_scan(upload: UploadFile) -> ScanResult:
    started = time.monotonic()
    root = workspace.create_workspace()
    try:
        source = workspace.save_upload(upload, root)

        findings, issues, warnings = [], [], []
        files_scanned = 0
        scanners_run: list[str] = []

        for scanner in get_scanners():
            if not scanner.is_available():
                issues.append(ScannerIssue(tool=scanner.name, message=f"{scanner.name} is not installed or not found on PATH. Run the backend through Docker."))
                continue
            try:
                output = scanner.scan(source)
            except ScannerError as exc:
                issues.append(ScannerIssue(tool=scanner.name, message=str(exc)))
                continue
            scanners_run.append(scanner.name)
            findings += output.findings
            warnings += output.warnings
            files_scanned = max(files_scanned, output.files_scanned)

        if not scanners_run:
            raise ScanFailedError(issues)

        findings = _dedupe(findings)
        findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.file, f.line))
        summary = ScanSummary(
            total=len(findings),
            by_severity={s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER},
            by_category={c: sum(f.category == c for f in findings) for c in ("Security", "Quality", "Secret")},
        )
        score = scoring.calculate_score(findings)
        threshold = get_settings().quality_gate_threshold
        result = ScanResult(
            scan_id=uuid.uuid4().hex,
            filename=upload.filename or "upload",
            status="completed",
            created_at=datetime.now(timezone.utc),
            duration_seconds=round(time.monotonic() - started, 2),
            files_scanned=files_scanned,
            score=score,
            rating=scoring.rating_for(score),
            gate=scoring.gate_for(score, threshold),
            threshold=threshold,
            summary=summary,
            findings=findings,
            scanners_run=scanners_run,
            scanner_errors=issues,
            warnings=warnings,
        )
        try:
            db.save_scan(result)
        except sqlite3.Error as exc:
            result.warnings.append(f"Result could not be saved to the database: {exc}")
        return result
    finally:
        workspace.cleanup_workspace(root)
