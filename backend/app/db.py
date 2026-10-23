import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

from app.config import get_settings
from app.models.schemas import AIAnalysis, Finding, ScanListItem, ScanResult, ScanSummary

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    duration_seconds REAL NOT NULL,
    files_scanned INTEGER NOT NULL,
    score INTEGER NOT NULL,
    rating TEXT NOT NULL,
    gate TEXT NOT NULL,
    threshold INTEGER NOT NULL,
    total INTEGER NOT NULL,
    by_severity TEXT NOT NULL,
    by_category TEXT NOT NULL,
    scanners_run TEXT NOT NULL,
    scanner_errors TEXT NOT NULL,
    warnings TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    position INTEGER NOT NULL,
    tool TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    message TEXT NOT NULL,
    code_snippet TEXT,
    cwe TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, position);
CREATE TABLE IF NOT EXISTS ai_analyses (
    finding_id TEXT PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    problem TEXT NOT NULL,
    why_dangerous TEXT NOT NULL,
    location TEXT NOT NULL,
    impact TEXT NOT NULL,
    how_to_fix TEXT NOT NULL,
    secure_example TEXT,
    note TEXT,
    created_at TEXT NOT NULL
);
"""


@contextmanager
def connect():
    path = Path(get_settings().database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)


def _finding_from_row(row: sqlite3.Row) -> Finding:
    data = {k: row[k] for k in Finding.model_fields}
    data["cwe"] = json.loads(row["cwe"])
    return Finding(**data)


def _summary_from_row(row: sqlite3.Row) -> ScanSummary:
    return ScanSummary(
        total=row["total"],
        by_severity=json.loads(row["by_severity"]),
        by_category=json.loads(row["by_category"]),
    )


def save_scan(result: ScanResult) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                result.scan_id, result.filename, result.status, result.created_at.isoformat(),
                result.duration_seconds, result.files_scanned, result.score, result.rating,
                result.gate, result.threshold, result.summary.total,
                json.dumps(result.summary.by_severity), json.dumps(result.summary.by_category),
                json.dumps(result.scanners_run),
                json.dumps([i.model_dump() for i in result.scanner_errors]),
                json.dumps(result.warnings),
            ),
        )
        conn.executemany(
            "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (
                    f.id, result.scan_id, position, f.tool, f.severity, f.category, f.rule_id,
                    f.title, f.file, f.line, f.end_line, f.message, f.code_snippet, json.dumps(f.cwe),
                )
                for position, f in enumerate(result.findings)
            ],
        )


def list_scans(limit: int = 50, offset: int = 0) -> list[ScanListItem]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?", (limit, offset)
        ).fetchall()
    return [
        ScanListItem(
            scan_id=r["id"], filename=r["filename"], status=r["status"],
            created_at=datetime.fromisoformat(r["created_at"]), score=r["score"],
            rating=r["rating"], gate=r["gate"], threshold=r["threshold"],
            summary=_summary_from_row(r),
        )
        for r in rows
    ]


def scan_exists(scan_id: str) -> bool:
    with connect() as conn:
        return conn.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,)).fetchone() is not None


def get_scan(scan_id: str) -> ScanResult | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        finding_rows = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY position", (scan_id,)
        ).fetchall()
    return ScanResult(
        scan_id=row["id"], filename=row["filename"], status=row["status"],
        created_at=datetime.fromisoformat(row["created_at"]),
        duration_seconds=row["duration_seconds"], files_scanned=row["files_scanned"],
        score=row["score"], rating=row["rating"], gate=row["gate"], threshold=row["threshold"],
        summary=_summary_from_row(row),
        findings=[_finding_from_row(r) for r in finding_rows],
        scanners_run=json.loads(row["scanners_run"]),
        scanner_errors=json.loads(row["scanner_errors"]),
        warnings=json.loads(row["warnings"]),
    )


def get_findings(
    scan_id: str, severity: str | None = None, category: str | None = None, tool: str | None = None
) -> list[Finding]:
    query = "SELECT * FROM findings WHERE scan_id = ?"
    params: list = [scan_id]
    for column, value in (("severity", severity), ("category", category), ("tool", tool)):
        if value:
            query += f" AND {column} = ?"  # column names are fixed above, values are bound
            params.append(value)
    with connect() as conn:
        rows = conn.execute(query + " ORDER BY position", params).fetchall()
    return [_finding_from_row(r) for r in rows]


def get_finding(finding_id: str) -> dict | None:
    with connect() as conn:
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    if row is None:
        return None
    return {**_finding_from_row(row).model_dump(), "scan_id": row["scan_id"]}


def save_analysis(a: AIAnalysis) -> None:
    with connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ai_analyses VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                a.finding_id, a.provider, a.model, a.problem, a.why_dangerous, a.location,
                a.impact, json.dumps(a.how_to_fix), a.secure_example, a.note, a.created_at.isoformat(),
            ),
        )


def get_analysis(finding_id: str) -> AIAnalysis | None:
    with connect() as conn:
        r = conn.execute("SELECT * FROM ai_analyses WHERE finding_id = ?", (finding_id,)).fetchone()
    if r is None:
        return None
    return AIAnalysis(
        finding_id=r["finding_id"], provider=r["provider"], model=r["model"], problem=r["problem"],
        why_dangerous=r["why_dangerous"], location=r["location"], impact=r["impact"],
        how_to_fix=json.loads(r["how_to_fix"]), secure_example=r["secure_example"], note=r["note"],
        created_at=datetime.fromisoformat(r["created_at"]),
    )
