from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Category = Literal["Security", "Quality", "Secret"]
Rating = Literal["Excellent", "Good", "Needs Improvement", "Critical"]
Gate = Literal["PASS", "FAIL"]


class Finding(BaseModel):
    """One normalized finding. Every scanner is converted into this shape."""

    id: str
    tool: str
    severity: Severity
    category: Category
    rule_id: str
    title: str
    file: str
    line: int
    end_line: int
    message: str
    code_snippet: str | None = None
    cwe: list[str] = Field(default_factory=list)


class FindingDetail(Finding):
    scan_id: str


class ScannerIssue(BaseModel):
    tool: str
    message: str


class ScanSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_category: dict[str, int]


class ScanListItem(BaseModel):
    scan_id: str
    filename: str
    status: Literal["completed"]
    created_at: datetime
    score: int
    rating: Rating
    gate: Gate
    threshold: int
    summary: ScanSummary


class ScanResult(BaseModel):
    scan_id: str
    filename: str
    status: Literal["completed"]
    created_at: datetime
    duration_seconds: float
    files_scanned: int
    score: int
    rating: Rating
    gate: Gate
    threshold: int
    summary: ScanSummary
    findings: list[Finding]
    scanners_run: list[str]
    scanner_errors: list[ScannerIssue]
    warnings: list[str]


class ExplanationContent(BaseModel):
    problem: str
    why_dangerous: str
    location: str
    impact: str
    how_to_fix: list[str]
    secure_example: str | None = None


class AIAnalysis(ExplanationContent):
    finding_id: str
    provider: str  # provider that actually wrote the text: mock | anthropic | openai
    model: str
    created_at: datetime
    note: str | None = None  # for example why the built-in fallback was used
