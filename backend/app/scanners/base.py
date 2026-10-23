from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from app.models.schemas import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# Maps different tools' severity words onto our four levels
_SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "ERROR": "HIGH",
    "MEDIUM": "MEDIUM",
    "MODERATE": "MEDIUM",
    "WARNING": "MEDIUM",
    "LOW": "LOW",
    "INFO": "LOW",
    "UNKNOWN": "LOW",
}


def normalize_severity(value: str | None) -> str:
    return _SEVERITY_MAP.get((value or "").upper(), "MEDIUM")


class ScannerError(Exception):
    """Raised when a scanner is installed but fails to run."""


@dataclass
class ScanOutput:
    findings: list[Finding]
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)


class Scanner(ABC):
    name: str

    @abstractmethod
    def is_available(self) -> bool:
        """True if the scanner binary can be found."""

    @abstractmethod
    def scan(self, target: Path) -> ScanOutput:
        """Scan a directory. Raise ScannerError on failure."""
