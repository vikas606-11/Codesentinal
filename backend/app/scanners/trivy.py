import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from app.config import get_settings
from app.models.schemas import Finding
from app.scanners.process import run_command
from app.scanners.base import ScanOutput, Scanner, ScannerError, normalize_severity


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _find_line(root: Path, target: str, package: str) -> tuple[int, str | None]:
    """Line of the package in its requirements file (Trivy does not report one)."""
    try:
        lines = (root / target).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 1, None
    for number, line in enumerate(lines, start=1):
        name = re.split(r"[=<>!~\[;\s]", line.strip(), maxsplit=1)[0]
        if name and _norm(name) == _norm(package):
            return number, line.strip()[:200]
    return 1, None


def parse_trivy_report(data: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            vuln_id = vuln.get("VulnerabilityID", "unknown")
            fixed = vuln.get("FixedVersion")
            line, snippet = _find_line(root, target, pkg)
            summary = vuln.get("Title") or vuln_id
            message = f"{pkg} {installed} is affected by {vuln_id}."
            message += f" Fixed in {fixed}." if fixed else " No fixed version is available yet."
            findings.append(
                Finding(
                    id=uuid.uuid4().hex,
                    tool="trivy",
                    severity=normalize_severity(vuln.get("Severity")),
                    category="Security",
                    rule_id=vuln_id,
                    title=f"{pkg} {installed}: {summary}"[:150],
                    file=target,
                    line=line,
                    end_line=line,
                    message=message,
                    code_snippet=snippet,
                    cwe=list(vuln.get("CweIDs") or []),
                )
            )
    return findings


class TrivyScanner(Scanner):
    name = "trivy"

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_available(self) -> bool:
        return shutil.which(self.settings.trivy_bin) is not None

    def _db_cached(self) -> bool:
        cache = Path(os.environ.get("TRIVY_CACHE_DIR") or Path.home() / ".cache" / "trivy")
        return (cache / "db" / "trivy.db").exists()

    def scan(self, target: Path) -> ScanOutput:
        timeout = self.settings.trivy_timeout_seconds
        if not self._db_cached() and not self.settings.trivy_auto_download_db:
            raise ScannerError(
                "Trivy vulnerability database not found. Download it once with: "
                "docker compose run --rm backend trivy fs --download-db-only /tmp"
            )
        cmd = [
            self.settings.trivy_bin, "fs",
            "--scanners", "vuln", "--format", "json",
            "--quiet", "--no-progress", "--offline-scan", "--skip-java-db-update",
            "--timeout", f"{timeout}s",
        ]
        # Reuse the cached database when we have one; only download on the first run
        if self._db_cached() and not self.settings.trivy_refresh_db:
            cmd.append("--skip-db-update")
        cmd.append(".")

        try:
            proc = run_command(
                cmd, cwd=target, timeout=timeout + 30,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"Trivy timed out after {timeout}s")
        except OSError as exc:
            raise ScannerError(f"Could not start Trivy: {exc}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = " ".join((proc.stderr or proc.stdout or "no output").split())[:350]
            hint = ""
            if "db" in detail.lower():
                hint = " The vulnerability database could not be downloaded; see README_CHUNK_3 (pre-download step)."
            raise ScannerError(f"Trivy failed (exit {proc.returncode}): {detail}{hint}")

        return ScanOutput(findings=parse_trivy_report(data, target))
