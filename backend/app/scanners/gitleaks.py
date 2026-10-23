import json
import shutil
import subprocess
import uuid
from pathlib import Path

from app.config import get_settings
from app.models.schemas import Finding
from app.scanners.process import run_command
from app.scanners.base import ScanOutput, Scanner, ScannerError


def _relative(path: str, root: Path) -> str:
    p = path.replace("\\", "/")
    if p.startswith("./"):
        p = p[2:]
    if Path(p).is_absolute():
        try:
            return Path(p).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return p
    return p


def normalize_leak(leak: dict, root: Path) -> Finding:
    rule_id = leak.get("RuleID", "secret")
    start = int(leak.get("StartLine") or 1)
    # Match is already redacted by --redact, so the real secret never leaves the scanner
    match = (leak.get("Match") or "").strip()[:200] or None
    return Finding(
        id=uuid.uuid4().hex,
        tool="gitleaks",
        severity="HIGH",
        category="Secret",
        rule_id=rule_id,
        title=leak.get("Description") or "Hardcoded secret",
        file=_relative(leak.get("File", ""), root),
        line=start,
        end_line=int(leak.get("EndLine") or start),
        message=f"Possible secret detected by rule '{rule_id}'. Remove it from the code and rotate the credential.",
        code_snippet=match,
        cwe=["CWE-798"],
    )


class GitleaksScanner(Scanner):
    name = "gitleaks"

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_available(self) -> bool:
        return shutil.which(self.settings.gitleaks_bin) is not None

    def scan(self, target: Path) -> ScanOutput:
        report = target.parent / "gitleaks-report.json"  # outside the scanned folder
        cmd = [
            self.settings.gitleaks_bin, "dir", ".",
            "--report-format", "json", "--report-path", str(report),
            "--redact", "--no-banner", "--exit-code", "0", "--log-level", "error",
        ]
        try:
            proc = run_command(
                cmd, cwd=target,
                timeout=self.settings.scan_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"Gitleaks timed out after {self.settings.scan_timeout_seconds}s")
        except OSError as exc:
            raise ScannerError(f"Could not start Gitleaks: {exc}")

        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "no output").strip()[-500:]
            raise ScannerError(f"Gitleaks failed (exit {proc.returncode}): {detail}")

        try:
            leaks = json.loads(report.read_text() or "[]") if report.exists() else []
        except (OSError, json.JSONDecodeError):
            raise ScannerError("Gitleaks produced an unreadable report")
        return ScanOutput(findings=[normalize_leak(leak, target) for leak in leaks or []])
