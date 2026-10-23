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

# Replaces Semgrep's default ignore list (which silently skips test/ and tests/ folders)
SEMGREPIGNORE = ".git/\nnode_modules/\n.venv/\nvenv/\n__pycache__/\n"


def _read_snippet(root: Path, rel_path: str, start: int, end: int) -> str | None:
    """Semgrep hides code lines unless logged in, so read them from the file."""
    try:
        root = root.resolve()
        path = (root / rel_path).resolve()
        if root not in path.parents:
            return None
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return "\n".join(lines[start - 1 : min(end, start + 7)])[:800]
    except OSError:
        return None


_STRING_LITERAL = re.compile(r"""(["'])(?:(?!\1).)*\1""")


def _mask_secret(snippet: str | None) -> str | None:
    """Hide the value of hardcoded credentials, so it is never returned or forwarded."""
    return _STRING_LITERAL.sub('"REDACTED"', snippet) if snippet else snippet


def _humanize(rule_id: str) -> str:
    return rule_id.replace("-", " ").replace("_", " ").capitalize()


def normalize_result(result: dict, root: Path) -> Finding:
    extra = result.get("extra", {})
    meta = extra.get("metadata") or {}

    rule_id = result.get("check_id", "unknown").split(".")[-1]
    start = result.get("start", {}).get("line", 1)
    end = result.get("end", {}).get("line", start)

    # Our own rules carry cs_severity; registry rules fall back to Semgrep's severity
    severity = normalize_severity(meta.get("cs_severity") or extra.get("severity"))
    category = "Security" if str(meta.get("category", "security")).lower() == "security" else "Quality"

    cwe = meta.get("cwe") or []
    if isinstance(cwe, str):
        cwe = [cwe]

    rel_path = result.get("path", "")
    snippet = _read_snippet(root, rel_path, start, end)
    if rule_id == "hardcoded-credential":
        snippet = _mask_secret(snippet)
    return Finding(
        id=uuid.uuid4().hex,
        tool="semgrep",
        severity=severity,
        category=category,
        rule_id=rule_id,
        title=meta.get("title") or _humanize(rule_id),
        file=rel_path,
        line=start,
        end_line=end,
        message=extra.get("message", ""),
        code_snippet=snippet,
        cwe=[str(c).split(":")[0] for c in cwe],
    )


class SemgrepScanner(Scanner):
    name = "semgrep"

    def __init__(self) -> None:
        self.settings = get_settings()

    def is_available(self) -> bool:
        return shutil.which(self.settings.semgrep_bin) is not None

    def scan(self, target: Path) -> ScanOutput:
        ignore_file = target / ".semgrepignore"
        if not ignore_file.exists():
            ignore_file.write_text(SEMGREPIGNORE)

        cmd = [
            self.settings.semgrep_bin, "scan",
            "--json", "--quiet", "--metrics=off", "--disable-version-check",
        ]
        for config in self.settings.semgrep_config_list:
            cmd += ["--config", config]
        cmd.append(".")

        env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
        try:
            proc = run_command(
                cmd, cwd=target, env=env,
                timeout=self.settings.scan_timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"Semgrep timed out after {self.settings.scan_timeout_seconds}s")
        except OSError as exc:
            raise ScannerError(f"Could not start Semgrep: {exc}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = (proc.stderr or proc.stdout or "no output").strip()[-500:]
            raise ScannerError(f"Semgrep failed (exit {proc.returncode}): {detail}")

        findings = [normalize_result(r, target) for r in data.get("results", [])]
        warnings = [
            f"semgrep: {e.get('path', '')}: {str(e.get('message', e.get('type', '')))[:120]}"
            for e in data.get("errors", [])
        ][:10]
        files = len(data.get("paths", {}).get("scanned", []))
        return ScanOutput(findings=findings, files_scanned=files, warnings=warnings)
