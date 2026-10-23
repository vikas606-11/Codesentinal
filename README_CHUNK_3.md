# CodeSentinel - Chunk 3: Gitleaks, Trivy and unified findings

## What this chunk adds
Three scanners now run on every upload and return one common finding format:

| Scanner | Finds | Category |
|---|---|---|
| Semgrep (Chunk 2) | code vulnerabilities, bugs, quality issues | Security / Quality |
| Gitleaks | hardcoded secrets (API keys, tokens) | Secret |
| Trivy | known vulnerabilities (CVEs) in dependencies, from `requirements.txt` | Security |

- Every finding uses the same fields: `tool, severity, category, rule_id, title, file, line, end_line, message, code_snippet, cwe`.
- Severity words from each tool are mapped to CRITICAL / HIGH / MEDIUM / LOW.
- **Scanner failures never kill a scan.** If one scanner is missing or fails, the others still return results and the response lists the problem in `scanner_errors`. Only if *no* scanner can run does the API return 503.
- The response now has `scanners_run` (which tools succeeded).
- **Secrets are never returned in clear text.** Gitleaks runs in redact mode, and Semgrep's hardcoded-credential snippets are masked (`"REDACTED"`). This also keeps secrets away from the AI provider in Chunk 6.
- **No double counting:** when Gitleaks and Semgrep flag the same line, only the Gitleaks finding is kept.
- Gitleaks and Trivy are shipped inside the ZIP (`backend/tools/`), so the Docker build needs no GitHub download.

## Install and run
1. Extract the ZIP into `C:\CodeSentinel` and choose **Replace** for existing files.
2. Check the two tool files arrived intact (sizes must match):
   ```cmd
   dir backend\tools
   ```
   gitleaks.tar.gz = 8,230,402 bytes, trivy.tar.gz = 51,704,231 bytes.
3. Rebuild (fast, no downloads):
   ```cmd
   cd C:\CodeSentinel
   docker compose down
   docker compose up --build
   ```
   The build prints the Gitleaks and Trivy versions (8.30.1 and 0.75.0).

## Trivy vulnerability database (one-time step)
Trivy needs its vulnerability database, a download of roughly 60 MB that cannot be shipped in the ZIP.
Download it once, with visible progress, before you demo:
```cmd
docker compose run --rm backend trivy fs --download-db-only /tmp
```
It is stored in a Docker volume and reused by every later scan (it survives `docker compose down`, but not `docker compose down -v`).
If it fails or stalls, rerun the command, or try another network.
Without the database the rest of the scan still works and Trivy appears in `scanner_errors`.

## Verify (http://localhost:8000/docs -> POST /api/v1/scan)
1. `samples/leaky_config.py`
   - `scanners_run` contains semgrep and gitleaks (and trivy once the database is downloaded)
   - 3 findings: 2 x **Secret** (gitleaks, `generic-api-key`, lines 3 and 4) and 1 x Security (semgrep `hardcoded-credential`, line 5)
   - code snippets show `"REDACTED"` instead of the values
2. `samples/vulnerable_app.py` still returns 15 findings (semgrep only).
3. `samples/vulnerable_project.zip` (this sample was updated and now contains a `requirements.txt`)
   - 6 findings from Semgrep and Gitleaks (2 critical, 3 high including 1 Secret, 1 medium)
   - plus several **trivy** findings (CVE ids) for `requests==2.19.1` and `PyYAML==5.3.1` once the database is downloaded
   - exact CVE counts change over time, because the database is updated daily

## Files added
`backend/app/scanners/gitleaks.py`, `backend/app/scanners/trivy.py`, `backend/tools/gitleaks.tar.gz`, `backend/tools/trivy.tar.gz`, `samples/leaky_config.py`, `README_CHUNK_3.md`

## Files modified
None (changed files are listed as replaced).

## Files replaced (overwrite your copy)
`README.md`, `.env.example`, `docker-compose.yml`, `backend/Dockerfile`, `backend/app/config.py`, `backend/app/models/schemas.py`, `backend/app/scanners/base.py`, `backend/app/scanners/semgrep.py`, `backend/app/services/scan_service.py`, `samples/vulnerable_project.zip`

## Dependencies added
Gitleaks 8.30.1 and Trivy 0.75.0 (binaries inside the Docker image). No new Python packages.

## Environment variables (all optional)
| Variable | Default | Purpose |
|---|---|---|
| GITLEAKS_BIN | gitleaks | Path to the gitleaks binary |
| TRIVY_BIN | trivy | Path to the trivy binary |
| TRIVY_TIMEOUT_SECONDS | 600 | Trivy timeout (the first run may download the database) |
| TRIVY_REFRESH_DB | false | true = re-download the database on every scan |

Trivy's own variables also work, for example `TRIVY_DB_REPOSITORY=ghcr.io/aquasecurity/trivy-db:2` to choose the download source.

## Troubleshooting
- **`trivy` shows in `scanner_errors` with a database message**: run the one-time database step above.
- **Build fails with a tar error**: the tool files did not extract correctly. Re-extract the ZIP and compare sizes with `dir backend\tools`. Checksums (SHA-256, first 16 characters): gitleaks 551f6fc83ea457d6, trivy c6e65abddb348e25. Check with `certutil -hashfile backend\tools\trivy.tar.gz SHA256`.
- **No Trivy findings for a project**: Trivy only reads dependency files such as `requirements.txt`. A lone `.py` file has no dependencies to check.
- **Trivy findings show line 1**: the package name was not found in the file, so the first line is used.
- **A scanner says "not installed"**: the backend is running an old image. Run `docker compose up --build`.
