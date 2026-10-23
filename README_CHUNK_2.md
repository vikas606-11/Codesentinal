# CodeSentinel - Chunk 2: Upload and Scan Engine

## What this chunk adds
Upload a `.py` file or a `.zip` project, scan it with Semgrep, and get normalized findings back.

Flow: upload -> temporary workspace -> Semgrep -> normalize -> JSON response -> workspace deleted.

- `POST /api/v1/scan` (multipart field `file`)
- Scanner abstraction (`Scanner` base class) so Gitleaks and Trivy plug in next chunk
- 11 bundled offline Semgrep rules for Python (SQL injection, eval/exec, command injection,
  hardcoded credentials, pickle, unsafe YAML, weak hashes, disabled TLS verification,
  debug mode, bare except, mutable default arguments)
- Safe zip handling (blocks path traversal, symlinks, oversized or corrupt archives)
- Sample vulnerable files in `samples/`

Results are not saved yet (database comes in Chunk 4). The frontend is unchanged (Chunk 5).

## Folder structure (new items marked +)
```
backend/
├── Dockerfile                  (replaced)
├── requirements.txt            (replaced)
├── rules/python-security.yml   +
└── app/
    ├── main.py, config.py      (replaced)
    ├── api/scan.py             +
    ├── models/schemas.py       +
    ├── scanners/base.py        +
    ├── scanners/semgrep.py     +
    └── services/workspace.py, scan_service.py   +
samples/vulnerable_app.py, vulnerable_project.zip   +
```

## Install and run (Docker - required for Semgrep on Windows)
The backend image changes (Semgrep is installed), so it must be rebuilt.
The first build takes a few minutes.

```cmd
cd C:\CodeSentinel
docker compose down
docker compose up --build
```

Semgrep does not run natively on Windows. On Mac/Linux you can instead run
`pip install semgrep` and start the backend as in Chunk 1.

## Verify
Easiest: open **http://localhost:8000/docs** -> `POST /api/v1/scan` -> **Try it out** ->
choose `samples/vulnerable_app.py` -> **Execute**.

Or from the command line:
```cmd
curl.exe -s -F "file=@samples\vulnerable_app.py" http://localhost:8000/api/v1/scan -o result.json
```
then open `result.json`. Also try `samples\vulnerable_project.zip`.

## Expected result
`samples/vulnerable_app.py` returns HTTP 200 with:
- `status: completed`, `files_scanned: 1`
- `summary.total: 15` -> CRITICAL 4, HIGH 6, MEDIUM 3, LOW 2 (Security 13, Quality 2)
- findings sorted by severity, each with `tool, severity, category, rule_id, title, file, line,
  end_line, message, code_snippet, cwe`

`samples/vulnerable_project.zip` returns 5 findings across 3 files (including the `tests/` folder).

Error cases: `.txt` upload -> 400, empty file -> 400, corrupt zip -> 400,
unsafe zip paths -> 400, no file -> 422, Semgrep missing -> 503.

Also check http://localhost:8000/health (version now 0.2.0) and http://localhost:5173 (still green).

## Files added
See the + items above, plus `README_CHUNK_2.md`.

## Files modified
None (changed files are listed as replaced).

## Files replaced (overwrite your copy)
`README.md`, `.env.example`, `docker-compose.yml`, `backend/Dockerfile`, `backend/requirements.txt`,
`backend/app/main.py`, `backend/app/config.py`

## Dependencies added
- `python-multipart` (file uploads)
- Semgrep 1.180.0 in its own virtualenv inside the Docker image (avoids conflicts with FastAPI)

## Environment variables (all optional)
| Variable | Default | Purpose |
|---|---|---|
| SEMGREP_CONFIG | bundled `backend/rules` | Rule sources, comma-separated (e.g. `p/python` needs internet) |
| SEMGREP_BIN | set inside the image | Path to the semgrep binary |
| MAX_UPLOAD_MB | 20 | Upload size limit |
| MAX_UNZIPPED_MB | 100 | Extracted size limit |
| MAX_ZIP_FILES | 5000 | File count limit per archive |
| SCAN_TIMEOUT_SECONDS | 180 | Semgrep timeout |
| WORKSPACE_DIR | system temp | Where temporary workspaces are created |

No API keys are needed.

## Troubleshooting
- **503 "Scanner not installed"**: the old backend image is still running. Run `docker compose up --build`.
- **Build fails at `pip install semgrep`**: network problem. Check your internet and retry.
- **First scan takes a few seconds**: normal. Raise `SCAN_TIMEOUT_SECONDS` for big projects.
- **Backend container exits during a scan (exit 137)**: out of memory. Docker Desktop -> Settings -> Resources -> raise memory to 4 GB or more.
- **0 findings**: only Python rules exist, so other languages return nothing. A `.py` file with syntax errors also returns 0 findings.
- **Edited `backend/rules/*.yml`**: rules are mounted into the container, so the next scan uses them without a rebuild.
- **413**: file is over `MAX_UPLOAD_MB`.
- **Port 8000 or 5173 in use**: stop local `uvicorn` / `npm run dev` processes (see Chunk 1).
