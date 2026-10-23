# CodeSentinel - Chunk 4: Database, Scoring and Quality Gate

## What this chunk adds
- **SQLite scan history.** Every scan and all its findings are saved and survive restarts.
- **Security/quality score (0-100)**, a rating, and a **PASS/FAIL quality gate** on every scan.
- **History endpoints** (see below).
- Two new demo files so you can show both a FAIL and a PASS.

No new packages: it uses Python's built-in `sqlite3`.

## Scoring rules (all in `backend/app/scoring.py`)
Start at 100, then subtract per finding:

| Finding | Points |
|---|---|
| Critical | -25 |
| High | -15 |
| Medium | -7 |
| Low | -3 |
| Secret (category) | -20 (used instead of its severity penalty) |

The score is limited to 0-100.

| Score | Rating |
|---|---|
| 90-100 | Excellent |
| 75-89 | Good |
| 60-74 | Needs Improvement |
| 0-59 | Critical |

**Quality gate:** PASS when `score >= QUALITY_GATE_THRESHOLD` (default **70**), otherwise FAIL.
Each saved scan keeps the threshold that was used when it ran.

## API
| Endpoint | Returns |
|---|---|
| `POST /api/v1/scan` | Runs a scan, saves it, returns the result (now with `score`, `rating`, `gate`, `threshold`) |
| `GET /api/v1/scans` | History, newest first (`limit`, `offset`) |
| `GET /api/v1/scans/{scan_id}` | One scan with all findings |
| `GET /api/v1/scans/{scan_id}/findings` | Findings, filter with `?severity=`, `?category=`, `?tool=` |
| `GET /api/v1/findings/{finding_id}` | One finding (includes its `scan_id`) |

Unknown ids return 404. An invalid `severity` or `category` returns 422.

## Install and run
1. Extract the ZIP into `C:\CodeSentinel` and choose **Replace** for existing files.
2. Rebuild (fast, nothing new to download):
   ```cmd
   cd C:\CodeSentinel
   docker compose down
   docker compose up --build
   ```
   (`docker compose down` keeps your data volumes. Do **not** add `-v`, it deletes the Trivy database.)

## Verify (http://localhost:8000/docs)
Run `POST /api/v1/scan` with each sample, then check the results:

| File | Findings | Score | Rating | Gate |
|---|---|---|---|---|
| `samples/vulnerable_app.py` | 15 | 0 | Critical | FAIL |
| `samples/leaky_config.py` | 3 | 45 | Critical | FAIL |
| `samples/clean_app.py` | 0 | 100 | Excellent | PASS |
| `samples/mostly_ok_app.py` | 3 | 83 | Good | PASS |
| `samples/vulnerable_project.zip` | 13 (with the Trivy database) | 0 | Critical | FAIL |

Then:
1. `GET /api/v1/scans` lists all of them, newest first.
2. Copy one `scan_id` into `GET /api/v1/scans/{scan_id}` to see the full result.
3. `GET /api/v1/scans/{scan_id}/findings` with `severity` = `MEDIUM` on the `mostly_ok_app.py` scan returns 2 findings.
4. **Persistence:** stop with `Ctrl+C`, run `docker compose up`, and call `GET /api/v1/scans` again. The history is still there.

## Files added
`backend/app/db.py`, `backend/app/scoring.py`, `backend/app/api/scans.py`, `samples/clean_app.py`, `samples/mostly_ok_app.py`, `README_CHUNK_4.md`

## Files modified
None (changed files are listed as replaced).

## Files replaced (overwrite your copy)
`README.md`, `.env.example`, `docker-compose.yml`, `backend/app/config.py`, `backend/app/main.py`, `backend/app/models/schemas.py`, `backend/app/services/scan_service.py`

## Dependencies added
None.

## Environment variables (optional)
| Variable | Default | Purpose |
|---|---|---|
| QUALITY_GATE_THRESHOLD | 70 | Pass mark for the quality gate |
| DATABASE_PATH | `/app/data/codesentinel.db` in Docker | SQLite file location |

To change the threshold, put `QUALITY_GATE_THRESHOLD=80` in your `.env` file and restart with `docker compose up`.

## Troubleshooting
- **History is empty after restart**: you probably ran `docker compose down -v`, which deletes the `scan-data` volume.
- **Reset only the scan history**: `docker compose down`, then `docker volume rm codesentinel_scan-data`. This keeps the Trivy database.
- **`warnings` says the result could not be saved**: the scan result is still returned, but it is not in the history. Check that the Docker volume is writable.
- **Scores look too harsh**: edit the numbers in `backend/app/scoring.py`. The change applies on the next scan (the folder is mounted, so no rebuild is needed).
- **Dependency CVEs lower the score a lot**: each Trivy finding counts like any other finding. This is by design in the scoring rules above.
