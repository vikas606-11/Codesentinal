# Patch 5A - scans can no longer hang

Problem: a scan could run for 1000+ seconds with no feedback.

Fixes
- Trivy no longer downloads its 119 MB database during a scan. If the database is missing, the scan
  finishes in seconds and shows a warning with the exact command to fix it:
  `docker compose run --rm backend trivy fs --download-db-only /tmp`
  (set `TRIVY_AUTO_DOWNLOAD_DB=true` to bring the old behavior back)
- A scanner that times out is now killed together with all its child processes, so it cannot keep the
  request waiting. Default timeouts are 120s per scanner (SCAN_TIMEOUT_SECONDS, TRIVY_TIMEOUT_SECONDS).
- The New scan page has a **Cancel** button and shows a hint after 45 seconds.

Files added: backend/app/scanners/process.py
Files replaced: backend/app/config.py, backend/app/scanners/semgrep.py, gitleaks.py, trivy.py,
frontend/src/api.js, frontend/src/pages/NewScan.jsx
No rebuild needed (these folders are mounted). Run `docker compose restart backend` after extracting.
