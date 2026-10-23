# CodeSentinel - Chunk 5: Frontend Dashboard

## What this chunk adds
A usable web interface at http://localhost:5173 (no backend changes, no new packages):

- **Dashboard**: total scans, pass rate, average score, latest score, a score trend chart, and the scan history table
- **New scan**: drag-and-drop or choose a `.py` / `.zip` file, with checks for type, empty files, and the 20 MB limit
- **Scan status**: while the scan runs it shows what is running and the elapsed seconds
- **Results**: score gauge, rating, PASS/FAIL gate, severity and category breakdown, the scanners that ran
- **Findings list**: filter by severity, category, and tool, search by title, file, or rule, and "Show more" for long lists
- **Finding details**: a side panel with the message, location, code snippet, and CWE / CVE reference links (Esc closes it)
- **Warnings**: a banner when a scanner did not run (for example Trivy without its database)
- **Basic report**: a "Download JSON" button on the results page
- **API status** light in the header

Not in this chunk: AI explanations (Chunk 6) and the full HTML report with the CI/CD gate (Chunk 7).

## Folder structure (new items marked +)
```
frontend/src/
├── App.jsx            (replaced)
├── api.js             (replaced)
├── lib/lib.js, router.js                  +
├── components/                            +
│   Badges, ScoreGauge, StatCard, SeverityBreakdown,
│   FindingsTable, FindingDrawer, ScanHistoryTable
└── pages/Dashboard.jsx, NewScan.jsx, ScanResults.jsx   +
```

## Install and run
1. Start **Docker Desktop** and wait until the engine is running.
2. Extract the ZIP into `C:\CodeSentinel` and choose **Replace** for existing files.
3. Start the app (no rebuild needed, the `src` folder is mounted into the container):
   ```cmd
   cd C:\CodeSentinel
   docker compose up
   ```
   Your scan history and the Trivy database are kept. Do **not** use `docker compose down -v`.
4. Open **http://localhost:5173**.

## Verify
1. The header shows a green **API online** light and the dashboard lists your earlier scans.
2. Click a scan to open its results: the score gauge, gate, and findings table appear.
3. **New scan** -> choose `samples\vulnerable_project.zip` -> **Start scan**. After a few seconds you land on the results page with 13 findings, including Trivy CVEs for `requests` and `PyYAML`.
4. Use the severity filter and the search box, then click a finding to open the details panel.
5. Try `samples\clean_app.py` (score 100, PASS) and a `.txt` file (clear error message).
6. **Download JSON** saves the scan as a file.

## Files added
Everything marked + above, plus `README_CHUNK_5.md`.

## Files modified
None (changed files are listed as replaced).

## Files replaced (overwrite your copy)
`README.md`, `frontend/src/App.jsx`, `frontend/src/api.js`

## Dependencies added
None. A small built-in hash router is used instead of a routing library.

## Environment variables
`VITE_API_URL` (already set to `http://localhost:8000` by docker-compose). Nothing new.

## Troubleshooting
- **Still the old page (only "Backend connection")**: press `Ctrl+F5`. If it persists, run `docker compose restart frontend`, or `docker compose up --build`.
- **Red "API offline" light**: the backend is not running or not on port 8000. Open http://localhost:8000/health.
- **A scan shows an amber "Some scanners did not run" banner**: that scanner is missing or failed. For Trivy, see the database step in `README_CHUNK_3.md`.
- **Upload error text appears in red**: it comes from the backend (for example an unsafe zip). The form stays so you can try another file.
- **Port 5173 or 8000 already in use**: stop any local `npm run dev` or `uvicorn` process (see Chunk 1).
