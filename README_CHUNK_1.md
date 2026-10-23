# CodeSentinel - Chunk 1: Project Foundation

## What this chunk adds
- FastAPI backend with a health endpoint and Swagger docs
- React + Vite + Tailwind frontend that shows live backend connection status
- Environment configuration (`.env.example`)
- Docker Compose setup for both services

Tested before packaging: backend endpoints, CORS, Swagger, and the frontend production build.
`docker compose` was NOT tested on my side, so run the Docker steps and report any error.

## Folder structure
```
.
├── .env.example
├── .gitignore
├── docker-compose.yml
├── README.md
├── README_CHUNK_1.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── config.py
│       └── api/health.py
├── frontend/
│   ├── Dockerfile, package.json, vite.config.js
│   ├── tailwind.config.js, postcss.config.js, index.html
│   └── src/ (main.jsx, App.jsx, api.js, index.css)
└── docs/
```

## Prerequisites
- Python 3.10+ and Node.js 18+ (for local run), or Docker Desktop (for Docker run)

## Run locally (2 terminals)

Terminal 1 - backend:
```bash
cd backend
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Mac/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Terminal 2 - frontend:
```bash
cd frontend
npm install
npm run dev
```

## Run with Docker
```bash
cp .env.example .env      # Windows: copy .env.example .env
docker compose up --build
```

## Expected result
- http://localhost:8000/health returns
  `{"status":"ok","service":"CodeSentinel","version":"0.1.0","environment":"development"}`
- http://localhost:8000/docs shows Swagger UI
- http://localhost:5173 shows the CodeSentinel page with a green **online** badge,
  service name, version, and environment

## Verification checklist
1. Backend `/health` returns status ok
2. `/docs` opens
3. Frontend loads and badge is **online**
4. Stop the backend: badge turns **offline**; start it and click **Retry**: back to **online**

## Files added
Everything listed in the folder structure above (this is the first chunk).

## Files modified
None.

## Files replaced
None.

## Dependencies added
- Backend: fastapi, uvicorn[standard], pydantic-settings
- Frontend: react, react-dom, vite, @vitejs/plugin-react, tailwindcss 3, postcss, autoprefixer

## Environment variables
| Variable | Used by | Default |
|---|---|---|
| APP_NAME | backend | CodeSentinel |
| ENVIRONMENT | backend | development |
| CORS_ORIGINS | backend | http://localhost:5173,http://127.0.0.1:5173 |
| VITE_API_URL | frontend | http://localhost:8000 |

No API keys are needed in this chunk.

## Troubleshooting
- **Badge says offline**: backend is not running, or it is not on port 8000. Open http://localhost:8000/health in the browser.
- **CORS error in browser console**: the frontend origin is not in `CORS_ORIGINS`. Add it to `.env` and restart the backend.
- **`python` not found (Windows)**: try `py -m venv .venv`.
- **Port 8000 or 5173 already in use**: stop the other process, or change the port (the frontend uses `strictPort`, so it fails instead of switching).
- **Docker: "env file .env not found"**: run `cp .env.example .env` first (needs a recent Docker Compose; the file is optional on current versions).
- **Docker: frontend does not hot-reload on Windows**: expected to work via polling; if not, restart the container.
- **`npm install` fails**: check `node --version` is 18 or higher.
