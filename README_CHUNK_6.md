# CodeSentinel - Chunk 6: AI Explanation and Remediation

## What this chunk adds
Open any finding and click **Explain this finding**. You get:
problem, why it is dangerous, where it is, potential impact, how to fix (steps), and a secure code example.

The **scanner finds** the problem. The **AI only explains** it. It never decides what is vulnerable.

- **Works with no API key.** The default `mock` provider writes the explanation from built-in templates
  (all 11 Semgrep rules, secrets, and dependency CVEs). The panel says "Built-in explanation (no AI model was used)".
- **Real AI is optional**, chosen with environment variables: `anthropic` (Claude API) or `openai`
  (OpenAI or any OpenAI-compatible service, such as Gemini, Groq, or a local Ollama).
- **It never breaks the demo.** If the key is missing, the provider is down, or the answer is not valid JSON,
  the built-in explanation is shown with a short note explaining why.
- Explanations are saved in the database, so reopening a finding does not call the AI again.
  **Regenerate** asks again.
- Nothing is explained automatically, so you control every AI call.

Also fixed in this ZIP:
- **The scan page no longer counts seconds forever after a scan finishes.** Cause: React StrictMode (used in
  development) made the page forget it was still open, so it never moved to the results. A regression test now covers it.
- The Cancel button is now **Stop waiting**, because it only stops the browser from waiting. The server finishes the scan,
  and you can find it on the dashboard.

## Privacy
With `mock`, nothing leaves your computer. With a real provider, the finding details and a short code snippet
(at most 800 characters) are sent to that provider. Secret values are already masked as `REDACTED` before they are stored,
so they are never sent.

## Install
1. Extract the ZIP into `C:\CodeSentinel` and choose **Replace** for existing files.
2. `docker compose restart backend` (no rebuild and no new packages). Reload http://localhost:5173 with `Ctrl+F5`.

## Verify (built-in explanations, no key needed)
1. Scan `samples\vulnerable_app.py` (it now opens the results page by itself after a few seconds).
2. Click a finding, then **Explain this finding**. The sections appear. The label says "Built-in explanation".
3. Close and reopen the same finding: the explanation is shown immediately (saved).
4. Try a Secret finding (`samples\leaky_config.py`) and a Trivy finding (`samples\vulnerable_project.zip`, a `requests` CVE).
   The CVE explanation tells you which version to upgrade to.
5. API: http://localhost:8000/docs -> `POST /api/v1/findings/{finding_id}/explain`.

## Use a real AI model (optional)
1. Open `C:\CodeSentinel\.env` and set, for example:
   ```
   AI_PROVIDER=anthropic
   AI_API_KEY=your-key-here
   ```
   (Do not share or commit this file. It is already git-ignored.)
2. Stop the app with `Ctrl+C` and start it again with `docker compose up`.
   (`docker compose restart` does not re-read `.env`.)
3. Click **Regenerate** on a finding. The label changes to "AI explanation by anthropic (model name)".

## API
| Endpoint | Returns |
|---|---|
| `POST /api/v1/findings/{finding_id}/explain` | Creates (or returns the saved) explanation. `?refresh=true` regenerates it |
| `GET /api/v1/findings/{finding_id}/explanation` | The saved explanation, or 404 if none yet |

Fields: `problem, why_dangerous, location, impact, how_to_fix[], secure_example, provider, model, created_at, note`.

## Files added
`backend/app/ai/` (`prompt.py`, `mock.py`, `llm.py`, `service.py`), `backend/app/api/explain.py`,
`frontend/src/components/AiExplanation.jsx`, `README_CHUNK_6.md`

## Files modified
None (changed files are listed as replaced).

## Files replaced (overwrite your copy)
`README.md`, `.env.example`, `backend/app/config.py`, `backend/app/db.py`, `backend/app/main.py`,
`backend/app/models/schemas.py`, `frontend/src/api.js`, `frontend/src/pages/NewScan.jsx`,
`frontend/src/components/FindingDrawer.jsx`

## Dependencies added
None (the AI calls use Python's standard library).

## Environment variables
| Variable | Default | Purpose |
|---|---|---|
| AI_PROVIDER | mock | `mock`, `anthropic`, or `openai` |
| AI_API_KEY | (empty) | The provider's key. Never hardcoded, never returned by the API |
| AI_MODEL | (empty) | Empty = default model (`claude-haiku-4-5-20251001` or `gpt-4o-mini`). Model names change, so check the provider's docs |
| AI_BASE_URL | (empty) | Empty = official address. Set it for OpenAI-compatible services |
| AI_TIMEOUT_SECONDS | 30 | How long to wait for the provider before using the built-in text |

## Troubleshooting
- **The note says "AI_API_KEY is empty"**: the key is not set, or you used `docker compose restart`. Stop the app and run `docker compose up` again.
- **The note says "HTTP 401"**: wrong key. **"HTTP 404"**: wrong `AI_MODEL` or `AI_BASE_URL`. **"HTTP 429"**: rate limit reached, wait and retry.
- **The note says "could not reach the AI provider"**: no internet from Docker, or the timeout is too short. Raise `AI_TIMEOUT_SECONDS`.
- **"the AI answer was not in the expected format"**: the model did not return JSON. Try another model.
- **Still the old scan page, or the timer never stops**: press `Ctrl+F5`, then `docker compose restart frontend`.
- **Ollama (local model)**: use `AI_PROVIDER=openai`, `AI_BASE_URL=http://host.docker.internal:11434/v1`, any text as `AI_API_KEY`, and the name of a model you have pulled.
