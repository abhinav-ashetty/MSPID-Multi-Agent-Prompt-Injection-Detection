# AIShield

AIShield is a prototype prompt-security assessment dashboard. The React app submits a prompt to a FastAPI backend. The backend combines phrase-based rules, a TF-IDF/logistic-regression classifier, and a Gemini assessment, assigns an experimental ALLOW/SANITIZE/BLOCK label, and stores the result in SQLite. The dashboard shows stored assessments and summary charts.

**This is a research prototype, not a production security control.** Its detector performed poorly on a small independent challenge set; do not automate access decisions with its output. See [detector validation](backend/DETECTOR_VALIDATION.md).

## Run locally

Requirements: Python 3.13+, Node.js 18+, and a Gemini API key for prompt analysis.

Backend, from the repository root:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit backend/.env and set GEMINI_API_KEY.
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The backend creates the SQLite tables at startup. API docs are at `http://localhost:8000/docs`; health is `http://localhost:8000/api/v1/health`.

Frontend, in another terminal from the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` to the backend. For a separately hosted frontend, set `VITE_API_BASE_URL` and configure the backend's comma-separated `FRONTEND_ORIGINS` to include that origin.

## Validate the detector

From `backend/`:

```powershell
python evaluate_detector.py
$env:DEBUG = 'true'
python -m pytest tests/test_health.py tests/test_security_api.py tests/test_rule_detector.py tests/test_hybrid_engine.py tests/test_persistence.py tests/test_persistence_integration.py tests/test_ml_classifier.py -q
```

The evaluation script prints the synthetic CSV holdout metrics and a separate hand-written challenge-set report for the offline ML and rule detectors. These are diagnostic checks only. The Gemini-dependent tests require valid credentials and network access.

## Main routes and endpoints

Frontend: `/dashboard`, `/analyze`, `/assessments`, `/assessments/:id`.

Backend: `POST /api/v1/security/analyze`, `GET /api/v1/security/assessments`, `GET /api/v1/security/assessments/{id}`, plus statistics, attacks, risk-distribution, timeline, and health endpoints.

Assessment prompts are stored in plain text in `backend/app/data/aishield.db`; do not submit sensitive material. See [privacy notes](backend/app/database/PRIVACY.md).

\n