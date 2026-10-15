# AIShield

AIShield is a prototype prompt-security assessment dashboard. The React app submits prompts to a FastAPI backend. The backend combines phrase-based rules and a TF-IDF/logistic-regression classifier, optionally adds a Gemini assessment, assigns an experimental ALLOW/SANITIZE/BLOCK label, and stores the result in SQLite. The Analyze page lets users disable Gemini and analyze locally without consuming Gemini API quota. The dashboard shows stored assessments and summary charts. A separate Simulation page generates an attack case, evaluates it with the Defender, runs a deterministic local Target, and checks the output for configured canaries.

**This is a research prototype, not a production security control.** Its detector performed poorly on a small independent challenge set; do not automate access decisions with its output. See [detector validation](backend/DETECTOR_VALIDATION.md).

## Run locally

Requirements: Python 3.13+, Node.js 18+, and a Gemini API key for Gemini-assisted prompt analysis and generated attack simulations. Prompt analysis can also run locally without a Gemini key.

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
npm ci
npm run dev
```

Open `http://localhost:5173`. Vite proxies `/api` to the backend. For a separately hosted frontend, set `VITE_API_BASE_URL` and configure the backend's comma-separated `FRONTEND_ORIGINS` to include that origin.

## Verify and demonstrate

With dependencies installed, run these from `frontend/`:

```powershell
npm run build
npm test -- --run
```

Run the offline simulation and detector tests from `backend/` with:

```powershell
$env:DEBUG = 'true'
python -m pytest -q tests/test_simulation_api.py tests/test_simulation_service.py tests/test_target_agent.py tests/test_leakage_detector.py
```

Other backend tests may initialize the configured database or call Gemini; inspect their fixtures and requirements before running them. Do not run Gemini integration tests without a configured key and explicit intent to use the live service.

For a local demonstration, start the backend and frontend as above, open `/analyze` to submit a prompt and `/assessments` to review saved results, then open `/simulations` to select an attack category, optionally enter a canary, and run a simulation. Show the decision, target status, outcome, history, statistics, and a details record. The Target is a deterministic stub, so a canary absent from its fixed response should produce `NO_LEAK`; this demonstrates orchestration and evaluation, not a live model's resistance to attacks. The Attacker and Defender use Gemini when available and require a valid `GEMINI_API_KEY`. Gemini calls in simulations have a 30-second stage timeout; if Gemini is rate-limited, temporarily unavailable, or times out, the affected stage continues with clearly labeled local fallback generation or scoring.

## Validate the detector

From `backend/`:

```powershell
python evaluate_detector.py
$env:DEBUG = 'true'
python -m pytest tests/test_health.py tests/test_security_api.py tests/test_rule_detector.py tests/test_hybrid_engine.py tests/test_persistence.py tests/test_persistence_integration.py tests/test_ml_classifier.py -q
```

The evaluation script prints the synthetic CSV holdout metrics and a separate hand-written challenge-set report for the offline ML and rule detectors. These are diagnostic checks only. The Gemini-dependent tests require valid credentials and network access.

## Main routes and endpoints

Frontend: `/dashboard`, `/analyze`, `/assessments`, `/assessments/:id`, `/simulations`, `/simulations/:simulationId`.

Backend: existing `/api/v1/security/*` assessment and analytics endpoints, plus `POST /api/v1/simulations/run`, `GET /api/v1/simulations`, `GET /api/v1/simulations/{simulation_id}`, and `GET /api/v1/simulations/statistics`.

The simulation Target is currently `LocalTargetAgent`, a deterministic test stub that returns a fixed response; it is not a production AI Target. A run can only count as successful when a configured canary matches the response. `SANITIZE` is a decision label only: the prompt is passed to the Target unchanged. Assessment and simulation APIs currently have no authentication; keep the demo bound to localhost and do not expose it to an untrusted network.

Assessment prompts, generated attack prompts, simulation results, and Target responses are stored in plain text in `backend/app/data/aishield.db`; simulation detail and assessment endpoints return stored prompt/response data. Do not submit real secrets or sensitive material. See [privacy notes](backend/app/database/PRIVACY.md).