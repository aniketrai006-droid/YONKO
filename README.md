# AI Document Contradiction Detector

This repository contains a Vite/React frontend and a FastAPI backend for analysing a bundle of citizen-submitted documents (PNG, JPG, JPEG images and PDF files). The backend uses OCR, extraction, conservative normalization, and field-specific comparison rules to flag contradictions while retaining raw values, confidence, and source bounding boxes.

All repository documents are synthetic specimens. Do not add real identities or production documents. Ground-truth labels are evaluation-only and are never read during normal analysis.

## Run the backend

The easiest way on Windows is the bundled script. It creates `.venv` if it is missing, installs `backend/requirements.txt`, puts Tesseract on `PATH`, reads the environment from the root `.env` file, refuses to start if the port is already taken, and then runs uvicorn:

```powershell
.\start-backend.ps1            # add -Reload for auto-reload, -Port to change the port
```

`JWT_SECRET` should be set in `.env` (see `.env.example`); when it is
unset the backend generates an ephemeral per-process signing key and all
tokens are invalidated on restart. To start the server by hand instead:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload
```

The API is available at `http://127.0.0.1:8000`:

- `GET /health`
- `GET /health/ocr`
- `GET /api/info`
- `POST /analyze`

Run backend tests with:

```powershell
pytest -q --basetemp .pytest-tmp
```

## Running with Docker

**Prerequisites:** Docker Desktop must be running.

```powershell
# 1. Copy the example env file and fill in DATABASE_URL / secrets
cp .env.example .env

# 2. Build images and start services in the background
docker compose up --build -d

# 3. Apply database migrations (run once after first start, or after schema changes)
docker compose exec api alembic upgrade head

# 4. Stop and remove containers + volumes when done
docker compose down -v
```

**Notes:**
- The `db` service has no published host port — it is on an internal network only and is reachable solely by the `api` service.
- `PERSIST_RESULTS` defaults to `false`. Set `PERSIST_RESULTS=true` in `.env` to save bundle metadata and findings to PostgreSQL after each analysis.
- The API is available at `http://localhost:8000` on the host machine.

## Run the frontend

From the repository root:

```powershell
npm install
npm run dev
```

The frontend defaults to `http://localhost:8000`. To target another backend address, create a root `.env` file:

```env
VITE_API_BASE_URL=http://localhost:8000
```

## Reviewer sign in

Authentication is handled by the backend JWT system (`/auth/login`,
`/auth/register`, `/auth/refresh`, `/auth/logout`). The frontend keeps
tokens in memory only — reloading the page signs you out. Citizens
self-register; reviewer and admin accounts are provisioned by an admin
via `POST /auth/admin/users`. Reviewers and admins additionally need a
TOTP code from an authenticator app at login (enroll via
`POST /auth/mfa/enroll`). See [docs/SECURITY.md](docs/SECURITY.md) for
the full authentication architecture.

## Analysis request

The frontend sends a multipart `POST /analyze` request using the `files` field. Submit 2–10 non-empty PNG, JPG, or JPEG images or PDF files with unique filenames. Each PDF may contain at most 10 pages. JPEG uploads are converted to PNG and every PDF page is rasterised to a PNG image in the backend's temporary directory before OCR, so the detection engine only ever sees images.

Uploads are processed in a temporary backend directory and removed after analysis. The UI therefore displays returned text evidence, confidence, bounding boxes, and warnings rather than durable image previews.

For the response contract, see [docs/API_CONTRACT.md](docs/API_CONTRACT.md). The frontend is configured to call this API directly.
