# AI Document Contradiction Detector

This repository contains a Vite/React frontend and a FastAPI backend for analysing a bundle of citizen-submitted documents (PNG, JPG, JPEG images and PDF files). The backend uses OCR, extraction, conservative normalization, and field-specific comparison rules to flag contradictions while retaining raw values, confidence, and source bounding boxes.

All repository documents are synthetic specimens. Do not add real identities or production documents. Ground-truth labels are evaluation-only and are never read during normal analysis.

## Run the backend

In Windows PowerShell:

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
- `POST /auth/google`
- `GET /auth/me`

Run backend tests with:

```powershell
pytest -q --basetemp .pytest-tmp
```

## Run the frontend

From the repository root:

```powershell
npm install
npm run dev
```

The frontend defaults to `http://localhost:8000`. To target another backend address, create a root `.env` file:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_GOOGLE_CLIENT_ID=1234567890-abcdef.apps.googleusercontent.com
```

## Reviewer sign in

The reviewer portal offers two sign in options side by side:

- **Email and password** — demo accounts live in this browser's `localStorage`, so they work with no backend configuration.
- **Google** — the account modal renders Google's own sign in button, the browser forwards Google's ID token to `POST /auth/google`, the backend checks it against Google (audience, issuer, expiry, verified email) and answers with a signed session token that `GET /auth/me` reads back.

To switch Google sign in on:

1. Google Cloud Console → **APIs & Services → OAuth consent screen**: pick *External*, add the `email` and `profile` scopes, and add your Google addresses under **Test users** while the app is in *Testing*.
2. **APIs & Services → Credentials → Create credentials → OAuth client ID**: choose **Web application** and add `http://localhost:5173` and `http://localhost:3000` under **Authorized JavaScript origins** (redirect URIs are not needed). Copy the Client ID.
3. Backend — set the environment variables before starting uvicorn:

   ```powershell
   $env:GOOGLE_CLIENT_ID = "1234567890-abcdef.apps.googleusercontent.com"
   $env:YONKO_SESSION_SECRET = "a-long-random-string"
   uvicorn app.main:app --reload
   ```

4. Frontend — put the same Client ID in the root `.env` file shown above as `VITE_GOOGLE_CLIENT_ID` and restart `npm run dev`.

Without `VITE_GOOGLE_CLIENT_ID` the modal shows a disabled *Sign in with Google* button, and email sign in is unaffected. `YONKO_SESSION_SECRET` signs the session tokens; when it is unset the backend generates a random secret at startup, so sessions then only last until the server restarts.

## Analysis request

The frontend sends a multipart `POST /analyze` request using the `files` field. Submit 2–10 non-empty PNG, JPG, or JPEG images or PDF files with unique filenames. Each PDF may contain at most 10 pages. JPEG uploads are converted to PNG and every PDF page is rasterised to a PNG image in the backend's temporary directory before OCR, so the detection engine only ever sees images.

Uploads are processed in a temporary backend directory and removed after analysis. The UI therefore displays returned text evidence, confidence, bounding boxes, and warnings rather than durable image previews.

For the response contract, see [docs/API_CONTRACT.md](docs/API_CONTRACT.md). The frontend is configured to call this API directly.
