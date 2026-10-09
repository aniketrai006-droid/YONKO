# API Contract

## `POST /analyze`

Send a `multipart/form-data` request with 2–10 values named `files`. Each item must be a non-empty PNG, JPG, or JPEG image or a PDF document of at most 10 pages. Filenames must be unique within a request and each upload must declare an `image/*` or `application/pdf` content type. The service processes files only in a private temporary directory and does not persist originals: JPEGs are converted to PNG and PDF pages are rasterised to PNG (2× zoom) before detection, after which the uploaded originals are deleted.

Success returns HTTP 200 and a `BundleDetectionResult` with `bundle_path`, `documents_processed`, `findings`, `summary`, and `warnings`. Each finding contains `field`, `decision`, `severity`, `reason`, optional `similarity`, complete `evidence`, and a `recommended_action`. Evidence preserves `document_type`, temporary `source_path`, `raw_value`, `normalized_value`, `comparison_key`, `source_confidence`, `source_bbox`, and `normalization_warnings`.

`source_bbox` is `[x1, y1, x2, y2]` in pixels of the original submitted image, or of the rendered page image when the source was a PDF. Treat `bundle_path` and `source_path` as diagnostic metadata, not stable client identifiers.

Client input errors return `{ "detail": "clear message" }` with HTTP 400. Unexpected processing failures use a generic HTTP 500 message and do not expose a traceback.

## Decision and severity meanings

- `conflict`: sufficiently reliable evidence disagrees across documents.
- `harmless_variant`: formatting, order, abbreviation, or a close spelling difference is safe to treat as equivalent.
- `review`: evidence is uncertain, weak, or materially different but not safe to label an automatic conflict.
- `insufficient_evidence`: fewer than two usable values were available.

`HIGH` covers contradictory dates of birth and valid 12-digit identity numbers. `MEDIUM` covers unrelated names and clear city, pincode, gender, or account-number differences. `LOW` covers income differences and uncertain reviews. `NONE` means no action is needed.

## Frontend guidance

Build a `FormData` object and append each selected file under `files`; do not set the multipart `Content-Type` header manually. Accept PNG, JPG, JPEG, and PDF files, render findings by field, show raw evidence and confidence, and use `source_bbox` to highlight the image or page region. Keep uploaded files client-side after the response; the service will not provide durable upload URLs. Development CORS permits Vite on ports 5173 and 3000 and can be configured with `CORS_ALLOW_ORIGINS`.

## `POST /auth/google`

Send `{ "credential": "<Google ID token>" }` as JSON. The service verifies the token with Google and requires `GOOGLE_CLIENT_ID` to be configured, an `aud` matching that client id, a Google `iss`, a verified email, and an unexpired `exp`. Success returns HTTP 200:

```json
{
  "access_token": "<signed session token>",
  "token_type": "bearer",
  "user": { "sub": "...", "email": "...", "name": "...", "picture": "..." }
}
```

A credential that fails any check returns HTTP 400/401 with `{ "detail": "clear message" }`; no user data is stored server-side.

## `GET /auth/me`

Send `Authorization: Bearer <access_token>`. A valid, unexpired token returns `{ "user": { "sub", "email", "name", "picture" } }` with HTTP 200. A missing, malformed, tampered, or expired token returns HTTP 401. Session tokens are HMAC-signed by the backend and expire after 7 days.
