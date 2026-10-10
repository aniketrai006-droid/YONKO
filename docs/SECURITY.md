# Security Model — AI Document Contradiction Detector

This document describes the security controls built into the backend, the
threats they address, and how to demonstrate them to an audience.

## Authentication and sessions

| Control | Implementation |
| --- | --- |
| Password storage | PBKDF2-HMAC-SHA256, 600k iterations, 16-byte random salt per user (`app/security.py`) |
| Password policy | Minimum 8 characters with at least one letter and one digit |
| Session tokens | 256-bit `secrets.token_urlsafe` values; only an HMAC-SHA256 keyed with `YONKO_SESSION_SECRET` is stored, so a leaked database cannot be replayed as live sessions |
| Session expiry | Every session has an `expires_at` (default 24 h, `SESSION_TTL_HOURS`); expired rows are purged on use |
| Logout | Deletes the hashed token server-side — the token is dead everywhere |
| Anti-enumeration | Sign-in returns the same `Incorrect email or password.` for unknown emails and wrong passwords, and a dummy PBKDF2 verification equalises response timing |
| Brute-force lockout | 5 consecutive failures (`AUTH_MAX_FAILURES`) lock the account for 15 minutes (`AUTH_LOCKOUT_MINUTES`) with `429` + `Retry-After` |
| Per-IP rate limit | 30 auth requests/minute/IP (`AUTH_RATE_LIMIT_PER_MINUTE`); 600 req/min global (`GLOBAL_RATE_LIMIT_PER_MINUTE`); 12 analyses/minute/account |

## Authorisation

- `/analyze` and every `/cases` route require a valid session (`401` otherwise).
- Cases are keyed by `(id, owner_email)`; a second reviewer requesting
  someone else's case gets `404`, not `403` (no existence leak).
- CORS allows only the origins in `CORS_ALLOW_ORIGINS`; a foreign site
  calling the API with a victim's browser gets no `Access-Control-Allow-Origin`.

## Input validation (document uploads)

| Control | Detail |
| --- | --- |
| Extension allow-list | `.png .jpg .jpeg .pdf` only |
| Content-type check | Must declare an image or PDF type |
| **Magic-byte check** | The file's first bytes must match its extension (PNG signature, JPEG `FF D8 FF`, PDF `%PDF-`) — a script or executable renamed to `.png`/`.pdf` is rejected |
| Size cap | 16 MB per file, enforced while streaming (`413`), so a huge body is refused before it is buffered |
| Page cap | PDFs limited to 10 pages before rasterisation |
| Path traversal | Client filenames are never used on disk; uploads are stored as `upload_NN.<ext>` in a private temp directory |
| Ephemeral storage | The temp directory is deleted in a `finally` block after analysis — no document is persisted |

## Data layer

- All SQL uses parameterised queries (no string concatenation); this is
  verified by the SQL-injection tests in `tests/test_security.py`.
- Sessions, cases, and audit rows are scoped by owner with foreign keys
  and `ON DELETE CASCADE`.
- The audit log (`audit_log` table) records `signup.*`, `signin.*`,
  `signout`, and `analyze.completed` events with the account email, client
  IP, and timestamp — without ever storing passwords, tokens, or document
  contents.
- SQLite for local development; set `DATABASE_URL` (Render does this
  automatically) to run the identical schema on managed PostgreSQL.

## Transport and browser hardening

- Security headers on every API response: `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none';
  frame-ancestors 'none'`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.
- `Strict-Transport-Security` is emitted only on HTTPS (never over plain
  HTTP in local dev).
- The Vercel deployment adds the equivalent headers plus a CSP for the
  SPA (`vercel.json`).
- The Docker image runs as a non-root user; session secrets and the CORS
  allow-list come from environment variables, never from the repository.

## Demonstrating the security to judges

Two artefacts exist for live proof:

1. **Automated test suite** — 24 attack simulations:

   ```powershell
   cd backend
   ..\.venv\Scripts\python.exe -m pytest tests/test_security.py -v
   ```

2. **Live attack script** — point real attacks at the running server and
   watch them fail:

   ```powershell
   .\start-backend.ps1        # terminal 1
   .\security-demo.ps1        # terminal 2
   ```

   It prints a green PASS for each resisted attack: forged sessions, SQL
   injection (sign-in and stored fields), cross-reviewer data access,
   anonymous analysis, content-spoofed uploads, oversized uploads, brute
   force lockout, missing CORS grants, and security headers — plus a
   positive control proving the legitimate flow still works.

## Reporting a vulnerability

This is a demonstration system using synthetic documents only. If you find
a security issue, please open a private security advisory on the GitHub
repository rather than a public issue.