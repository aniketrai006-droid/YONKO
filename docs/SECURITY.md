# YONKO Security Notes

## Data Minimization

### Identity Number Handling
- Raw Aadhaar, PAN, DL, and account numbers are **never stored** in the database or logs.
- `masking.mask_id(value)` retains only the last 4 characters for display.
- `masking.hash_id(value)` produces an HMAC-SHA256 digest (secret from `ID_HMAC_SECRET` env var) for cross-document matching.
- Matching two documents by the same identity number compares `id_hash` values only.

### File Storage
- When `PERSIST_UPLOADS=false` (default): uploaded files are processed in memory and discarded. No file bytes are written anywhere.
- When `PERSIST_UPLOADS=true`: files are stored in MinIO with AES256 server-side encryption. Only the `storage_key` and `file_hash` (SHA-256) are written to the database. File bytes never enter the DB.

### Synthetic Data Notice
All document processing uses synthetically generated test documents. No real personal data is used in development, testing, or CI.

---

## Verifying Data Minimization

To confirm no raw identity values are stored, query the `documents` table after running with `PERSIST_RESULTS=true`:

```sql
-- All rows should show masked_value as '****XXXX' (last 4 only), or NULL if no identity field was detected.
-- No column should ever contain a full 12-digit Aadhaar or other raw identity number.
SELECT id, document_type, masked_value, id_hash, file_hash, storage_key
FROM documents;
```

Expected observations:
- `masked_value`: either `NULL` (no identity field in that document) or a string with asterisks padding all but the last 4 characters.
- `id_hash`: either `NULL` or a 64-character hex string (HMAC-SHA256 digest).
- `file_hash`: either `NULL` (when `PERSIST_UPLOADS=false`) or a 64-character hex SHA-256 of the original file bytes.
- `storage_key`: either `NULL` or a MinIO object path (e.g. `uploads/<bundle-id>/<doc-id>/<filename>`).
- No column should contain a raw multi-digit identity number (Aadhaar, PAN, DL, account number).

---

## HMAC Secret Configuration

Set `ID_HMAC_SECRET` to a strong random value (â‰¥ 32 bytes) in production:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

An empty `ID_HMAC_SECRET` allows the application to start but produces predictable
HMAC outputs that offer no cross-document collision resistance. Always set this
via the environment before handling any real (or synthetic) identity data.

---

## MinIO Encryption

When `PERSIST_UPLOADS=true`, the `upload_file()` function in `app/storage.py` sets
`ServerSideEncryption="AES256"` on every `put_object` call. This instructs MinIO
to apply SSE-S3 (server-managed AES-256 key encryption) at rest. Even if the MinIO
storage volume is accessed directly, individual files are unreadable without the
MinIO server's key material.

The MinIO service is gated behind a Docker Compose profile (`--profile uploads`) so
it does not start in default development mode.

## Authentication (JWT + TOTP MFA)

### Password Storage

Passwords are hashed with **Argon2id** (argon2-cffi, OWASP baseline: 19 MiB
memory, 2 iterations). Each hash embeds a random salt. Plaintext passwords
are never stored or logged. A minimum policy applies at registration:
at least 12 characters with one letter and one digit (NIST SP 800-63B
favors length over complexity rules).

### Token Design

- **Access tokens** are HS256 JWTs with a 15-minute TTL. Claims are limited
to `sub` (opaque user UUID), `role`, and `mfa_ok` — no email or other PII
is placed in tokens (Rule 7). Signing keys are derived per token type via
HMAC so an access token can never be replayed as a refresh token.
- **Refresh tokens** are rotated on every `/auth/refresh` call. Only the
SHA-256 of each issued token is stored (in `refresh_tokens`). Presenting a
consumed token is treated as theft and revokes the entire token family
(RFC 9700, section 4.14.2).
- `JWT_SECRET` comes from the environment. When unset, an ephemeral
per-process key is generated and a warning is logged — a deployment can
therefore never fall back to a *constant* forgeable secret.

### Roles and MFA

Roles are `citizen`, `reviewer`, and `admin`. Self-registration only creates
citizens; reviewer/admin accounts are provisioned out of band
(privilege-escalation guard). Every privileged route uses the
`require_role(...)` FastAPI dependency (401 unauthenticated, 403 wrong role).

TOTP MFA (pyotp) is **required for reviewer and admin**:

1. Before enrollment, a password-only login yields a *bootstrap* token
(`mfa_ok=false`). Bootstrap tokens are rejected everywhere except
`/auth/mfa/enroll`, so an unenrolled reviewer can enroll but do nothing else.
2. `/auth/mfa/enroll` returns an `otpauth://` provisioning URI; the shared
secret is stored AES-GCM encrypted, never in plaintext.
3. After enrollment, login requires a valid 6-digit TOTP code (±1 interval
window for clock skew). Only then do tokens carry `mfa_ok=true`.

### Account Lockout

After `AUTH_MAX_FAILED_ATTEMPTS` (default 5) failed password or TOTP
attempts the account is locked for `AUTH_LOCKOUT_MINUTES` (default 15).
Locked accounts cannot log in **and** previously issued tokens are rejected
by `get_current_user`. Login responses never reveal whether an email exists
(uniform 401 message, dummy hash comparison for timing parity).

### Audit Trail

Auth events (REGISTER, LOGIN_OK, LOGIN_FAILED, LOGIN_FAILED_MFA,
LOGIN_BLOCKED_LOCKED, REFRESH_OK, REFRESH_REUSE_DETECTED, LOGOUT,
MFA_ENROLL) are written to `audit_log_pg` with the opaque user UUID as
`actor_id` — never emails, passwords, or tokens (Rule 7).

## Review Decisions and Protected Endpoints

### POST /analyze

`POST /analyze` requires a valid JWT access token (any role: citizen,
reviewer, admin). Unauthenticated requests are rejected with **401** before
any file is read or any OCR work happens. When `PERSIST_RESULTS=true`, the
`bundles.owner_email` row records the *authenticated* caller's email (no
more `system@yonko.internal` sentinel), satisfying the FK with a real
`users_pg` row.

### PATCH /findings/{id} (reviewer decisions)

- Restricted to `reviewer` and `admin` roles via `require_role` (401
  unauthenticated, 403 for citizens).
- **Assignment enforcement:** a reviewer may only decide on findings whose
  bundle has `assigned_reviewer_id` equal to their own user id — deciding on
  someone else's case returns 403. Admins bypass the assignment check.
- The request body is validated by Pydantic (`Literal["accepted",
  "dismissed"]`); any other status is a 422 without touching the database.
- Each decision is an append-only row in `review_decisions` recording the
  opaque reviewer UUID (`reviewer_id`), a denormalized email for display,
  and a **server-side** timestamp (`decided_at`) — the client cannot supply
  the attribution or the time.

### PATCH /bundles/{id}/assign (admin only)

Assignment is an admin-only operation (403 for reviewers and citizens) so
reviewers cannot reassign work to themselves. The target must be an active
`reviewer` or `admin` account (400 otherwise).

### Frontend token handling

The React app keeps the JWT access and refresh tokens **in memory only**
(`src/api/session.js` module state). Nothing is written to `localStorage`
or `sessionStorage`; a page reload deliberately signs the user out. Any
legacy `yonko_reviewer_session` entry in localStorage is removed at startup.

## Authentication Architecture (Summary)

One system, five moving parts. All endpoints that touch user data or cost
compute go through it; the legacy SQLite session auth has been fully removed.

```
React SPA                         FastAPI                        PostgreSQL
---------                         -------                        ----------
tokens in memory only --Bearer--? get_current_user / require_role ? users_pg
  (no localStorage)               ¦                                refresh_tokens
                                  +- Argon2id verify (login)       review_decisions
                                  +- HS256 JWT mint (15 min)       audit_log_pg
                                  +- TOTP check (reviewer/admin)
                                  +- lockout counter (5 / 15 min)
```

1. **Passwords — Argon2id** (`app/auth/passwords.py`). OWASP baseline
   (19 MiB, t=2, p=1), per-hash random salt, constant-time verify.
   Policy: =12 chars with at least one letter and one digit.

2. **Sessions — short JWT access + rotating refresh** (`app/auth/tokens.py`).
   Access tokens live 15 minutes and carry only `sub` (opaque UUID), `role`,
   and `mfa_ok` — no PII in tokens. Refresh tokens rotate on every
   `/auth/refresh`; only their SHA-256 is stored. Replaying a consumed
   refresh token revokes its whole family (theft detection). Signing keys
   are derived per token type so an access token can never be verified as a
   refresh token. `JWT_SECRET` comes from the environment; an unset value
   falls back to an ephemeral per-process key (tokens die on restart) rather
   than a forgeable constant.

3. **MFA — TOTP for reviewer/admin** (`app/auth/totp.py`, pyotp). Secrets
   are stored AES-GCM encrypted. Before enrollment, a password-only login
   yields a bootstrap token (`mfa_ok=false`) that is rejected everywhere
   except `/auth/mfa/enroll` — an unenrolled reviewer can enroll but do
   nothing else. After enrollment, every login requires a valid 6-digit code.

4. **Roles & provisioning.** `citizen` self-registers via
   `POST /auth/register`. `reviewer`/`admin` accounts are created only by an
   admin via `POST /auth/admin/users` (privilege-escalation guard).
   Authorization uses the `require_role(...)` FastAPI dependency — 401
   unauthenticated, 403 wrong role. Reviewers additionally may only decide
   on bundles assigned to them (`PATCH /findings/{id}`).

5. **Client storage — memory only.** The React app keeps the access and
   refresh tokens in module state (`src/api/session.js`); nothing is written
   to `localStorage`/`sessionStorage`, so a reload signs the user out and
   script-injection bugs cannot exfiltrate persistent credentials.

Brute force: 5 failed password or TOTP attempts lock the account for 15
minutes; locked accounts lose previously issued tokens too. Audit events
(login, refresh reuse, provisioning, MFA enrollment) land in `audit_log_pg`
with obfuscated actor UUIDs only — never emails, passwords, or tokens.
