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

## PostgreSQL Row-Level Security (Defence in Depth)

From migration 0006 the database itself enforces access control — even a
compromised API process or a SQL-injection bug cannot read another user's
rows, because the filtering happens inside PostgreSQL, not in Python.

### Database roles

| Role              | Used by            | Privileges |
|-------------------|--------------------|------------|
| `app_user`        | the running API    | SELECT/INSERT/UPDATE on app tables; **INSERT-only** on `audit_log_pg`; no DELETE anywhere; no DDL; not superuser |
| `migration_user`  | `alembic upgrade`  | owns the schema (table owner bypasses RLS); not used at runtime |

Passwords come from `APP_DB_PASSWORD` / `MIGRATION_USER_PASSWORD` (env only).
The API's `DATABASE_URL` connects as `app_user`; Alembic uses
`MIGRATION_DATABASE_URL` when set (see `docker-compose.yml`).

### Policies

RLS is ENABLEd on `bundles`, `documents`, `findings_pg` and
`review_decisions`. Policies read two session GUCs — `app.current_user_id`
and `app.current_role` — set with **SET LOCAL** from the verified JWT
subject in `get_current_user` (never from client input):

- **admin** sees and writes all rows.
- **citizen** sees rows where `owner_id` is their own user id.
- **reviewer** sees rows on bundles where `assigned_reviewer_id` is theirs.
- Child tables (documents, findings, decisions) are filtered through their
  parent bundle, so one ownership rule covers the whole graph.
- `review_decisions` writes are restricted to admin or the *assigned*
  reviewer at the DB layer — citizens cannot insert decisions even if the
  API's `require_role` check were bypassed.

**Fail-closed:** if the GUCs are unset (e.g. a bare `psql` session as
`app_user`), every policy evaluates to NULL and no rows are visible.

### Audit log tamper-evidence

`audit_log_pg` is **INSERT-only** for `app_user`: no SELECT (cannot read
the trail back), no UPDATE, no DELETE (cannot tamper). Retention and
expiry are offline operations performed as `migration_user`.

### Tests

`backend/tests/test_rls_postgres.py` verifies all of the above against a
real PostgreSQL server with **raw SQL as `app_user`** — including that a
SELECT with no WHERE clause returns none of another user's rows. The tests
skip when no Postgres is reachable; CI provides one via
`RLS_TEST_SUPERUSER_URL`.

## Encryption in Transit and at Rest

### Field-level encryption at rest (AES-256-GCM)

`app/security/crypto.py` encrypts sensitive free text before it reaches
the database, via the SQLAlchemy `EncryptedType` decorator:

| Column | Contents |
|---|---|
| `findings_pg.reason` | evidence quotes (the closest thing this schema persists to raw evidence) |
| `review_decisions.reviewer_email` | display email (reviewer_id UUID is the authoritative key) |
| `users_pg.totp_secret` | MFA shared secret |

Raw identity numbers are never persisted at all (Rule 2 — masked last-4
+ HMAC only), so there are no Aadhaar/PAN columns to encrypt.
`users_pg.email` stays in clear because it is the login lookup key and an
FK target; it contains synthetic-only identifiers per project rules.

Token format: `enc:v1:<key_id>:<base64url(nonce[12] || ct || tag)>`.
Each encryption uses a fresh random 96-bit nonce (equal plaintexts ?
different ciphertexts), and the key id is authenticated as AAD so a
payload cannot be replayed under a different key. Tampering raises
`InvalidTokenError` — AES-GCM never returns unauthenticated data.

**Keys come only from environment variables** (`DATA_KEY_V1`,
`DATA_KEY_V2`, ...) — never from the database. `DATA_KEY_ACTIVE`
selects which key encrypts new values; every token names the key it was
encrypted with, so old-key rows keep decrypting during rotation. With no
`DATA_KEY_*` set (dev/test), an auto-generated key is used and a warning
is logged.

**Searchable HMAC:** `hmac_field(value)` produces a deterministic
HMAC-SHA256 for equality lookups on encrypted data (key: `HMAC_INDEX_KEY`
or derived from the active data key). The `documents.id_hash` column
already uses this pattern for cross-document identity matching.

**Key rotation:**

1. Generate a new key: `python -c "from app.security.crypto import generate_data_key; print(generate_data_key())"`
2. Add `DATA_KEY_V2=<key>` to the environment and set `DATA_KEY_ACTIVE=v2`.
3. Run `python backend/scripts/rotate_data_keys.py` (use
   `MIGRATION_DATABASE_URL`; `--dry-run` first). It decrypts each row with
   the key id embedded in the token and re-encrypts with the active key.
4. Verify, then remove `DATA_KEY_V1` from the environment.

Legacy `enc:<payload>` rows (pre-keyid format) still decrypt; the same
script migrates them.

### TLS in transit

**API ? PostgreSQL:** the docker-compose `db` service starts with
`ssl=on` using a self-signed certificate (generate once with
`python backend/scripts/gen_selfsigned_cert.py`, which writes
`docker/tls/` — gitignored). The API and Alembic connect with
`sslmode=require`, so all DB traffic is encrypted. `require` does not
verify the certificate chain, which is acceptable for a self-signed cert
on a Docker-internal network where both endpoints are yours.

**Production PostgreSQL:** obtain a certificate from your CA (or ACME),
mount it into the database container as above, and change the connection
URL to `sslmode=verify-full` so the client verifies the server certificate
against the CA — this defeats man-in-the-middle even on untrusted
networks.

**API ? clients (reverse proxy):** uvicorn itself listens on plain HTTP
behind the Docker network. Terminate TLS at a reverse proxy in front of
the API. With nginx + certbot:

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.gov.in;
    ssl_certificate     /etc/letsencrypt/live/api.example.gov.in/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.gov.in/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://api:8000;          # Docker service name
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
server {
    listen 80;
    server_name api.example.gov.in;
    return 301 https://$host$request_uri;    # redirect plaintext to TLS
}
```

With Caddy (automatic ACME certificates):

```
api.example.gov.in {
    reverse_proxy api:8000
}
```

Never expose port 8000 directly to the internet — the compose file maps
it to localhost for development only. The reverse proxy is the only
internet-facing component; everything behind it (API, DB, MinIO) stays
on the internal Docker network.
