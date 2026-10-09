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

Set `ID_HMAC_SECRET` to a strong random value (≥ 32 bytes) in production:

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
