"""Password hashing, session tokens, and field-level encryption for sensitive data."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

SESSION_TTL_HOURS = 8
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
PBKDF2_ITERATIONS = 260_000  # NIST 2024 recommendation for SHA-256


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_expiry() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=SESSION_TTL_HOURS)).isoformat()


def is_expired(expiry_iso: str) -> bool:
    try:
        expiry = datetime.fromisoformat(expiry_iso)
        return datetime.now(timezone.utc) > expiry
    except (ValueError, TypeError):
        return True


# ---------------------------------------------------------------------------
# Password hashing  (PBKDF2-HMAC-SHA256, 260k iterations)
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


# ---------------------------------------------------------------------------
# Session tokens
# ---------------------------------------------------------------------------

def new_token() -> str:
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Field-level encryption  (AES-256-GCM)
#
# Key is derived from SAMANVAY_SECRET_KEY env var (required in production).
# In development, a stable key is auto-generated once and stored in
# backend/data/.encryption_key so restarts don't break existing records.
# ---------------------------------------------------------------------------

_KEY_FILE_PATH = (
    __import__("pathlib").Path(__file__).resolve().parents[1]
    / "data"
    / ".encryption_key"
)


def _load_or_create_dev_key() -> bytes:
    """Load existing dev key or create a new one (development only)."""
    _KEY_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if _KEY_FILE_PATH.exists():
        raw = _KEY_FILE_PATH.read_bytes().strip()
        return base64.urlsafe_b64decode(raw)
    key = os.urandom(32)
    _KEY_FILE_PATH.write_bytes(base64.urlsafe_b64encode(key))
    # Restrict permissions on POSIX systems
    try:
        import stat
        _KEY_FILE_PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    return key


def _get_encryption_key() -> bytes:
    env_key = os.getenv("SAMANVAY_SECRET_KEY")
    if env_key:
        raw = base64.urlsafe_b64decode(env_key.encode())
        if len(raw) != 32:
            raise RuntimeError("SAMANVAY_SECRET_KEY must be a 32-byte base64url value.")
        return raw
    return _load_or_create_dev_key()


def encrypt_field(plaintext: str) -> str:
    """Encrypt a sensitive string field.  Returns a base64url token safe to store in DB."""
    if not plaintext:
        return plaintext
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    # Format: base64(nonce + ciphertext), prefixed with "enc:" to detect encrypted values
    payload = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return f"enc:{payload}"


def decrypt_field(token: str) -> str:
    """Decrypt a value previously encrypted with encrypt_field."""
    if not token or not token.startswith("enc:"):
        return token  # plain-text legacy value — return as-is
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    raw = base64.urlsafe_b64decode(token[4:])
    nonce, ciphertext = raw[:12], raw[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")


def mask_field(value: str) -> str:
    """Return a masked version safe for logs (e.g. '****1234')."""
    if not value:
        return ""
    decrypted = decrypt_field(value)
    visible = min(4, len(decrypted) // 3)
    return "*" * (len(decrypted) - visible) + decrypted[-visible:]
