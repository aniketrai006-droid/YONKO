"""Password hashing, session tokens, and secret handling.

Security properties provided here:

- Passwords are stored as PBKDF2-HMAC-SHA256 with a per-user random salt
  (OWASP-recommended 600k iterations).
- Session tokens are high-entropy random strings; only an HMAC-SHA256 of the
  token (keyed with YONKO_SESSION_SECRET) is persisted, so a leaked database
  cannot be replayed as live sessions.
- Password policy: minimum 8 characters containing at least one letter and
  one digit.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

PBKDF2_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8

# Ephemeral fallback so the app still works without a configured secret
# (sessions then do not survive a process restart).
_FALLBACK_SECRET = secrets.token_bytes(32)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def session_ttl_hours() -> int:
    try:
        hours = int(os.getenv("SESSION_TTL_HOURS", "24"))
    except ValueError:
        hours = 24
    return max(1, hours)


def session_expiry() -> str:
    expiry = datetime.now(timezone.utc) + timedelta(hours=session_ttl_hours())
    return expiry.isoformat()


def _session_secret() -> bytes:
    secret = os.getenv("YONKO_SESSION_SECRET", "").strip()
    return secret.encode("utf-8") if secret else _FALLBACK_SECRET


def hash_session_token(token: str) -> str:
    """Keyed hash of a session token; this is what reaches the database."""
    return hmac.new(_session_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def password_problem(password: str) -> str | None:
    """Return a user-facing message when the password fails the policy."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return (f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if not any(character.isalpha() for character in password):
        return "Password must include at least one letter."
    if not any(character.isdigit() for character in password):
        return "Password must include at least one digit."
    return None


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


def new_token() -> str:
    return secrets.token_urlsafe(32)
