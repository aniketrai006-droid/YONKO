"""JWT creation and verification for access and refresh tokens.

Security rationale (steering rule 8):
- HS256 with a single env-provided secret (JWT_SECRET). When the secret is
  empty the app uses an *ephemeral* per-process key, so a misconfigured
  deployment gets tokens that die on restart rather than tokens signed with
  a publicly known constant.
- Access tokens are short-lived (15 min default) and carry only the claims
  needed for authorization: sub (user UUID), role, mfa_ok. No email or other
  PII is placed in the token body — Rule 7.
- Refresh tokens are JWTs whose SHA-256 is persisted in refresh_tokens so
  rotation and theft detection work server-side (see api/auth_jwt_routes).
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt

from app.config import settings

logger = logging.getLogger(__name__)

ALGORITHM = "HS256"
TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"

# Ephemeral fallback used only when JWT_SECRET is unset (dev/test).
# Regenerated on every process start: no stable forgeable key ever exists.
_ephemeral_secret: str | None = None


def _signing_key(purpose: str) -> bytes:
    """Return the signing key for a token purpose.

    Domain separation: access and refresh tokens are signed with
    purpose-derived keys so a refresh token can never be replayed as an
    access token even if claim validation had a bug.
    """
    global _ephemeral_secret
    if settings.JWT_SECRET:
        base = settings.JWT_SECRET.encode("utf-8")
    else:
        if _ephemeral_secret is None:
            _ephemeral_secret = secrets.token_hex(32)
            logger.warning(
                "JWT_SECRET is not set — using an ephemeral per-process key. "
                "All tokens will be rejected after restart. "
                "Set JWT_SECRET in the environment for production."
            )
        base = _ephemeral_secret.encode("utf-8")
    return hashlib.sha256(base + b"|jwt|" + purpose.encode("utf-8")).digest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def create_access_token(
    user_id: uuid.UUID, role: str, mfa_ok: bool
) -> tuple[str, datetime]:
    """Create a signed access token. Returns (token, expires_at)."""
    expires_at = _now() + timedelta(
        minutes=settings.AUTH_ACCESS_TOKEN_TTL_MINUTES
    )
    payload = {
        "sub": str(user_id),
        "role": role,
        "mfa_ok": mfa_ok,
        "type": TOKEN_TYPE_ACCESS,
        "iat": _now(),
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
    }
    token = pyjwt.encode(payload, _signing_key(TOKEN_TYPE_ACCESS),
                         algorithm=ALGORITHM)
    return token, expires_at


def create_refresh_token(
    user_id: uuid.UUID, family_id: uuid.UUID
) -> tuple[str, datetime]:
    """Create a signed refresh token bound to a rotation family.
    Returns (token, expires_at)."""
    expires_at = _now() + timedelta(
        days=settings.AUTH_REFRESH_TOKEN_TTL_DAYS
    )
    payload = {
        "sub": str(user_id),
        "family": str(family_id),
        "type": TOKEN_TYPE_REFRESH,
        "iat": _now(),
        "exp": expires_at,
        "jti": uuid.uuid4().hex,
    }
    token = pyjwt.encode(payload, _signing_key(TOKEN_TYPE_REFRESH),
                         algorithm=ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> dict | None:
    """Decode and validate an access token.

    Returns the payload dict, or None when the token is invalid, expired, or
    of the wrong type. Callers must treat None as unauthenticated (401).
    """
    try:
        payload = pyjwt.decode(
            token, _signing_key(TOKEN_TYPE_ACCESS), algorithms=[ALGORITHM]
        )
    except pyjwt.PyJWTError:
        return None
    if payload.get("type") != TOKEN_TYPE_ACCESS:
        return None
    return payload


def decode_refresh_token(token: str) -> dict | None:
    """Decode and validate a refresh JWT's signature and claims.

    Returns the payload dict, or None when invalid/expired/wrong-type.
    Server-side state (used/revoked) is checked separately in the route.
    """
    try:
        payload = pyjwt.decode(
            token, _signing_key(TOKEN_TYPE_REFRESH), algorithms=[ALGORITHM]
        )
    except pyjwt.PyJWTError:
        return None
    if payload.get("type") != TOKEN_TYPE_REFRESH:
        return None
    return payload


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a refresh token for server-side lookup.
    The raw token is never persisted (steering rule: never store tokens)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
