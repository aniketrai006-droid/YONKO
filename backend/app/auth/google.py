"""Google ID token verification and stateless reviewer session tokens."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

GOOGLE_TOKEN_INFO_URL = "https://oauth2.googleapis.com/tokeninfo"
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
SESSION_TTL_SECONDS = 7 * 24 * 60 * 60

_generated_secret: bytes | None = None


class GoogleAuthError(Exception):
    """Raised when a Google credential cannot be trusted."""


def google_client_id() -> str:
    """Return the OAuth client id this deployment is allowed to accept."""
    return os.getenv("GOOGLE_CLIENT_ID", "").strip()


def _session_secret() -> bytes:
    configured = os.getenv("YONKO_SESSION_SECRET", "").strip()
    if configured:
        return configured.encode("utf-8")
    global _generated_secret
    if _generated_secret is None:
        _generated_secret = secrets.token_bytes(32)
    return _generated_secret


def _as_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _fetch_claims(credential: str) -> dict[str, object]:
    """Ask Google to decode the credential and return its signed claims."""
    query = urllib.parse.urlencode({"id_token": credential})
    request = urllib.request.Request(
        f"{GOOGLE_TOKEN_INFO_URL}?{query}",
        headers={"Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise GoogleAuthError("Google rejected the credential.") from exc
    if not isinstance(payload, dict):
        raise GoogleAuthError("Google returned an unreadable credential.")
    return payload


def _verify_claims(claims: dict[str, object], client_id: str) -> dict[str, str]:
    """Validate audience, issuer, expiry and email before trusting a session."""
    if claims.get("aud") != client_id:
        raise GoogleAuthError("Credential was issued for a different application.")
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise GoogleAuthError("Credential was not issued by Google.")
    if str(claims.get("email_verified", "")).lower() != "true":
        raise GoogleAuthError("Google account email is not verified.")
    expires = _as_int(claims.get("exp"))
    if expires is None or expires <= int(time.time()):
        raise GoogleAuthError("Credential has expired.")
    email = str(claims.get("email") or "").strip().lower()
    if "@" not in email:
        raise GoogleAuthError("Credential does not contain an email address.")
    return {
        "sub": str(claims.get("sub") or ""),
        "email": email,
        "name": str(claims.get("name") or "").strip() or email,
        "picture": str(claims.get("picture") or "").strip(),
    }


async def verify_google_credential(credential: str) -> dict[str, str]:
    """Verify a Google ID token and return the reviewer it belongs to."""
    token = (credential or "").strip()
    if not token:
        raise GoogleAuthError("Google credential is missing.")
    client_id = google_client_id()
    if not client_id:
        raise GoogleAuthError("GOOGLE_CLIENT_ID is not configured on the server.")
    claims = await asyncio.to_thread(_fetch_claims, token)
    return _verify_claims(claims, client_id)


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: dict[str, object]) -> str:
    body = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_encode(signature)}"


def issue_session(user: dict[str, str]) -> str:
    """Mint a signed, expiring session token for a verified Google account."""
    now = int(time.time())
    return _sign({
        "sub": user.get("sub", ""),
        "email": user["email"],
        "name": user.get("name", user["email"]),
        "picture": user.get("picture", ""),
        "iat": now,
        "exp": now + SESSION_TTL_SECONDS,
    })


def read_session(token: str) -> dict[str, str] | None:
    """Return the session user for a valid token, or None if it cannot be trusted."""
    value = (token or "").strip()
    if value.count(".") != 1:
        return None
    body, signature = value.split(".")
    expected = _encode(hmac.new(_session_secret(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, signature):
        return None
    try:
        payload = json.loads(_decode(body))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    expires = _as_int(payload.get("exp"))
    if expires is None or expires <= int(time.time()):
        return None
    email = str(payload.get("email") or "").strip()
    if "@" not in email:
        return None
    return {
        "sub": str(payload.get("sub") or ""),
        "email": email,
        "name": str(payload.get("name") or "").strip() or email,
        "picture": str(payload.get("picture") or "").strip(),
    }
