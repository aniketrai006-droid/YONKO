"""Reviewer sign up, sign in, and profile. Accounts live in the database.

Hardened against common attacks:

- Brute force: per-account failure lockout plus a per-IP rate limit.
- User enumeration: sign-in answers with one generic error whether the
  account exists or the password is wrong (timing is equalised too).
- Session safety: the database stores only an HMAC of the session token;
  tokens expire after SESSION_TTL_HOURS.
- Every attempt is written to the audit log with the client IP.
"""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.db import get_connection, record_audit
from app.ratelimit import (
    auth_rate_limit_per_minute,
    get_client_ip,
    limiter,
    login_failures,
)
from app.security import (
    hash_password,
    hash_session_token,
    new_token,
    password_problem,
    session_expiry,
    utc_now,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

# Fixed hash used to equalise response time when the email is unknown, so
# attackers cannot distinguish "no such account" from "wrong password".
_DUMMY_HASH = hash_password("timing-equalisation-placeholder-1")


class Credentials(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class ProfileUpdate(BaseModel):
    name: str = Field(max_length=200)
    dob: str = Field(max_length=40)


def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _validate_credentials(email: str, password: str) -> str:
    normalized = _normalize_email(email)
    if not EMAIL_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter a valid official email address, for example reviewer@department.gov.in.",
        )
    problem = password_problem(password)
    if problem:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=problem)
    return normalized


def _enforce_rate_limit(request: Request, key: str) -> None:
    allowed, retry_after = limiter.check(
        key, auth_rate_limit_per_minute(), window_seconds=60)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many attempts. Please wait a minute and try again.",
            headers={"Retry-After": str(retry_after)},
        )


def _enforce_lockout(email: str, ip: str) -> None:
    remaining = login_failures.locked_for(email)
    if remaining > 0:
        record_audit("signin.locked_out", email=email, ip=ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked after too many failed attempts. "
                   "Please try again later.",
            headers={"Retry-After": str(int(remaining) + 1)},
        )


def _user_payload(row, token: str | None = None) -> dict:
    name = row["name"] or ""
    body = {
        "email": row["email"],
        "name": name,
        "dob": row["dob"] or "",
        "needsProfile": not bool(name.strip()),
    }
    if token:
        body["token"] = token
    return body


def get_current_user(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in required.",
        )
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sign in required.",
        )
    token_hash = hash_session_token(token)
    with get_connection() as connection:
        # Opportunistic cleanup keeps expired sessions out of the table.
        connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?", (utc_now(),))
        row = connection.execute(
            """
            SELECT users.email, users.name, users.dob
            FROM sessions
            JOIN users ON users.email = sessions.email
            WHERE sessions.token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )
    return {"email": row["email"], "name": row["name"], "dob": row["dob"], "token": token}


def _issue_session(connection, email: str) -> str:
    token = new_token()
    connection.execute(
        """
        INSERT INTO sessions (token_hash, email, created_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (hash_session_token(token), email, utc_now(), session_expiry()),
    )
    return token


@router.post("/signup")
def signup(body: Credentials, request: Request) -> dict:
    email = _validate_credentials(body.email, body.password)
    ip = get_client_ip(request)
    _enforce_rate_limit(request, f"auth:{ip}")
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT email FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
            record_audit("signup.duplicate", email=email, ip=ip)
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account already exists for this email. Sign in instead.",
            )
        connection.execute(
            """
            INSERT INTO users (email, password_hash, name, dob, created_at)
            VALUES (?, ?, '', '', ?)
            """,
            (email, hash_password(body.password), utc_now()),
        )
        token = _issue_session(connection, email)
        row = connection.execute(
            "SELECT email, name, dob FROM users WHERE email = ?", (email,)
        ).fetchone()
    record_audit("signup.success", email=email, ip=ip)
    payload = _user_payload(row, token)
    payload["needsProfile"] = True
    return payload


@router.post("/signin")
def signin(body: Credentials, request: Request) -> dict:
    email = _validate_credentials(body.email, body.password)
    ip = get_client_ip(request)
    _enforce_rate_limit(request, f"auth:{ip}")
    _enforce_lockout(email, ip)
    with get_connection() as connection:
        row = connection.execute(
            "SELECT email, password_hash, name, dob FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        # Always run a verification so unknown emails take the same time as
        # a wrong password (timing-safe sign-in).
        stored = row["password_hash"] if row else _DUMMY_HASH
        password_ok = verify_password(body.password, stored)
        if not row or not password_ok:
            login_failures.record_failure(email)
            record_audit("signin.failed", email=email, ip=ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password.",
            )
        login_failures.clear(email)
        token = _issue_session(connection, email)
    record_audit("signin.success", email=email, ip=ip)
    return _user_payload(row, token)


@router.post("/profile")
def save_profile(body: ProfileUpdate, user: dict = Depends(get_current_user)) -> dict:
    clean_name = " ".join(str(body.name or "").split())
    clean_dob = str(body.dob or "").strip()
    if len(clean_name) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Enter your full name."
        )
    if not clean_dob:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter your date of birth.",
        )
    with get_connection() as connection:
        connection.execute(
            "UPDATE users SET name = ?, dob = ? WHERE email = ?",
            (clean_name, clean_dob, user["email"]),
        )
        row = connection.execute(
            "SELECT email, name, dob FROM users WHERE email = ?",
            (user["email"],),
        ).fetchone()
    return _user_payload(row, user["token"])


@router.post("/logout")
def logout(user: dict = Depends(get_current_user)) -> dict:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (hash_session_token(user["token"]),),
        )
    record_audit("signout", email=user["email"])
    return {"ok": True}
