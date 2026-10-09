"""Reviewer sign up, sign in, and profile. Accounts live in SQLite."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.db import audit, get_connection, purge_expired_sessions
from app.security import (
    decrypt_field,
    encrypt_field,
    hash_password,
    is_expired,
    new_token,
    session_expiry,
    utc_now,
    verify_password,
    LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS,
)

router = APIRouter(prefix="/auth", tags=["auth"])

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class Credentials(BaseModel):
    email: str
    password: str = Field(min_length=1)


class ProfileUpdate(BaseModel):
    name: str
    dob: str = Field(max_length=20)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def _validate_credentials(email: str, password: str) -> str:
    normalized = _normalize_email(email)
    if not EMAIL_PATTERN.match(normalized):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter a valid official email address, for example reviewer@department.gov.in.",
        )
    if len(password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 8 characters long.",
        )
    return normalized


def _user_payload(row, token: str | None = None) -> dict:
    name = decrypt_field(row["name"] or "")
    body = {
        "email": row["email"],
        "name": name,
        "dob": decrypt_field(row["dob"] or ""),
        "needsProfile": not bool(name.strip()),
    }
    if token:
        body["token"] = token
    return body


def _client_ip(request: Request | None) -> str:
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or str(request.client.host if request.client else "")


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
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT users.email, users.name, users.dob, sessions.expires_at
            FROM sessions
            JOIN users ON users.email = sessions.email
            WHERE sessions.token = ?
            """,
            (token,),
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )
    if is_expired(row["expires_at"]):
        # Clean up stale token
        with get_connection() as connection:
            connection.execute("DELETE FROM sessions WHERE token = ?", (token,))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
        )
    return {"email": row["email"], "name": decrypt_field(row["name"] or ""),
            "dob": decrypt_field(row["dob"] or ""), "token": token}


def _issue_session(connection, email: str) -> str:
    token = new_token()
    connection.execute(
        "INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?, ?, ?, ?)",
        (token, email, utc_now(), session_expiry()),
    )
    return token


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/signup")
def signup(body: Credentials, request: Request) -> dict:
    email = _validate_credentials(body.email, body.password)
    with get_connection() as connection:
        existing = connection.execute(
            "SELECT email FROM users WHERE email = ?", (email,)
        ).fetchone()
        if existing:
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
        audit(connection, email, "SIGNUP", ip=_client_ip(request))

    payload = _user_payload(row, token)
    payload["needsProfile"] = True
    return payload


@router.post("/signin")
def signin(body: Credentials, request: Request) -> dict:
    email = _validate_credentials(body.email, body.password)
    ip = _client_ip(request)

    with get_connection() as connection:
        row = connection.execute(
            "SELECT email, password_hash, name, dob, failed_attempts, locked_until FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No account for this email. Please sign up first.",
            )

        # Brute-force lockout check
        if row["locked_until"] and not is_expired(row["locked_until"]):
            audit(connection, email, "SIGNIN_LOCKED", ip=ip)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked due to too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes.",
            )

        if not verify_password(body.password, row["password_hash"]):
            new_attempts = (row["failed_attempts"] or 0) + 1
            locked_until = None
            if new_attempts >= MAX_FAILED_ATTEMPTS:
                from datetime import timedelta, timezone
                from datetime import datetime
                locked_until = (datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            connection.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE email = ?",
                (new_attempts, locked_until, email),
            )
            audit(connection, email, "SIGNIN_FAILED",
                  detail=f"attempt {new_attempts}", ip=ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password.",
            )

        # Successful login — reset lockout counters, purge expired sessions
        connection.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE email = ?",
            (email,),
        )
        purge_expired_sessions(connection)
        token = _issue_session(connection, email)
        audit(connection, email, "SIGNIN_OK", ip=ip)

    return _user_payload(row, token)


@router.post("/profile")
def save_profile(body: ProfileUpdate, request: Request,
                 user: dict = Depends(get_current_user)) -> dict:
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
            (encrypt_field(clean_name), encrypt_field(clean_dob), user["email"]),
        )
        row = connection.execute(
            "SELECT email, name, dob FROM users WHERE email = ?",
            (user["email"],),
        ).fetchone()
        audit(connection, user["email"], "PROFILE_UPDATE", ip=_client_ip(request))
    return _user_payload(row, user["token"])


@router.post("/logout")
def logout(request: Request, user: dict = Depends(get_current_user)) -> dict:
    with get_connection() as connection:
        connection.execute("DELETE FROM sessions WHERE token = ?", (user["token"],))
        audit(connection, user["email"], "LOGOUT", ip=_client_ip(request))
    return {"ok": True}
