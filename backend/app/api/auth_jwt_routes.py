"""JWT authentication routes: register, login, refresh, logout, me, MFA.

Replaces the demo local-storage reviewer accounts. All state lives in
PostgreSQL (users_pg, refresh_tokens); the SQLite session layer is untouched
here and gets removed in a later part once the frontend is migrated.

Security decisions (steering rule 8 — see also docs/SECURITY.md):
- Passwords hashed with Argon2id (app.auth.passwords).
- Access tokens: 15-minute HS256 JWTs carrying sub/role/mfa_ok only — no PII.
- Refresh tokens: rotated on every use; only their SHA-256 is stored. Reusing
  a consumed token revokes the whole family (theft detection, RFC 9700).
- Reviewer/admin logins require a TOTP code once enrolled; before enrollment
  a password-only bootstrap token is issued but is rejected by
  get_current_user on every protected endpoint (see app.auth.deps).
- Repeated failed logins lock the account for AUTH_LOCKOUT_MINUTES.
- Audit rows record opaque user UUIDs only — never emails or tokens (Rule 7).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.auth import totp as totp_helper
from app.auth.deps import (
    MFA_REQUIRED_ROLES,
    get_current_user,
    get_user_bootstrap_or_verified,
)
from app.auth.passwords import (
    hash_password,
    validate_password,
    verify_password,
)
from app.auth.tokens import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_token,
)
from app.config import settings
from app.database import get_db
from app.models import AuditLogPg, RefreshToken, UserPg

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth-jwt"])


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class RegisterBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    role: str = Field(default="citizen")


class LoginBody(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1)
    totp_code: str | None = None


class RefreshBody(BaseModel):
    refresh_token: str = Field(min_length=1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(
    db: Session,
    actor_id: uuid.UUID | None,
    action: str,
    outcome: str = "success",
) -> None:
    """Append a security event to the audit log.

    Security: actor_id is the opaque user UUID — never an email, name, or
    token (steering rule 7). Failures here must not break the auth flow, so
    exceptions are swallowed after logging.
    """
    try:
        db.add(AuditLogPg(
            actor_id=str(actor_id) if actor_id else None,
            action=action,
            resource_type="auth",
            outcome=outcome,
        ))
        db.commit()
    except Exception:  # pragma: no cover - audit must never break auth
        db.rollback()
        logger.exception("Failed to write audit event %s", action)


def _find_user(db: Session, email: str) -> UserPg | None:
    return db.execute(
        select(UserPg).where(UserPg.email == email)
    ).scalar_one_or_none()


def _issue_tokens(db: Session, user: UserPg, mfa_ok: bool) -> dict:
    """Create an access token plus a new refresh-token family."""
    access_token, _ = create_access_token(user.id, user.role, mfa_ok)

    # The root refresh row is its own family anchor (self-referencing FK).
    family_id = uuid.uuid4()
    refresh_token, expires_at = create_refresh_token(user.id, family_id)
    db.add(RefreshToken(
        id=family_id,
        user_id=user.id,
        token_hash=hash_token(refresh_token),
        family_id=family_id,
        expires_at=expires_at.replace(tzinfo=None),
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.AUTH_ACCESS_TOKEN_TTL_MINUTES * 60,
        "mfa_ok": mfa_ok,
    }


def _revoke_family(db: Session, family_id: uuid.UUID) -> None:
    """Revoke every outstanding refresh token in a rotation family."""
    db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id)
        .values(revoked=True)
    )


def _locked(user: UserPg) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < locked_until


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterBody, db: Session = Depends(get_db)) -> dict:
    """Create an account.

    Self-registration is limited to the 'citizen' role — reviewer and admin
    accounts must be provisioned out-of-band (privilege-escalation guard,
    steering rule 6). Returns 201 with the account summary; no tokens are
    issued here (login is a separate, auditable step).
    """
    email = body.email.lower().strip()
    if body.role not in {"citizen"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the 'citizen' role can be self-registered.",
        )
    policy_error = validate_password(body.password)
    if policy_error:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=policy_error
        )
    if _find_user(db, email):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account already exists for this email.",
        )

    user = UserPg(
        email=email,
        password_hash=hash_password(body.password),
        role="citizen",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _audit(db, user.id, "REGISTER")
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.post("/login")
def login(body: LoginBody, db: Session = Depends(get_db)) -> dict:
    """Authenticate with email + password (+ TOTP for reviewer/admin).

    MFA bootstrap: a reviewer/admin who has not yet enrolled may log in with
    the password alone; the resulting tokens carry mfa_ok=False and are
    rejected by get_current_user on every protected endpoint until they
    complete a TOTP login after enrolling.
    """
    email = body.email.lower().strip()
    user = _find_user(db, email)

    # Uniform failure message: never reveal whether the account exists.
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password.",
    )

    if user is None or not user.is_active:
        # Run a dummy verify to keep timing roughly constant.
        verify_password(body.password, hash_password("dummy-timing-pad-pw"))
        raise invalid

    if _locked(user):
        _audit(db, user.id, "LOGIN_BLOCKED_LOCKED", outcome="failure")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Account locked due to too many failed attempts. "
                f"Try again in {settings.AUTH_LOCKOUT_MINUTES} minutes."
            ),
        )

    if not verify_password(body.password, user.password_hash):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= settings.AUTH_MAX_FAILED_ATTEMPTS:
            user.locked_until = (
                _now() + timedelta(minutes=settings.AUTH_LOCKOUT_MINUTES)
            ).replace(tzinfo=None)
        db.commit()
        _audit(db, user.id, "LOGIN_FAILED", outcome="failure")
        raise invalid

    # Password is correct — evaluate MFA requirements.
    mfa_ok = True
    if user.role in MFA_REQUIRED_ROLES:
        if user.totp_secret is None:
            # Pre-enrollment bootstrap: password-only token, not usable on
            # protected endpoints (get_current_user checks mfa_ok).
            mfa_ok = False
        else:
            secret = totp_helper.decrypt_secret(user.totp_secret)
            if not totp_helper.verify_code(secret, body.totp_code or ""):
                user.failed_attempts = (user.failed_attempts or 0) + 1
                if user.failed_attempts >= settings.AUTH_MAX_FAILED_ATTEMPTS:
                    user.locked_until = (
                        _now() + timedelta(
                            minutes=settings.AUTH_LOCKOUT_MINUTES
                        )
                    ).replace(tzinfo=None)
                db.commit()
                _audit(db, user.id, "LOGIN_FAILED_MFA", outcome="failure")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or missing MFA code.",
                )
            mfa_ok = True

    # Successful login — reset lockout state and issue rotated tokens.
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()

    tokens = _issue_tokens(db, user, mfa_ok)
    _audit(db, user.id, "LOGIN_OK")
    return {
        **tokens,
        "user": {
            "id": str(user.id),
            "email": user.email,
            "role": user.role,
            "mfa_enrolled": user.totp_secret is not None,
        },
    }


@router.post("/refresh")
def refresh(body: RefreshBody, db: Session = Depends(get_db)) -> dict:
    """Exchange a refresh token for a new access + refresh token pair.

    Rotation: the presented token is marked used and a new token joins the
    same family. Presenting an already-used or revoked token is treated as
    theft — the entire family is revoked and the caller gets 401.
    """
    payload = decode_refresh_token(body.refresh_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    row = db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(body.refresh_token)
        )
    ).scalar_one_or_none()
    if row is None or row.revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )
    if row.used:
        # Reuse of a consumed token — assume theft, kill the family.
        _revoke_family(db, row.family_id)
        db.commit()
        _audit(db, row.user_id, "REFRESH_REUSE_DETECTED", outcome="failure")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected. Session revoked.",
        )

    expires = row.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    user = db.get(UserPg, row.user_id)
    if user is None or not user.is_active or _locked(user):
        _revoke_family(db, row.family_id)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    # Rotate: consume this token and issue a fresh one in the same family.
    # A refresh never *raises* mfa_ok above the bootstrap state: a
    # password-only bootstrap session stays bootstrap until the user logs
    # in with a TOTP code.
    row.used = True
    access_token, _ = create_access_token(
        user.id, user.role,
        mfa_ok=user.role not in MFA_REQUIRED_ROLES,
    )
    new_refresh, new_expires = create_refresh_token(user.id, row.family_id)
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hash_token(new_refresh),
        family_id=row.family_id,
        expires_at=new_expires.replace(tzinfo=None),
    ))
    db.commit()
    _audit(db, user.id, "REFRESH_OK")
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.AUTH_ACCESS_TOKEN_TTL_MINUTES * 60,
    }


@router.post("/logout")
def logout(
    body: RefreshBody,
    user: UserPg = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke the caller's refresh-token family and return ok.

    Requires a valid access token so logout cannot be used to probe token
    validity. Revocation is family-wide: every device in the session tree
    is signed out.
    """
    payload = decode_refresh_token(body.refresh_token)
    if payload is None or payload.get("sub") != str(user.id):
        # Never reveal whether the token belongs to someone else.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid refresh token.",
        )
    row = db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == hash_token(body.refresh_token)
        )
    ).scalar_one_or_none()
    if row is not None:
        _revoke_family(db, row.family_id)
        db.commit()
    _audit(db, user.id, "LOGOUT")
    return {"ok": True}


@router.get("/me")
def me(user: UserPg = Depends(get_current_user)) -> dict:
    """Return the authenticated user's profile (no secrets)."""
    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role,
        "mfa_enrolled": user.totp_secret is not None,
    }


@router.post("/mfa/enroll")
def mfa_enroll(
    user: UserPg = Depends(get_user_bootstrap_or_verified),
    db: Session = Depends(get_db),
) -> dict:
    """Generate a TOTP secret and return the otpauth:// provisioning URI.

    The secret is stored AES-GCM encrypted. The user must then log in with
    a valid TOTP code for mfa_ok to become true on their tokens.
    """
    if user.totp_secret is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enrolled for this account.",
        )
    secret = totp_helper.generate_totp_secret()
    user.totp_secret = totp_helper.encrypt_secret(secret)
    db.commit()
    _audit(db, user.id, "MFA_ENROLL")
    return {
        "provisioning_uri": totp_helper.provisioning_uri(secret, user.email),
        "secret": secret,  # shown once for manual entry; never logged
        "digits": totp_helper.TOTP_DIGITS,
        "interval": totp_helper.TOTP_INTERVAL,
    }


