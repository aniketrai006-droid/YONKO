"""FastAPI auth dependencies: get_current_user and require_role.

Security rationale (steering rule 6): every privileged endpoint must call
require_role(...). The dependency validates the Bearer access token,
loads the user from the database (so deactivated or locked accounts lose
access immediately, unlike stateless-only checks), and enforces that
reviewer/admin tokens were issued after MFA verification.
"""
from __future__ import annotations

import uuid
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.tokens import decode_access_token
from app.database import get_db
from app.models import UserPg

# Roles that must complete TOTP MFA at login before their token is usable
# on protected endpoints.
MFA_REQUIRED_ROLES = {"reviewer", "admin"}


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def _resolve_user(
    request: Request, db: Session, *, allow_bootstrap: bool
) -> UserPg:
    """Core user resolution shared by both public dependencies."""
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        raise _unauthorized("Authentication required.")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise _unauthorized("Authentication required.")

    payload = decode_access_token(token)
    if payload is None:
        raise _unauthorized("Invalid or expired token.")

    try:
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError):
        raise _unauthorized("Invalid token payload.")

    user = db.execute(
        select(UserPg).where(UserPg.id == user_id)
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise _unauthorized("Account is not active.")

    # A locked-out account cannot use previously issued tokens either.
    from datetime import datetime, timezone
    if user.locked_until is not None:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) < locked_until:
            raise _unauthorized("Account is temporarily locked.")

    # Reviewer/admin tokens only count as fully authenticated when they were
    # minted after a successful TOTP check (mfa_ok claim). Password-only
    # tokens (pre-enrollment bootstrap) are deliberately insufficient —
    # except on the enrollment route, which is how they bootstrap.
    if (
        user.role in MFA_REQUIRED_ROLES
        and not payload.get("mfa_ok")
        and not allow_bootstrap
    ):
        raise _unauthorized(
            "Multi-factor authentication required. Provide a valid TOTP "
            "code at login."
        )

    # Bind the verified identity to the DB session for Row-Level Security.
    # Values come from the UserPg row loaded above (server-side), never from
    # client-supplied headers or body fields. Placed AFTER every check so a
    # rejected request never receives a database identity.
    from app.database import set_rls_context

    set_rls_context(db, user.id, user.role)

    return user


def get_current_user(
    request: Request, db: Session = Depends(get_db)
) -> UserPg:
    """Resolve the authenticated user from the Authorization header.

    Raises 401 when the header is missing, the token is invalid or expired,
    the account was deleted/deactivated, or the account is currently locked.
    Reviewer/admin tokens must carry mfa_ok=True (i.e. be minted after a
    successful TOTP login); pre-enrollment bootstrap tokens are rejected.
    """
    return _resolve_user(request, db, allow_bootstrap=False)


def get_user_bootstrap_or_verified(
    request: Request, db: Session = Depends(get_db)
) -> UserPg:
    """Like get_current_user but accepts pre-MFA-enrollment bootstrap tokens.

    Used ONLY by POST /auth/mfa/enroll: an unenrolled reviewer must be able
    to reach this one endpoint or they could never complete enrollment.
    Every other protected endpoint uses get_current_user or require_role,
    which reject bootstrap tokens for reviewer/admin.
    """
    return _resolve_user(request, db, allow_bootstrap=True)


def require_role(*allowed_roles: str) -> Callable[..., UserPg]:
    """Dependency factory: allow only the listed roles.

    Usage:
        @router.post("/example")
        def example(user: UserPg = Depends(require_role("admin"))):
            ...

    Raises 401 when unauthenticated and 403 when the authenticated user's
    role is not in allowed_roles (steering rule 6).
    """
    if not allowed_roles:
        raise ValueError("require_role needs at least one role")

    def dependency(user: UserPg = Depends(get_current_user)) -> UserPg:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Role '{user.role}' is not permitted to access this "
                    "resource."
                ),
            )
        return user

    return dependency
