"""HTTP routes for signing in with Google."""

from __future__ import annotations

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from app.auth.google import (GoogleAuthError, issue_session, read_session,
                             verify_google_credential)

router = APIRouter(prefix="/auth", tags=["auth"])


class GoogleCredential(BaseModel):
    credential: str


@router.post("/google")
async def sign_in_with_google(payload: GoogleCredential) -> dict[str, object]:
    """Verify a Google ID token and return a signed session for the reviewer."""
    try:
        user = await verify_google_credential(payload.credential)
    except GoogleAuthError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    return {
        "access_token": issue_session(user),
        "token_type": "bearer",
        "user": user,
    }


@router.get("/me")
def current_session(authorization: str | None = Header(default=None)) -> dict[str, object]:
    """Return the signed-in reviewer for a session token issued by /auth/google."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Sign in with Google to continue.")
    user = read_session(token.strip())
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Session is invalid or expired.")
    return {"user": user}
