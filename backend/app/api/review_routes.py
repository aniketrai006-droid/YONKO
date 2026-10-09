"""Reviewer decision endpoints: PATCH /findings/{id} and bundle assignment.

Security decisions (steering rule 8):
- PATCH /findings/{id} requires the reviewer/admin role (require_role) AND,
  for reviewers, that the finding's bundle is assigned to them. Admins may
  decide on any bundle. Unassigned bundles are decideable by admins only.
- Decisions are append-only rows in review_decisions recording the opaque
  reviewer UUID and a server timestamp — the client cannot influence either.
- PATCH /bundles/{id}/assign is admin-only: reviewers cannot reassign work
  to themselves or others (privilege-escalation guard, steering rule 6).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.database import get_db
from app.models import Bundle, FindingPg, ReviewDecision, UserPg

router = APIRouter(tags=["review"])


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class DecisionBody(BaseModel):
    # Literal gives Pydantic-native validation: any other value is a 422.
    status: Literal["accepted", "dismissed"]


class AssignBody(BaseModel):
    reviewer_email: str = Field(min_length=3)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.patch("/findings/{finding_id}")
def decide_on_finding(
    finding_id: uuid.UUID,
    body: DecisionBody,
    user: UserPg = Depends(require_role("reviewer", "admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Record an accept/dismiss decision on a finding.

    Reviewers may only decide on findings whose bundle is assigned to them
    (403 otherwise). Admins may decide on any finding. The decision, the
    reviewer's opaque UUID, and a server-side timestamp are persisted in
    review_decisions; the response echoes them.
    """
    finding = db.execute(
        select(FindingPg).where(FindingPg.id == finding_id)
    ).scalar_one_or_none()
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found.",
        )

    bundle = db.execute(
        select(Bundle).where(Bundle.id == finding.bundle_id)
    ).scalar_one_or_none()

    # Authorization: admins bypass assignment; reviewers must be assigned.
    if user.role != "admin":
        if bundle is None or bundle.assigned_reviewer_id != user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "This case is not assigned to you. Only the assigned "
                    "reviewer or an admin may decide on its findings."
                ),
            )

    decision = ReviewDecision(
        finding_id=finding.id,
        reviewer_id=user.id,
        # Denormalized for the existing dashboard queries; the UUID above is
        # the authoritative attribution.
        reviewer_email=user.email,
        decision=body.status,
        decided_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    db.add(decision)
    db.commit()
    db.refresh(decision)

    return {
        "finding_id": str(finding.id),
        "status": decision.decision,
        "reviewer_id": str(decision.reviewer_id),
        "decided_at": decision.decided_at.isoformat(),
    }


@router.patch("/bundles/{bundle_id}/assign")
def assign_bundle(
    bundle_id: uuid.UUID,
    body: AssignBody,
    user: UserPg = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    """Assign a bundle to a reviewer (admin only).

    The target must be an existing active account with the reviewer or admin
    role. Reviewers cannot call this endpoint at all (403).
    """
    bundle = db.execute(
        select(Bundle).where(Bundle.id == bundle_id)
    ).scalar_one_or_none()
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Bundle not found.",
        )

    reviewer = db.execute(
        select(UserPg).where(UserPg.email == body.reviewer_email.lower().strip())
    ).scalar_one_or_none()
    if reviewer is None or not reviewer.is_active or reviewer.role not in {
        "reviewer", "admin"
    }:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active reviewer account for that email.",
        )

    bundle.assigned_reviewer_id = reviewer.id
    db.commit()

    return {
        "bundle_id": str(bundle.id),
        "assigned_reviewer_id": str(reviewer.id),
    }
