"""Tests for PATCH /findings/{id} and PATCH /bundles/{id}/assign.

Covers steering rule 6 (401 unauthenticated / 403 wrong role / assignment
enforcement) and rule 4 (Pydantic validation of the decision body). All
identities are synthetic.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models import Bundle, FindingPg, ReviewDecision

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures: seed reviewers, an admin, a citizen, and one bundle + finding
# ---------------------------------------------------------------------------

@pytest.fixture()
def seeded(api_db):
    """Create reviewer_a (assigned), reviewer_b (unassigned), admin, citizen,
    plus a bundle and finding. Returns ids, ORM users, and auth headers."""
    from app.auth.tokens import create_access_token
    from app.models import UserPg

    def _user(role: str):
        session = api_db()
        try:
            user = UserPg(
                email=f"{role}-{uuid.uuid4().hex[:8]}@synthetic.example.com",
                password_hash="not-a-real-hash",
                role=role,
            )
            session.add(user)
            session.commit()
            session.refresh(user)
            token, _ = create_access_token(user.id, role, mfa_ok=True)
            return user, {"Authorization": f"Bearer {token}"}
        finally:
            session.close()

    reviewer_a, headers_a = _user("reviewer")
    reviewer_b, headers_b = _user("reviewer")
    admin, headers_admin = _user("admin")
    citizen, headers_citizen = _user("citizen")

    session = api_db()
    try:
        bundle = Bundle(
            owner_email=citizen.email,
            bundle_ref=f"synthetic-{uuid.uuid4().hex[:8]}",
            assigned_reviewer_id=reviewer_a.id,
        )
        session.add(bundle)
        session.flush()
        finding = FindingPg(
            bundle_id=bundle.id,
            field="name",
            decision="conflict",
            severity="HIGH",
            reason="Synthetic test conflict.",
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        finding_id = finding.id
        bundle_id = bundle.id
    finally:
        session.close()

    return {
        "finding_id": finding_id,
        "bundle_id": bundle_id,
        "session_factory": api_db,
        "reviewer_a": reviewer_a,
        "reviewer_b": reviewer_b,
        "admin": admin,
        "citizen": citizen,
        "headers_a": headers_a,
        "headers_b": headers_b,
        "headers_admin": headers_admin,
        "headers_citizen": headers_citizen,
    }


def _decide(finding_id, headers, status_value="accepted"):
    return client.patch(
        f"/findings/{finding_id}", headers=headers, json={"status": status_value}
    )


# ---------------------------------------------------------------------------
# PATCH /findings/{id}
# ---------------------------------------------------------------------------

def test_decide_requires_authentication(seeded):
    response = client.patch(
        f"/findings/{seeded['finding_id']}", json={"status": "accepted"}
    )
    assert response.status_code == 401


def test_decide_rejects_citizen_role(seeded):
    response = _decide(seeded["finding_id"], seeded["headers_citizen"])
    assert response.status_code == 403


def test_decide_rejects_unassigned_reviewer(seeded):
    """reviewer_b is a reviewer but the bundle is assigned to reviewer_a."""
    response = _decide(seeded["finding_id"], seeded["headers_b"])
    assert response.status_code == 403
    assert "not assigned" in response.json()["detail"]


def test_assigned_reviewer_can_accept(seeded):
    response = _decide(seeded["finding_id"], seeded["headers_a"], "accepted")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "accepted"
    assert body["reviewer_id"] == str(seeded["reviewer_a"].id)
    assert body["decided_at"]

    # The decision row persisted with reviewer id and timestamp.
    session = seeded["session_factory"]()
    try:
        row = session.query(ReviewDecision).one()
        assert row.decision == "accepted"
        assert row.reviewer_id == seeded["reviewer_a"].id
        assert row.reviewer_email == seeded["reviewer_a"].email
        assert row.decided_at is not None
    finally:
        session.close()


def test_assigned_reviewer_can_dismiss(seeded):
    response = _decide(seeded["finding_id"], seeded["headers_a"], "dismissed")
    assert response.status_code == 200
    assert response.json()["status"] == "dismissed"


def test_admin_can_decide_on_unassigned_bundle(api_db, seeded):
    """An admin may decide even when the reviewer assignment belongs to
    someone else — and also on a completely unassigned bundle."""
    session = api_db()
    try:
        bundle = session.get(Bundle, seeded["bundle_id"])
        bundle.assigned_reviewer_id = None
        session.commit()
    finally:
        session.close()

    response = _decide(seeded["finding_id"], seeded["headers_admin"], "dismissed")
    assert response.status_code == 200
    assert response.json()["reviewer_id"] == str(seeded["admin"].id)


def test_unknown_finding_returns_404(seeded):
    response = _decide(uuid.uuid4(), seeded["headers_a"])
    assert response.status_code == 404


def test_invalid_status_rejected_by_pydantic(seeded):
    response = _decide(seeded["finding_id"], seeded["headers_a"], "obliterated")
    assert response.status_code == 422


# ---------------------------------------------------------------------------
# PATCH /bundles/{id}/assign (admin only)
# ---------------------------------------------------------------------------

def test_assign_requires_authentication(seeded):
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        json={"reviewer_email": seeded["reviewer_a"].email},
    )
    assert response.status_code == 401


def test_reviewer_role_cannot_assign_bundles(seeded):
    """Assignment is admin-only: a reviewer gets 403 even for their own bundle."""
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        headers=seeded["headers_a"],
        json={"reviewer_email": seeded["reviewer_b"].email},
    )
    assert response.status_code == 403


def test_citizen_role_cannot_assign_bundles(seeded):
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        headers=seeded["headers_citizen"],
        json={"reviewer_email": seeded["reviewer_a"].email},
    )
    assert response.status_code == 403


def test_admin_can_reassign_bundle(seeded):
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        headers=seeded["headers_admin"],
        json={"reviewer_email": seeded["reviewer_b"].email},
    )
    assert response.status_code == 200
    assert response.json()["assigned_reviewer_id"] == str(seeded["reviewer_b"].id)

    # After reassignment reviewer_b can decide and reviewer_a cannot.
    assert _decide(seeded["finding_id"], seeded["headers_b"]).status_code == 200
    assert _decide(seeded["finding_id"], seeded["headers_a"]).status_code == 403


def test_assign_to_unknown_email_returns_400(seeded):
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        headers=seeded["headers_admin"],
        json={"reviewer_email": "ghost@synthetic.example.com"},
    )
    assert response.status_code == 400


def test_assign_to_citizen_email_returns_400(seeded):
    """Citizens cannot be assigned as reviewers."""
    response = client.patch(
        f"/bundles/{seeded['bundle_id']}/assign",
        headers=seeded["headers_admin"],
        json={"reviewer_email": seeded["citizen"].email},
    )
    assert response.status_code == 400


def test_unknown_bundle_returns_404(seeded):
    response = client.patch(
        f"/bundles/{uuid.uuid4()}/assign",
        headers=seeded["headers_admin"],
        json={"reviewer_email": seeded["reviewer_a"].email},
    )
    assert response.status_code == 404


