"""Per-reviewer cases. Each account only sees the applications it created."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.auth.deps import get_current_user
from app.db import get_connection
from app.models import UserPg

router = APIRouter(tags=["cases"])

VALID_DECISIONS = {"pending", "accepted", "dismissed"}
VALID_STATUSES = {
    "draft",
    "processing",
    "needs_review",
    "conflicts_found",
    "cleared",
}
SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


class CreateCaseBody(BaseModel):
    applicantName: str
    applicationType: str
    notes: str = ""


class FindingDecisionBody(BaseModel):
    decision: str


class CaseStatusBody(BaseModel):
    status: str


class NotesBody(BaseModel):
    notes: str = ""


class AnalysisBody(BaseModel):
    documents_processed: int | None = None
    findings: list[dict] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ImportCaseBody(BaseModel):
    case: dict


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _not_found(case_id: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Case {case_id} was not found.",
    )


def _load_case(connection, owner_email: str, case_id: str) -> dict:
    row = connection.execute(
        "SELECT payload FROM cases WHERE id = ? AND owner_email = ?",
        (case_id, owner_email),
    ).fetchone()
    if not row:
        raise _not_found(case_id)
    return json.loads(row["payload"])


def _save_case(connection, owner_email: str, item: dict) -> dict:
    item["updatedAt"] = _now()
    connection.execute(
        """
        INSERT INTO cases (id, owner_email, payload, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(id, owner_email) DO UPDATE SET
            payload = excluded.payload,
            updated_at = excluded.updated_at
        """,
        (item["id"], owner_email, json.dumps(item), item["updatedAt"]),
    )
    return item


def derive_status(item: dict) -> str:
    findings = item.get("findings") or []
    if not findings:
        return "cleared" if item.get("status") == "cleared" else item.get("status") or "draft"

    decisions = item.get("decisions") or {}
    pending = [
        finding
        for finding in findings
        if decisions.get(finding.get("id"), "pending") == "pending"
    ]
    if not pending:
        return "cleared"

    highest = 0
    for finding in pending:
        rank = SEVERITY_RANK.get(str(finding.get("severity") or "").upper(), 0)
        if rank > highest:
            highest = rank
    return "conflicts_found" if highest >= SEVERITY_RANK["HIGH"] else "needs_review"


def conflict_count(item: dict) -> int:
    return len(item.get("findings") or [])


def status_counts(cases: list[dict]) -> dict:
    return {
        "total": len(cases),
        "needsReview": sum(1 for item in cases if item.get("status") == "needs_review"),
        "conflictsFound": sum(1 for item in cases if item.get("status") == "conflicts_found"),
        "cleared": sum(1 for item in cases if item.get("status") == "cleared"),
    }


def _owner_cases(connection, owner_email: str) -> list[dict]:
    rows = connection.execute(
        "SELECT payload FROM cases WHERE owner_email = ?",
        (owner_email,),
    ).fetchall()
    return [json.loads(row["payload"]) for row in rows]


@router.get("/cases")
def list_cases(
    query: str = "",
    status_filter: str = Query("all", alias="status"),
    page: int = 1,
    pageSize: int = 6,
    user: UserPg = Depends(get_current_user),
) -> dict:
    with get_connection() as connection:
        cases = _owner_cases(connection, user.email)

    counts = status_counts(cases)
    needle = query.strip().lower()
    filtered = []
    for item in cases:
        matches_query = (
            not needle
            or needle in str(item.get("id", "")).lower()
            or needle in str(item.get("applicantName", "")).lower()
        )
        matches_status = status_filter == "all" or item.get("status") == status_filter
        if matches_query and matches_status:
            filtered.append(item)

    filtered.sort(key=lambda item: item.get("updatedAt") or "", reverse=True)
    start = max(page - 1, 0) * pageSize
    return {
        "items": filtered[start : start + pageSize],
        "total": len(filtered),
        "page": page,
        "pageSize": pageSize,
        "counts": counts,
    }


@router.post("/cases")
def create_case(body: CreateCaseBody, user: UserPg = Depends(get_current_user)) -> dict:
    applicant = body.applicantName.strip()
    application_type = body.applicationType.strip()
    if not applicant:
        raise HTTPException(status_code=400, detail="Applicant name is required.")
    if not application_type:
        raise HTTPException(status_code=400, detail="Application type is required.")

    with get_connection() as connection:
        cases = _owner_cases(connection, user.email)
        highest = 1000
        for item in cases:
            digits = re.sub(r"\D", "", str(item.get("id", "")))
            if digits.isdigit():
                highest = max(highest, int(digits))
        timestamp = _now()
        created = {
            "id": f"CASE-{highest + 1}",
            "applicantName": applicant,
            "applicationType": application_type,
            "notes": body.notes.strip(),
            "documentCount": 0,
            "createdAt": timestamp,
            "updatedAt": timestamp,
            "status": "draft",
            "decisions": {},
            "findings": [],
            "ignored": [],
        }
        _save_case(connection, user.email, created)
    return created


@router.post("/cases/import")
def import_case(body: ImportCaseBody, user: UserPg = Depends(get_current_user)) -> dict:
    """Move a locally created case (for example Piyush) onto this reviewer."""
    source = dict(body.case or {})
    case_id = str(source.get("id") or "").strip()
    if not case_id:
        raise HTTPException(status_code=400, detail="Imported case is missing an id.")
    if not str(source.get("applicantName") or "").strip():
        raise HTTPException(status_code=400, detail="Imported case is missing an applicant.")

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM cases WHERE id = ? AND owner_email = ?",
            (case_id, user.email),
        ).fetchone()
        if existing:
            return _load_case(connection, user.email, case_id)
        source.setdefault("notes", "")
        source.setdefault("documentCount", 0)
        source.setdefault("status", "draft")
        source.setdefault("decisions", {})
        source.setdefault("findings", [])
        source.setdefault("ignored", [])
        source.setdefault("createdAt", _now())
        return _save_case(connection, user.email, source)


@router.get("/cases/{case_id}")
def get_case(case_id: str, user: UserPg = Depends(get_current_user)) -> dict:
    with get_connection() as connection:
        return _load_case(connection, user.email, case_id)


@router.patch("/cases/{case_id}/findings/{finding_id}")
def update_finding(
    case_id: str,
    finding_id: str,
    body: FindingDecisionBody,
    user: UserPg = Depends(get_current_user),
) -> dict:
    if body.decision not in VALID_DECISIONS:
        raise HTTPException(status_code=400, detail=f"Unknown decision: {body.decision}")
    with get_connection() as connection:
        item = _load_case(connection, user.email, case_id)
        decisions = dict(item.get("decisions") or {})
        decisions[finding_id] = body.decision
        item["decisions"] = decisions
        item["status"] = derive_status(item)
        return _save_case(connection, user.email, item)


@router.patch("/cases/{case_id}/status")
def update_case_status(
    case_id: str,
    body: CaseStatusBody,
    user: UserPg = Depends(get_current_user),
) -> dict:
    if body.status not in VALID_STATUSES:
        raise HTTPException(status_code=400, detail=f"Unknown status: {body.status}")
    with get_connection() as connection:
        item = _load_case(connection, user.email, case_id)
        item["status"] = body.status
        return _save_case(connection, user.email, item)


@router.patch("/cases/{case_id}/notes")
def save_notes(
    case_id: str, body: NotesBody, user: UserPg = Depends(get_current_user)
) -> dict:
    with get_connection() as connection:
        item = _load_case(connection, user.email, case_id)
        item["notes"] = str(body.notes or "")
        return _save_case(connection, user.email, item)


@router.post("/cases/{case_id}/analysis")
def attach_analysis(
    case_id: str, body: AnalysisBody, user: UserPg = Depends(get_current_user)
) -> dict:
    with get_connection() as connection:
        item = _load_case(connection, user.email, case_id)
        source = body.findings or []
        if body.documents_processed is not None:
            item["documentCount"] = body.documents_processed

        item["findings"] = [
            {
                "id": f"{entry.get('field')}-{index}",
                "field": entry.get("field"),
                "severity": str(entry.get("severity") or "NONE").upper(),
                "values": [
                    {
                        "document": evidence.get("document_type"),
                        "value": evidence.get("raw_value")
                        or evidence.get("normalized_value")
                        or "—",
                    }
                    for evidence in (entry.get("evidence") or [])
                ],
                "location": {
                    "document": (entry.get("evidence") or [{}])[0].get(
                        "document_type", "—"
                    )
                    if entry.get("evidence")
                    else "—",
                    "field": str(entry.get("field") or "")
                    .replace("_", " ")
                    .lower()
                    .title(),
                },
                "explanation": entry.get("reason") or entry.get("recommended_action") or "",
            }
            for index, entry in enumerate(source)
            if entry.get("decision") != "harmless_variant"
        ]

        harmless = [
            {
                "id": f"harmless-{index}",
                "field": entry.get("field"),
                "values": [
                    evidence.get("raw_value") or evidence.get("normalized_value")
                    for evidence in (entry.get("evidence") or [])
                    if evidence.get("raw_value") or evidence.get("normalized_value")
                ],
                "reason": entry.get("reason") or "",
            }
            for index, entry in enumerate(source)
            if entry.get("decision") == "harmless_variant"
        ]

        ignored = list(item.get("ignored") or []) + harmless
        seen: set[str] = set()
        unique = []
        for entry in ignored:
            key = f"{entry.get('field')}|{'|'.join(entry.get('values') or [])}"
            if key in seen:
                continue
            seen.add(key)
            unique.append(entry)
        item["ignored"] = unique

        decisions = dict(item.get("decisions") or {})
        for entry in item["findings"]:
            decisions.setdefault(entry["id"], "pending")
        item["decisions"] = decisions
        item["status"] = derive_status(item)
        return _save_case(connection, user.email, item)
