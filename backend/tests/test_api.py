"""API contract tests using only the repository's synthetic images."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _bundle_files():
    root = "data/synthetic/bundle_0001"
    return [
        ("files", (name, open(f"{root}/{name}", "rb"), "image/png"))
        for name in ("id_card.png", "address_proof.png", "income_certificate.png")
    ]


def test_health_endpoints_remain_available():
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/health/ocr").status_code == 200


def test_api_info_describes_upload_contract():
    response = client.get("/api/info")
    assert response.status_code == 200
    body = response.json()
    assert body["minimum_file_count"] == 2
    assert body["maximum_file_count"] == 10
    assert body["image_only"] is False
    assert ".png" in body["supported_file_types"]
    assert ".pdf" in body["supported_file_types"]


def test_analyze_requires_authentication():
    """POST /analyze is auth-protected: no token means 401 (steering rule 6)."""
    files = _bundle_files()
    try:
        response = client.post("/analyze", files=files)
    finally:
        for _, (_, handle, _) in files:
            handle.close()
    assert response.status_code == 401


def test_analyze_accepts_synthetic_images_and_does_not_persist_uploads(auth_headers):
    files = _bundle_files()
    try:
        response = client.post("/analyze", files=files, headers=auth_headers())
    finally:
        for _, (_, handle, _) in files:
            handle.close()
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["documents_processed"] == 3
    assert "summary" in body
    assert "findings" in body


def test_analyze_rejects_too_few_files(auth_headers):
    with open("data/synthetic/bundle_0001/id_card.png", "rb") as image:
        response = client.post(
            "/analyze", files={"files": ("id_card.png", image, "image/png")},
            headers=auth_headers())
    assert response.status_code == 400
    assert "between 2 and 10" in response.json()["detail"]


def test_analyze_rejects_non_image_upload(auth_headers):
    with open("data/synthetic/bundle_0001/id_card.png", "rb") as image:
        files = [
            ("files", ("id_card.png", image, "image/png")),
            ("files", ("note.txt", b"not an image", "text/plain")),
        ]
        response = client.post("/analyze", files=files, headers=auth_headers())
    assert response.status_code == 400
    assert "Only PNG" in response.json()["detail"]
