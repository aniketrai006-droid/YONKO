"""PDF upload tests built from the repository's synthetic images."""

from __future__ import annotations

import pymupdf
from fastapi.testclient import TestClient
from PIL import Image

from app.api.routes import MAX_PDF_PAGES
from app.main import app

client = TestClient(app)

ROOT = "data/synthetic/bundle_0001"


def _pdf_bytes(*image_names: str) -> bytes:
    """Wrap synthetic PNGs as one PDF page each."""
    document = pymupdf.open()
    for name in image_names:
        path = f"{ROOT}/{name}"
        with Image.open(path) as image:
            width, height = image.size
        page = document.new_page(width=width, height=height)
        page.insert_image(pymupdf.Rect(0, 0, width, height), filename=path)
    payload = document.tobytes()
    document.close()
    return payload


def _open_image(name: str):
    return open(f"{ROOT}/{name}", "rb")


def test_api_info_lists_pdf_support():
    body = client.get("/api/info").json()
    assert ".pdf" in body["supported_file_types"]
    assert body["pdf_pages_rendered_as_images"] is True
    assert body["maximum_pdf_pages_per_file"] == MAX_PDF_PAGES


def test_analyze_accepts_a_pdf_beside_an_image(auth_headers):
    with _open_image("address_proof.png") as image:
        response = client.post(
            "/analyze",
            headers=auth_headers(),
            files=[("files", ("id_card.pdf", _pdf_bytes("id_card.png"),
                              "application/pdf")),
                   ("files", ("address_proof.png", image, "image/png"))])
    assert response.status_code == 200, response.text
    assert response.json()["documents_processed"] >= 2


def test_analyze_renders_every_page_of_a_pdf(auth_headers):
    pdf = _pdf_bytes("id_card.png", "income_certificate.png")
    with _open_image("address_proof.png") as image:
        response = client.post(
            "/analyze",
            headers=auth_headers(),
            files=[("files", ("bundle.pdf", pdf, "application/pdf")),
                   ("files", ("address_proof.png", image, "image/png"))])
    assert response.status_code == 200, response.text
    assert response.json()["documents_processed"] == 3


def test_analyze_rejects_unreadable_pdf(auth_headers):
    with _open_image("address_proof.png") as image:
        response = client.post(
            "/analyze",
            headers=auth_headers(),
            files=[("files", ("broken.pdf", b"%PDF-1.7 broken", "application/pdf")),
                   ("files", ("address_proof.png", image, "image/png"))])
    assert response.status_code == 400
    assert "not a readable PDF" in response.json()["detail"]


def test_analyze_rejects_pdf_above_the_page_limit(auth_headers):
    oversized = _pdf_bytes(*["id_card.png"] * (MAX_PDF_PAGES + 1))
    with _open_image("address_proof.png") as image:
        response = client.post(
            "/analyze",
            headers=auth_headers(),
            files=[("files", ("oversized.pdf", oversized, "application/pdf")),
                   ("files", ("address_proof.png", image, "image/png"))])
    assert response.status_code == 400
    assert f"the limit is {MAX_PDF_PAGES}" in response.json()["detail"]


def test_analyze_rejects_pdf_content_declared_as_something_else(auth_headers):
    with _open_image("address_proof.png") as image:
        response = client.post(
            "/analyze",
            headers=auth_headers(),
            files=[("files", ("id_card.pdf", _pdf_bytes("id_card.png"),
                              "text/plain")),
                   ("files", ("address_proof.png", image, "image/png"))])
    assert response.status_code == 400
    assert "content type" in response.json()["detail"]
