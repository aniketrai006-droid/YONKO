"""HTTP routes for temporary, privacy-preserving document analysis.

Hardened for untrusted input:

- ``/analyze`` requires a signed-in reviewer (no anonymous OCR jobs) and is
  rate limited per account.
- Uploads are capped per file (MAX_UPLOAD_BYTES) while streaming, so a huge
  body is rejected before it is buffered.
- The declared extension must match the file's magic bytes, defeating
  content-spoofing (for example a script renamed to ``.png``).
- Files are written under generated names in a private temp directory;
  client paths are never trusted, and everything is deleted afterwards.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import (APIRouter, Depends, File, HTTPException, Request,
                     UploadFile, status)

from app.api.auth_routes import get_current_user
from app.db import record_audit
from app.detect.engine import detect_bundle
from app.detect.types import DetectionError
from app.ocr.types import OCRError
from app.ratelimit import (analyze_rate_limit_per_minute, get_client_ip,
                           limiter)

router = APIRouter(tags=["analysis"])

MIN_FILES = 2
MAX_FILES = 10
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg"}
PDF_SUFFIX = ".pdf"
ALLOWED_SUFFIXES = IMAGE_SUFFIXES | {PDF_SUFFIX}
MAX_PDF_PAGES = 10
PDF_RENDER_ZOOM = 2.0
MAX_UPLOAD_BYTES = 16 * 1024 * 1024  # 16 MB per file

_MAGIC_PREFIXES = {
    ".png": (b"\x89PNG\r\n\x1a\n",),
    ".jpg": (b"\xff\xd8\xff",),
    ".jpeg": (b"\xff\xd8\xff",),
    ".pdf": (b"%PDF-",),
}


def _bad_request(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def _render_pdfs(temp_dir: Path) -> None:
    """Rasterize every uploaded PDF into PNG pages for the OCR pipeline.

    The original PDF is deleted as soon as its pages exist, so only derived
    images ever reach the detection engine.
    """
    import pymupdf

    for pdf_path in sorted(temp_dir.glob(f"*{PDF_SUFFIX}")):
        document = None
        try:
            document = pymupdf.open(stream=pdf_path.read_bytes(),
                                    filetype="pdf")
            page_count = document.page_count
            if page_count < 1:
                raise _bad_request(
                    f"Uploaded PDF '{pdf_path.name}' has no pages.")
            if page_count > MAX_PDF_PAGES:
                raise _bad_request(
                    f"Uploaded PDF '{pdf_path.name}' has {page_count} pages; "
                    f"the limit is {MAX_PDF_PAGES} pages per file.")
            for index in range(page_count):
                pixmap = document.load_page(index).get_pixmap(
                    matrix=pymupdf.Matrix(PDF_RENDER_ZOOM, PDF_RENDER_ZOOM))
                (temp_dir / f"{pdf_path.stem}_page{index + 1:02d}.png"
                 ).write_bytes(pixmap.tobytes("png"))
        except HTTPException:
            raise
        except Exception as exc:
            raise _bad_request(
                f"Uploaded file '{pdf_path.name}' is not a readable PDF."
            ) from exc
        finally:
            if document is not None:
                try:
                    document.close()
                except Exception:  # pragma: no cover - defensive cleanup
                    pass
            try:
                pdf_path.unlink(missing_ok=True)
            except OSError:  # pragma: no cover - locked temp file on Windows
                pass


@router.get("/api/info")
def api_info() -> dict[str, object]:
    """Describe the upload contract without exposing any user data."""
    return {
        "project_name": "AI Document Contradiction Detector",
        "supported_file_types": sorted(ALLOWED_SUFFIXES),
        "minimum_file_count": MIN_FILES,
        "maximum_file_count": MAX_FILES,
        "image_only": False,
        "pdf_pages_rendered_as_images": True,
        "maximum_pdf_pages_per_file": MAX_PDF_PAGES,
        "maximum_upload_bytes": MAX_UPLOAD_BYTES,
        "synthetic_demo_data_only": True,
    }


def _matches_magic(suffix: str, head: bytes) -> bool:
    expected = _MAGIC_PREFIXES.get(suffix)
    if not expected:
        return False
    return any(head.startswith(prefix) for prefix in expected)


async def _read_capped(upload: UploadFile, suffix: str) -> bytes:
    """Stream one upload with a hard size cap and magic-byte validation."""
    buffer = bytearray()
    while len(buffer) <= MAX_UPLOAD_BYTES:
        chunk = await upload.read(min(1024 * 1024, MAX_UPLOAD_BYTES + 1 - len(buffer)))
        if not chunk:
            break
        buffer.extend(chunk)
    if len(buffer) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Uploaded file '{upload.filename}' exceeds the "
                   f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit.",
        )
    if not buffer:
        raise _bad_request(f"Uploaded file '{upload.filename}' is empty.")
    if not _matches_magic(suffix, bytes(buffer[:16])):
        raise _bad_request(
            f"Uploaded file '{upload.filename}' does not match its file type. "
            "Only genuine PNG, JPG, JPEG, and PDF files are accepted.")
    return bytes(buffer)


@router.post("/analyze")
async def analyze(
    request: Request,
    files: list[UploadFile] = File(...),
    user: dict = Depends(get_current_user),
) -> dict[str, object]:
    """Analyze 2--10 images or PDFs in a request-scoped temporary directory.

    Requires a signed-in reviewer; every run is recorded in the audit log.
    """
    allowed, retry_after = limiter.check(
        f"analyze:{user['email']}", analyze_rate_limit_per_minute(), 60)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Analysis rate limit reached. Please wait a minute.",
            headers={"Retry-After": str(retry_after)},
        )

    if not MIN_FILES <= len(files) <= MAX_FILES:
        raise _bad_request(
            f"Upload between {MIN_FILES} and {MAX_FILES} files.")

    names: list[str] = []
    for upload in files:
        filename = upload.filename or ""
        suffix = Path(filename).suffix.lower()
        if not filename.strip():
            raise _bad_request("Each upload must have a filename.")
        if suffix not in ALLOWED_SUFFIXES:
            raise _bad_request(
                "Only PNG, JPG, JPEG, and PDF files are supported.")
        if upload.content_type:
            content_type = upload.content_type.lower()
            if not (content_type.startswith("image/")
                    or "pdf" in content_type
                    or (content_type == "application/octet-stream" and suffix == PDF_SUFFIX)):
                raise _bad_request(
                    "Each upload must declare an image or PDF content type.")
        names.append(filename)
    if len({name.casefold() for name in names}) != len(names):
        raise _bad_request("Duplicate filenames are not allowed in one upload.")

    temp_dir = Path(tempfile.mkdtemp(prefix="document-analysis-"))
    try:
        for index, upload in enumerate(files):
            # Do not use client paths.  An index prevents traversal and keeps
            # ordering deterministic while retaining the genuine extension.
            suffix = Path(upload.filename or "").suffix.lower()
            destination = temp_dir / f"upload_{index:02d}{suffix}"
            contents = await _read_capped(upload, suffix)
            destination.write_bytes(contents)

        # The detector works from PNGs. Convert JPEG uploads and PDF pages in
        # the private temp directory, then remove the originals immediately.
        from PIL import Image
        for image_path in list(temp_dir.iterdir()):
            if image_path.suffix.lower() in {".jpg", ".jpeg"}:
                png_path = image_path.with_suffix(".png")
                try:
                    with Image.open(image_path) as image:
                        image.convert("RGB").save(png_path, "PNG")
                except Exception as exc:
                    raise _bad_request(
                        f"Uploaded file '{image_path.name}' is not a readable image.") from exc
                image_path.unlink()
        _render_pdfs(temp_dir)

        result = detect_bundle(temp_dir)
        record_audit(
            "analyze.completed",
            email=user["email"],
            ip=get_client_ip(request),
            detail=f"documents={len(files)}",
        )
        return result.model_dump()
    except HTTPException:
        raise
    except (DetectionError, OCRError) as exc:
        raise _bad_request(f"Unable to analyze the submitted documents: {exc}") from exc
    except Exception as exc:
        # Keep implementation details and tracebacks out of HTTP responses.
        raise HTTPException(status_code=500, detail="Document analysis failed.") from exc
    finally:
        for upload in files:
            await upload.close()
        shutil.rmtree(temp_dir, ignore_errors=True)
