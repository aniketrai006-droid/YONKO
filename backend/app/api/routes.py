"""HTTP routes for temporary, privacy-preserving document analysis."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.config import settings
from app.database import get_db
from app.detect.engine import detect_bundle
from app.detect.types import BundleDetectionResult, DetectionError
from app.models import Bundle, Document, FindingPg
from app.ocr.types import OCRError

logger = logging.getLogger(__name__)

router = APIRouter(tags=["analysis"])

MIN_FILES = 2
MAX_FILES = 10
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg"}
PDF_SUFFIX = ".pdf"
ALLOWED_SUFFIXES = IMAGE_SUFFIXES | {PDF_SUFFIX}
MAX_PDF_PAGES = 10
PDF_RENDER_ZOOM = 2.0


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


# ---------------------------------------------------------------------------
# Persistence helper
# ---------------------------------------------------------------------------

# PERSIST_RESULTS: when True, bundle metadata and findings are saved to PostgreSQL.
# Failure to persist does not affect the analysis response (fire-and-forget).
# No file bytes or PII are stored — only document types, field names, and decisions.

def _persist_bundle(result: BundleDetectionResult, temp_dir: Path) -> None:
    """
    Write a Bundle row, one Document row per unique document type, and one
    FindingPg row per finding to the configured database.

    Security: no file bytes, raw field values, or PII are stored here.
    Only document types, field names, decisions, and severity are persisted.

    The session is opened and closed entirely inside this function so that the
    /analyze route signature stays unchanged (no db: Session = Depends(...)
    parameter). Using `next(get_db())` pulls one session from the generator and
    we close it explicitly in the finally block.
    """
    db = next(get_db())
    try:
        # Create Bundle row — bundle_ref is the temp-dir name for diagnostics only,
        # not a reconstructable filesystem path after the temp dir is deleted.
        bundle = Bundle(
            # System-level bundles have no user owner; use a fixed sentinel email.
            # In a multi-user flow this would be the authenticated user's email.
            owner_email="system@yonko.internal",
            bundle_ref=temp_dir.name,
        )
        db.add(bundle)
        db.flush()  # obtain bundle.id without committing yet

        # Derive unique document types from evidence across all findings.
        # We create one Document row per distinct document_type rather than one
        # per uploaded file because the detection engine maps files → doc types.
        seen_doc_types: set[str] = set()
        for finding in result.findings:
            for ev in finding.evidence:
                doc_type = ev.document_type
                if doc_type and doc_type not in seen_doc_types:
                    seen_doc_types.add(doc_type)
                    doc = Document(
                        bundle_id=bundle.id,
                        # filename here records the source_path basename for
                        # traceability; no actual file bytes are stored.
                        filename=Path(ev.source_path).name if ev.source_path else doc_type,
                        document_type=doc_type,
                        page_count=1,
                    )
                    db.add(doc)

        # Create one FindingPg row per finding.
        for finding in result.findings:
            finding_row = FindingPg(
                bundle_id=bundle.id,
                field=finding.field,
                decision=finding.decision,
                severity=finding.severity,
                reason=finding.reason,
                similarity=finding.similarity,
                recommended_action=finding.recommended_action,
            )
            db.add(finding_row)

        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


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
        "synthetic_demo_data_only": True,
    }


@router.post("/analyze")
async def analyze(files: list[UploadFile] = File(...)) -> dict[str, object]:
    """Analyze 2--10 images or PDFs in a request-scoped temporary directory."""
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
            contents = await upload.read()
            if not contents:
                raise _bad_request(f"Uploaded file '{upload.filename}' is empty.")
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

        # PERSIST_RESULTS: when True, bundle metadata and findings are saved to PostgreSQL.
        # Failure to persist does not affect the analysis response (fire-and-forget).
        # No file bytes or PII are stored — only document types, field names, and decisions.
        if settings.PERSIST_RESULTS:
            try:
                _persist_bundle(result, temp_dir)
            except Exception:
                # A DB write failure must never surface as an HTTP error.
                # Log the exception for operator visibility without exposing
                # internal details (no PII, no tokens) in the response.
                logger.exception(
                    "PERSIST_RESULTS: failed to persist bundle results to DB "
                    "(bundle_ref=%s). Analysis response is unaffected.",
                    temp_dir.name,
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
