"""HTTP routes for temporary, privacy-preserving document analysis."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile, status

from app.detect.engine import detect_bundle
from app.detect.types import DetectionError
from app.ocr.types import OCRError

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
                    or content_type == "application/pdf"):
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
