import os
import tempfile
from typing import List
from pdf2image import convert_from_bytes
import pytesseract
from PIL import Image

# ---------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------
# DPI for PDF rasterisation – lower values speed up OCR at the cost of
# some visual fidelity. 150 dpi is a good trade‑off for most text PDFs.
DEFAULT_DPI = int(os.getenv("OCR_DPI", "150"))


def pdf_bytes_to_images(pdf_bytes: bytes, dpi: int = DEFAULT_DPI) -> List[Image.Image]:
    """Convert PDF bytes to a list of Pillow images.

    The conversion uses ``poppler`` (installed in the Docker image) and
    respects the provided DPI value. Lower DPI reduces the number of pixels
    fed to Tesseract, dramatically speeding up OCR.
    """
    return convert_from_bytes(pdf_bytes, dpi=dpi)


def ocr_image(img: Image.Image) -> str:
    """Run Tesseract OCR on a Pillow image and return plain text."""
    return pytesseract.image_to_string(img)


def ocr_pdf(pdf_bytes: bytes) -> str:
    """Full OCR pipeline: PDF → rasterised images → OCR → concatenated text."""
    images = pdf_bytes_to_images(pdf_bytes)
    texts = [ocr_image(img) for img in images]
    return "\n".join(texts)
