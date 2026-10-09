# Dockerfile for the YONKO API service.
# Base image: python:3.12-slim (stable slim variant; 3.14 slim not yet widely available).
#
# Tesseract is bundled here so the container is self-contained for OCR.
# In local dev, Tesseract is expected to be installed on the host.

FROM python:3.12-slim

# Install system dependencies.
# - tesseract-ocr: OCR engine used by pytesseract (bundled for container use)
# - libgl1, libglib2.0-0: required by opencv-python-headless at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies first (layer-cache friendly).
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source.
# alembic/ is copied by FEAT-002 once the directory exists; the COPY is safe
# even if alembic/ is absent at build time because the glob will simply match nothing.
COPY app/ ./app/

# Alembic directory (created in FEAT-002); copy only if present.
# Use a shell-form copy so Docker doesn't error when the dir is missing yet.
COPY alembic* ./

# Default command: run the FastAPI app with uvicorn on all interfaces.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
