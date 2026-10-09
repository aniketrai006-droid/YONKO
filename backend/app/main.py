import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth_routes import router as auth_router
from app.api.routes import router as api_router

app = FastAPI(title="AI Document Contradiction Detector")
allowed_origins = [origin.strip() for origin in os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.include_router(api_router)
app.include_router(auth_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/health/ocr")
def health_ocr():
    try:
        import pytesseract

        languages = pytesseract.get_languages(config="")
        return {"tesseract_found": True, "languages": languages}
    except Exception as exc:
        return {
            "tesseract_found": False,
            "languages": [],
            "message": (
                "Tesseract is not available. Install Tesseract OCR and make sure "
                "the 'tesseract' executable is on your PATH "
                f"(underlying error: {exc})"
            ),
        }
