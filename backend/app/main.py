import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.auth_jwt_routes import router as auth_jwt_router
from app.api.auth_routes import router as auth_router
from app.api.case_routes import router as case_router
from app.api.routes import router as api_router
from app.config import settings

logger = logging.getLogger(__name__)

# Minimum acceptable length for ID_HMAC_SECRET when persistence is enabled.
# A secret shorter than 16 characters provides insufficient entropy for HMAC.
_MIN_HMAC_SECRET_LEN = 16


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup / shutdown lifecycle for YONKO.

    Security check: when PERSIST_RESULTS=True, ID_HMAC_SECRET must be set and
    long enough to provide adequate HMAC security. An empty or very short secret
    produces attacker-predictable digests — warn loudly so operators notice before
    any data is written. We warn (not raise) to keep the app deployable while still
    surfacing the misconfiguration.
    """
    if settings.PERSIST_RESULTS:
        secret_len = len(settings.ID_HMAC_SECRET)
        if secret_len < _MIN_HMAC_SECRET_LEN:
            logger.warning(
                "SECURITY WARNING: PERSIST_RESULTS=True but ID_HMAC_SECRET is %s "
                "(length %d, minimum %d). Identity hashes will be attacker-predictable. "
                "Set a strong random ID_HMAC_SECRET in the environment before "
                "writing any data.",
                "empty" if secret_len == 0 else "too short",
                secret_len,
                _MIN_HMAC_SECRET_LEN,
            )
    yield  # application runs here


app = FastAPI(title="AI Document Contradiction Detector", lifespan=lifespan)
allowed_origins = [origin.strip() for origin in os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)
# The JWT auth router is mounted BEFORE the legacy SQLite session router so
# its /auth/logout, etc. take precedence. The legacy router remains only for
# the not-yet-migrated frontend flows (signup/signin/profile) and will be
# removed once the frontend switches to JWT endpoints.
app.include_router(auth_jwt_router)
app.include_router(api_router)
app.include_router(auth_router)
app.include_router(case_router)


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
