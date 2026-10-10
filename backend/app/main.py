import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.auth_routes import router as auth_router
from app.api.case_routes import router as case_router
from app.api.routes import router as api_router
from app.ratelimit import (get_client_ip, global_rate_limit_per_minute,
                           limiter)

app = FastAPI(title="AI Document Contradiction Detector")

# CORS is opt-in per origin: only the origins listed in CORS_ALLOW_ORIGINS
# (the Vercel site plus local dev servers) may call the API from a browser.
allowed_origins = [origin.strip() for origin in os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000",
).split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@app.middleware("http")
async def harden_and_rate_limit(request: Request, call_next):
    # Global per-IP budget blunts credential-stuffing and scanning noise
    # before it reaches route handlers.
    allowed, retry_after = limiter.check(
        f"ip:{get_client_ip(request)}", global_rate_limit_per_minute(), 60)
    if not allowed:
        response = JSONResponse(
            {"detail": "Too many requests. Please slow down."},
            status_code=429,
        )
        response.headers["Retry-After"] = str(retry_after)
    else:
        response = await call_next(request)
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    # Only advertise HTTPS once the deployment actually terminates TLS.
    if request.url.scheme == "https" or request.headers.get(
            "x-forwarded-proto", "").lower() == "https":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=63072000; includeSubDomains")
    return response


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
