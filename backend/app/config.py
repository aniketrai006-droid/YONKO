"""
Application settings loaded from environment variables or a .env file.

Security note: this module contains no secrets — only the *schema* for settings.
Real values come from the environment or a .env file that is gitignored.
Never import this module into db.py (the existing SQLite helper) to avoid
circular-import and cross-layer coupling.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Database connection string.
    # Security: defaults to the local SQLite file so the app boots in dev without
    # Postgres.  In production, override with a postgresql+psycopg2:// URL that
    # carries real credentials supplied via the environment, never hardcoded.
    DATABASE_URL: str = (
        "sqlite+pysqlite:///./backend/data/samanvay.sqlite"
    )

    # When False (default) the /analyze endpoint does not write to the database,
    # keeping analysis stateless.  Set to True in environments where persistence
    # is desired.  Keeping this opt-in prevents accidental writes during local dev.
    PERSIST_RESULTS: bool = False

    # Secret key used for signing tokens and HMAC-masked ID values.
    # Security: must be a strong random string (≥ 32 bytes) in production.
    # An empty default here means the app will start but token verification will
    # be insecure — operators MUST set this via the environment.
    SECRET_KEY: str = ""

    # HMAC-SHA256 secret for identity-number hashing (data minimization).
    # Security: must be a strong random string in production.
    # An empty default means hashing works but is NOT collision-resistant —
    # operators MUST set this via the environment before going to production.
    ID_HMAC_SECRET: str = ""

    # When True, uploaded file bytes are stored in MinIO object storage with
    # AES-256 server-side encryption. The DB stores only a SHA-256 file hash
    # and the object key — never the file bytes themselves.
    PERSIST_UPLOADS: bool = False

    # MinIO / S3-compatible object storage configuration.
    # All four values are required when PERSIST_UPLOADS=True.
    MINIO_ENDPOINT: str = ""
    MINIO_ACCESS_KEY: str = ""
    MINIO_SECRET_KEY: str = ""
    MINIO_BUCKET: str = "yonko-uploads"

    # Comma-separated list of allowed CORS origins for the FastAPI CORS middleware.
    # Security: restrict this to actual frontend origins in production.
    CORS_ALLOW_ORIGINS: str = (
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
    )

    # ---------------------------------------------------------------------------
    # JWT authentication (Part A: register/login/refresh/logout/me + MFA)
    # ---------------------------------------------------------------------------

    # Secret used to sign access and refresh JWTs (HS256).
    # Security: MUST be a strong random string in production
    # (generate: python -c "import secrets; print(secrets.token_hex(32))").
    # When empty the app falls back to an ephemeral per-process dev key and
    # logs a startup warning — tokens then invalidate on every restart, so an
    # empty value can never produce a forgeable *constant* signing key.
    JWT_SECRET: str = ""

    # Access tokens are deliberately short-lived (steering rule: 15 minutes).
    AUTH_ACCESS_TOKEN_TTL_MINUTES: int = 15

    # Refresh tokens live longer and are rotated on every /auth/refresh call.
    # Each token's SHA-256 is stored server-side so reuse can be detected.
    AUTH_REFRESH_TOKEN_TTL_DAYS: int = 7

    # Account lockout after repeated failed logins.
    AUTH_MAX_FAILED_ATTEMPTS: int = 5
    AUTH_LOCKOUT_MINUTES: int = 15

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Ignore extra keys in .env so adding project-level vars doesn't break loading.
        extra="ignore",
    )


# Module-level singleton — import `settings` everywhere instead of instantiating
# Settings() repeatedly, which would re-read the environment on each import.
settings = Settings()
