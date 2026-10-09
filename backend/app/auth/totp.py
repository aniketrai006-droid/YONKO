"""TOTP (time-based one-time password) helpers for reviewer/admin MFA.

Security rationale (steering rule 8): TOTP secrets are generated with
pyotp's CSPRNG (base32, 32 chars ≈ 160 bits). The shared secret is stored
AES-GCM encrypted via app.security_helpers.encrypt_field, so a database
dump alone does not yield usable TOTP seeds. Verification accepts a
±1 window (30 s steps) to tolerate clock skew and uses pyotp's
constant-time comparison internally.
"""
from __future__ import annotations

import pyotp

from app.security_helpers import decrypt_field, encrypt_field

ISSUER_NAME = "YONKO"
TOTP_DIGITS = 6
TOTP_INTERVAL = 30


def generate_totp_secret() -> str:
    """Generate a new base32 TOTP shared secret."""
    return pyotp.random_base32(length=32)


def encrypt_secret(secret: str) -> str:
    """Encrypt the shared secret for at-rest storage."""
    return encrypt_field(secret)


def decrypt_secret(stored: str) -> str:
    """Decrypt a stored shared secret for verification."""
    return decrypt_field(stored)


def provisioning_uri(secret: str, email: str) -> str:
    """Return an otpauth:// URI the frontend renders as a QR code."""
    totp = pyotp.TOTP(
        secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL
    )
    return totp.provisioning_uri(name=email, issuer_name=ISSUER_NAME)


def verify_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code against the shared secret.

    Accepts a ±1 interval window for clock skew. Returns False for empty or
    malformed codes instead of raising.
    """
    if not code or not code.strip().isdigit():
        return False
    totp = pyotp.TOTP(
        secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL
    )
    return totp.verify(code.strip(), valid_window=1)
