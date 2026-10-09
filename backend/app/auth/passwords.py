"""Argon2id password hashing and the minimum password policy.

Security rationale (steering rule 8): Argon2id is the OWASP-recommended
password hashing function (memory-hard, resistant to GPU/ASIC cracking).
Each hash embeds its own random salt, so identical passwords produce
different hashes. Verification is constant-time via the argon2-cffi
implementation of the reference libargon2.
"""
from __future__ import annotations

import re

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)

# OWASP baseline for Argon2id: 19 MiB memory, 2 iterations, 1 degree of
# parallelism. Tuned for a small API instance; raise memory_cost on beefier
# hardware and never lower it below 8 MiB.
_hasher = PasswordHasher(
    memory_cost=19_456,  # 19 MiB
    time_cost=2,
    parallelism=1,
)

# Minimum password policy: at least 12 characters containing at least one
# letter and one digit. Length is weighted above complexity (NIST SP 800-63B).
MIN_PASSWORD_LENGTH = 12
_PASSWORD_RE = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).+$")


def validate_password(password: str) -> str | None:
    """Return an error message if the password fails policy, else None.

    Kept separate from the Pydantic models so the policy lives in one place
    and can be unit-tested directly.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )
    if not _PASSWORD_RE.match(password):
        return "Password must contain at least one letter and one digit."
    return None


def hash_password(password: str) -> str:
    """Hash a password with Argon2id. Returns the full encoded hash string
    (algorithm params + salt + digest) suitable for opaque storage."""
    return _hasher.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification of a password against an Argon2id hash.

    Returns False for any malformed or legacy-format hash instead of raising,
    so callers can treat verification failure uniformly.
    """
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
