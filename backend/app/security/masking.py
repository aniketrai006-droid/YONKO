"""
Identity number masking and hashing for data minimization.

Security rationale:
- Raw identity numbers (Aadhaar, PAN, DL, account numbers) are NEVER stored
  in the database or logs.
- mask_id() retains only the last 4 characters for display purposes.
- hash_id() produces an HMAC-SHA256 digest for cross-document matching.
  Two documents carrying the same identity number will produce the same hash
  when the same secret is used, enabling deduplication without raw-value storage.
- The raw value is used only transiently in memory during a single request.
"""
from __future__ import annotations

import hashlib
import hmac

from app.config import settings


def mask_id(value: str) -> str:
    """Return '*' repeated for all but the last 4 chars.

    Raises ValueError if len(value) < 4.
    Security: never store the input value or this function's output in logs.
    Only the last-4 masked form is safe for display and persistence.
    """
    if len(value) < 4:
        raise ValueError(
            f"mask_id requires at least 4 characters, got {len(value)}"
        )
    return "*" * (len(value) - 4) + value[-4:]


def hash_id(value: str, secret: str | None = None) -> str:
    """HMAC-SHA256 hex digest of value.

    Uses settings.ID_HMAC_SECRET when secret is None.
    Security: the secret is never logged or returned in responses.
    Two documents with the same identity number and the same secret
    will produce the same digest, enabling cross-document matching
    without storing raw identity values.
    """
    key = (secret if secret is not None else settings.ID_HMAC_SECRET)
    return hmac.new(
        key.encode("utf-8"),
        value.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
