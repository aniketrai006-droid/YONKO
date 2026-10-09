"""Backwards-compatible facade over app.security.crypto.

The pre-keyid AES-GCM helpers that used to live here have moved to
app.security.crypto (key-id prefixed tokens, rotation support). These
re-exports keep `from app.security_helpers import encrypt_field` working;
they now produce/consume the new `enc:v1:<key_id>:<payload>` format and
still decrypt legacy `enc:<payload>` rows. Prefer importing
app.security.crypto directly in new code.
"""

from __future__ import annotations

from app.security.crypto import (  # noqa: F401  re-export for backwards compat
    InvalidTokenError,
    decrypt_field,
    encrypt_field,
)
