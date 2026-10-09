# app.security is a package (it hosts app.security.masking). The pre-existing
# encryption helpers live in app.security_helpers and are re-exported here so
# `from app.security import encrypt_field` keeps working:
#
#   from app.security import encrypt_field, decrypt_field   # AES-GCM field crypto
#   from app.security.masking import mask_id, hash_id       # identity minimization
#
# The legacy session-token / PBKDF2 password re-exports were removed with the
# SQLite auth system; use app.auth.passwords and app.auth.tokens instead.
from app.security_helpers import (  # noqa: F401  re-export for backwards compat
    decrypt_field,
    encrypt_field,
)
