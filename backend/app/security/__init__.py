# Re-export all symbols from the pre-existing app.security_helpers module
# so that existing imports like `from app.security import decrypt_field` continue
# to work after app/security was promoted to a package directory.
#
# Background: the original app/security.py contained auth/crypto helpers used by
# app.api.auth_routes and app.db. Promoting security/ to a package to add the
# masking sub-module (app.security.masking) would shadow security.py. The file
# was renamed to security_helpers.py and these re-exports keep backwards compat.
#
# The masking sub-module (app.security.masking) is imported explicitly by callers:
#   from app.security.masking import mask_id, hash_id
from app.security_helpers import (  # noqa: F401  re-export for backwards compat
    decrypt_field,
    encrypt_field,
    hash_password,
    is_expired,
    new_token,
    session_expiry,
    utc_now,
    verify_password,
    LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS,
)
