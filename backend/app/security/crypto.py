"""Field-level encryption for PII at rest (AES-256-GCM, key-id prefixed).

Security rationale (steering rule 8):

- Every value is encrypted with a fresh random 96-bit nonce, so two equal
  plaintexts always produce different ciphertexts (no equality leakage).
- Each token is self-describing: ``enc:v1:<key_id>:<base64url(nonce||ct||tag)>``.
  The key id lets us decrypt with an OLD key after the active key has been
  rotated — see scripts/rotate_data_keys.py for re-encryption.
- Keys come ONLY from environment variables (DATA_KEY_V1, DATA_KEY_V2, ...)
  — never from the database. If no DATA_KEY_* is configured (dev/test), a
  key is derived from the existing SAMANVAY_SECRET_KEY / dev key file so
  the developer experience matches the rest of the codebase, and a warning
  is logged once.
- Tampering is detected: AES-GCM authenticates the ciphertext, so any
  bit-flip raises InvalidTokenError instead of returning garbage.
- hmac_field() provides a *searchable* deterministic HMAC for columns that
  need equality lookups without decrypting (the documents.id_hash column
  already uses this pattern for identity matching; hmac_field generalises
  it).

Applied via EncryptedType (a SQLAlchemy TypeDecorator) to the columns that
persist sensitive free text in this schema: findings_pg.reason (evidence
quotes), review_decisions.reviewer_email, users_pg.totp_secret. Raw
identity numbers are never persisted at all (Rule 2 — masked + HMAC only),
so there are no Aadhaar/PAN columns to encrypt. users_pg.email stays in
clear because it is the login lookup key and an FK target; it is a
synthetic-only identifier per project rules.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.types import Text, TypeDecorator

logger = logging.getLogger(__name__)

# Token layout: enc:v1:<key_id>:<base64url(nonce[12] || ciphertext||tag)>
_TOKEN_VERSION = "v1"
_NONCE_LEN = 12  # 96-bit nonce per NIST SP 800-38D for GCM
_KEY_ENV_PREFIX = "DATA_KEY_"
_ACTIVE_KEY_ENV = "DATA_KEY_ACTIVE"
_HMAC_KEY_ENV = "HMAC_INDEX_KEY"

_LEGACY_ENV = "SAMANVAY_SECRET_KEY"
_LEGACY_KEY_FILE = (
    Path(__file__).resolve().parents[2] / "data" / ".encryption_key"
)

_dev_key_cache: bytes | None = None
_warned_dev_key = False


class InvalidTokenError(ValueError):
    """Ciphertext failed authentication (tampered or wrong key)."""


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def _decode_key(raw: str) -> bytes:
    """Accept a 32-byte key encoded as hex (64 chars) or base64url."""
    raw = raw.strip()
    if len(raw) == 64 and re.fullmatch(r"[0-9a-fA-F]+", raw):
        return bytes.fromhex(raw)
    key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    if len(key) != 32:
        raise RuntimeError(
            "Encryption keys must decode to exactly 32 bytes "
            "(64 hex chars or base64url)."
        )
    return key


def keyring() -> dict[str, bytes]:
    """All configured data keys, mapping key id -> 32 bytes.

    Read from the environment on every call so rotation scripts and tests
    can add/switch keys without restarting the process.
    """
    keys: dict[str, bytes] = {}
    for name, value in os.environ.items():
        if name.startswith(_KEY_ENV_PREFIX) and name != _ACTIVE_KEY_ENV and value:
            keys[name[len(_KEY_ENV_PREFIX):].lower()] = _decode_key(value)
    return keys


def _legacy_key() -> bytes:
    """Key for the pre-keyid token format ('enc:<payload>') and dev fallback."""
    global _dev_key_cache, _warned_dev_key
    env_key = os.getenv(_LEGACY_ENV)
    if env_key:
        key = base64.urlsafe_b64decode(env_key.encode())
        if len(key) != 32:
            raise RuntimeError(
                f"{_LEGACY_ENV} must be a 32-byte base64url value."
            )
        return key
    if _dev_key_cache is None:
        _LEGACY_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        if _LEGACY_KEY_FILE.exists():
            _dev_key_cache = base64.urlsafe_b64decode(
                _LEGACY_KEY_FILE.read_bytes().strip()
            )
        else:
            _dev_key_cache = os.urandom(32)
            _LEGACY_KEY_FILE.write_bytes(
                base64.urlsafe_b64encode(_dev_key_cache)
            )
            try:
                _LEGACY_KEY_FILE.chmod(0o600)
            except OSError:  # Windows
                pass
        if not _warned_dev_key:
            logger.warning(
                "No DATA_KEY_* environment variables configured — using an "
                "auto-generated development key. Set DATA_KEY_V1 (and "
                "optionally DATA_KEY_ACTIVE) for production."
            )
            _warned_dev_key = True
    return _dev_key_cache


def active_key_id() -> str:
    """Key id used for NEW encryptions.

    DATA_KEY_ACTIVE wins when set; otherwise the highest-numbered
    DATA_KEY_* env var; in dev/test with no DATA_KEY_* at all, 'dev'
    (the legacy key source).
    """
    keys = keyring()
    if not keys:
        return "dev"
    wanted = os.getenv(_ACTIVE_KEY_ENV, "").strip().lower()
    if wanted:
        if wanted not in keys:
            raise RuntimeError(
                f"{_ACTIVE_KEY_ENV}={wanted!r} but no DATA_KEY_"
                f"{wanted.upper()} environment variable is set."
            )
        return wanted
    numeric = [k for k in keys if k[1:].isdigit()]
    if numeric:
        return max(numeric, key=lambda k: int(k[1:]))
    return sorted(keys)[0]


def _active_key() -> tuple[str, bytes]:
    kid = active_key_id()
    if kid == "dev":
        return "dev", _legacy_key()
    return kid, keyring()[kid]


def generate_data_key() -> str:
    """Mint a new 32-byte key as hex — for .env / secret-manager use."""
    import secrets

    return secrets.token_hex(32)


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def encrypt_field(plaintext: str, key_id: str | None = None) -> str:
    """Encrypt a string; returns a self-describing token safe to store.

    Each call uses a fresh random nonce, so equal plaintexts produce
    different tokens (tested). ``key_id`` defaults to the active key;
    the rotation script passes an explicit id when re-encrypting.
    """
    if plaintext is None or plaintext == "":
        return plaintext
    if plaintext.startswith("enc:"):
        return plaintext  # already a token — never double-encrypt

    if key_id is None:
        kid, key = _active_key()
    else:
        kid = key_id.lower()
        if kid == "dev":
            key = _legacy_key()
        else:
            ring = keyring()
            if kid not in ring:
                raise RuntimeError(f"Unknown encryption key id: {kid!r}")
            key = ring[kid]

    nonce = os.urandom(_NONCE_LEN)
    # AAD binds the token version + key id into the authentication tag so a
    # payload cannot be replayed under a different key id.
    aad = f"{_TOKEN_VERSION}:{kid}".encode()
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), aad)
    payload = base64.urlsafe_b64encode(nonce + ciphertext).decode()
    return f"enc:{_TOKEN_VERSION}:{kid}:{payload}"


def decrypt_field(token: str) -> str:
    """Decrypt a token produced by encrypt_field (any key id in the ring).

    Legacy tokens ('enc:<payload>' without a version segment) are
    decrypted with the SAMANVAY_SECRET_KEY / dev key so rows written
    before this module existed keep working; run scripts/rotate_data_keys.py
    to migrate them to the keyid format.

    Raises InvalidTokenError when authentication fails (tampered or the
    key is not configured). Plaintext values that were never encrypted
    (legacy rows) pass through unchanged — the rotation script encrypts them.
    """
    if token is None or token == "" or not token.startswith("enc:"):
        return token

    parts = token.split(":", 3)
    if len(parts) == 4 and parts[1] == _TOKEN_VERSION:
        _, _, kid, payload = parts
        ring = keyring()
        if kid == "dev" or not ring:
            key = _legacy_key()
        else:
            if kid not in ring:
                raise InvalidTokenError(
                    f"Token was encrypted with key {kid!r} which is not "
                    f"configured (DATA_KEY_{kid.upper()})."
                )
            key = ring[kid]
        aad = f"{_TOKEN_VERSION}:{kid}".encode()
    elif len(parts) == 2:
        # Legacy pre-keyid format — signed without AAD by the old code.
        _, payload = parts
        key = _legacy_key()
        aad = None
    else:
        raise InvalidTokenError("Malformed encrypted token.")

    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception as exc:
        raise InvalidTokenError("Malformed encrypted token.") from exc
    nonce, ciphertext = raw[:_NONCE_LEN], raw[_NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad).decode("utf-8")
    except InvalidTag as exc:
        raise InvalidTokenError(
            "Ciphertext failed authentication (tampered or wrong key)."
        ) from exc



# ---------------------------------------------------------------------------
# Searchable HMAC (equality lookups without decryption)
# ---------------------------------------------------------------------------

def hmac_field(value: str, domain: str = "idx") -> str:
    """Deterministic HMAC-SHA256 for equality lookups on sensitive values.

    Key order: HMAC_INDEX_KEY env var, else derived from the active data
    key with a domain separator (never the raw data key itself). The
    result is stable across processes given the same environment, so an
    indexed column can be compared with = without ever decrypting —
    the same pattern documents.id_hash already uses for identity matching.
    """
    raw_key = os.getenv(_HMAC_KEY_ENV, "").strip()
    if raw_key:
        key = _decode_key(raw_key)
    else:
        _, data_key = _active_key()
        key = hmac.new(data_key, b"|hmac-index", hashlib.sha256).digest()
    return hmac.new(
        key, f"{domain}:{value}".encode("utf-8"), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# SQLAlchemy TypeDecorator
# ---------------------------------------------------------------------------

class EncryptedType(TypeDecorator):
    """Store a column's value encrypted; transparent decrypt on read.

    - bind: plaintext -> enc:v1:<kid>:<payload> (values already starting
      with 'enc:' pass through so the rotation script and legacy callers
      never double-encrypt).
    - result: token -> plaintext; legacy plaintext rows pass through so
      pre-existing data keeps working until scripts/rotate_data_keys.py
      re-encrypts it.
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect) -> str | None:
        if value is None or value == "":
            return value
        if value.startswith("enc:"):
            return value
        return encrypt_field(value)

    def process_result_value(self, value: str | None, dialect) -> str | None:
        if value is None or not value.startswith("enc:"):
            return value
        return decrypt_field(value)


