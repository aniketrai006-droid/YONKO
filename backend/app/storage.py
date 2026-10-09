"""
Object-storage helper for optional encrypted file uploads (PERSIST_UPLOADS).

Security rationale for AES-256 SSE:
  Server-side encryption ensures that files at rest in MinIO are encrypted
  using AES-256. Even if the storage volume is accessed directly, the file
  contents are unreadable without the MinIO server's encryption key. This
  satisfies the requirement to protect uploaded document images beyond the
  DB-level masking already applied to identity fields.

  Encryption is applied via the S3 'ServerSideEncryption' parameter set to
  'AES256', which instructs MinIO to apply SSE-S3 (server-managed keys).

This module is NOT imported at application startup — it is imported lazily
inside _persist_bundle only when PERSIST_UPLOADS=True, so missing boto3
in the environment does not break the default (no-upload) path.
"""

from __future__ import annotations

import hashlib
import uuid

from app.config import settings


def get_storage_client():
    """Return a boto3 S3 client pointed at the configured MinIO endpoint.

    Raises ImportError if boto3 is not installed (only required when
    PERSIST_UPLOADS=True).
    """
    import boto3  # lazy import — only needed when PERSIST_UPLOADS=True

    return boto3.client(
        "s3",
        endpoint_url=settings.MINIO_ENDPOINT,
        aws_access_key_id=settings.MINIO_ACCESS_KEY,
        aws_secret_access_key=settings.MINIO_SECRET_KEY,
    )


def upload_file(file_bytes: bytes, storage_key: str | None = None) -> str:
    """Upload file_bytes to MinIO with AES-256 server-side encryption.

    Args:
        file_bytes: raw bytes of the file to upload.
        storage_key: object key to use; auto-generated UUID4 key if None.

    Returns:
        The storage_key used (caller stores this in the Document row).

    Security: AES256 SSE-S3 is requested via ServerSideEncryption='AES256'.
    The DB stores only the object key — never the file bytes themselves.
    """
    key = storage_key or str(uuid.uuid4())
    client = get_storage_client()
    client.put_object(
        Bucket=settings.MINIO_BUCKET,
        Key=key,
        Body=file_bytes,
        ServerSideEncryption="AES256",  # SSE-S3: MinIO-managed AES-256 key
    )
    return key


def sha256_hex(data: bytes) -> str:
    """Return the hex SHA-256 digest of data. Used for file integrity checks."""
    return hashlib.sha256(data).hexdigest()
