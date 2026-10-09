"""Generate a self-signed certificate for local PostgreSQL TLS.

Usage (from backend/, or anywhere):

    python scripts/gen_selfsigned_cert.py [--dir docker/tls]

Writes server.crt / server.key into the target directory (default:
<repo>/docker/tls). The key is chmod-ed 600 on POSIX. These certificates
are for LOCAL DEVELOPMENT ONLY — the postgres container mounts them read-
only and starts with ssl=on; the API connects with sslmode=require.

For production, use certificates from your own CA or ACME (Let's Encrypt)
and set sslmode=verify-full — see docs/SECURITY.md.
"""
from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate(out_dir: Path, days: int = 365) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "yonko-dev-postgres"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("db"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = out_dir / "server.crt"
    key_path = out_dir / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    try:
        key_path.chmod(0o600)
    except OSError:  # Windows
        pass
    return cert_path, key_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        default=str(Path(__file__).resolve().parents[2] / "docker" / "tls"),
        help="Output directory (default: <repo>/docker/tls)",
    )
    args = parser.parse_args()

    cert_path, key_path = generate(Path(args.dir))
    print(f"Wrote {cert_path}")
    print(f"Wrote {key_path}")
    print("LOCAL DEVELOPMENT ONLY — do not use these certificates in production.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())