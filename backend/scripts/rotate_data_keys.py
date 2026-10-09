"""Re-encrypt PII columns with the current active data key.

Usage (from backend/):

    # Dry run — show what would be re-encrypted:
    python scripts/rotate_data_keys.py --dry-run

    # Real rotation to a new key:
    #   1. Add the new key to the environment: DATA_KEY_V2=<64-hex>
    #   2. Point the active key at it:        DATA_KEY_ACTIVE=v2
    #   3. Run this script (decrypts with the key id embedded in each
    #      token, re-encrypts with the active key).
    #   4. After verifying, remove the old DATA_KEY_V1 from the environment.
    python scripts/rotate_data_keys.py

Security notes:
- Connection URL comes from MIGRATION_DATABASE_URL / DATABASE_URL env
  (use the migration_user credentials — app_user has no SELECT on some
  columns by design and RLS would filter rows).
- The script re-encrypts the three EncryptedType columns: users_pg.totp_secret,
  findings_pg.reason, review_decisions.reviewer_email.
- Legacy plaintext rows (no 'enc:' prefix) are encrypted for the first time.
- Parameterised SQL only (steering rule 3); never logs plaintext or keys.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# Allow running as `python scripts/rotate_data_keys.py` from backend/.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import create_engine, text  # noqa: E402

from app.security.crypto import (  # noqa: E402
    active_key_id,
    decrypt_field,
    encrypt_field,
)

# (table, column) pairs holding EncryptedType values.
_PII_COLUMNS = (
    ("users_pg", "totp_secret"),
    ("findings_pg", "reason"),
    ("review_decisions", "reviewer_email"),
)


def rotate(url: str, dry_run: bool = False) -> dict[str, int]:
    """Re-encrypt every value in the PII columns. Returns per-column counts."""
    engine = create_engine(url)
    kid = active_key_id()
    counts: dict[str, int] = {}
    try:
        with engine.begin() as conn:
            for table, column in _PII_COLUMNS:
                rows = conn.execute(text(
                    f"SELECT id, {column} FROM {table} "
                    f"WHERE {column} IS NOT NULL AND {column} != ''"
                )).fetchall()
                changed = 0
                for row_id, value in rows:
                    # decrypt_field handles both keyid and legacy tokens and
                    # passes plaintext through; re-encrypt with the active key.
                    plaintext = decrypt_field(value)
                    new_value = encrypt_field(plaintext, key_id=kid)
                    if new_value != value:
                        changed += 1
                        if not dry_run:
                            conn.execute(
                                text(
                                    f"UPDATE {table} SET {column} = :value "
                                    "WHERE id = :row_id"
                                ),
                                {"value": new_value, "row_id": row_id},
                            )
                counts[f"{table}.{column}"] = changed
    finally:
        engine.dispose()
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report counts without writing.",
    )
    args = parser.parse_args()

    url = os.environ.get("MIGRATION_DATABASE_URL") or os.environ.get(
        "DATABASE_URL", ""
    )
    if not url:
        print(
            "ERROR: set MIGRATION_DATABASE_URL or DATABASE_URL.", file=sys.stderr
        )
        return 2

    print(f"Active key id: {active_key_id()}")
    counts = rotate(url, dry_run=args.dry_run)
    verb = "would re-encrypt" if args.dry_run else "re-encrypted"
    for column, count in counts.items():
        print(f"  {column}: {count} value(s) {verb}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())