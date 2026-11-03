#!/usr/bin/env python3
"""Upgrade a database written by an older release, or by the predecessor project.

The migration runner can open an older database in place — it adds the columns
that are missing and rebuilds the ``findings`` table when it still carries the
legacy global ``id`` primary key. This script wraps that in a safe, explicit
operation: it takes a backup first and prints what it did.

Usage::

    python scripts/migrate_legacy_db.py data/kaal.db data/trishul.db
    python scripts/migrate_legacy_db.py data/kaal.db

With one argument the file is upgraded in place, after a timestamped backup is
written next to it.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.core.migrations import current_version, run_migrations  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="The database to upgrade.")
    parser.add_argument(
        "target",
        nargs="?",
        default="",
        help="Where to write the upgraded database. Defaults to upgrading in place.",
    )
    args = parser.parse_args()

    source = Path(args.source).expanduser().resolve()
    if not source.is_file():
        print(f"error: {source} does not exist", file=sys.stderr)
        return 1

    target = Path(args.target).expanduser().resolve() if args.target else source

    if target == source:
        backup = source.with_suffix(source.suffix + ".backup")
        shutil.copy2(source, backup)
        print(f"Backup written to {backup}")
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        print(f"Copied {source} -> {target}")

    migrations_dir = PROJECT_ROOT / "migrations"
    result = run_migrations(target, migrations_dir)

    print(f"Applied migrations   : {', '.join(result['applied']) or 'none'}")
    print(f"Reconciled columns   : {', '.join(result['reconciled_columns']) or 'none'}")
    print(f"Rebuilt findings key : {'yes' if result['rebuilt_findings'] else 'no (already correct)'}")
    print(f"Schema version       : {current_version(target)}")
    print(f"Database             : {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
