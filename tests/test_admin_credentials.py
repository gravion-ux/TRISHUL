"""Regression tests for the administrator credential bootstrap.

Importing ``backend.app.main`` used to write the administrator password hash
into the *live* credential store.  Because the test suite imports the app
with ``TRISHUL_ADMIN_PASSWORD`` pinned to the test password, running
``pytest`` inside a deployment silently replaced the operator's password --
the dashboard then answered every login with ``401 Invalid username or
password`` even though ``data/admin-credentials.txt`` still showed the
correct password.

Two invariants are enforced here:

* importing the application must not mutate the credential store;
* starting the application must make the stored hash agree with the
  password of record, repairing a store that was corrupted by an earlier
  version.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAIN_SOURCE = ROOT / "backend" / "app" / "main.py"


# ---------------------------------------------------------------------------
# Structural: the import must not write to the credential store
# ---------------------------------------------------------------------------


def _import_time_calls(tree: ast.Module) -> list[int]:
    """Return the line numbers of credential writes that run at import time."""
    offenders: list[int] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Function and class bodies do not execute on import.
            continue
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr in {"set", "delete", "clear"}
                and isinstance(child.func.value, ast.Name)
                and child.func.value.id == "credentials"
            ):
                offenders.append(child.lineno)
    return offenders


def test_importing_the_app_does_not_write_to_the_credential_store():
    tree = ast.parse(MAIN_SOURCE.read_text(encoding="utf-8"))
    offenders = _import_time_calls(tree)
    assert offenders == [], (
        "backend/app/main.py writes to the credential store at import time "
        f"(lines {offenders}); move the write into the application lifespan"
    )


def test_the_password_is_applied_in_the_lifespan():
    source = MAIN_SOURCE.read_text(encoding="utf-8")
    assert "_apply_admin_password()" in source
    assert "async def lifespan" in source


# ---------------------------------------------------------------------------
# Behavioural: an import leaves the store untouched
# ---------------------------------------------------------------------------


def _isolated_config(tmp_path: Path, db_path: Path) -> Path:
    """Write a config that points every runtime path at ``tmp_path``."""
    config = tmp_path / "config.yaml"
    config.write_text(
        "app:\n"
        f"  db_path: {db_path.as_posix()}\n"
        f"  reports_dir: {(tmp_path / 'reports').as_posix()}\n"
        f"  plugins_dir: {(tmp_path / 'plugins').as_posix()}\n"
        "auth:\n"
        "  enabled: true\n"
        "  username: admin\n",
        encoding="utf-8",
    )
    return config


def test_an_import_leaves_the_credential_store_untouched(tmp_path):
    db_path = tmp_path / "trishul.db"
    config = _isolated_config(tmp_path, db_path)
    credential_file = tmp_path / "credentials.enc"

    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    env["TRISHUL_CONFIG"] = str(config)
    env["TRISHUL_ADMIN_PASSWORD"] = "a-password-that-must-not-be-persisted"

    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import backend.app.main as m; print('IMPORTED', len(m.app.routes))",
        ],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert "IMPORTED" in completed.stdout

    # The store must not exist at all: the import wrote nothing.
    assert not credential_file.exists(), (
        "importing the application created the credential store; "
        "the password hash must only be written when the app starts serving"
    )


# ---------------------------------------------------------------------------
# Behavioural: starting the app repairs and applies the password
# ---------------------------------------------------------------------------


def test_starting_the_app_stores_a_verifiable_hash(tmp_path):
    from backend.app.core.security import hash_password, verify_password
    from backend.app.core.secrets import CredentialStore

    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("admin:password_hash", hash_password("the-operator-password"))

    # Simulate what the lifespan does, using the real helper.
    import backend.app.main as main_module

    original_store = main_module.credentials
    original_password = main_module.settings.auth.password
    original_admin_password = main_module.ADMIN_PASSWORD
    try:
        main_module.credentials = store
        main_module.settings.auth.password = ""
        main_module.ADMIN_PASSWORD = "the-operator-password"
        main_module._apply_admin_password()
    finally:
        main_module.credentials = original_store
        main_module.settings.auth.password = original_password
        main_module.ADMIN_PASSWORD = original_admin_password

    stored = store.get("admin:password_hash") or ""
    assert stored
    assert verify_password("the-operator-password", stored)


def test_starting_the_app_repairs_a_hash_that_does_not_match(tmp_path):
    """A store corrupted by the old import-time write is repaired on start."""
    from backend.app.core.security import hash_password, verify_password
    from backend.app.core.secrets import CredentialStore

    store = CredentialStore(tmp_path / "credentials.enc")
    # The hash an earlier version wrote while the test suite was running.
    store.set("admin:password_hash", hash_password("trishul-test-password"))

    import backend.app.main as main_module

    original_store = main_module.credentials
    original_password = main_module.settings.auth.password
    original_admin_password = main_module.ADMIN_PASSWORD
    try:
        main_module.credentials = store
        main_module.settings.auth.password = ""
        main_module.ADMIN_PASSWORD = "the-operator-password"
        main_module._apply_admin_password()
    finally:
        main_module.credentials = original_store
        main_module.settings.auth.password = original_password
        main_module.ADMIN_PASSWORD = original_admin_password

    stored = store.get("admin:password_hash") or ""
    assert verify_password("the-operator-password", stored)
    assert not verify_password("trishul-test-password", stored)


def test_an_explicit_password_wins_over_the_credentials_file(tmp_path):
    from backend.app.core.security import verify_password
    from backend.app.core.secrets import CredentialStore

    store = CredentialStore(tmp_path / "credentials.enc")

    import backend.app.main as main_module

    original_store = main_module.credentials
    original_password = main_module.settings.auth.password
    original_admin_password = main_module.ADMIN_PASSWORD
    try:
        main_module.credentials = store
        main_module.settings.auth.password = "rotated-by-the-operator"
        main_module.ADMIN_PASSWORD = "the-operator-password"
        main_module._apply_admin_password()
    finally:
        main_module.credentials = original_store
        main_module.settings.auth.password = original_password
        main_module.ADMIN_PASSWORD = original_admin_password

    stored = store.get("admin:password_hash") or ""
    assert verify_password("rotated-by-the-operator", stored)


def test_starting_the_app_does_not_rewrite_a_correct_hash(tmp_path):
    from backend.app.core.security import hash_password
    from backend.app.core.secrets import CredentialStore

    store = CredentialStore(tmp_path / "credentials.enc")
    store.set("admin:password_hash", hash_password("the-operator-password"))
    before = store.get("admin:password_hash")

    import backend.app.main as main_module

    original_store = main_module.credentials
    original_password = main_module.settings.auth.password
    original_admin_password = main_module.ADMIN_PASSWORD
    try:
        main_module.credentials = store
        main_module.settings.auth.password = ""
        main_module.ADMIN_PASSWORD = "the-operator-password"
        main_module._apply_admin_password()
    finally:
        main_module.credentials = original_store
        main_module.settings.auth.password = original_password
        main_module.ADMIN_PASSWORD = original_admin_password

    assert store.get("admin:password_hash") == before


@pytest.mark.parametrize("method", ["get", "names"])
def test_the_credential_store_exposes_what_the_tests_need(method):
    from backend.app.core.secrets import CredentialStore

    assert hasattr(CredentialStore, method)
