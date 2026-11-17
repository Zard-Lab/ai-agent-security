from __future__ import annotations

from agentsec.guards.cleartext_secret_storage import CleartextSecretStorageGuard
from tests.guards._common import *  # noqa: F401,F403


def test_cleartext_secret_storage_fires_on_cookie_value(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def remember(resp, password):\n    resp.set_cookie('remember', password)\n", encoding="utf-8"
    )
    findings = CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cleartext-secret-storage/cookie-value"
    assert findings[0].severity == "high"

def test_cleartext_secret_storage_fires_on_file_write(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def dump(f, client_secret):\n    f.write(client_secret)\n", encoding="utf-8"
    )
    findings = CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cleartext-secret-storage/plaintext-file-write"

def test_cleartext_secret_storage_fires_on_write_text(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def dump(path, private_key):\n    path.write_text(private_key)\n", encoding="utf-8"
    )
    findings = CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cleartext-secret-storage/plaintext-file-write"

def test_cleartext_secret_storage_silent_on_token_cookie(tmp_path: Path) -> None:
    # FP-bait: session tokens are the correct, designed-for-this pattern.
    (tmp_path / "a.py").write_text(
        "def login(resp, raw_token):\n    resp.set_cookie('token', raw_token)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_hashed_password(tmp_path: Path) -> None:
    # FP-bait: the value has already been through a one-way transform.
    (tmp_path / "a.py").write_text(
        "def dump(f, hashed_password):\n    f.write(hashed_password)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_in_memory_stream_write(tmp_path: Path) -> None:
    # FP-bait (review #395 M finding): io.StringIO() is not a file — a `.write()` on one never
    # touches disk, so the old "filesystem/backup" message was misleading.
    (tmp_path / "a.py").write_text(
        "import io\n"
        "def dump(private_key):\n"
        "    io.StringIO().write(private_key)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_stream_variable_write(tmp_path: Path) -> None:
    # Same FP class via an intermediate variable assigned from StringIO()/BytesIO().
    (tmp_path / "a.py").write_text(
        "import io\n"
        "def dump(secret_key):\n"
        "    buf = io.StringIO()\n"
        "    buf.write(secret_key)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_nested_call(tmp_path: Path) -> None:
    # FP-bait: not a bare identifier — the guard can't evaluate what encrypt() does.
    (tmp_path / "a.py").write_text(
        "def dump(f, secret_key):\n    f.write(encrypt(secret_key))\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "# security: allow-cleartext-secret-storage\n"
        "def remember(resp, password):\n    resp.set_cookie('remember', password)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_secretary_substring(tmp_path: Path) -> None:
    # #395 M: `secret` is a substring of `secretary` but not a secret stem there — must not fire.
    (tmp_path / "a.py").write_text(
        "def dump(f, secretary_name):\n    f.write(secretary_name)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_silent_on_metadata_suffix(tmp_path: Path) -> None:
    # #395 M: `client_secret_expiry_days` is an int describing a secret, not the secret value.
    (tmp_path / "a.py").write_text(
        "def dump(f, client_secret_expiry_days):\n    f.write(client_secret_expiry_days)\n", encoding="utf-8"
    )
    assert CleartextSecretStorageGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_cleartext_secret_storage_not_applies_without_python() -> None:
    assert CleartextSecretStorageGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False
