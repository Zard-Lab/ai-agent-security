from __future__ import annotations

from agentsec.guards.refresh_token_plaintext import RefreshTokenPlaintextGuard
from tests.guards._common import *  # noqa: F401,F403


def test_refresh_token_plaintext_fires(tmp_path: Path) -> None:
    """Raw secrets.token_urlsafe assigned to 'token', then db.add within 10 lines — must fire."""
    (tmp_path / "tokens.py").write_text(
        "token = secrets.token_urlsafe(32)\n"
        "db.add(RefreshToken(user_id=uid, token=token))\n",
        encoding="utf-8",
    )
    findings = RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule == "refresh-token-plaintext/token-stored-unhashed"
    assert f.severity == "high"
    assert f.check_id == "refresh-token-plaintext"
    assert "OWASP:A02" in f.standards
    assert "CWE-257" in f.standards
    # location should point at the db.add line (line 2), not the generation line
    assert f.location.endswith(":2")

def test_refresh_token_plaintext_silent_with_hash(tmp_path: Path) -> None:
    """hashlib hash between generation and db.add — must stay silent."""
    (tmp_path / "tokens.py").write_text(
        "raw = secrets.token_urlsafe(32)\n"
        "hashed = hashlib.sha256(raw.encode()).hexdigest()\n"
        "db.add(RefreshToken(user_id=uid, token=hashed))\n",
        encoding="utf-8",
    )
    assert RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_refresh_token_plaintext_pragma_opt_out(tmp_path: Path) -> None:
    """File-level pragma suppresses the finding entirely."""
    (tmp_path / "tokens.py").write_text(
        "# security: allow-refresh-token-plaintext\n"
        "token = secrets.token_urlsafe(32)\n"
        "db.add(RefreshToken(user_id=uid, token=token))\n",
        encoding="utf-8",
    )
    assert RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_refresh_token_plaintext_not_applicable_without_python() -> None:
    """Guard must not apply when 'python' is not in features."""
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert RefreshTokenPlaintextGuard().applies(prof) is False

def test_refresh_token_plaintext_uuid_fires(tmp_path: Path) -> None:
    """uuid.uuid4() assigned to 'token' then session.add — must fire."""
    (tmp_path / "auth.py").write_text(
        "token = uuid.uuid4()\n"
        "session.add(RefreshToken(user_id=uid, token=str(token)))\n",
        encoding="utf-8",
    )
    findings = RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "refresh-token-plaintext/token-stored-unhashed"

def test_refresh_token_plaintext_bcrypt_silent(tmp_path: Path) -> None:
    """bcrypt.hashpw between generation and write — must stay silent."""
    (tmp_path / "auth.py").write_text(
        "refresh_token = secrets.token_hex(32)\n"
        "hashed = bcrypt.hashpw(refresh_token.encode(), bcrypt.gensalt())\n"
        "db.add(Token(user_id=uid, token=hashed))\n",
        encoding="utf-8",
    )
    assert RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_refresh_token_plaintext_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a token-gen + db.add EXAMPLE inside a docstring must not fire within the
    # look-ahead window. strip_python_strings blanks the docstring content.
    (tmp_path / "auth.py").write_text(
        '"""Anti-pattern:\n'
        "\n"
        "    refresh_token = secrets.token_urlsafe(32)\n"
        "    db.add(Token(user_id=uid, token=refresh_token))\n"
        '"""\n'
        "import secrets\n",
        encoding="utf-8",
    )
    assert RefreshTokenPlaintextGuard().run(tmp_path, _pyprof(tmp_path)) == []

