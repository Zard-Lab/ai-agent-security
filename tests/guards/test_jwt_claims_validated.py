from __future__ import annotations

from agentsec.guards.jwt_claims_validated import JwtClaimsValidatedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_jwt_claims_flags_verify_exp_false(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        'jwt.decode(token, key, options={"verify_exp": False, "verify_aud": True})\n',
        encoding="utf-8",
    )
    findings = JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-claims-validated/verify-disabled"
    assert findings[0].severity == "high"
    assert "verify_exp" in findings[0].message

def test_jwt_claims_flags_verify_signature_false(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        'jwt.decode(token, options={"verify_signature": False})\n',
        encoding="utf-8",
    )
    findings = JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-claims-validated/verify-disabled"
    assert findings[0].severity == "high"
    assert "verify_signature" in findings[0].message

def test_jwt_claims_flags_single_quoted_options(tmp_path: Path) -> None:
    # jwt HIGH (FN): single-quoted option keys must fire too — the check is not
    # syntactically limited to double quotes.
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "jwt.decode(token, key, options={'verify_exp': False})\n",
        encoding="utf-8",
    )
    findings = JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-claims-validated/verify-disabled"
    assert "verify_exp" in findings[0].message

def test_jwt_claims_silent_on_safe_decode(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        'jwt.decode(token, key, algorithms=["RS256"])\n',
        encoding="utf-8",
    )
    assert JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_claims_silent_on_all_true(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        'jwt.decode(token, key, algorithms=["HS256"], options={"verify_exp": True})\n',
        encoding="utf-8",
    )
    assert JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_claims_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "# security: allow-jwt-no-verify\n"
        "import jwt\n"
        'jwt.decode(token, key, options={"verify_exp": False})\n',
        encoding="utf-8",
    )
    assert JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_claims_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a `jwt.decode(..., options={"verify_exp": False})` EXAMPLE inside a
    # docstring must not fire (this guard's own module docstring self-matched on it).
    (tmp_path / "auth.py").write_text(
        '"""Disabling a claim check is the anti-pattern:\n'
        "\n"
        '    jwt.decode(token, key, options={"verify_exp": False})\n'
        '"""\n'
        "import jwt\n",
        encoding="utf-8",
    )
    assert JwtClaimsValidatedGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_claims_not_applicable_without_python(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"frontend"})
    assert JwtClaimsValidatedGuard().applies(prof) is False

