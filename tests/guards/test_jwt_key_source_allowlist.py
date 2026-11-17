from __future__ import annotations

from agentsec.guards.jwt_key_source_allowlist import JwtKeySourceAllowlistGuard
from tests.guards._common import *  # noqa: F401,F403


def test_jwt_key_source_allowlist_flags_jku(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "import requests\n"
        "\n"
        "def verify(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    jwk_url = header[\"jku\"]\n"
        "    key = requests.get(jwk_url).json()\n"
        "    return jwt.decode(token, key, algorithms=[\"RS256\"])\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-key-source-allowlist/untrusted-key-source"
    assert findings[0].severity == "high"

def test_jwt_key_source_allowlist_flags_x5u(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "from jose import jwt\n"
        "\n"
        "def verify(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    cert_url = header.get(\"x5u\")\n"
        "    return fetch_and_verify(token, cert_url)\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-key-source-allowlist/untrusted-key-source"
    assert findings[0].severity == "high"

def test_jwt_key_source_allowlist_flags_jwk_as_critical(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "from jwt.algorithms import RSAAlgorithm\n"
        "\n"
        "def verify(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    embedded_jwk = header[\"jwk\"]\n"
        "    key = RSAAlgorithm.from_jwk(embedded_jwk)\n"
        "    return jwt.decode(token, key, algorithms=[\"RS256\"])\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-key-source-allowlist/untrusted-key-source"
    assert findings[0].severity == "critical"

def test_jwt_key_source_allowlist_dedupes_same_field_same_line(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    if header[\"jku\"] and header[\"jku\"]:\n"
        "        return None\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1

def test_jwt_key_source_allowlist_silent_without_unverified_header(tmp_path: Path) -> None:
    # "jku" here is just an unrelated dict key -- no get_unverified_header anchor in the file.
    (tmp_path / "config.py").write_text(
        "settings = {}\n"
        "value = settings[\"jku\"]\n",
        encoding="utf-8",
    )
    assert JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_key_source_allowlist_silent_ordinary_claim_access(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def peek(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    return header[\"kid\"], header.get(\"typ\")\n",
        encoding="utf-8",
    )
    assert JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_key_source_allowlist_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "auth_verify.py").write_text(
        "# security: allow-jwt-key-source-header\n"
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    header = jwt.get_unverified_header(token)\n"
        "    return header[\"jku\"]\n",
        encoding="utf-8",
    )
    assert JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_key_source_allowlist_silent_on_hash_comment(tmp_path: Path) -> None:
    # Dean's review, High 2: a comment describing this pattern in prose must not fire.
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        '    # TODO: we call get_unverified_header(token) and read header["jku"] one day\n'
        "    header = jwt.get_unverified_header(token)\n"
        '    return header["kid"]\n',
        encoding="utf-8",
    )
    assert JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_key_source_allowlist_silent_on_log_string(tmp_path: Path) -> None:
    # Dean's review, High 2: a log/diagnostic string mentioning header['jku'] as prose,
    # not a real field access, must not fire.
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    h = jwt.get_unverified_header(token)\n"
        "    logger.debug(\"looked up header['jku'] for diagnostics\")\n"
        '    return h["kid"]\n',
        encoding="utf-8",
    )
    assert JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_key_source_allowlist_still_flags_real_access_on_same_pattern(tmp_path: Path) -> None:
    # Same bracket/quote shape as the log-string FP-bait above, but a REAL field access --
    # confirms the fix narrows precisely, not by breaking detection generally.
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    h = jwt.get_unverified_header(token)\n"
        '    return h["jku"]\n',
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1

def test_jwt_key_source_allowlist_flags_formatter_split_access(tmp_path: Path) -> None:
    # #686 fix-commit round, High 2: the original per-physical-line loop can't match
    # `_KEY_SOURCE_ACCESS`'s `\s*` across a line break, so a formatter (black/ruff) that
    # wraps a long subscript across lines made the access go undetected entirely.
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    h = jwt.get_unverified_header(token)\n"
        "    return h[\n"
        '        "jku"\n'
        "    ]\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-key-source-allowlist/untrusted-key-source"


def test_jwt_key_source_allowlist_flags_fstring_nested_access(tmp_path: Path) -> None:
    # #686 fix-commit round, High 3: `_is_standalone_quoted_field` isn't f-string aware --
    # `f"{h['jku']}"` reads as one big double-quoted span (the content class doesn't
    # exclude `'`), so the nested single-quoted access was never recognized as standalone.
    (tmp_path / "auth_verify.py").write_text(
        "import jwt\n"
        "\n"
        "def verify(token):\n"
        "    h = jwt.get_unverified_header(token)\n"
        "    logger.info(f\"jku is {h['jku']}\")\n",
        encoding="utf-8",
    )
    findings = JwtKeySourceAllowlistGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-key-source-allowlist/untrusted-key-source"


def test_jwt_key_source_allowlist_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert JwtKeySourceAllowlistGuard().applies(profile) is False

def test_jwt_key_source_allowlist_applies_with_python() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert JwtKeySourceAllowlistGuard().applies(profile) is True
