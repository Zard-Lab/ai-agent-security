from __future__ import annotations

import pytest

from agentsec.guards.jwt_alg import JwtAlgGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_jwt_alg_flags_unpinned_decode(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "def verify(token, key):\n"
        "    return jwt.decode(token, key)\n", encoding="utf-8"  # verifies, but no algorithms= pin
    )
    findings = JwtAlgGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-alg/unpinned-algorithms"
    assert findings[0].severity == "medium"

def test_jwt_alg_flags_none_algorithm(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        'payload = jwt.decode(token, key, algorithms=["HS256", "none"])\n', encoding="utf-8"
    )
    findings = JwtAlgGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-alg/none-algorithm"
    assert findings[0].severity == "high"

def test_jwt_alg_pinned_multiline_is_silent(tmp_path: Path) -> None:
    # Mirrors the flagship's secure decode: multi-line call with algorithms pinned.
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "payload = jwt.decode(\n"
        "    token,\n"
        "    SECRET,\n"
        '    algorithms=["HS256"],\n'
        '    audience="hwh-widget",\n'
        ")\n", encoding="utf-8"
    )
    assert JwtAlgGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_alg_verify_disabled_is_skipped(tmp_path: Path) -> None:
    # Signature-disabled decode is the Semgrep pack's finding, not this guard's —
    # mirrors the flagship's deliberate non-security metadata reads.
    (tmp_path / "meta.py").write_text(
        "import jwt\n"
        'claims = jwt.decode(token, options={"verify_signature": False})\n', encoding="utf-8"
    )
    assert JwtAlgGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_alg_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "auth.py").write_text(
        "import jwt\n"
        "claims = jwt.decode(token, key)  # security: allow-unpinned-jwt\n", encoding="utf-8"
    )
    assert JwtAlgGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_alg_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a `jwt.decode(token, key)` EXAMPLE inside a docstring must not fire
    # (this guard's own module docstring self-matched on it).
    (tmp_path / "auth.py").write_text(
        '"""Example of the unpinned-algorithm anti-pattern:\n'
        "\n"
        "    claims = jwt.decode(token, key)\n"
        '"""\n'
        "import jwt\n",
        encoding="utf-8",
    )
    assert JwtAlgGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_jwt_alg_not_applicable_without_python() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert JwtAlgGuard().applies(prof) is False


# --- Node jsonwebtoken.verify(token, false) disabled (codeql js/jwt-missing-verification) ---

def test_jwt_alg_applies_on_express() -> None:
    assert JwtAlgGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_jwt_alg_js_flags_verify_disabled(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "const jwt = require('jsonwebtoken');\n"
        "function check(token) {\n"
        "  return jwt.verify(token, false);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "jwt-alg/js-verify-disabled"
    assert findings[0].severity == "critical"


def test_jwt_alg_js_silent_with_real_secret(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "jwt.verify(token, process.env.JWT_SECRET);\n", encoding="utf-8"
    )
    assert JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_jwt_alg_js_silent_on_commented_call(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text("// jwt.verify(token, false);\n", encoding="utf-8")
    assert JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_jwt_alg_js_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "auth.js").write_text(
        "jwt.verify(token, false);  // security: allow-jwt-verify-disabled\n", encoding="utf-8"
    )
    assert JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_jwt_alg_js_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # M2 (the PR #905 review): scope the Express scan to product code, matching
    # this PR's own sibling insecure_cookies.py — a critical finding must not fire inside
    # tests/fixtures.
    d = tmp_path / "tests"
    d.mkdir()
    (d / "auth.test.js").write_text("jwt.verify(token, false);\n", encoding="utf-8")
    assert JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []



# --- #1055: `jwt.verify(token, false)` counts only when the call and the `false` are live code ----

def _run_js_verify(tmp_path: Path, line: str) -> list[str]:
    (tmp_path / "auth.js").write_text("const jwt = require('jsonwebtoken');\n" + line + "\n", encoding="utf-8")
    findings = JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    return [f"{f.rule}@{f.location.replace(chr(92), '/')}" for f in findings]


@pytest.mark.parametrize(
    "line",
    [
        "log('jwt.verify(token, false) disables signature checks');",
        "log(`jwt.verify(token, false) disables signature checks`);",
        # The `false` sits in template text, not in the argument list.
        "jwt.verify(`${token}, false`, key);",
    ],
)
def test_jwt_alg_js_verify_spelled_in_a_string_stays_silent(tmp_path: Path, line: str) -> None:
    assert _run_js_verify(tmp_path, line) == []


@pytest.mark.parametrize(
    "line",
    [
        "jwt.verify(token, false);",
        # The real call nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "log(`${jwt.verify(token, false)}`);",
        # A quoted copy earlier on the line must not hide the real call after it.
        "log('jwt.verify(t, false)'); jwt.verify(token, false);",
    ],
)
def test_jwt_alg_js_real_verify_disabled_still_fires(tmp_path: Path, line: str) -> None:
    assert _run_js_verify(tmp_path, line) == ["jwt-alg/js-verify-disabled@auth.js:2"]


def test_jwt_alg_js_pragma_still_suppresses_a_code_anchored_call(tmp_path: Path) -> None:
    line = "log('jwt.verify(t, false)'); jwt.verify(token, false);"
    assert len(_run_js_verify(tmp_path, line)) == 1
    assert _run_js_verify(tmp_path, line + "  // security: allow-jwt-verify-disabled") == []


def test_jwt_alg_js_scan_stays_linear_on_comma_free_verify_lines(tmp_path: Path) -> None:
    # #1157 round-1 M1: `_JS_JWT_VERIFY_DISABLED`'s `[^,]+` also crosses newlines, so a whole-file
    # search over `jwt.verify(` lines with no comma backtracks to EOF from every call: quadratic
    # (measured 1.08s at 8000 lines, 17.37s at 32000). The scan stays per line, where `[^,]+` is
    # bounded by the line, and a real call after the hostile run still fires.
    def scan(size: int) -> None:
        root = tmp_path / str(size)
        root.mkdir(exist_ok=True)
        (root / "auth.js").write_text("jwt.verify(\n" * size, encoding="utf-8")
        JwtAlgGuard().run(root, mkprofile(root, features={"express"}))

    assert_growth(scan, [2_000, 4_000, 8_000, 16_000], expected="linear")
    (tmp_path / "auth.js").write_text("jwt.verify(\n" * 4_000 + "jwt.verify(token, false);\n", encoding="utf-8")
    findings = JwtAlgGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert [f.location.replace("\\", "/") for f in findings] == ["auth.js:4001"]
