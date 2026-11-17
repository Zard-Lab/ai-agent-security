from __future__ import annotations

from agentsec.guards.js_secure_cookies import JsSecureCookiesGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_secure_cookies_flags_sensitive_no_options(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/login', (req, res) => {\n"
        "  res.cookie('session', token);\n"
        "  res.json({ok: true});\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsSecureCookiesGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-secure-cookies/no-options"
    assert findings[0].severity == "medium"


def test_js_secure_cookies_flags_httponly_false(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "res.cookie('auth_token', token, { httpOnly: false });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsSecureCookiesGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-secure-cookies/missing-flags"
    assert "Secure" in findings[0].title
    assert "HttpOnly" in findings[0].title


def test_js_secure_cookies_flags_samesite_none_without_secure(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "res.cookie('session', token, { httpOnly: true, sameSite: 'none' });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsSecureCookiesGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    rules = {f.rule for f in findings}
    assert "js-secure-cookies/samesite-none" in rules


def test_js_secure_cookies_silent_all_flags_present(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsSecureCookiesGuard().run(tmp_path, profile) == []


def test_js_secure_cookies_silent_nonsensitive_no_options(tmp_path: Path) -> None:
    # A non-sensitive cookie with no options object at all is common (theme/locale prefs) and
    # should not be flagged — mirrors insecure_cookies.py's own sensitive-name scoping.
    (tmp_path / "app.js").write_text(
        "res.cookie('theme_preference', 'dark');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsSecureCookiesGuard().run(tmp_path, profile) == []


def test_js_secure_cookies_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "res.cookie('session', token);  // security: allow-js-secure-cookies\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsSecureCookiesGuard().run(tmp_path, profile) == []


def test_js_secure_cookies_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("res.cookie('session', token);\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features=set())
    assert not JsSecureCookiesGuard().applies(profile)


def test_js_secure_cookies_flags_multiline_missing_secure(tmp_path: Path) -> None:
    # Adversarial self-test: a Prettier-formatted multi-line options object missing `secure`
    # must still be found — a naive same-line regex would miss it.
    (tmp_path / "app.js").write_text(
        "res.cookie('session', token, {\n"
        "  httpOnly: true,\n"
        "  sameSite: 'lax'\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsSecureCookiesGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-secure-cookies/missing-flags"


def test_js_secure_cookies_silent_multiline_all_flags_present(tmp_path: Path) -> None:
    # Adversarial self-test: same shape as above but with both flags set — proves the
    # bracket-counting scan finds a multi-line options object correctly in BOTH directions.
    (tmp_path / "app.js").write_text(
        "res.cookie('session', token, {\n"
        "  httpOnly: true,\n"
        "  secure: true\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsSecureCookiesGuard().run(tmp_path, profile) == []


def test_js_secure_cookies_silent_on_commented_call(tmp_path: Path) -> None:
    # Adversarial self-test: a comment merely mentioning res.cookie( must not fire — confirms
    # strip_js_comments is actually applied before pattern matching, not just imported.
    (tmp_path / "app.js").write_text(
        "// res.cookie('session', token);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsSecureCookiesGuard().run(tmp_path, profile) == []
