from __future__ import annotations

from agentsec.guards.insecure_cookies import InsecureCookiesGuard
from tests.guards._common import *  # noqa: F401,F403


def test_insecure_cookies_flags_missing_flags(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def login(response, token):\n    response.set_cookie('session', token)\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/missing-flags"
    assert findings[0].severity == "medium" and "HttpOnly" in findings[0].title

def test_insecure_cookies_flags_missing_secure_only(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n    resp.set_cookie('s', t, httponly=True, samesite='Lax')\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1 and "Secure" in findings[0].title and "HttpOnly" not in findings[0].title

def test_insecure_cookies_passes_all_flags(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n    resp.set_cookie('s', t, httponly=True, secure=True, samesite='Lax')\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_insecure_cookies_multiline_call(tmp_path: Path) -> None:
    # flags spread across lines must still be detected as present
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n    resp.set_cookie(\n        's',\n        t,\n"
        "        httponly=True,\n        secure=True,\n        samesite='Lax',\n    )\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_insecure_cookies_pragma(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n    resp.set_cookie('s', t)  # security: allow-insecure-cookie\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_insecure_cookies_na_without_python() -> None:
    assert InsecureCookiesGuard().applies(mkprofile(Path("/tmp"), features={"frontend"})) is False

def test_insecure_cookies_flags_samesite_none_on_sensitive_cookie(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n"
        "    resp.set_cookie('session_id', t, httponly=True, secure=True, samesite='none')\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/samesite-none"
    assert findings[0].severity == "medium"

def test_insecure_cookies_flags_samesite_none_alongside_missing_flags(tmp_path: Path) -> None:
    # Both findings can fire on the same cookie — different concerns, different remediation.
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n    resp.set_cookie('auth_token', t, samesite=\"None\")\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"insecure-cookies/missing-flags", "insecure-cookies/samesite-none"}

def test_insecure_cookies_silent_on_samesite_none_for_non_sensitive_cookie(tmp_path: Path) -> None:
    # FP-bait: a widget/embed preference cookie legitimately needs SameSite=None.
    (tmp_path / "a.py").write_text(
        "def f(resp, v):\n"
        "    resp.set_cookie('widget_theme', v, httponly=True, secure=True, samesite='none')\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []

def test_insecure_cookies_flags_samesite_none_with_keyword_name_arg(tmp_path: Path) -> None:
    # FN-bait (review #395 M finding): `key="session_id"` (keyword form) previously extracted
    # NO name at all (only the positional first-arg form was recognized), so a real
    # CSRF-exposed session cookie went completely unflagged.
    (tmp_path / "a.py").write_text(
        "def f(resp, sess):\n"
        "    resp.set_cookie(key=\"session_id\", value=sess, httponly=True, secure=True, "
        "samesite=\"none\")\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/samesite-none"

def test_insecure_cookies_flags_samesite_none_with_unextractable_name(tmp_path: Path) -> None:
    # Safer default: when the name can't be statically extracted at all (a variable, not a
    # literal), treat it as sensitive rather than silently passing.
    (tmp_path / "a.py").write_text(
        "def f(resp, name_var, t):\n"
        "    resp.set_cookie(name_var, t, httponly=True, secure=True, samesite=\"none\")\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/samesite-none"

def test_insecure_cookies_silent_on_bare_none_sentinel(tmp_path: Path) -> None:
    # FP-bait: samesite=None (unquoted Python None) means "don't set the attribute" in Flask,
    # a different and safe behavior from the literal SameSite=None cookie attribute value.
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n"
        "    resp.set_cookie('session_id', t, httponly=True, secure=True, samesite=None)\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []


# --- Express/JS (codeql js/client-exposed-cookie + js/samesite-none-cookie) ---

def test_insecure_cookies_applies_on_express() -> None:
    assert InsecureCookiesGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_insecure_cookies_js_flags_missing_httponly(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "app.get('/x', (req, res) => { res.cookie('session_id', tok, { secure: true }); });",
        encoding="utf-8",
    )
    findings = InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/missing-flags"
    assert "httpOnly" in findings[0].title


def test_insecure_cookies_js_passes_all_flags(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "res.cookie('session_id', tok, { httpOnly: true, secure: true, sameSite: 'lax' });",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_js_passes_all_flags_with_closing_paren_in_string(tmp_path: Path) -> None:
    # M4 (the PR #905 review): a `)` inside a string VALUE used to truncate the
    # naive depth-counting arg scan early, so httpOnly/secure past it were invisible and the
    # guard wrongly reported both missing. Verified failing before the fix.
    (tmp_path / "a.js").write_text(
        "res.cookie('session_id', tok, "
        "{ note: 'legacy)', httpOnly: true, secure: true, sameSite: 'lax' });",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_py_passes_all_flags_with_closing_paren_in_string(tmp_path: Path) -> None:
    # L-1 (PR #905 review): the `_balanced_args`->`matching_close_paren` quote-awareness fix (M4)
    # touched the Python path too, but only the JS side had the paren-in-string FP-bait. A `)`
    # inside a string arg VALUE positioned before httponly/secure used to truncate the naive
    # depth counter and wrongly report both flags missing; the quote-aware helper reads past it,
    # so a fully-flagged cookie stays silent. Closes the both-directions symmetry.
    (tmp_path / "auth.py").write_text(
        "from fastapi import Response\n\n\n"
        "def login(response: Response, token: str) -> None:\n"
        "    response.set_cookie(\"session\", token, path=\"/legacy)\", "
        "httponly=True, secure=True, samesite=\"lax\")\n",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"python"})) == []


def test_insecure_cookies_js_flags_samesite_none_on_sensitive_cookie(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "res.cookie('session_id', tok, { httpOnly: true, secure: true, sameSite: 'none' });",
        encoding="utf-8",
    )
    findings = InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "insecure-cookies/samesite-none"


def test_insecure_cookies_js_silent_on_samesite_none_for_non_sensitive_cookie(tmp_path: Path) -> None:
    # FP-bait: a widget/embed preference cookie legitimately needs SameSite=None.
    (tmp_path / "a.js").write_text(
        "res.cookie('widget_theme', v, { httpOnly: true, secure: true, sameSite: 'none' });",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_js_silent_on_document_cookie(tmp_path: Path) -> None:
    # FP-bait: document.cookie is a property assignment, not a res.cookie(...) call — httpOnly
    # is a server-set flag, meaningless for client-side document.cookie.
    (tmp_path / "a.js").write_text("document.cookie = 'theme=dark';", encoding="utf-8")
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_js_silent_on_unrelated_cookie_method(tmp_path: Path) -> None:
    # FP-bait: a `.cookie(` call on a receiver that isn't res/response (e.g. a cookie-parser lib).
    (tmp_path / "a.js").write_text("parser.cookie('x', 'y');", encoding="utf-8")
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_js_pragma(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text(
        "res.cookie('session_id', tok);  // security: allow-insecure-cookie",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_insecure_cookies_silent_on_nonproduct_path(tmp_path: Path) -> None:
    # Corpus-scan FP: the real repro was `tests/test_frontend.py` in
    # `tiangolo/full-stack-fastapi-template` — `tests/` is already in the shared
    # `is_nonproduct_path` list, but this guard never called it before this fix.
    d = tmp_path / "tests"
    d.mkdir()
    (d / "test_frontend.py").write_text(
        "def login(response, token):\n    response.set_cookie('session', token)\n", encoding="utf-8"
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_insecure_cookies_still_fires_at_a_normal_path(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a sibling non-product directory must not
    # silence the same violation shape at an ordinary path.
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_frontend.py").write_text(
        "def login(response, token):\n    response.set_cookie('session', token)\n", encoding="utf-8"
    )
    (tmp_path / "a.py").write_text(
        "def login(response, token):\n    response.set_cookie('session', token)\n", encoding="utf-8"
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert any(f.location.startswith("a.py") for f in findings)
    assert not any(f.location.startswith("tests") for f in findings)



# #613: the span walk read `'''` as three separate quotes, so an apostrophe inside one left the
# span unresolvable and the scan read to END OF FILE, where a LATER cookie's flags counted for this
# one: a cookie set with no flags at all went silent.
def test_insecure_cookies_triple_quoted_arg_does_not_borrow_a_later_cookies_flags(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text(
        "def f(resp, t, p):\n"
        "    resp.set_cookie('sid', t, path='''/the user's area''')\n"
        "    resp.set_cookie('prefs', p, httponly=True, secure=True, samesite='Lax')\n",
        encoding="utf-8",
    )
    findings = InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [("insecure-cookies/missing-flags", "a.py:2")]


def test_insecure_cookies_triple_quoted_arg_with_its_own_flags_passes(tmp_path: Path) -> None:
    # FP-bait for the widening above: the span now ends at the call's own `)`, and flags set
    # after the triple-quoted argument are still inside it.
    (tmp_path / "a.py").write_text(
        "def f(resp, t):\n"
        "    resp.set_cookie('sid', t, path='''/the user's area''', httponly=True, secure=True, samesite='Lax')\n",
        encoding="utf-8",
    )
    assert InsecureCookiesGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_insecure_cookies_js_pragma_after_a_form_feed_stays_on_its_own_line(tmp_path: Path) -> None:
    # #1040: the call's line is counted by "\n"; a view split by `splitlines` also breaks on the form
    # feed in the template literal, so every view line below it sat one line low.
    def findings(above: str, own: str) -> int:
        (tmp_path / "a.js").write_text(
            f"const doc = `a{chr(12)}b`;\nconst x = 1;{above}\nres.cookie('session_id', tok);{own}\n",
            encoding="utf-8",
        )
        return len(InsecureCookiesGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})))

    pragma = "  // security: allow-insecure-cookie"
    assert findings("", "") == 1  # control
    assert findings("", pragma) == 0
    assert findings(pragma, "") == 1  # the line above does not reach
