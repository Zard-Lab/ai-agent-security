from __future__ import annotations

from agentsec.guards.js_server_side_open_redirect import JsServerSideOpenRedirectGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_direct_query_param(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect(req.query.target);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsServerSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].rule == "js-server-side-open-redirect/request-derived-redirect-target"
    assert findings[0].location.endswith(":2")


def test_flags_bracket_notation_query_param(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect(req.query[\"next\"]);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsServerSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_flags_variable_assigned_from_req_body_earlier_in_file(tmp_path: Path) -> None:
    # File-scoped taint: the assignment sits well before the sink line.
    (tmp_path / "app.js").write_text(
        "app.post('/go', (req, res) => {\n"
        "  const theVar = req.body.url;\n"
        "  console.log('redirecting');\n"
        "  res.redirect(theVar);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsServerSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")


def test_flags_location_header_via_res_set(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.set('Location', req.query.target);\n"
        "  res.status(302).end();\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsServerSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


def test_silent_on_static_dashboard_path(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect('/dashboard');\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsServerSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_silent_on_static_fixed_url(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect('https://example.com/fixed-path');\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsServerSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect(req.query.target);  // security: allow-js-server-side-open-redirect\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsServerSideOpenRedirectGuard().run(tmp_path, profile) == []


def test_not_applies_without_express(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "res.redirect(req.query.target);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert not JsServerSideOpenRedirectGuard().applies(profile)


# --- Adversarial self-test findings (see design doc "Known bypasses" / "When NOT to flag") ---


def test_flags_redirect_with_leading_status_code_argument(tmp_path: Path) -> None:
    # Express's res.redirect() accepts an optional leading status-code argument
    # (res.redirect([status,] path)) — the tainted URL is the SECOND positional argument here,
    # not the first. Confirms the guard still finds it (the target is always the LAST arg).
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect(302, req.query.target);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsServerSideOpenRedirectGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")


def test_silent_on_req_session_source(tmp_path: Path) -> None:
    # req.session is server-controlled (populated by session middleware from previously
    # validated data), not directly attacker-supplied on this request — unlike req.query/
    # req.params/req.body. A common, legitimate post-login-redirect idiom must stay silent.
    (tmp_path / "app.js").write_text(
        "app.get('/go', (req, res) => {\n"
        "  res.redirect(req.session.returnUrl);\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsServerSideOpenRedirectGuard().run(tmp_path, profile) == []
