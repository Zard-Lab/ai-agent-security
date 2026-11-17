from __future__ import annotations

from agentsec.guards.js_host_header_email_link import JsHostHeaderEmailLinkGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_host_header_email_link_flags_template_literal(tmp_path: Path) -> None:
    (tmp_path / "mailer.js").write_text(
        "async function sendReset(user, token) {\n"
        "  const link = `https://${req.headers.host}/reset?token=${token}`;\n"
        "  await transporter.sendMail({ to: user.email, html: link });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-host-header-email-link/host-header-in-email-url"
    assert findings[0].severity == "high"


def test_js_host_header_email_link_flags_concatenation(tmp_path: Path) -> None:
    (tmp_path / "mailer.js").write_text(
        "const link = 'https://' + req.headers.host + '/invite?code=' + code;\n"
        "transporter.sendMail({ to: user.email, html: link });\n",
        encoding="utf-8",
    )
    findings = JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_js_host_header_email_link_silent_without_mail_context(tmp_path: Path) -> None:
    # FP-bait: a URL is built from the Host header, but this file never sends email.
    (tmp_path / "redirect.js").write_text(
        "const base = `https://${req.headers.host}`;\nres.redirect(base);\n",
        encoding="utf-8",
    )
    assert JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_host_header_email_link_silent_host_logged_no_scheme(tmp_path: Path) -> None:
    # FP-bait: Host header present in a mail-sending file, but only logged, never spliced into a URL.
    (tmp_path / "mailer.js").write_text(
        "console.log('host:', req.headers.host);\n"
        "transporter.sendMail({ to: 'x@example.com', text: 'hi' });\n",
        encoding="utf-8",
    )
    assert JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_host_header_email_link_silent_trusted_base_url(tmp_path: Path) -> None:
    # FP-bait: the link is built from a trusted config var, not the request's Host header.
    (tmp_path / "mailer.js").write_text(
        "const link = `https://${process.env.APP_BASE_URL}/reset`;\n"
        "transporter.sendMail({ to: user.email, html: link });\n",
        encoding="utf-8",
    )
    assert JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_host_header_email_link_pragma(tmp_path: Path) -> None:
    (tmp_path / "mailer.js").write_text(
        "const link = `https://${req.headers.host}/reset`; // security: allow-js-host-header-email-link\n"
        "transporter.sendMail({ to: user.email, html: link });\n",
        encoding="utf-8",
    )
    assert JsHostHeaderEmailLinkGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_host_header_email_link_not_applies_without_express() -> None:
    assert JsHostHeaderEmailLinkGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False
