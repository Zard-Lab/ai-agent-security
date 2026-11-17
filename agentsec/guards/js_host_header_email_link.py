"""Guard: HTTP Host header used to build a link in an outgoing email (checklist §6a).

Sourced from GitHub CodeQL's `js/host-header-forgery-in-email-generation` query
(`javascript/ql/src/Security/CWE-640/HostHeaderPoisoningInEmailGeneration.ql` +
`HostHeaderPoisoningInEmailGenerationQuery.qll`, verified against real fetched source,
codeql `@security-severity 9.8`).

An attacker fully controls the HTTP `Host` header on their own request (unlike most
other headers, no infrastructure between attacker and app is guaranteed to normalize
it). If a route handler builds an absolute URL from `req.headers.host` (or
`req.get('host')` / `req.hostname`) and embeds that URL in an outgoing email — a
password-reset link, an invite link, an email-verification link — the attacker can
poison the Host header on the request that triggers the email, causing the link a
*different, real* user receives to point at an attacker-controlled domain. Following
that link leaks the reset/invite token straight to the attacker. CWE-640, OWASP:A01.

This is a new checklist item — the existing `6a-trusted-host-middleware` item is
FastAPI-only (`TrustedHostMiddleware`'s host allowlist) and doesn't cover Express, nor
the email-specific sink (the Python side has no equivalent "host header in an email
body" check either).

**Detection design.** Two conditions must both hold, file-scoped (not per-call — the
host-header read and the `sendMail` call are typically separate statements, not one
expression):

1. The file contains a mail-send indicator: a `.sendMail(` call, or a `nodemailer`
   `require`/`import`.
2. Some line in the file reads the Host header (`req.headers.host` /
   `req.headers['host']` / `req.get('host')` / `req.hostname`) AND that same line
   contains a URL-scheme marker (`://`) — i.e. the host-header read is being spliced
   into an absolute URL, not just logged or compared.

Fires HIGH per matching line:

    const link = `https://${req.headers.host}/reset?token=${token}`;  // security: allow-js-host-header-email-link
    await transporter.sendMail({ to: user.email, html: `Click ${link}` });

Suppress a reviewed exception (e.g. the app is only ever deployed behind a validated
reverse proxy that rewrites Host) with `// security: allow-js-host-header-email-link`
on the URL-building line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-host-header-email-link"

_MAIL_SEND_INDICATOR = re.compile(
    r"""\.sendMail\s*\(|require\(\s*['"]nodemailer['"]\s*\)|from\s+['"]nodemailer['"]""",
    re.IGNORECASE,
)
_HOST_HEADER_READ = re.compile(
    r"""\b(?:req|request)\.(?:headers\.host\b|headers\[['"]host['"]\]"""
    r"""|get\(\s*['"]host['"]\s*\)|hostname\b)""",
    re.IGNORECASE,
)
_URL_SCHEME_MARK = re.compile(r"://")


class JsHostHeaderEmailLinkGuard(Guard):
    id = "js-host-header-email-link"
    title = "Host header used to build a link in an outgoing email"
    area = "Web setup"

    # express_mailer.js: link built from req.headers.host, embedded in a sendMail call ->
    # fires js-host-header-email-link/host-header-in-email-url. Requires "express" (turned
    # on via js-cors-wildcard's express_app.js package.json dep).
    canary_plant = CanaryPlant(
        files={
            "express_mailer.js": (
                "async function sendReset(user, token) {\n"
                "  const link = `https://${req.headers.host}/reset?token=${token}`;\n"
                "  await transporter.sendMail({ to: user.email, html: link });\n"
                "}\n"
            ),
        },
        expects=frozenset({"js-host-header-email-link/host-header-in-email-url"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            if not _MAIL_SEND_INDICATOR.search(code):
                continue
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(code.splitlines(), start=1):
                if not (_HOST_HEADER_READ.search(line) and _URL_SCHEME_MARK.search(line)):
                    continue
                line_text = view_lines[i - 1] if i - 1 < len(view_lines) else ""
                if _PRAGMA in line_text:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This URL is built from the request's own Host header and this "
                            "file sends email. An attacker fully controls the Host header on "
                            "their own request — poisoning it here causes a password-reset/"
                            "invite/verification link sent to a *different* real user to point "
                            "at an attacker-controlled domain, leaking the token when they "
                            "click it."
                        ),
                        remediation=(
                            "Build the link from a trusted, configured base URL "
                            "(e.g. `process.env.APP_BASE_URL`) instead of the request's Host "
                            "header. If the Host header must be trusted, validate it against "
                            "an explicit allowlist first."
                        ),
                        rule="js-host-header-email-link/host-header-in-email-url",
                        standards=["OWASP:A01", "CWE-640"],
                    )
                )
        return out
