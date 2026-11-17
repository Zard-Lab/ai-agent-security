"""Guard: Express login route writes req.session without regenerating it first (checklist §2a,
new item — session fixation, CWE-384).

Reusing an existing session as a different (now-authenticated) user lets an attacker who fixed
a session identifier before login — planted a cookie, or shared a login link carrying a session
id — walk in behind the victim once they log in. The synchronizer defence is to regenerate the
session (rotate its identifier) at the moment of authentication, before writing any
authenticated-user data into it.

Sourced from GitHub CodeQL's `js/session-fixation` query
(`javascript/ql/src/Security/CWE-384/SessionFixation.ql`, verified against real fetched source):
a route whose path matches `%login%`, whose handler writes to `req.session.*`, is flagged unless
the same handler also calls `req.session.regenerate(...)` — CodeQL notes that Passport used to be
recognized as an exemption but "they have since added built-in protection against session
fixation", so no library-based exemption is carried here either.

Fires MEDIUM, at most once per matched route: a route registration (`app.get/post/put(...)` or
`router.get/post/put(...)`) whose path string contains "login" (case-insensitive), followed
within the next 30 lines by a `req.session.<prop> = ...` write, with no `req.session.regenerate(`
anywhere in that same window.

**Scope:** JS/TS files only, Express-shaped (`req.session`). Deliberately single-pass and
window-bounded rather than a real brace-matched handler-body walk — a route whose body exceeds
30 lines before writing to the session, or whose `regenerate()` call sits past that window, is a
false negative. A route split across a router-mount plus a separate handler function defined
elsewhere is also not tracked (the handler must be inline at the route registration site).

Suppress an audited case (e.g. a login route with no persistent side effects worth fixing, or a
custom rotation scheme that doesn't call `.regenerate(` by name) with
`// security: allow-session-fixation` on the route registration line.
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
_PRAGMA_TEXT = "security: allow-session-fixation"

_WINDOW = 30

# A route registration whose path string mentions "login" — any receiver (app/router/etc.),
# any of the three state-changing HTTP verbs a login endpoint realistically uses.
_LOGIN_ROUTE = re.compile(
    r"\.\s*(?:get|post|put)\s*\(\s*[\"'][^\"']*login[^\"']*[\"']", re.IGNORECASE
)
_SESSION_WRITE = re.compile(r"\breq\.session\.\w+\s*=(?!=)")
_SESSION_REGENERATE = re.compile(r"\breq\.session\.regenerate\s*\(")

_STANDARDS = ["OWASP:A07", "CWE-384"]


class SessionFixationNoRegenerateGuard(Guard):
    id = "session-fixation-no-regenerate"
    title = "Login route writes session without regenerating it first — session fixation"
    area = "Login & access"

    # express_login.js: /login route writes req.session without regenerate() ->
    # fires session-fixation-no-regenerate/login-writes-session-without-regenerate.
    # Must NOT contain: req.session.regenerate(, or the allow-session-fixation pragma.
    canary_plant = CanaryPlant(
        files={
            "express_login.js": (
                "app.post('/login', (req, res) => {\n"
                "  const user = authenticate(req.body.username, req.body.password);\n"
                "  req.session.userId = user.id;\n"
                "  res.json({ ok: true });\n"
                "});\n"
            ),
        },
        expects=frozenset({"session-fixation-no-regenerate/login-writes-session-without-regenerate"}),
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
            lines = code.splitlines()
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(lines):
                if not _LOGIN_ROUTE.search(line):
                    continue
                if _PRAGMA_TEXT in (view_lines[i] if i < len(view_lines) else ""):
                    continue
                window_end = min(len(lines), i + 1 + _WINDOW)
                window_lines = lines[i:window_end]
                window_text = "\n".join(window_lines)
                if not _SESSION_WRITE.search(window_text):
                    continue
                if _SESSION_REGENERATE.search(window_text):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}:{i + 1}",
                        message=(
                            "This login route writes to `req.session` but never calls "
                            "`req.session.regenerate()` first. An attacker who fixed the "
                            "victim's session identifier before login (a planted cookie, or "
                            "a login link carrying a session id) inherits the now-authenticated "
                            "session once the victim logs in — session fixation (CWE-384)."
                        ),
                        remediation=(
                            "Call `req.session.regenerate((err) => { ... })` before writing "
                            "any authenticated-user data into `req.session`, so a new session "
                            "identifier is issued at the moment of login. If this route has no "
                            "session data worth fixating (e.g. a stateless token exchange), "
                            "suppress with `// security: allow-session-fixation`."
                        ),
                        rule="session-fixation-no-regenerate/login-writes-session-without-regenerate",
                        standards=list(_STANDARDS),
                    )
                )
        return out
