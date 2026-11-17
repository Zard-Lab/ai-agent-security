"""Guard: authentication token stored in localStorage or sessionStorage (§2a — Authentication).

Storing JWTs, session tokens, access tokens, and similar credentials in Web Storage
(localStorage / sessionStorage) is a well-known, widely exploited vulnerability. Any
JavaScript running on the same origin — including third-party scripts loaded via CDN,
npm packages with supply-chain compromise, or injected XSS payloads — can read
`localStorage` in full. There is no HttpOnly flag, no SameSite policy, no browser
sandboxing between first-party and third-party code on the same origin. A single
XSS vulnerability anywhere on the page silently exfiltrates every stored token.

The correct mitigations are:
  - Store authentication state in HttpOnly, Secure, SameSite=Strict cookies (the
    browser enforces access — JavaScript cannot read them).
  - For SPAs that must persist tokens client-side, use an in-memory store (a module-
    level variable or React context) that does not survive a page refresh. Accept the
    UX tradeoff of the user re-authenticating after refresh rather than accepting
    persistent token theft.
  - BFF (Backend-For-Frontend) pattern: the BFF issues a session cookie after exchanging
    the OAuth code, so the SPA never sees the token at all.

One statically detectable pattern:

  **`localstorage-setitem`** (HIGH): A .js/.jsx/.ts/.tsx line that calls
  `localStorage.setItem(` or `sessionStorage.setItem(` where the first argument
  (the key name string) contains a credential stem — `token`, `jwt`, `bearer`,
  `credential`, `password`, `secret`, `api_key`, `authorization`, or a standalone
  `auth` (see `_STORAGE_SETITEM` below for the exact word boundaries). The key-name
  match distinguishes credential storage from legitimate UI-state storage (theme,
  locale, cart contents).

**Why HIGH?** Token theft via XSS is one of the most common and impactful attack
classes in web applications. A stolen JWT grants persistent, invisible session access
until the token expires (often hours to days). Unlike cookie theft, the attacker
receives the token's raw value and can use it from any origin, bypassing same-origin
restrictions on the victim's session.

**OWASP mapping:**
  - OWASP:A07 — Identification and Authentication Failures

**False-negative scope:** This guard only catches direct string-literal key names passed
to setItem(). Dynamic key names (`localStorage.setItem(tokenKey, val)` where `tokenKey`
is a variable) are NOT caught — they require dataflow analysis beyond line-level detection.
Wrapping setItem in a utility function also bypasses detection.

**Checklist items:** `2a-tokens-not-in-localstorage`, `6a-no-token-in-web-storage`.

**Suppress:** `// security: allow-token-in-localstorage` anywhere in a file silences this
check for that file. Use only when you have confirmed the stored value is not a credential
(e.g. a feature flag named "session_mode" that controls UI layout, not auth state).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-token-in-localstorage"

_STANDARDS = ["OWASP:A07"]

# Matches the key-name argument (first string literal) passed to localStorage.setItem(
# or sessionStorage.setItem( when the key name contains a credential-like term.
# Examples that fire:
#   localStorage.setItem("token", jwt)
#   localStorage.setItem('auth_token', resp.token)
#   sessionStorage.setItem("jwt", accessToken)
#   localStorage.setItem("authKey", k)          # camelCase, auth-namespaced credential
#   localStorage.setItem("authorization", hdr)  # explicit Authorization-header value
# Examples that stay silent:
#   localStorage.setItem("theme", "dark")
#   localStorage.setItem("authorFlag", "true")  # "author…", not a standalone `auth` token
#
# Credential keyword set deliberately tightened: bare `session` was dropped (a real session
# *token* is still caught by `token`), and `id_token`/`access_token`/`refresh` all collapse
# into `token`. The `auth` alternative fires only when `auth` is a STANDALONE identifier
# token, never when it is the prefix of a longer lowercase word (`author`, `authorize`,
# `authenticate`):
#   - the left boundary `(?<![a-z])` (under IGNORECASE, so either case) drops `reauth`/`oauth`;
#   - the scoped, case-SENSITIVE `(?-i:(?![a-z]))` right boundary drops only a following
#     LOWERCASE letter — so `author…` is excluded, while a separator (`auth_token`), an
#     uppercase camelCase hump (`authToken`/`authKey`/`authData`), a digit, or the closing
#     quote all still fire. A plain `(?![a-z])` under the global IGNORECASE would *also*
#     exclude the uppercase hump, silently dropping `authKey`/`authData`/`authState` — the
#     over-narrowing this scoped form repairs (#904 M1).
# `authorization` continues with a lowercase `o`, so it can't be reached via the `auth`
# branch and gets its own explicit alternative — safe because no `author…` FP contains the
# full word "authorization".
_STORAGE_SETITEM = re.compile(
    r"""(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"]"""
    r"""[^'"]*(?:token|jwt|bearer|credential|password|secret|api[_-]?key"""
    r"""|authorization|(?<![a-z])auth(?-i:(?![a-z])))[^'"]*['"]""",
    re.IGNORECASE,
)

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")


class TokenInLocalstorageGuard(Guard):
    id = "token-in-localstorage"
    title = "Authentication token stored in localStorage / sessionStorage"
    area = "Web & browser"

    # components/auth.js: localStorage.setItem("token", ...) -> fires token-in-localstorage.
    # components/auth.js: localStorage.setItem("token", ...) -> localstorage-setitem.
    canary_plant = CanaryPlant(
        files={
            "components/auth.js": (
                "function storeToken(token) {\n"
                '    localStorage.setItem("token", token);\n'
                '    localStorage.setItem("jwt", token);\n'
                "}\n"
            ),
        },
        expects=frozenset({"token-in-localstorage/localstorage-setitem"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or "javascript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue  # test/example storage keys are not a live credential leak
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # Blank `//` and `/* */` comments (line numbers preserved) so a commented-out or
            # documented `localStorage.setItem('token', ...)` EXAMPLE doesn't fire (issue #424).
            for lineno, line in enumerate(strip_js_comments(text).splitlines(), 1):
                if _STORAGE_SETITEM.search(line):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="Authentication token stored in Web Storage",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "A credential-named key is written to localStorage or "
                                "sessionStorage. Web Storage is fully accessible to any "
                                "JavaScript on the same origin — including third-party "
                                "scripts and XSS payloads — with no HttpOnly equivalent. "
                                "A single XSS vulnerability anywhere on the page silently "
                                "exfiltrates all stored tokens."
                            ),
                            remediation=(
                                "Store auth tokens in HttpOnly, Secure, SameSite=Strict "
                                "cookies instead (the browser enforces JS-inaccessibility). "
                                "For SPAs, prefer an in-memory store (React context / module "
                                "variable) that does not survive a page refresh, or adopt "
                                "the BFF pattern so the SPA never receives the token at all. "
                                "Suppress with `// security: allow-token-in-localstorage` "
                                "only after confirming the stored value is not a credential."
                            ),
                            rule="token-in-localstorage/localstorage-setitem",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
