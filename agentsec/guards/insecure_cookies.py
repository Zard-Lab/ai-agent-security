"""Guard: cookies set with the security flags (checklist §6a).

A cookie set without `httponly=True` is readable by JavaScript (so any XSS steals
the session); without `secure=True` it is sent over plain HTTP (so a network
attacker reads it); without `samesite` it rides along on cross-site requests (CSRF).
A session/auth cookie missing these is account takeover. OWASP A05.

Fires MEDIUM on a `set_cookie(...)` call (Flask/FastAPI/Starlette/Django response)
that is missing `httponly=True` or `secure=True`. The call is read across lines.
Suppress an audited case (e.g. a deliberately readable non-session cookie) with a
`# security: allow-insecure-cookie` comment on the `set_cookie` line.

Also fires MEDIUM, independently of the above, when a **sensitive** cookie sets
`samesite="none"` (or `'None'`) — CodeQL `py/samesite-none-cookie`'s pattern. Setting
SameSite explicitly to None (as opposed to leaving it unset, which most frameworks
default to Lax) re-enables the cookie riding along on cross-site requests, the exact
CSRF exposure SameSite exists to prevent. Only fires for a cookie name that looks
sensitive (session/auth/token/csrf-named) — a deliberately cross-site cookie for a
non-sensitive purpose (e.g. an embeddable widget's preference cookie) is a legitimate
and common use of `SameSite=None` and should not be flagged.

**Express/Node (codeql `js/client-exposed-cookie` + `js/samesite-none-cookie`,
`javascript/ql/src/Security/CWE-1004` + `CWE-1275`).** The same two checks apply to
`res.cookie(name, value, {...})` / `response.cookie(...)`: missing `httpOnly`/`secure`
in the options object, or `sameSite: 'none'` on a sensitive-named cookie. Scoped to a
`res`/`response`-named receiver (not a bare `.cookie(` match) to stay clear of
`document.cookie` string assignment and unrelated `.cookie(` methods.
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
    matching_close_paren,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

_SET_COOKIE = re.compile(r"\bset_cookie\s*\(")
_HTTPONLY = re.compile(r"httponly\s*=\s*True", re.IGNORECASE)
_SECURE = re.compile(r"secure\s*=\s*True", re.IGNORECASE)
_SAMESITE = re.compile(r"samesite\s*=", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-insecure-cookie")

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_COOKIE_CALL = re.compile(r"\b(?:res|response)\.cookie\s*\(")
_JS_HTTPONLY = re.compile(r"\bhttpOnly\s*:\s*true", re.IGNORECASE)
_JS_SECURE = re.compile(r"\bsecure\s*:\s*true", re.IGNORECASE)
_JS_SAMESITE = re.compile(r"\bsameSite\s*:", re.IGNORECASE)
_JS_SAMESITE_NONE = re.compile(r"""\bsameSite\s*:\s*['"]none['"]""", re.IGNORECASE)
_JS_PRAGMA_TEXT = "security: allow-insecure-cookie"

# samesite="none" / 'None' — quoted only, so the Python `None` sentinel (many frameworks'
# "don't set this attribute" default) is not confused with the literal cookie attribute value.
_SAMESITE_NONE = re.compile(r"samesite\s*=\s*['\"]none['\"]", re.IGNORECASE)
# The cookie's own name — used to scope samesite=None to sensitive cookies only, mirroring
# CodeQL's own cookie.isSensitive() gate for this exact query. Matches either the first
# POSITIONAL arg or a `key="..."` KEYWORD arg (review #395 M finding: `set_cookie(key=
# "session_id", value=sess, ...)` previously extracted no name at all, since only the
# positional form was recognized, so a real CSRF-exposed session cookie went unflagged).
_FIRST_ARG_NAME = re.compile(r"^\(\s*['\"]([^'\"]+)['\"]")
_KEY_KWARG_NAME = re.compile(r"""\bkey\s*=\s*['"]([^'"]+)['"]""")
_SENSITIVE_NAME = re.compile(
    r"session|auth|token|csrf|credential|secret|jwt|\bsid\b|api[_-]?key", re.IGNORECASE
)


def _cookie_name(args: str) -> tuple[str, bool]:
    """Return `(name, extracted)` for a `set_cookie(...)` call's argument text.

    Tries the positional form first, then the `key=` keyword form. If neither is found, `name`
    is `""` and `extracted` is `False` — the caller then treats an unextractable name as
    sensitive (the safer default) rather than silently passing a cookie whose name it simply
    couldn't parse."""
    m = _FIRST_ARG_NAME.match(args)
    if m:
        return m.group(1), True
    m2 = _KEY_KWARG_NAME.search(args)
    if m2:
        return m2.group(1), True
    return "", False


def _balanced_args(text: str, open_idx: int, *, python: bool = False) -> str:
    """Return `set_cookie(...)` arg text from the `(` at open_idx to its match.

    M4 (the PR #905 review): the naive character-by-character depth counter this
    used to be was NOT quote-aware, so a `)` inside a string value (e.g. `{ note: 'legacy)',
    httpOnly: true, secure: true }`) truncated the scan early and reported "missing httpOnly,
    secure" even though both flags were present just past the string. Now uses `base.py`'s
    quote- and escape-aware `matching_close_paren`, shared with several other guards rather
    than a homegrown walker reused into the new JS scan. `python` reads a tripled quote as one
    delimiter (#613); the Python scan sets it and the JS scan leaves it off.
    """
    close_idx = matching_close_paren(text, open_idx, python=python)
    end = close_idx + 1 if close_idx is not None else len(text)
    return text[open_idx:end]


class InsecureCookiesGuard(Guard):
    id = "insecure-cookies"
    title = "Cookies set with HttpOnly + Secure (+ SameSite)"
    area = "Web & browser"

    # set_cookie without httponly/secure -> fires insecure-cookies.
    # sensitive cookie with httponly+secure present but samesite="none" -> insecure-cookies/samesite-none.
    canary_plant = CanaryPlant(
        files={
            "auth.py": (
                "from fastapi import Response\n\n\n"
                "def login(response: Response, token: str) -> None:\n"
                "    response.set_cookie(\"session\", token)\n"
            ),
            "auth_samesite.py": (
                "from fastapi import Response\n\n\n"
                "def login(response: Response, token: str) -> None:\n"
                "    response.set_cookie(\"session_id\", token, httponly=True, secure=True, samesite=\"none\")\n"
            ),
            # express_cookie.js: res.cookie(...) missing httpOnly -> fires the same
            # insecure-cookies/missing-flags rule on the JS/Express branch (regression lock
            # for the JS scan path specifically, alongside the Python plant above).
            "express_cookie.js": (
                "app.get('/login', (req, res) => {\n"
                "  res.cookie('session_id', token, { secure: true });\n"
                "  res.json({ ok: true });\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "insecure-cookies/missing-flags",
            "insecure-cookies/samesite-none",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features or "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    if is_nonproduct_path(rel(root, f), profile.archive_segments):
                        continue
                    out.extend(self._scan(root, f))
        if "express" in profile.features:
            for f in iter_files(root, _JS_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_js(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # Split on "\n" as `line` counts below: `splitlines` also breaks on a form feed (#1132).
        view_lines = comment_view(text, "python").split("\n")  # same length: comments only (#424)
        for m in _SET_COOKIE.finditer(text):
            open_idx = text.find("(", m.start())
            if open_idx < 0:
                continue
            line = text.count("\n", 0, m.start()) + 1
            line_text = view_lines[line - 1] if line - 1 < len(view_lines) else ""
            if _PRAGMA.search(line_text):
                continue
            args = _balanced_args(text, open_idx, python=True)
            missing = []
            if not _HTTPONLY.search(args):
                missing.append("HttpOnly")
            if not _SECURE.search(args):
                missing.append("Secure")
            samesite = bool(_SAMESITE.search(args))
            if missing:
                also = "" if samesite else " (and consider SameSite)"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=f"Cookie set without {', '.join(missing)}",
                        location=f"{rel(root, f)}:{line}",
                        message=(
                            f"This cookie is set without {', '.join(missing)}. Without HttpOnly any XSS "
                            "reads it; without Secure it travels over plain HTTP — a session cookie like "
                            "this is account takeover."
                        ),
                        remediation=(
                            "Set `httponly=True, secure=True, samesite=\"Lax\"` (or stricter) on the "
                            f"cookie{also}. Suppress an audited non-session cookie with "
                            "`# security: allow-insecure-cookie`."
                        ),
                        rule="insecure-cookies/missing-flags",
                        standards=["OWASP:A05"],
                    )
                )
            if _SAMESITE_NONE.search(args):
                cookie_name, extracted = _cookie_name(args)
                # An unextractable name is treated as sensitive (the safer default) rather than
                # silently passing a cookie whose name the guard couldn't parse at all.
                if not extracted or _SENSITIVE_NAME.search(cookie_name):
                    display_name = cookie_name if extracted else "(name not statically determined)"
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Sensitive cookie with SameSite=None",
                            location=f"{rel(root, f)}:{line}",
                            message=(
                                f"Cookie '{display_name}' explicitly sets SameSite=None, which "
                                "re-enables it riding along on cross-site requests — the exact "
                                "CSRF exposure SameSite exists to prevent. This looks like a "
                                "session/auth/token cookie, where that exposure matters."
                            ),
                            remediation=(
                                'Use samesite="Lax" (or "Strict" if the cookie is never needed '
                                "cross-site) unless this cookie genuinely must be sent on "
                                "cross-site requests (e.g. a third-party embed callback) — if so, "
                                "suppress with `# security: allow-insecure-cookie` and document why."
                            ),
                            rule="insecure-cookies/samesite-none",
                            standards=["OWASP:A05", "CWE-1275"],
                        )
                    )
        return out

    def _scan_js(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        code = strip_js_comments(raw)
        # Split on "\n" as `line` counts below: `splitlines` also breaks on a form feed (#1132).
        view_lines = comment_view(raw, "js").split("\n")  # same length: comments only (#424)
        for m in _JS_COOKIE_CALL.finditer(code):
            open_idx = code.find("(", m.start())
            if open_idx < 0:
                continue
            line = code.count("\n", 0, m.start()) + 1
            line_text = view_lines[line - 1] if line - 1 < len(view_lines) else ""
            if _JS_PRAGMA_TEXT in line_text:
                continue
            args = _balanced_args(code, open_idx)
            missing = []
            if not _JS_HTTPONLY.search(args):
                missing.append("httpOnly")
            if not _JS_SECURE.search(args):
                missing.append("secure")
            samesite = bool(_JS_SAMESITE.search(args))
            if missing:
                also = "" if samesite else " (and consider sameSite)"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=f"Cookie set without {', '.join(missing)}",
                        location=f"{rel(root, f)}:{line}",
                        message=(
                            f"This cookie is set without {', '.join(missing)}. Without httpOnly any XSS "
                            "reads it; without secure it travels over plain HTTP — a session cookie like "
                            "this is account takeover."
                        ),
                        remediation=(
                            "Set `{ httpOnly: true, secure: true, sameSite: \"lax\" }` (or stricter) on "
                            f"the cookie{also}. Suppress an audited non-session cookie with "
                            "`// security: allow-insecure-cookie`."
                        ),
                        rule="insecure-cookies/missing-flags",
                        standards=["OWASP:A05"],
                    )
                )
            if _JS_SAMESITE_NONE.search(args):
                cookie_name, extracted = _cookie_name(args)
                if not extracted or _SENSITIVE_NAME.search(cookie_name):
                    display_name = cookie_name if extracted else "(name not statically determined)"
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Sensitive cookie with SameSite=None",
                            location=f"{rel(root, f)}:{line}",
                            message=(
                                f"Cookie '{display_name}' explicitly sets sameSite: 'none', which "
                                "re-enables it riding along on cross-site requests — the exact "
                                "CSRF exposure SameSite exists to prevent. This looks like a "
                                "session/auth/token cookie, where that exposure matters."
                            ),
                            remediation=(
                                'Use sameSite: "lax" (or "strict" if the cookie is never needed '
                                "cross-site) unless this cookie genuinely must be sent on "
                                "cross-site requests (e.g. a third-party embed callback) — if so, "
                                "suppress with `// security: allow-insecure-cookie` and document why."
                            ),
                            rule="insecure-cookies/samesite-none",
                            standards=["OWASP:A05", "CWE-1275"],
                        )
                    )
        return out
