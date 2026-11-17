"""Guard: Express cookies set with the security flags (checklist §6a, extends `insecure-cookies`
to `express`).

A cookie set without `httpOnly: true` is readable by JavaScript (so any XSS steals the session);
without `secure: true` it is sent over plain HTTP (so a network attacker reads it); without
`sameSite` it rides along on cross-site requests (CSRF). A session/auth cookie missing these is
account takeover. OWASP A05.

Fires MEDIUM on a `res.cookie(name, value, options)` call (Express's cookie-setting API) whose
`options` object literal is missing `httpOnly: true` or `secure: true` — either because the key is
simply absent, or explicitly set `false` — or on `res.cookie(name, value)` with no options object
at all (the same "no security flags" exposure). The call is read across lines (a Prettier-formatted
multi-line options object is found via a bracket-counting scan, not a single-line regex). Suppress
an audited case with a `// security: allow-js-secure-cookies` comment on the `res.cookie(` line.

Also fires MEDIUM, independently of the above, when a **sensitive** cookie sets `sameSite: 'none'`
(or `"None"`) without a sibling `secure: true` — CodeQL `py/samesite-none-cookie`'s pattern, carried
over from the Python sibling guard. Setting SameSite explicitly to None (as opposed to leaving it
unset, which Express defaults to no attribute at all — most browsers then apply Lax) re-enables the
cookie riding along on cross-site requests, the exact CSRF exposure SameSite exists to prevent.

**Scope note (departure from the Python sibling):** `insecure_cookies.py`'s missing-flags rule
applies to ALL cookies, while its SameSite=None rule gates on a sensitive-looking name only. This
guard gates **all three** of its rules on the sensitive-name heuristic instead — see the module
docstring in `wiki/guards/js-secure-cookies.md` for why: `res.cookie()` is used
pervasively in Express apps for pure client-UX state (theme, locale, A/B flags) with no options
object at all, and an ALL-cookies missing-flags rule would flood on every one of those. Uses the
SAME sensitive-name identifier list as `insecure_cookies.py` (imported, not duplicated), so the two
guards can never drift apart on what counts as "sensitive".
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, strip_js_comments
from .insecure_cookies import _SENSITIVE_NAME

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-secure-cookies"

_RES_COOKIE = re.compile(r"\bres\.cookie\s*\(")
_HTTPONLY_TRUE = re.compile(r"\bhttpOnly\s*:\s*true\b", re.IGNORECASE)
_SECURE_TRUE = re.compile(r"\bsecure\s*:\s*true\b", re.IGNORECASE)
_SAMESITE_NONE = re.compile(r"""\bsameSite\s*:\s*['"]none['"]""", re.IGNORECASE)
_STRING_LITERAL = re.compile(r"""^['"]([^'"]*)['"]$""")


def _call_args(code: str, open_idx: int) -> list[str] | None:
    """Split a call's `(...)` arguments on TOP-LEVEL commas, from the `(` at `open_idx`.

    Tracks `(){}[]` nesting together (so an options object literal's own commas, or a nested
    call inside an argument, never split early) and skips over string/template literals (so a
    comma or brace inside a quoted value is never mistaken for a real one). This is the same
    bracket-counting technique `js_cors_wildcard.py::_cors_config_object` uses for its config
    object, generalized to also split the call's own top-level argument list — needed here
    because `{ httpOnly: true, secure: true }`'s internal comma sits at the SAME `()`-depth as
    a real second/third argument would, so a paren-only counter (like `insecure_cookies.py`'s
    `_balanced_args`) cannot tell them apart. Returns None if the call never closes
    (malformed/truncated source)."""
    n = len(code)
    depth = 0
    i = open_idx
    quote = ""
    start = open_idx + 1
    args: list[str] = []
    while i < n:
        ch = code[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                args.append(code[start:i])
                return args
        elif ch == "," and depth == 1:
            args.append(code[start:i])
            start = i + 1
        i += 1
    return None  # unterminated call — never reached a matching close


def _cookie_name(name_arg: str) -> tuple[str, bool]:
    """Return `(name, extracted)` for a `res.cookie(...)` call's first argument text.

    Only a literal quoted string is statically resolvable. If the name is a variable/expression
    (`res.cookie(cookieName, ...)`), `extracted` is False and the caller treats it as sensitive —
    the safer default, same policy `insecure_cookies.py::_cookie_name` uses — rather than silently
    passing a cookie whose name it simply couldn't parse."""
    m = _STRING_LITERAL.match(name_arg.strip())
    if m:
        return m.group(1), True
    return "", False


class JsSecureCookiesGuard(Guard):
    id = "js-secure-cookies"
    title = "Express cookies set with HttpOnly + Secure (+ SameSite)"
    area = "Web & browser"

    # express_insecure_cookie.js: sensitive cookie with no options object at all ->
    # fires js-secure-cookies/no-options.
    canary_plant = CanaryPlant(
        files={
            "express_insecure_cookie.js": (
                "app.get('/login', (req, res) => {\n"
                "  res.cookie('session', token);\n"
                "  res.json({ok: true});\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-secure-cookies/no-options"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        code = strip_js_comments(raw)
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        for m in _RES_COOKIE.finditer(code):
            open_idx = m.end() - 1  # the `(` itself
            lineno = code.count("\n", 0, m.start()) + 1
            line_text = view_lines[lineno - 1] if lineno - 1 < len(view_lines) else ""
            if _PRAGMA in line_text:
                continue
            args = _call_args(code, open_idx)
            if args is None or len(args) < 2:
                continue  # unterminated call, or too few args to be a real res.cookie(name, value)
            name, extracted = _cookie_name(args[0])
            # An unextractable name is treated as sensitive (the safer default), mirroring
            # insecure_cookies.py's own policy for the same ambiguity.
            sensitive = not extracted or bool(_SENSITIVE_NAME.search(name))
            display_name = name if extracted else "(name not statically determined)"
            if len(args) == 2:
                # No options object at all — no security flags of any kind.
                if sensitive:
                    out.append(self._no_options_finding(root, f, lineno, display_name))
                continue
            options = args[2].strip()
            if not (options.startswith("{") and options.endswith("}")):
                continue  # options passed as a variable/spread — can't statically analyze
            missing = []
            if not _HTTPONLY_TRUE.search(options):
                missing.append("HttpOnly")
            if not _SECURE_TRUE.search(options):
                missing.append("Secure")
            if missing and sensitive:
                out.append(self._missing_flags_finding(root, f, lineno, display_name, missing))
            if sensitive and _SAMESITE_NONE.search(options) and not _SECURE_TRUE.search(options):
                out.append(self._samesite_none_finding(root, f, lineno, display_name))
        return out

    def _no_options_finding(self, root: Path, f: Path, line: int, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Cookie set without HttpOnly, Secure",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"Cookie '{name}' is set with `res.cookie()` and no options object at all — no "
                "HttpOnly, no Secure, no SameSite. Without HttpOnly any XSS reads it; without "
                "Secure it travels over plain HTTP — a session cookie like this is account takeover."
            ),
            remediation=(
                "Pass `{ httpOnly: true, secure: true, sameSite: \"lax\" }` (or stricter) as the "
                "third argument to `res.cookie()`. Suppress an audited non-session cookie with "
                "`// security: allow-js-secure-cookies`."
            ),
            rule="js-secure-cookies/no-options",
            standards=["OWASP:A05"],
        )

    def _missing_flags_finding(
        self, root: Path, f: Path, line: int, name: str, missing: list[str]
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=f"Cookie set without {', '.join(missing)}",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"Cookie '{name}' is set without {', '.join(missing)}. Without HttpOnly any XSS "
                "reads it; without Secure it travels over plain HTTP — a session cookie like this "
                "is account takeover."
            ),
            remediation=(
                "Set `httpOnly: true, secure: true, sameSite: \"lax\"` (or stricter) in the "
                "options object. Suppress an audited non-session cookie with "
                "`// security: allow-js-secure-cookies`."
            ),
            rule="js-secure-cookies/missing-flags",
            standards=["OWASP:A05"],
        )

    def _samesite_none_finding(self, root: Path, f: Path, line: int, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Sensitive cookie with SameSite=None",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"Cookie '{name}' explicitly sets sameSite: 'none' without secure: true, which "
                "re-enables it riding along on cross-site requests — the exact CSRF exposure "
                "SameSite exists to prevent. This looks like a session/auth/token cookie, where "
                "that exposure matters."
            ),
            remediation=(
                'Use sameSite: "lax" (or "strict" if the cookie is never needed cross-site) unless '
                "this cookie genuinely must be sent on cross-site requests (e.g. a third-party embed "
                "callback) — if so, pair it with secure: true and suppress with "
                "`// security: allow-js-secure-cookies` if still flagged, documenting why."
            ),
            rule="js-secure-cookies/samesite-none",
            standards=["OWASP:A05", "CWE-1275"],
        )
