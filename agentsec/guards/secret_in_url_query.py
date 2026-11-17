"""Guard: secret-like parameter name passed in a URL query string (§6a — Frontend Security).

A common mistake in Python code: embedding a secret value (API key, token, password, etc.)
directly in a URL query string — either via an f-string like
`f"https://api.com?api_key={key}"` or via a `params={"secret": ...}` dict passed to
`requests.get()`. Both approaches place the secret in the URL, where it is:

  - Recorded in server access logs, proxy logs, and CDN logs in plaintext
  - Exposed in the browser history and Referer headers to third-party sites
  - Visible to any network observer between the client and the server (even over TLS,
    the URL path + query are in the SNI and HTTP host header, and many load balancers
    log the full URL)
  - Leaked in error messages that echo the request URL
  - Stored in observability tools (Datadog, Splunk, CloudWatch) as part of request traces

Secrets must travel in HTTP headers (Authorization, X-Api-Key) or in the request body,
never in the URL query string.

Three statically detectable patterns:

  **`secret-in-query-param`** (HIGH): A Python line that either:

  (a) Contains an f-string that embeds a value into a query parameter whose name matches
      a secret pattern: `f"...?{param}=..."` or `f"...&{param}=..."` where param is one of
      api_key, apikey, token, secret, password, auth, key, pass, cred, private.

  (b) Passes a `params=` dict literal to a requests call where one of the dict keys matches
      the same secret-name pattern.

  (c) **`secret-query-param-declared`** (HIGH): A FastAPI route handler *accepts* a
      secret-sounding value via `Query(...)` — the receiving side, not just outbound URL
      construction: `def login(password: str = Query(...))`. This is the app's own endpoint
      requiring the caller to put the secret in the query string, so it lands in server
      access logs / proxy logs / browser history on every legitimate call, not just when a
      developer misuses `requests`.

**Why HIGH?** URL-logged secrets are persistent, hard to rotate, and silently copied to
many downstream systems. A single leaked URL can expose a credential to a large number of
actors (log aggregation, third-party analytics, monitoring) without any active attack.

**OWASP mapping:** OWASP:A02 — Cryptographic Failures (secrets exposed in transit / logs).

**False-negative scope:** Multi-line query constructions (building the URL on one line,
appending `?api_key=` on another) are not caught — they require dataflow analysis. Variable-
name substitution where the param name is not a literal is also not caught.

**Checklist item:** `6a-no-secret-in-url-query`.

**Suppress:** `security: allow-secret-in-url-query` anywhere in a file silences this check
for that file. Use only after confirming the parameter is not actually secret (e.g. a public
API key used for analytics with no associated permissions).

**Express/Node receiving side (codeql `js/sensitive-get-query`,
`javascript/ql/src/Security/CWE-598/SensitiveGetQuery.ql`).** Mirrors pattern (c) above for
Express: `req.query.password` / `req.query['api_key']` in a route handler is the same
receiving-side exposure as FastAPI's `password: str = Query(...)` — the caller must put the
secret in the URL query string on every legitimate call. Uses the same boundaried secret-stem
vocabulary as the Python side (`key` alone stays excluded — `cache_key`/`sort_key` FP history).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    boundaried_stems,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-secret-in-url-query"

_STANDARDS = ["OWASP:A02"]

# Secret-sounding parameter names (case-insensitive).
_SECRET_PARAM = re.compile(
    r"(?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)",
    re.IGNORECASE,
)

# Pattern (a): f-string with a secret param name in a query string.
# Matches lines that contain an f-string opening AND a query-param slot like
# ?api_key= or &token= where the param name is secret-sounding.
# The param name can be preceded by ? or &.
_FSTRING_OPEN = re.compile(r"""\bf['"]""")
_QUERY_SECRET_PARAM = re.compile(
    r"""[?&](?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)=""",
    re.IGNORECASE,
)

# Pattern (b): params={"secret_name": ...} dict literal in a requests call.
# Matches params={"api_key": ..., "token": ..., etc.} on the same line.
_PARAMS_DICT_SECRET = re.compile(
    r"""params\s*=\s*\{[^}]*['"](?:api_key|apikey|token|secret|password|auth|key|pass|cred|private)['"]\s*:""",
    re.IGNORECASE,
)

# Pattern (c): a FastAPI route parameter bound to Query(...) whose name is secret-sounding —
# `password: str = Query(...)` or `password = Query(...)`. The optional non-capturing group
# handles the type annotation; both annotated and bare-default forms are matched.
#
# The secret stems are BOUNDARIED (guards/base.py::boundaried_stems), not bare substrings, so a
# stem can't bleed into an ordinary identifier: `auth` no longer fires `author`, `pass` no longer
# fires `passthrough`. Bare `key` is deliberately DROPPED from the standalone stems (it is a clean
# segment of the extremely common `cache_key`/`sort_key`/`foreign_key` and fired HIGH on all of
# them) — `api_key`/`apikey` still cover the real secret form. Compound secrets (`auth_token`,
# `my_secret`, `x_api_key`) still match via `\w*` around the boundaried segment.
_SECRET_STEMS = r"api_key|apikey|token|secret|password|passwd|auth|pass|cred|credential|private"  # nosec B105 (detection pattern, not a credential)
# A secret-sounding parameter name, then EITHER the `= Query(` default form (optionally typed)
# OR the modern `Annotated[str, Query(...)]` idiom, where `Query(` sits inside the type annotation
# with no `=` before it (review #395 M8: the annotated form was a false negative).
_NAME_SECRET = r"\b\w*" + boundaried_stems(_SECRET_STEMS) + r"\w*"
_QUERY_PARAM_SECRET = re.compile(
    _NAME_SECRET + r"""\s*(?:"""
    r"""(?::[^=,\n]*)?=\s*Query\s*\("""          # name [: type] = Query(
    r"""|:\s*Annotated\[[^\]]*Query\s*\("""       # name: Annotated[..., Query(...)]
    r""")""",
    re.IGNORECASE,
)

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_SECRET_NAME_RE = re.compile(_NAME_SECRET, re.IGNORECASE)
_JS_QUERY_DOT = re.compile(r"""\breq\.query\.(\w+)""")
_JS_QUERY_BRACKET = re.compile(r"""\breq\.query\[\s*['"](\w+)['"]\s*\]""")


class SecretInUrlQueryGuard(Guard):
    id = "secret-in-url-query"
    title = "Secret passed as a URL query parameter (logs, history, Referer exposure)"
    area = "Secrets"

    # api_client.py plant (shared, owned by no guard, xxe_safe.py's ownership rule) ->
    # secret-in-query-param. This guard additionally owns its own JS plant below.
    # express_secret_query.js: req.query.password read in a route handler -> fires
    # secret-in-url-query/secret-query-param-declared on the JS/Express branch.
    canary_plant = CanaryPlant(
        files={
            "express_secret_query.js": (  # nosec B105 (canary fixture text, not a real credential)
                "app.get('/login', (req, res) => {\n"
                "  const pw = req.query.password;\n"
                "  res.json({ ok: true });\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "secret-in-url-query/secret-in-query-param",
            "secret-in-url-query/secret-query-param-declared",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features or "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "express" in profile.features:
            # M3 (the PR #905 review): scope to product code, matching this PR's
            # own sibling insecure_cookies.py.
            for f in iter_files(root, _JS_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_js(root, f))
        if "python" not in profile.features:
            return out
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                for lineno, line in enumerate(text.splitlines(), 1):
                    if _QUERY_PARAM_SECRET.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="Route parameter accepts a secret via the URL query string",
                                location=f"{rel(root, f)}:{lineno}",
                                message=(
                                    "This route declares a parameter with a secret-sounding name "
                                    "(api_key, token, secret, password, auth, key, etc.) bound to "
                                    "Query(...) — callers must put the secret in the URL query "
                                    "string to use this endpoint. Every legitimate call then logs "
                                    "the secret in server access logs, proxy logs, browser "
                                    "history, and Referer headers."
                                ),
                                remediation=(
                                    "Accept the secret via a request header (e.g. "
                                    "`Authorization`/`X-Api-Key` with `Header(...)`) or in the "
                                    "request body instead of `Query(...)`. Suppress with "
                                    "`# security: allow-secret-in-url-query` only after "
                                    "confirming the parameter is not sensitive."
                                ),
                                rule="secret-in-url-query/secret-query-param-declared",
                                standards=list(_STANDARDS),
                            )
                        )
                        continue
                    if self._line_fires(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="Secret passed as a URL query parameter",
                                location=f"{rel(root, f)}:{lineno}",
                                message=(
                                    "A parameter with a secret-sounding name (api_key, token, "
                                    "secret, password, auth, key, etc.) is being placed in the "
                                    "URL query string. Query parameters are recorded in server "
                                    "access logs, proxy logs, browser history, and Referer "
                                    "headers — all of which may be accessible to parties who "
                                    "should not see the secret. Even over HTTPS the URL is "
                                    "visible in load-balancer logs and CDN telemetry."
                                ),
                                remediation=(
                                    "Move the secret to an HTTP header instead: use "
                                    "`headers={'Authorization': f'Bearer {token}'}` or "
                                    "`headers={'X-Api-Key': api_key}` in the requests call. "
                                    "For POST/PUT, pass the secret in the JSON body. Never "
                                    "put secrets in the URL query string. Suppress with "
                                    "`# security: allow-secret-in-url-query` only after "
                                    "confirming the parameter is not sensitive."
                                ),
                                rule="secret-in-url-query/secret-in-query-param",
                                standards=list(_STANDARDS),
                            )
                        )
        return out

    def _line_fires(self, line: str) -> bool:
        # Pattern (a): f-string AND a query-param slot with a secret name.
        if _FSTRING_OPEN.search(line) and _QUERY_SECRET_PARAM.search(line):
            return True
        # Pattern (b): params= dict literal with a secret key name.
        return bool(_PARAMS_DICT_SECRET.search(line))

    def _scan_js(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        if pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
            return out
        code = strip_js_comments(raw)
        pragma_lines = pragma_line_set(_PRAGMA, raw, dialect="js")  # the finding's own line (#424)
        for i, line in enumerate(code.splitlines(), start=1):
            name = None
            m = _JS_QUERY_DOT.search(line)
            if m:
                name = m.group(1)
            else:
                m = _JS_QUERY_BRACKET.search(line)
                if m:
                    name = m.group(1)
            if name is None or not _SECRET_NAME_RE.search(name):
                continue
            if i in pragma_lines:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Route parameter accepts a secret via the URL query string",
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        f"`req.query.{name}` reads a secret-sounding value (api_key, token, "
                        "secret, password, auth, key, etc.) from the URL query string — callers "
                        "must put the secret in the URL to use this endpoint. Every legitimate "
                        "call then logs the secret in server access logs, proxy logs, browser "
                        "history, and Referer headers."
                    ),
                    remediation=(
                        "Accept the secret via a request header (e.g. `Authorization`/"
                        "`X-Api-Key`) or in the request body instead of the query string. "
                        "Suppress with `// security: allow-secret-in-url-query` only after "
                        "confirming the parameter is not sensitive."
                    ),
                    rule="secret-in-url-query/secret-query-param-declared",
                    standards=list(_STANDARDS),
                )
            )
        return out
