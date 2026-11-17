"""Guard: Express/Node CORS response wildcarded to any origin (§6a, CWE-346).

An Express handler that sets `Access-Control-Allow-Origin: *` (directly via
`res.set`/`res.header`/`res.writeHead`, or via the `cors` npm package wired to
`app.options('*', cors())`) accepts cross-origin requests from any website. In
an app with cookie or token auth, any malicious page can make an authenticated
request on the user's behalf — the same CORS/CSRF misconfiguration the
existing `cors-wildcard` guard already checks for FastAPI's `CORSMiddleware`.

Sourced from njsscan's `header_cors_star.yaml` rule pack (`ajinabraham/njsscan`,
real Semgrep-syntax rules — `generic_cors` + `express_cors`), verified against
the real fetched source. Adapted from Semgrep AST `pattern-inside`/metavariable
matching to same-file regex (agentsec has no JS AST engine).

Fires HIGH for any of these shapes:

    app.options('*', cors())                                    // security: allow-cors-wildcard
    res.set('Access-Control-Allow-Origin', '*')                 // security: allow-cors-wildcard
    res.header('Access-Control-Allow-Origin', '*')              // security: allow-cors-wildcard
    res.writeHead(200, { 'Access-Control-Allow-Origin': '*' })  // security: allow-cors-wildcard
    cors({ origin: true })                                      // security: allow-cors-wildcard
    cors({ origin: null })                                      // security: allow-cors-wildcard

The `origin: true`/`origin: null` shape is a distinct config surface from the
literal `'*'` string: verified against GitHub CodeQL's
`javascript/ql/src/Security/CWE-942/CorsPermissiveConfiguration.ql` +
`CorsPermissiveConfigurationCustomizations.qll`. The `cors` npm middleware
treats `origin: true` as "reflect whatever `Origin` header the request sent" —
effectively any origin, without the literal `*` string ever appearing in the
response. CodeQL treats this config as sanitized ONLY when `credentials: false`
is also set in the same config object, since `origin: true` combined with
`credentials: true` (or an unspecified `credentials`, alongside cookie/auth
usage elsewhere) is what lets cookies/auth headers ride along to an
attacker-controlled, reflected origin. This guard mirrors that logic: silent
only when `credentials: false` also appears within the same `cors({...})`
object literal.

**Checklist item:** extends `6a-cors-restricted` (adds `"express"` to
`applies_when` alongside the existing `"fastapi"` gate) rather than a new
item — same language, same misconfiguration, same fix (an explicit origin
allowlist).

**Reflected-origin + credentials (codeql `js/cors-misconfiguration-for-credentials`,
`javascript/ql/src/Security/CWE-346/CorsMisconfigurationForCredentials.ql`).** A distinct
shape from the above: a handler that manually echoes the request's own `Origin` header back
as `Access-Control-Allow-Origin` (`req.headers.origin` / `req.header('origin')` /
`req.get('origin')`) — never going through the `cors` npm package at all, so the
`origin: true`/`credentials: false` config-object check above doesn't see it — combined with
`Access-Control-Allow-Credentials: true` set anywhere in the same file. This is functionally
"any origin" (same as `origin: true` + `credentials: true`) but constructed by hand. Precision
is file-scoped, not object-scoped, since the two header calls are typically separate `res.set()`
statements rather than one config literal.

Every shape above counts only when it is live code, tested on the shared anchor mask
(`js_code_matches`, #1055): a call on its `(`, a config key on its first character, never on the
`'*'` or header-name literal the patterns read on purpose. A `'credentials: false'` spelled out in a
note string no longer clears a permissive config, and a CORS call spelled out in a docs string no
longer fires; one nested in a `${...}` substitution still does.
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-cors-wildcard"
_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# app.options('*', cors(...)) — the cors npm package wired to a wildcard preflight route.
_OPTIONS_CORS = re.compile(r"""\.options\s*\(\s*['"]\*['"]\s*,\s*cors\s*\(""")

# res.set/.header('Access-Control-Allow-Origin', '*', ...) — direct header call, name+value args.
_HEADER_CALL_WILDCARD = re.compile(
    r"""\.(?:set|header)\s*\(\s*['"]access-control-allow-origin['"]\s*,\s*['"]\*['"]""",
    re.IGNORECASE,
)

# res.set(...) / res.writeHead(...) with an object-literal argument carrying the header, e.g.
# res.writeHead(200, { 'Access-Control-Allow-Origin': '*' }).
_HEADER_OBJECT_WILDCARD = re.compile(
    r"""\.(?:set|writeHead)\s*\([^{]{0,80}\{[^}]{0,200}['"]?access-control-allow-origin['"]?\s*:\s*['"]\*['"]""",
    re.IGNORECASE | re.DOTALL,
)

# A `cors(` call — the npm `cors` middleware factory, invoked either standalone (`app.use(cors({...}))`)
# or nested inside `app.options('*', cors({...}))` (already covered by `_OPTIONS_CORS` for its own
# literal-'*' shape; this pattern additionally inspects the config OBJECT that shape's `cors(` may carry).
# `\b` before "cors" keeps this from matching an unrelated identifier ending in "cors" (e.g. `mycors(`).
_CORS_CALL = re.compile(r"\bcors\s*\(")

# `origin: true` / `origin: null` inside a `cors({...})` config object — the `cors` npm package's
# "reflect the request's Origin header" / "no explicit allow" shapes (CodeQL CWE-942).
_ORIGIN_PERMISSIVE = re.compile(r"\borigin\s*:\s*(?:true|null)\b")

# `credentials: false` inside the same config object — CodeQL's sanitizer: without credentials, a
# reflected/any origin can't ride cookies/auth headers cross-origin, so this is the safe combination.
_CREDENTIALS_FALSE = re.compile(r"\bcredentials\s*:\s*false\b")

# .set(/.header('Access-Control-Allow-Origin', <value expr>) — captures the value expression
# (not just a literal '*') so it can be checked against _ORIGIN_HEADER_READ below.
# The value expression may itself contain one level of parens — `req.get('origin')`,
# `req.header('origin')` — so the capture is balanced to one nesting level rather than the
# earlier `[^)]+`, which stopped at that inner `)` and truncated the capture. Since
# _ORIGIN_HEADER_READ's `get(...)`/`header(...)` alternatives require the closing paren, the
# truncated capture never matched and those two idiomatic Express header reads went silent
# despite this guard's docstring claiming them (PR #905 review M-1). The two alternation
# branches are disjoint on their first char (`[^()]` excludes `(`), so this is ReDoS-safe.
_ORIGIN_SET_VALUE = re.compile(
    r"""\.(?:set|header)\s*\(\s*['"]access-control-allow-origin['"]\s*,\s*"""
    r"""((?:[^()]|\([^()]*\))+?)\s*\)""",
    re.IGNORECASE,
)

# The value expression reads the request's own Origin header back — a manual reflection,
# never going through the `cors` npm package's origin:true handling above.
_ORIGIN_HEADER_READ = re.compile(
    r"""\b(?:req|request)\.(?:headers\.origin\b|headers\[['"]origin['"]\]"""
    r"""|header\(\s*['"]origin['"]\s*\)|get\(\s*['"]origin['"]\s*\))""",
    re.IGNORECASE,
)

# .set(/.header('Access-Control-Allow-Credentials', true|'true') anywhere in the file —
# CodeQL's own sink characterization for this query (the credentials header, not the config object).
_CREDENTIALS_TRUE_CALL = re.compile(
    r"""\.(?:set|header)\s*\(\s*['"]access-control-allow-credentials['"]\s*,\s*['"]?true['"]?\s*\)""",
    re.IGNORECASE,
)


def _call_paren(m: re.Match[str]) -> int:
    """The anchor of a header call or `cors(` call (#1055): the match's first `(`, never the `'*'` or
    header-name literal the pattern reads on purpose."""
    return m.start() + m.group().index("(")


def _start(m: re.Match[str]) -> int:
    return m.start()


def _cors_config_object(code: str, after: int) -> tuple[str, int] | None:
    """From `after` (just past a `cors(` call's opening paren), return the `{...}` object-literal
    argument as `(blob, blob_start_index)`, or `None` if the next non-whitespace token isn't `{`
    (e.g. `cors()` with no args, or `cors(myConfigVar)` — a variable this guard can't resolve) or
    the object literal never closes (malformed/truncated source).

    A small bracket-counting scan rather than a single regex: `origin:` and `credentials:` are
    typically on separate lines within the same call (Prettier-formatted), so the config must be
    captured as one blob before either sub-pattern can be checked against it."""
    i, n = after, len(code)
    while i < n and code[i].isspace():
        i += 1
    if i >= n or code[i] != "{":
        return None
    start = i
    depth = 0
    while i < n:
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1], start
        i += 1
    return None  # unterminated object literal — never reached a matching close


class JsCorsWildcardGuard(Guard):
    id = "js-cors-wildcard"
    title = "Express/Node CORS response wildcarded to any origin"
    area = "Web setup"

    # express_app.js: app.options('*', cors()) and res.set(...'*') -> fires both
    # js-cors-wildcard sub-rules. Requires "express" as a root package.json dependency
    # to turn on the "express" StackProfile feature.
    canary_plant = CanaryPlant(
        files={
            "express_app.js": (
                "const cors = require('cors');\n"
                "const app = require('express')();\n"
                "app.options('*', cors());\n"
                "app.get('/data', (req, res) => {\n"
                "  res.set('Access-Control-Allow-Origin', '*');\n"
                "  res.json({ ok: true });\n"
                "});\n"
            ),
            # express_cors_credentials.js: manual Origin-header reflection + Access-Control-Allow-
            # Credentials: true -> fires js-cors-wildcard/reflected-origin-with-credentials.
            "express_cors_credentials.js": (
                "app.get('/account', (req, res) => {\n"
                "  res.set('Access-Control-Allow-Origin', req.headers.origin);\n"
                "  res.set('Access-Control-Allow-Credentials', 'true');\n"
                "  res.json({ ok: true });\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "js-cors-wildcard/explicit-options-wildcard",
            "js-cors-wildcard/response-header-wildcard",
            "js-cors-wildcard/reflected-origin-with-credentials",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            # Skip a target's test/example/fixture trees, for parity with the sibling JS guards
            # (insecure_cookies/jwt_alg/secret_in_url_query) that gained this skip in this same
            # batch (PR #905 M2/M3) — a CORS misconfig planted in example code is not a real
            # finding on the audited app. The whole-file pragma below still governs product code.
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            code = strip_js_comments(raw)  # comments only — cors matches string VALUES ('*'), keep them
            # The anchor mask (#1055): same layout as `code`, so whole-text and per-line offsets
            # both line up. Every match below must be anchored in live code on it.
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            rows = zip(code.splitlines(), mask.splitlines(), strict=True)
            for i, (line, mask_line) in enumerate(rows, start=1):
                if _PRAGMA in view_lines[i - 1]:
                    continue
                if any(js_code_matches(_OPTIONS_CORS, line, mask_line, anchor=_call_paren)):
                    out.append(self._finding(root, f, i, "explicit-options-wildcard"))
                elif any(js_code_matches(_HEADER_CALL_WILDCARD, line, mask_line, anchor=_call_paren)):
                    out.append(self._finding(root, f, i, "response-header-wildcard"))
            # The object-literal header form is scanned on the WHOLE file, not per line: a
            # Prettier-formatted `res.writeHead(200, {\n  'Access-Control-Allow-Origin': '*',\n})`
            # spans lines, which the per-line pass above can't see (PR #407 review — the DOTALL on
            # _HEADER_OBJECT_WILDCARD was dead under per-line matching).
            for m in js_code_matches(_HEADER_OBJECT_WILDCARD, code, mask, anchor=_call_paren):
                lineno = code.count("\n", 0, m.start()) + 1
                if _PRAGMA in view_lines[lineno - 1]:
                    continue
                out.append(self._finding(root, f, lineno, "response-header-wildcard"))
            # cors({ origin: true|null }) without a sibling `credentials: false` — object-scoped
            # (spans lines), so also matched on the whole file rather than per line.
            for cm in js_code_matches(_CORS_CALL, code, mask, anchor=_call_paren):
                config = _cors_config_object(code, cm.end())
                if config is None:
                    continue
                blob, blob_start = config
                # Both keys must be live code (#1055): a note string that spells out
                # `credentials: false` used to clear a real permissive config.
                blob_mask = mask[blob_start : blob_start + len(blob)]
                om = next(js_code_matches(_ORIGIN_PERMISSIVE, blob, blob_mask, anchor=_start), None)
                if om is None or any(js_code_matches(_CREDENTIALS_FALSE, blob, blob_mask, anchor=_start)):
                    continue
                lineno = code.count("\n", 0, blob_start + om.start()) + 1
                if _PRAGMA in view_lines[lineno - 1]:
                    continue
                out.append(self._finding(root, f, lineno, "permissive-origin-config"))
            # Manual Origin-header reflection + Access-Control-Allow-Credentials: true anywhere
            # in the same file — the two header calls are typically separate res.set()
            # statements, not one object literal, so this is file-scoped rather than block-scoped.
            if any(js_code_matches(_CREDENTIALS_TRUE_CALL, code, mask, anchor=_call_paren)):
                for vm in js_code_matches(_ORIGIN_SET_VALUE, code, mask, anchor=_call_paren):
                    value, value_mask = vm.group(1), mask[vm.start(1) : vm.end(1)]
                    if not any(js_code_matches(_ORIGIN_HEADER_READ, value, value_mask, anchor=_start)):
                        continue
                    lineno = code.count("\n", 0, vm.start()) + 1
                    if _PRAGMA in view_lines[lineno - 1]:
                        continue
                    out.append(self._finding(root, f, lineno, "reflected-origin-with-credentials"))
        return out

    def _finding(self, root: Path, f: Path, line: int, slug: str) -> Finding:
        if slug == "reflected-origin-with-credentials":
            message = (
                "Access-Control-Allow-Origin is set to a value read from the request's own "
                "Origin header, and Access-Control-Allow-Credentials is set to true elsewhere "
                "in this file. This manually reproduces the same 'any origin, with credentials' "
                "exposure as `cors({ origin: true })` — an attacker-controlled page can make an "
                "authenticated cross-origin request and read the response, since its own Origin "
                "is always echoed back and accepted."
            )
        elif slug == "permissive-origin-config":
            message = (
                "The `cors` middleware config sets `origin: true` (or `origin: null`) without a "
                "sibling `credentials: false`. `origin: true` reflects whatever `Origin` header the "
                "request sent — effectively any origin — and combined with credentials enabled "
                "(cookies/auth headers), lets an attacker-controlled page make an authenticated "
                "cross-origin request and read the response."
            )
        else:
            message = (
                "Access-Control-Allow-Origin is set to \"*\". This disables the Same-Origin "
                "Policy for this response — any website can read it, and in an app with cookie "
                "or token auth, any page can make an authenticated request on the user's behalf."
            )
        return Finding(
            check_id=self.id,
            severity="high",
            title="CORS response wildcarded to any origin",
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=(
                "Restrict the origin to an explicit allowlist (e.g. the `cors` package's "
                "`origin: [\"https://app.example.com\"]` option, or validate `req.headers.origin` "
                "against a known list before echoing it back). If this endpoint is intentionally "
                "public and unauthenticated, suppress with `// security: allow-cors-wildcard`."
            ),
            rule=f"js-cors-wildcard/{slug}",
            standards=["OWASP:A05", "CWE-346"],
        )
