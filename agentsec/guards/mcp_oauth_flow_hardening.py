"""Guard: an MCP OAuth 2.1 client flow is missing PKCE/S256, forwards an inbound
Authorization header verbatim, allows a wildcard redirect_uri, is bearer-only with no
proof-of-possession, or doesn't conform to the 2026-07-28 MCP auth profile (RFC 9207/8707/
9728) (checklist §4, new item; agent-audit-kit's `oauth_misconfig.py` AAK-OAUTH-001..008).

MCP spec 2025-11-25 makes OAuth 2.1 mandatory with PKCE+S256, RFC 8707 Resource Indicators,
and RFC 9728 Protected Resource Metadata; the 2026-07-28 profile adds RFC 9207 issuer
validation. This is distinct from the existing `mcp-oauth-scope-creep` guard, which checks
scope BREADTH (a wildcard/`admin` scope value) and a dangerous authorization-URL scheme —
none of the eight checks here overlap it.

Baseline OAuth 2.1 hygiene:

  1. **`missing-pkce`** (HIGH): an `authorize(`/`authorization_endpoint` call site with no
     PKCE fields (`code_verifier`/`code_challenge`/`pkce`, or an authorization server's
     `code_challenge_methods_supported` advertising `S256`) anywhere in the file.
  2. **`pkce-plain-method`** (HIGH): `code_challenge_method` set to `"plain"` — S256 is
     required.
  3. **`token-passthrough`** (HIGH): an `Authorization` header populated directly from the
     inbound request (`headers["Authorization"] = request.headers[...]`) — the caller's own
     token is forwarded verbatim rather than the server's own credential being used.
  4. **`wildcard-redirect-uri`** (HIGH): a `redirect_uri`/`redirect_uris` value of `*`, a
     `http(s)://*` wildcard, a bare `http://localhost` (optionally with a trailing `/`) with no
     port or path pin, or a localhost port or path wildcard (`http://localhost:*`,
     `http://localhost/*`). `http://localhost:3000/cb` is pinned and does not match, nor does a
     `*` past a query, fragment or list separator (`http://localhost:3000/cb&scope=*`).
  5. **`bearer-only-no-dpop`** (MEDIUM): a file uses Bearer-token auth with no DPoP/mTLS
     proof-of-possession marker anywhere.

2026-07-28 MCP auth profile conformance:

  6. **`missing-iss-validation`** (HIGH, RFC 9207 / SEP-2468): an authorization-code
     response is handled (`grant_type=authorization_code`, an `exchangeCodeForToken`-shaped
     call, or a callback reading `code`/`state`) with no `iss` reference anywhere in the
     file.
  7. **`missing-resource-indicator`** (HIGH, RFC 8707): a token-acquisition flow
     (`grant_type=`, `authorization_endpoint`/`token_endpoint`, `authorize(`,
     `response_type=code`, or an `/oauth2?/authorize|token` path) with no `resource`
     parameter anywhere — issued tokens are not audience-bound to this MCP server.
  8. **`missing-prm-discovery`** (MEDIUM, RFC 9728 / SEP-2468): an MCP remote-server auth
     surface (a remote transport config or server source enforcing bearer auth) with no
     Protected Resource Metadata discovery (`/.well-known/oauth-protected-resource`,
     `authorization_servers`, ...) — the client relies on a static/embedded credential
     instead of spec-driven discovery.

Scope and limits (the checks are text scans, not data-flow analysis):

  * A finding anchors only on the MCP surface (#1023). The repo-wide `mcp` feature says the repo
    uses MCP, not that every OAuth-looking line in it is MCP OAuth. A file is on the surface
    when it carries an MCP marker itself (an import of the Python `mcp`/`fastmcp` SDK or of a JS/TS
    MCP SDK or framework, read with comments blanked; or, for a JSON/YAML/TOML config, an MCP
    config filename or an `mcpServers`/`mcp_servers` key), or when a product-path marker file
    imports it directly (one hop: a JS/TS relative specifier, a Python relative import, or a
    Python package import resolved against the marker's ancestor directories). Lockfiles,
    `*.gen.{ts,tsx,js,jsx,mjs}`, `*.d.{ts,mts,cts}`, `__snapshots__/` and files with a
    generated header never anchor.
    Unresolved imports (tsconfig path aliases, workspace packages) and helpers two hops away are
    known blind spots.
  * Every finding carries `path:line` of its anchor. Whole-line comments are not call sites.
  * PKCE and the RFC 8707 `resource` parameter are resolved across the scanned tree through
    the class hierarchy (Python `class A(B)`, TS/JS `class A extends B`, matched by class
    NAME), and PKCE also through construction of an OAuth-flavoured class defined in a file
    that carries PKCE. That index reads EVERY scanned file, on the surface or not, so a PKCE
    base class in a non-MCP or generated file still vouches for its MCP subclass. `iss`, DPoP
    and PRM discovery are still single-file.
  * `bearer-only-no-dpop` needs a client-side call site (an outgoing `Authorization` header
    assigned a Bearer value); server-side `WWW-Authenticate: Bearer` challenges do not match.
  * A `.json` file that is itself a JSON-Schema document is skipped; a real config that merely
    carries a `$schema` key is still scanned.
  * The `missing-*` rules and `bearer-only-no-dpop` are review signals
    (`surfacing_rule_prefixes`); they cannot tell a client from a resource server or see a
    mitigation delivered by composition. Wiki: `wiki/guards/mcp-oauth-flow-hardening.md`.

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-mcp-oauth-flow-hardening
    // security: allow-mcp-oauth-flow-hardening   (JS/TS)
"""
from __future__ import annotations

import json
import re
from bisect import bisect_left
from pathlib import Path
from typing import Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-mcp-oauth-flow-hardening")

_SCAN_EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".yaml", ".yml", ".toml")

# A JSON file that IS a JSON-Schema document (a top-level `properties`/`$defs`/`definitions`
# with `$schema` pointing at a json-schema.org meta-schema) describes the SHAPE of a config, it
# is not a live MCP client/server runtime file, however OAuth-flavored its own content looks. A
# real config that merely CARRIES a `$schema` key (editors / schemastore tooling add
# `"$schema": "https://json.schemastore.org/..."` to ordinary files) is still scanned: the old
# whole-file skip on any `$schema` key silently dropped a live `redirect_uri: "*"` config.
# The Mintlify docs-site manifest (`docs.json`) FP that motivated the old skip is closed by the
# path-like-string masking below, not by trusting `$schema`.
_JSON_SCHEMA_META_RE = re.compile(r"json-schema\.org", re.IGNORECASE)


def _is_json_schema_document(text: str) -> bool:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):  # hostile deep nesting: not a usable schema doc
        return False
    if not isinstance(data, dict):
        return False
    meta = data.get("$schema")
    if not isinstance(meta, str) or not _JSON_SCHEMA_META_RE.search(meta):
        return False
    return any(k in data for k in ("properties", "$defs", "definitions"))


# continued: a doc-nav manifest / FRAGMENT (a Mintlify docs.json, or a fragment it
# references -- confirmed on fastmcp's real docs/v2-navigation.json,
# docs/v3-navigation.json) is a plain array of page-path STRINGS like "clients/auth/oauth" or
# "servers/auth/remote-oauth". A real OAuth config/code value never has this multi-segment
# slash-path shape, so blanking any quoted string matching it before the hint search removes
# the FP source without touching genuine "client_id"/"oauth" occurrences as a key, identifier,
# or single-segment value.
_PATH_LIKE_STRING_RE = re.compile(r'"[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+){1,}"')


def _mask_path_like_strings(text: str) -> str:
    return _PATH_LIKE_STRING_RE.sub(lambda m: " " * len(m.group(0)), text)

# (Dean's review, corpus-scan review): `authorize\(` used to gate this too, and
# it is not an OAuth-specific token -- it is a common English verb, and a plain permission
# check function/call named `authorize(...)` (a GitHub Actions "may this PR deploy a
# preview" helper, a role-based-access gate, ...) is not an OAuth 2.1 client flow at all.
# Confirmed on the real python-sdk repo: `.github/scripts/docs_preview.js`'s
# `async function authorize({ github, context, core })` (a PR-permission check, zero OAuth
# content) tripped the whole-file gate, then every "no PKCE/resource-indicator anywhere"
# absence check fired on a file that was never implementing an OAuth flow to begin with.
# The canary's own plant still fires without it (`client_id=client_id` matches the
# `client_id` alternative), and a real OAuth authorization-code flow almost always mentions
# `oauth`/`authorization_endpoint`/`token_endpoint`/`client_id` somewhere in the same file.
_OAUTH_HINT = re.compile(r"\b(?:oauth|authorization_endpoint|token_endpoint|client_id)", re.IGNORECASE)

# `pkce` is matched with `_` treated as a separator (`_generate_pkce_pair`, `use_pkce`), and
# `code_challenge` only when it is not the `code_challenge_method` key on its own.
_PKCE_PRESENT_RE = re.compile(
    r"\bcode_verifier\b|(?<![A-Za-z0-9])pkce(?![A-Za-z0-9])|code_challenge(?!_method)"
    # An authorization server advertising S256: a kwarg or an unquoted object key, as a server
    # builds its RFC 8414 metadata. A QUOTED key is a client holding discovery data it fetched
    # (`{'code_challenge_methods_supported': ['S256']}`), which says nothing about its own flow.
    r"|(?<![\"'\w])code_challenge_methods_supported\s*[:=]\s*\[?[^\]\n]{0,40}S256",
    re.IGNORECASE,
)
_PKCE_PLAIN_RE = re.compile(r"code_challenge_method['\"]?\s*[:=]\s*['\"]?plain\b", re.IGNORECASE)
# The localhost arm matches a BARE `http://localhost` (an optional trailing `/`, then the end of
# the value) or a localhost value carrying a `*` port or path wildcard (`http://localhost:*`,
# `http://localhost/*`). The `*` scan stops at the value's closing quote, whitespace, or a query,
# fragment or list separator (`?`, `#`, `&`, `,`, `;`), so the `*` of `.../cb&scope=*` is not the
# redirect URI's, and it is bounded at 512 characters, since an unbounded run rescanned a long
# unbroken line from every `redirect_uri=http://localhost:` start (quadratic). The arm used to
# match the `http://localhost` prefix of every localhost URL, so a port- and path-pinned
# `http://localhost:3000/confirm` fired too (#1023).
_WILDCARD_REDIRECT_RE = re.compile(
    r"""redirect_uri(?:s)?['\"]?\s*[:=]\s*['\"]?\[\s*['\"]\*['\"]|"""
    r"""redirect_uri(?:s)?['\"]?\s*[:=]\s*['\"]?(?:\*|https?://\*|"""
    r"""http://localhost(?:[:/][^'\"\s,;&#?]{0,512}\*|/?(?=['\"\s,\]]|$)))|"""
    r"""redirect_uri(?:s)?\s*:\s*\[\s*['\"]\*['\"]""",
    re.IGNORECASE,
)
_TOKEN_FORWARD_RE = re.compile(
    r"""(?:["']Authorization["']\s*:\s*(?:request|req|event|input)\.headers\s*\[|"""
    r"""(?:headers|request\.headers)\s*\[\s*['\"]Authorization['\"]\s*\]\s*=\s*(?:request\.|req\.|event\.|input\.))""",
    re.IGNORECASE,
)
# A CLIENT-SIDE call site: an outgoing `Authorization` header (dict item, subscript or kwarg)
# being assigned a Bearer value -- a literal token, or an f-string/template-literal
# interpolation (`f'Bearer {token}'`, `` `Bearer ${token}` ``, the overwhelmingly common
# real-world shape). Server-side files that merely CHALLENGE with `WWW-Authenticate: Bearer`
# or validate an inbound bearer token never assign an `Authorization` header, so they no
# longer match (the previous "the word Bearer plus the word Authorization anywhere" gate
# fired on fastmcp's `middleware.py`, which is a server building a challenge).
_BEARER_ONLY_RE = re.compile(
    r"""\bAuthorization\b['"\]]*\s*[:=,]\s*[fFbB]?['"`]Bearer\s+['"]?"""
    r"""(?:[a-zA-Z0-9_\-.]+|\{[^}]{1,80}\}|\$\{[^}]{1,80}\})""",
    re.IGNORECASE,
)
_DPOP_HINT_RE = re.compile(r"\b(?:DPoP|dpop)\b|cnf\b", re.IGNORECASE)

_AUTHCODE_FLOW_RE = re.compile(
    r"grant_type['\"]?\s*[:=]\s*['\"]?authorization_code"
    r"|\bexchange[_A-Za-z]*code[_A-Za-z]*token\b"
    r"|\bexchangeCodeForToken\b"
    r"|(?:args|query|params|query_params|searchParams|GET)\s*(?:\.get\s*\(|\[)\s*['\"]code['\"]",
    re.IGNORECASE,
)
_ISS_PRESENT_RE = re.compile(r"\biss\b")

# `grant_type` counts only as a request field (a quoted dict key, a `grant_type=` kwarg or form
# field), never as a type annotation (`grant_type: str = ...`) or the tail of a constant name
# (`DEVICE_AUTH_GRANT_TYPE = ...`); a bare `token_endpoint: str` parameter annotation is not a
# token request either.
_TOKEN_ACQUISITION_RE = re.compile(
    r"['\"]grant_type['\"]\s*:|(?<![A-Za-z0-9_])grant_type\s*=(?!=)"
    r"|\b(?:authorization|token)_endpoint\b(?!\s*:\s*[A-Za-z_])"
    r"|\bauthorize\s*\("
    r"|response_type['\"]?\s*[:=]\s*['\"]?code"
    r"|/(?:oauth2?/)?(?:authorize|token)\b",
    re.IGNORECASE,
)
_RESOURCE_PARAM_RE = re.compile(
    r"[?&]resource="
    r"|['\"]resource['\"]\s*[:=]"
    r"|\bresource\s*=\s*"
    r"|\bresource_indicators?\b"
    r"|\bRFC\s?8707\b",
    re.IGNORECASE,
)

_MCP_REMOTE_RE = re.compile(
    r'"type"\s*:\s*"(?:streamable-?http|http|sse|streamable)"'
    r'|"transport"\s*:\s*"(?:streamable-?http|http|sse|streamable)"'
    r'|"url"\s*:\s*"https?://',
    re.IGNORECASE,
)
_MCP_INLINE_AUTH_RE = re.compile(
    r'"Authorization"\s*:'
    r"|\bBearer\b"
    r'|"auth"\s*:\s*\{'
    r"|\b--oauth\b"
    r'|"(?:access_token|api_key|token)"\s*:\s*"',
    re.IGNORECASE,
)
_MCP_SERVER_AUTH_RE = re.compile(
    r"\bWWW-Authenticate\b|\bBearerAuthProvider\b|\bRequireAuthMiddleware\b|\brequire_auth\b",
    re.IGNORECASE,
)
_PRM_DISCOVERY_RE = re.compile(
    r"oauth-protected-resource"
    r"|protected[_-]?resource[_-]?metadata"
    r"|\bresource_metadata\b"
    r"|\bauthorization_servers\b"
    r"|\bRFC\s?9728\b",
    re.IGNORECASE,
)

_STD_BASELINE = ["OWASP:A07", "OWASP-ASI:ASI04"]
_STD_PROFILE = ["OWASP:A07", "OWASP-ASI:ASI04"]

_MESSAGES: dict[str, str] = {
    "missing-pkce": "OAuth authorize call without PKCE fields (code_verifier/code_challenge) — required by MCP spec 2025-11-25.",
    "pkce-plain-method": "PKCE code_challenge_method=plain — S256 is required by MCP spec 2025-11-25.",
    "token-passthrough": "Authorization header populated verbatim from the inbound request (token passthrough) — the caller's token is forwarded instead of the server's own credential.",
    "wildcard-redirect-uri": "Wildcard or overly-broad redirect_uri — any destination can receive the authorization code.",
    "bearer-only-no-dpop": "Bearer-only auth with no DPoP/mTLS proof-of-possession — a leaked bearer token is directly usable by anyone.",
    "missing-iss-validation": "OAuth authorization-code response handled without validating the `iss` parameter (RFC 9207 / MCP 2026-07-28 SEP-2468).",
    "missing-resource-indicator": "OAuth flow builds authorization/token requests without the RFC 8707 `resource` parameter — issued tokens are not audience-bound to this MCP server.",
    "missing-prm-discovery": "MCP OAuth surface has no RFC 9728 Protected Resource Metadata discovery (/.well-known/oauth-protected-resource) — remote auth relies on a static/embedded credential.",
}
_SEVERITY: dict[str, Literal["high", "medium"]] = {
    "missing-pkce": "high",
    "pkce-plain-method": "high",
    "token-passthrough": "high",
    "wildcard-redirect-uri": "high",
    "bearer-only-no-dpop": "medium",
    "missing-iss-validation": "high",
    "missing-resource-indicator": "high",
    "missing-prm-discovery": "medium",
}


_PY_CLASS_RE = re.compile(r"^[^\S\n]*class\s+(\w+)\s*(?:\(([^)]*)\))?\s*:", re.MULTILINE)
_JS_CLASS_RE = re.compile(r"\bclass\s+(\w+)(?:<[^>{]*>)?(?:\s+extends\s+([\w.]+))?")
_BASE_NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\[.*)?$")

_HASH_COMMENT_EXTS = (".py", ".yaml", ".yml", ".toml")


_PY_TRIPLE_QUOTE_RE = re.compile(r'("""|\'\'\')(?:(?!\1).)*?\1', re.DOTALL)


def _blank_python_docstrings(text: str) -> str:
    """Blank the CONTENTS of every Python triple-quoted string (length- and newline-preserving),
    whether it is used as a docstring or an ordinary multi-line string literal. A "Known bypasses"/
    example paragraph that mentions `oauth/authorize` in prose is not a call site, and the
    whole-line `#` comment blanking below never reaches text inside a triple-quoted block."""
    def _blank(m: re.Match[str]) -> str:
        return "".join(c if c == "\n" else " " for c in m.group(0))
    return _PY_TRIPLE_QUOTE_RE.sub(_blank, text)


def _blank_comment_lines(text: str, suffix: str) -> str:
    """Blank whole-line comments (length- and newline-preserving, so offsets and line numbers
    stay aligned). Used for the POSITIVE anchors only (`authorize(`, `/token`, ...) so a
    comment that mentions them is not a call site; mitigation markers (`code_verifier`,
    `resource`, ...) are still searched in the untouched text, where a comment claiming the
    mitigation is the conservative direction."""
    if suffix.lower() == ".py":
        text = _blank_python_docstrings(text)
    hash_style = suffix.lower() in _HASH_COMMENT_EXTS
    out: list[str] = []
    for line in text.split("\n"):
        st = line.lstrip()
        if (hash_style and st.startswith("#")) or (
            not hash_style and st.startswith(("//", "/*", "*"))
        ):
            out.append(" " * len(line))
        else:
            out.append(line)
    return "\n".join(out)


def _class_bases(text: str, suffix: str) -> dict[str, list[str]]:
    """`{class name: [base class names]}` declared in one file (Python `class A(B, C):` and
    JS/TS `class A extends B`)."""
    found: dict[str, list[str]] = {}
    if suffix.lower() == ".py":
        for m in _PY_CLASS_RE.finditer(text):
            bases: list[str] = []
            for part in (m.group(2) or "").split(","):
                part = part.strip()
                if not part or "=" in part:
                    continue
                bm = _BASE_NAME_RE.search(part.split(".")[-1] if "[" not in part else part)
                if bm:
                    bases.append(bm.group(1))
            found[m.group(1)] = bases
    elif suffix.lower() in (".ts", ".tsx", ".js", ".jsx", ".mjs"):
        for m in _JS_CLASS_RE.finditer(text):
            found[m.group(1)] = [m.group(2).split(".")[-1]] if m.group(2) else []
    return found


def _inherits(own: dict[str, list[str]], all_bases: dict[str, list[str]], marker_classes: set[str]) -> bool:
    """True when a class this file declares inherits (transitively, across the scanned tree)
    from a class whose defining file carries the mitigation marker."""
    seen: set[str] = set()
    stack = [b for bases in own.values() for b in bases]
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        if name in marker_classes:
            return True
        stack.extend(all_bases.get(name, []))
    return False


_OAUTHISH_NAME_RE = re.compile(r"oauth|auth|proxy|provider|pkce", re.IGNORECASE)
# Args captured too (any nesting depth: `Foo(x=Bar(str(y)))`), so the caller can require the
# construction to actually CONFIGURE something, not merely name-and-marker-match a bare `Foo()`
# built for an unrelated reason elsewhere in the same file.
_CLASS_CALL_START_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s*\(")
_UNCLOSED_ARGS_LIMIT = 4000  # chars of argument span taken for a call whose paren never closes
# Strings and comments, masked before paren pairing so `note="see (draft"` or `/* see (x */` cannot
# unbalance it. Each language gets only its own tokens: a backtick is a template literal in JS/TS
# but not a string in Python, `#` starts a comment in Python but not in JS/TS, and `//` is floor
# division in Python. The next token START is found by regex and its END by `str.find` or an
# escape-aware walk, so each character is visited once whatever the input.
_PY_TOKEN_START_RE = re.compile(r"\"\"\"|'''|[\"'#]")
_JS_TOKEN_START_RE = re.compile(r"/\*|//|[`\"']")
_QUOTE_START_RE = re.compile(r"[\"']")
_JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs")
_NOT_NEWLINE_RE = re.compile(r"[^\n]")


def _quote_end(text: str, i: int, quote: str, one_line: bool) -> int:
    """Index just past the closing `quote` for a literal whose body starts at `i`, honouring
    backslash escapes; -1 when a one-line literal meets a newline (so it was not a string)."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        if ch == "\n" and one_line:
            return -1
        i += 1
    return -1 if one_line else n


def _mask_strings(text: str, suffix: str = ".py") -> str:
    """Blank every string literal and comment of `suffix`'s language (Python: quotes, triple
    quotes, `#`; JS/TS: quotes, template literals, `//`, `/* */`; anything else: quotes), keeping
    newlines and length so offsets stay aligned."""
    suffix = suffix.lower()
    starts = _PY_TOKEN_START_RE if suffix == ".py" else _JS_TOKEN_START_RE if suffix in _JS_EXTS else _QUOTE_START_RE
    out: list[str] = []
    pos = 0  # start of the text not yet copied to `out`
    scan = 0  # where the next token search starts
    n = len(text)
    while True:
        m = starts.search(text, scan)
        if not m:
            break
        tok, s = m.group(0), m.start()
        if tok in ('"""', "'''"):
            e = text.find(tok, s + 3)
            end = n if e < 0 else e + 3
        elif tok in ("#", "//"):
            e = text.find("\n", s)
            end = n if e < 0 else e
        elif tok == "/*":
            e = text.find("*/", s + 2)
            end = n if e < 0 else e + 2
        else:  # a one-line quote, or a JS/TS template literal (which may span lines)
            end = _quote_end(text, s + 1, tok, one_line=tok != "`")
            if end < 0:
                scan = s + 1  # an unclosed one-line quote is an apostrophe, not a string
                continue
        out.append(text[pos:s])
        out.append(_NOT_NEWLINE_RE.sub(" ", text[s:end]))
        pos = scan = end
    out.append(text[pos:])
    return "".join(out)


def _class_calls(text: str, suffix: str = ".py") -> list[tuple[str, int, int]]:
    """Each `ClassName(...)` call as `(name, args_start, args_end)` offsets into `text`. String
    literals are masked first, then one pass pairs every `(` with its `)` on a stack, so the cost
    is linear however many calls are nested or unclosed, and returning offsets (not argument
    slices) keeps deep nesting linear too. A regex with a quantified group around `[^()]*`
    backtracks exponentially on an unclosed or doubly-nested call, which every real SDK has."""
    masked = _mask_strings(text, suffix)
    close_of: dict[int, int] = {}
    opens: list[int] = []
    for i, ch in enumerate(masked):
        if ch == "(":
            opens.append(i)
        elif ch == ")" and opens:
            close_of[opens.pop()] = i
    out: list[tuple[str, int, int]] = []
    for m in _CLASS_CALL_START_RE.finditer(masked):
        start = m.end()
        out.append((m.group(1), start, close_of.get(start - 1, min(len(masked), start + _UNCLOSED_ARGS_LIMIT))))
    return out


_KWARG_RE = re.compile(r"\b[A-Za-z_]\w*\s*=(?!=)")


def _instantiates(text: str, marker_classes: set[str], suffix: str = ".py") -> bool:
    """True when the file constructs an OAuth-flavoured class (name mentions oauth/auth/proxy/
    provider/pkce) that is defined in a file carrying the mitigation marker, WITH at least one
    keyword argument: the file configures a PKCE-implementing proxy rather than implementing the
    flow itself. A bare, no-config `Foo()` (constructed for some unrelated reason -- logging,
    a factory, a different call site entirely) does not count; requiring a kwarg is the same
    shape the genuine fastmcp case already has (`OAuthProxy(upstream_authorization_endpoint=...)`).
    The name filter keeps a generic class name (`Client`, `Config`) that merely shares a file with
    a PKCE mention from suppressing the finding."""
    kwargs = [m.start() for m in _KWARG_RE.finditer(_mask_strings(text, suffix))]
    for name, start, end in _class_calls(text, suffix):
        if name in marker_classes and _OAUTHISH_NAME_RE.search(name):
            i = bisect_left(kwargs, start)
            if i < len(kwargs) and kwargs[i] < end:
                return True
    return False


def _line_loc(r: str, text: str, offset: int) -> str:
    return f"{r}:{text.count(chr(10), 0, offset) + 1}"


# ── MCP surface: where a finding may anchor (#1023) ──────────────────────────────────────────
# The rule vocabulary is generic OAuth text (`/token`, `authorize(`, `token_endpoint`), so once the
# repo-wide `mcp` feature is on, a product monorepo's lockfile, generated route tree, NextAuth
# provider or Slack installer all fired. Anchors are now tied to MCP code. The class/PKCE/resource
# indexes still read every file (CLAUDE.md rule 4): this narrows where a finding may ANCHOR only.

_LOCKFILE_NAMES = frozenset({"pnpm-lock.yaml", "package-lock.json", "npm-shrinkwrap.json"})
_ARTIFACT_NAME_RE = re.compile(r"\.gen\.(?:ts|tsx|js|jsx|mjs)$|\.d\.[cm]?ts$", re.IGNORECASE)
# The generated-header sniff mirrors `mcp_stateless_migration._is_generated`: only the head is read.
_GENERATED_HEADER_RE = re.compile(r"@generated|\bdo not (?:edit|modify)\b", re.IGNORECASE)


def _is_artifact(key: str, raw: str) -> bool:
    """A lockfile, generated module, type declaration or test snapshot: never an OAuth flow."""
    parts = key.split("/")
    name = parts[-1]
    if name.lower() in _LOCKFILE_NAMES or _ARTIFACT_NAME_RE.search(name) or "__snapshots__" in parts[:-1]:
        return True
    head = "\n".join(raw.split("\n", 10)[:10]).lower()
    return "@generated" in head or ("generated" in head and bool(_GENERATED_HEADER_RE.search(head)))


# Import-shaped MCP use only: an identifier, a comment or prose that says "MCP" is not a marker.
# Python: the official `mcp` SDK and `fastmcp`. JS/TS: the official SDK packages plus the server
# frameworks that wrap it (Cloudflare's `agents/mcp`, Vercel's `mcp-handler`/`@vercel/mcp-adapter`,
# `mcp-framework`, `@mastra/mcp`, `xmcp`). A framework missing from this list is a blind spot.
# `import(?:\s*\()?` and not `import\s*\(?\s*`: two adjacent `\s*` around an optional `(` backtrack
# quadratically on a long whitespace run (1.3 s at 20,000 spaces, measured).
_PY_MCP_IMPORT_RE = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.MULTILINE)
_JS_MCP_IMPORT_RE = re.compile(
    r"""(?:\bfrom|\brequire\s*\(|\bimport(?:\s*\()?)\s*['"]"""
    r"""(?:@modelcontextprotocol/|(?:fastmcp|agents/mcp|mcp-handler|@vercel/mcp-adapter|mcp-framework"""
    r"""|@mastra/mcp|xmcp)['"/])"""
)
_MCP_PREFILTER_RE = re.compile(r"mcp|modelcontextprotocol", re.IGNORECASE)
# Config markers: detect.py's MCP config names, any config whose filename carries an `mcp` token
# (`mcp.json`, `.mcp.json`, `mcp-servers.json`, `mcp_client_config.yaml`), a `.mcp/` directory,
# or the client-config key every MCP host uses.
_MCP_CONFIG_NAMES = frozenset({"servers.json", "claude_desktop_config.json"})
_MCP_CONFIG_NAME_RE = re.compile(r"(?<![a-z0-9])(?:fast)?mcp(?![a-z0-9])", re.IGNORECASE)
_MCP_CONFIG_KEY_RE = re.compile(r"\b(?:mcpServers|mcp_servers)\b")
_CONFIG_EXTS = (".json", ".yaml", ".yml", ".toml")

# One hop: the relative/package imports of a marker file.
_JS_REL_IMPORT_RE = re.compile(r"""(?:\bfrom|\bimport|\brequire\s*\(|\bimport\s*\()\s*['"](\.{1,2}/[^'"\n]+)['"]""")
# Linear by construction (#1027): `(?=\S)` makes `from[ \t]+` take the whole space run, so it cannot
# split one with `[ \t]+import` when the module is empty; the module starts with an identifier
# letter (`[^\W\d]`, Unicode-aware like Python 3 itself), so it cannot take a dot from `(\.*)`;
# and the paren group is bounded, so an unclosed `(` line does not scan to EOF. Each of the three
# used to backtrack quadratically.
_PY_FROM_IMPORT_RE = re.compile(
    r"^[ \t]*from[ \t]+(?=\S)(\.*)([^\W\d][\w.]*)?[ \t]+import[ \t]+(\([^)]{0,4000}\)|[^\n]*)",
    re.MULTILINE,
)
_PY_IMPORT_RE = re.compile(r"^[ \t]*import[ \t]+([^\n]+)", re.MULTILINE)
_PY_ALIAS_RE = re.compile(r"\bas[ \t]+\w+")
_PY_HASH_COMMENT_RE = re.compile(r"#[^\n]*")
_IDENT_RE = re.compile(r"[^\W\d]\w*")  # a Python 3 identifier, non-ASCII letters included


def _is_mcp_config(key: str, raw: str) -> bool:
    parts = key.split("/")
    return bool(
        parts[-1].lower() in _MCP_CONFIG_NAMES
        or _MCP_CONFIG_NAME_RE.search(parts[-1])
        or ".mcp" in parts[:-1]
        or _MCP_CONFIG_KEY_RE.search(raw)
    )


def _join(base_dir: str, spec: str) -> str | None:
    """`base_dir/spec` normalised (`.`/`..` collapsed); None when it climbs above the scan root."""
    parts = [p for p in base_dir.split("/") if p]
    for seg in spec.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(seg)
    return "/".join(parts)


def _js_targets(key: str, code: str) -> set[str]:
    """Candidate keys for each relative specifier: the path as written, with each JS/TS extension,
    the ESM `.js` -> `.ts` mapping, and `dir/index.*`."""
    base_dir = key.rsplit("/", 1)[0] if "/" in key else ""
    out: set[str] = set()
    for spec in _JS_REL_IMPORT_RE.findall(code):
        target = _join(base_dir, spec)
        if target is None:
            continue
        out.add(target)
        stem, dot, ext = target.rpartition(".")
        if dot and ext in ("js", "jsx", "mjs"):
            out.update(f"{stem}.{e}" for e in ("ts", "tsx"))
        out.update(f"{target}{e}" for e in _JS_EXTS)
        out.update(f"{target}/index{e}" for e in _JS_EXTS)
    return out


def _py_targets(key: str, code: str) -> set[str]:
    """Candidate keys for each import: a relative import resolved from the file's package, and a
    package-absolute one under each of the file's ancestor directories (a source root is always
    one of them). For `from M import N`, `N` may be a submodule, so `M/N` is a candidate too."""
    dirs = key.split("/")[:-1]
    ancestors = ["/".join(dirs[:i]) for i in range(len(dirs), -1, -1)]
    modules: list[tuple[list[str], str]] = []  # (base dirs to resolve under, dotted module path)
    for dots, mod, names in _PY_FROM_IMPORT_RE.findall(code):
        if dots:
            up = len(dots) - 1
            if up > len(dirs):
                continue
            bases = ["/".join(dirs[: len(dirs) - up])]
        else:
            bases = ancestors
        subs = _IDENT_RE.findall(_PY_ALIAS_RE.sub("", _PY_HASH_COMMENT_RE.sub("", names)))
        if mod:
            modules.append((bases, mod))
        modules.extend((bases, f"{mod}.{n}" if mod else n) for n in subs)
    for line in _PY_IMPORT_RE.findall(code):
        for item in _PY_ALIAS_RE.sub("", _PY_HASH_COMMENT_RE.sub("", line)).split(","):
            dotted = item.strip()
            if dotted and all(_IDENT_RE.fullmatch(p) for p in dotted.split(".")):
                modules.append((ancestors, dotted))
    out: set[str] = set()
    for bases, dotted in modules:
        rel_mod = dotted.replace(".", "/")
        for b in bases:
            prefix = f"{b}/{rel_mod}" if b else rel_mod
            out.add(f"{prefix}.py")
            out.add(f"{prefix}/__init__.py")
    return out


def _mcp_surface(scanned: list[_Scanned]) -> set[str]:
    """Keys of the MCP files: every marker file, plus every file a product-path marker imports
    directly. A marker on a test/example path is not evidence that the product module it imports
    is MCP code, so it does not extend the surface. A generated marker does: a codegen'd MCP
    server entry that imports a hand-written auth module puts that module on the surface. The
    caller still refuses an anchor in any artifact, on the surface or not."""
    keys = {sc.key for sc in scanned}
    surface: set[str] = set()
    for sc in scanned:
        if sc.suffix in _CONFIG_EXTS:
            if _is_mcp_config(sc.key, sc.raw):
                surface.add(sc.key)
            continue
        if not _MCP_PREFILTER_RE.search(sc.raw):
            continue
        # Comments (and Python docstrings) blanked; strings kept, since a specifier is one. A
        # leading BOM (kept by `read()`) is dropped first, or the `^`-anchored Python marker and
        # import regexes miss a first-line import and the file silently leaves the surface.
        is_py = sc.suffix == ".py"
        src = sc.raw.removeprefix("\ufeff")
        code = _blank_comment_lines(src, ".py") if is_py else strip_js_comments(src)
        if not (_PY_MCP_IMPORT_RE if is_py else _JS_MCP_IMPORT_RE).search(code):
            continue
        surface.add(sc.key)
        if not sc.nonproduct:
            targets = _py_targets(sc.key, code) if is_py else _js_targets(sc.key, code)
            surface.update(targets & keys)
    return surface


class _Scanned:
    __slots__ = ("path", "rel", "key", "raw", "text", "suffix", "skip", "nonproduct", "artifact", "classes")

    def __init__(self, path: Path, rel_path: str, raw: str, nonproduct: bool, skip: bool) -> None:
        self.path = path
        self.rel = rel_path
        self.key = rel_path.replace("\\", "/")  # import resolution works on forward-slash keys
        self.raw = raw
        self.suffix = path.suffix.lower()
        self.nonproduct = nonproduct
        self.skip = skip
        self.artifact = _is_artifact(self.key, raw)
        self.text = raw
        if not skip and self.suffix in (".json", ".yaml", ".yml", ".toml"):
            self.text = _mask_path_like_strings(raw)
        self.classes = _class_bases(raw, self.suffix)


class McpOauthFlowHardeningGuard(Guard):
    id = "mcp-oauth-flow-hardening"
    title = "MCP OAuth flow is missing PKCE, forwards tokens, or doesn't conform to the 2026-07-28 auth profile"
    area = "AI agent"

    # The presence/absence rules cannot prove a mitigation is genuinely missing (it may live in
    # a helper, a wrapper package, or a base class this text scan cannot resolve), and a
    # file-level match cannot tell a client from a server. They are review signals, not proven
    # bugs. The presence rules (plain PKCE, token passthrough, wildcard redirect) stay proven.
    surfacing_rule_prefixes = (
        "mcp-oauth-flow-hardening/missing-",
        "mcp-oauth-flow-hardening/bearer-only-no-dpop",
    )

    # oauth_client.py: an MCP module (the import puts it on the MCP surface) whose authorize()
    # call has no PKCE fields -> fires mcp-oauth-flow-hardening/missing-pkce.
    canary_plant = CanaryPlant(
        files={
            "oauth_client.py": (
                "from mcp.server.fastmcp import FastMCP\n\n"
                "def start_login(client_id):\n"
                "    return authorize(client_id=client_id, response_type='code')\n"
            ),
        },
        expects=frozenset({
            "mcp-oauth-flow-hardening/missing-pkce",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # Pass 1: read every candidate. Files that are skipped as anchors (non-product paths,
        # pragma, JSON-Schema documents, artifacts, anything off the MCP surface) are still
        # indexed for class hierarchy, so an `OAuthProxy`-style base class implementing PKCE is
        # visible to its subclasses wherever it lives.
        scanned: list[_Scanned] = []
        for f in iter_files(root, _SCAN_EXTS):
            raw = read(f)
            if not raw:
                continue
            r = rel(root, f)
            nonproduct = is_nonproduct_path(r, profile.archive_segments)
            skip = (
                nonproduct
                or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f))
                or (f.suffix.lower() == ".json" and _is_json_schema_document(raw))
            )
            scanned.append(_Scanned(f, r, raw, nonproduct, skip))

        all_bases: dict[str, list[str]] = {}
        pkce_classes: set[str] = set()
        resource_classes: set[str] = set()
        for sc in scanned:
            all_bases.update(sc.classes)
            if sc.classes and _PKCE_PRESENT_RE.search(sc.raw):
                pkce_classes.update(sc.classes)
            if sc.classes and _RESOURCE_PARAM_RE.search(sc.raw):
                resource_classes.update(sc.classes)

        surface = _mcp_surface(scanned)
        out: list[Finding] = []
        for sc in scanned:
            if sc.skip or sc.artifact or sc.key not in surface:
                continue
            out.extend(self._check_file(
                sc,
                pkce_inherited=(
                    _inherits(sc.classes, all_bases, pkce_classes)
                    or _instantiates(sc.raw, pkce_classes, sc.suffix)
                ),
                resource_inherited=_inherits(sc.classes, all_bases, resource_classes),
            ))
        return out

    def _check_file(self, sc: _Scanned, pkce_inherited: bool, resource_inherited: bool) -> list[Finding]:
        r, raw, text = sc.rel, sc.raw, sc.text
        code = _blank_comment_lines(text, sc.suffix)
        out: list[tuple[str, int]] = []

        # PRM markers are matched against the UNMASKED text: masking blanks quoted
        # slash-path strings, and `".well-known/oauth-protected-resource"` is exactly that shape.
        if not _PRM_DISCOVERY_RE.search(raw):
            remote_auth = bool(_MCP_REMOTE_RE.search(code) and _MCP_INLINE_AUTH_RE.search(code))
            anchor = _MCP_INLINE_AUTH_RE.search(code) if remote_auth else _MCP_SERVER_AUTH_RE.search(code)
            if anchor is not None:
                out.append(("missing-prm-discovery", anchor.start()))

        if _OAUTH_HINT.search(text):
            # The annotation exclusion `_TOKEN_ACQUISITION_RE` already carries for
            # `authorization_endpoint` (never a type annotation, e.g. `authorization_endpoint: str`
            # on a plain data-schema class) -- this anchor needs the same one, since a call-site
            # anchor with no exclusion fires on the identical field-declaration shape.
            authorize_call = re.search(
                r"\bauthorize\s*\(|authorization_endpoint(?!\s*:\s*[A-Za-z_])", code, re.IGNORECASE,
            )
            if authorize_call and not (_PKCE_PRESENT_RE.search(raw) or pkce_inherited):
                out.append(("missing-pkce", authorize_call.start()))
            if m := _PKCE_PLAIN_RE.search(code):
                out.append(("pkce-plain-method", m.start()))
            if m := _TOKEN_FORWARD_RE.search(code):
                out.append(("token-passthrough", m.start()))
            if m := _WILDCARD_REDIRECT_RE.search(code):
                out.append(("wildcard-redirect-uri", m.start()))
            if (m := _BEARER_ONLY_RE.search(code)) and not _DPOP_HINT_RE.search(raw):
                out.append(("bearer-only-no-dpop", m.start()))
            if (m := _AUTHCODE_FLOW_RE.search(code)) and not _ISS_PRESENT_RE.search(raw):
                out.append(("missing-iss-validation", m.start()))
            if (
                (m := _TOKEN_ACQUISITION_RE.search(code))
                and not _RESOURCE_PARAM_RE.search(raw)
                and not resource_inherited
            ):
                out.append(("missing-resource-indicator", m.start()))

        return [self._finding(_line_loc(r, text, off), rule) for rule, off in out]

    def _finding(self, location: str, rule_suffix: str) -> Finding:
        standards = _STD_PROFILE if rule_suffix.startswith(("missing-iss", "missing-resource", "missing-prm")) else _STD_BASELINE
        return Finding(
            check_id=self.id,
            severity=_SEVERITY[rule_suffix],
            title=self.title,
            location=location,
            message=_MESSAGES[rule_suffix],
            remediation=(
                "Bring the OAuth flow into MCP-spec conformance: require PKCE+S256 on "
                "every authorize call, never forward an inbound Authorization header "
                "verbatim, scope redirect_uri to exact registered values, add DPoP/mTLS "
                "proof-of-possession, validate `iss` on authorization-code responses "
                "(RFC 9207), send the `resource` parameter (RFC 8707), and publish/consume "
                "Protected Resource Metadata (RFC 9728)."
            ),
            rule=f"mcp-oauth-flow-hardening/{rule_suffix}",
            standards=list(standards),
        )
