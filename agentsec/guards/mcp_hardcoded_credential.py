"""Guard: an MCP server's own source hardcodes a credential-shaped variable as a literal
string (checklist §4, new item; mined from sentrymcp's `MCPA-AUTH-STATIC-CRED-001`,
fetched and read in full).

A variable, object field, or dict key named like a credential (`api_key`, `secret`, `token`,
`password`, `access_key` — any casing/separator) is assigned a quoted string literal of 8+
characters directly, rather than read from an environment variable or secret store:

    API_KEY = "sk-live-abc123def456"          # Python
    const apiKey = "sk-live-abc123def456";    // JS/TS
    { "accessKey": "AKIAABCDEFGH12345678" }   // JS/TS object literal

The literal is committed to source control, embedded in every clone/fork/Docker image, and
visible to anyone with repo read access — a different failure from a client-side-bundled
provider-key leak (`client-side-secret-literal`, provider-prefix-gated, JS/TS-only) or a
known-weak `SECRET_KEY` default (`weak-secret-key-literal`): this is a NAME-based check with no
provider-prefix requirement at all, so it also catches an opaque or custom-format credential
`client-side-secret-literal`'s provider allowlist would never recognize.

**Why MCP-gated, not a general-purpose guard.** sentrymcp's own rule has no `safe_indicators`
exclusion by design (env-var reads are already excluded by construction: the sink pattern
requires a quoted literal directly after the operator) and no provider-prefix requirement, so
it is a much broader net than `client-side-secret-literal`. Applied to ANY Python/JS/TS repo,
a credential-shaped variable name assigned any 8+ character literal would be noisy — test
fixtures, example/tutorial code, and ordinary config scaffolding all do this routinely. Scoping
`applies()` to `"mcp" in profile.features` keeps the same broad name-based vocabulary safe the
same way `mcp-tool-path-traversal`/`mcp-transport-no-auth` scope their own widened rules to MCP
repos rather than general application code — an MCP SERVER's own source is a narrower, higher-
signal population: a credential hardcoded there ships with every deployment of that server.

One statically detectable pattern:

  **`hardcoded-credential-literal`** (MEDIUM, `surfacing` — a review signal, not a gate; see
  "Why a review signal" below): any
  identifier, followed by an optional type annotation, then `:` or `=`, then a quoted string
  literal of 8+ non-whitespace characters with no spaces inside the quotes — AND the identifier is
  credential-shaped: split into lowercase segments on `_`/`-` and camelCase/SCREAMING_CASE
  boundaries, any segment is `secret`/`token`/`password`, or an adjacent pair is `api`+`key`/
  `access`+`key`. Matching the WHOLE identifier first and asking whether any SEGMENT of it is a
  credential word (rather than matching a credential word directly and requiring the operator
  immediately after it) is what lets the word sit anywhere in the name — `GITHUB_TOKEN`,
  `tokenValue`, `client_secret` all fire now; the prior substring-plus-`\b` approach could only
  ever reach the whole-name case (`api_key = "..."`), since anything else leaves identifier
  characters between the word and the operator that a boundary check alone cannot cross.

**Placeholder, mask, and key-name exclusions.** A literal that reads as an obvious placeholder
(starts with `your-`/`<`/`${`, or contains `xxx`/`changeme`/`example`/`placeholder`/`todo`/
`fixme`, case-insensitive) does not fire — sentrymcp's own source rule has no such exclusion, but
shipping it unfiltered would flag the overwhelmingly common `API_KEY = "your-api-key-here"`
tutorial/scaffolding idiom. Neither does a masked/redacted display value (`"********"`,
`"***REDACTED***"`) or a value that is itself shaped like a lookup-key NAME rather than a secret
— all-lowercase words joined only by `_`/`-` with no digits at all (`"access_token"`, an
`"auth-token-storage-key"` localStorage key) or an HTTP header name (`"X-API-Key"`,
`"Authorization"`) — added after H3 of the #1058 review measured the first two as CRITICAL false
positives. The lowercase test is case-SENSITIVE: a real secret reliably carries digits or capitals
(`sk-live-abc123def456`, `AKIAABCDEFGH12345678`, this guard's own canary plants included), so
"all-lowercase words with separators, zero digits" is a safe-enough shape to read as a name, and
an all-letter value with capitals still fires. Nor does a value that LOCATES or dates a secret
rather than being one: a URL without userinfo, an absolute path, an ARN, an ISO-8601 date, or an
all-lowercase relative path (`TOKEN_URL`, `SECRET_ARN`, `PASSWORD_RESET_PATH`, round 2 of the
#1058 review). A URL that embeds `user:password@` still fires.

**Why a review signal, not a gate.** A name plus a value SHAPE cannot prove a secret. Three
review rounds of #1058 each tuned the value filters and each exposed the next shape: an
all-letter capitalised value is a password (`"SuperSecretPassword"`) as often as it is a class
or enum label (`TOKEN_TYPE = "BearerToken"`), and nothing on the line tells them apart. So the
finding is MEDIUM with `surfacing = True`: it ranks below proven findings and stays under the
default `--fail-on high`. What still gates a real credential elsewhere is narrower than that
sounds (measured in round 4 of the #1058 review): a provider-prefixed key in a `.py`/`.go` file
(`hardcoded-llm-provider-key`), one in JS/TS when `frontend`, `javascript` or `typescript` is
detected (`client-side-secret-literal`; a pure-TS repo since #1082), a Stripe live key with
`payments` (`stripe-payments`), and gitleaks in a full audit of a committed tree. A secret
assigned to a generic variable or field name (`dbPassword`) is usually gated by no guard (a few
guards cover specific shapes, such as a password default argument or a weak Django/Flask secret
key), so there this MEDIUM finding is the only signal, and in a pure-TS MCP repo a provider-key
line now reports twice: this MEDIUM plus the gating HIGH (#1080's same-line class).

**False-negative scope:** single-line regex only, comment-stripped (so a documented example in
a `#`/`//` comment doesn't fire) but not string-stripped (the credential value itself must
survive as a real string literal for the check to work at all). A value assembled from
concatenation, a template literal with any interpolation, or passed through a wrapper function
is not recognized. A QUOTED object-literal key (`{ "password": "..." }`) is also not recognized —
only an unquoted key or a plain variable name (`{ password: "..." }`, `const password = "..."`)
matches. (The compound-name false negative previously documented here — `secret_token` not
matching because `_` counted as a word character — was the same regex defect H3 fixed; it is
gone as a side effect, not tracked separately.) The value filters trade some misses for less
noise, by design: a secret embedded in a URL's path or query (a webhook URL, `?api_key=`) reads
as a locator, a secret that begins with `/` reads as a path, and an all-lowercase digit-free
secret reads as a key name.

Suppress an audited case with:

    # security: allow-mcp-hardcoded-credential   (Python)
    // security: allow-mcp-hardcoded-credential  (JS/TS)
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-mcp-hardcoded-credential"
_STANDARDS = ["OWASP:A02", "CWE-798"]

# An assignment-shaped candidate: ANY identifier, optionally type-annotated, assigned a quoted
# literal of 8+ non-whitespace characters. Whether the identifier is actually credential-shaped
# is decided separately by `_is_credential_shaped_name` below — see H3 for why. The leading
# lookbehind is what keeps this linear (round-2 H1 of the #1058 review): without it the engine
# retried from every position INSIDE a long identifier run (an embedded hex/base64 blob) and
# backtracked across the rest of it each time, quadratic — a 16 KB blob line measured 3.7 s.
_ASSIGNMENT_CANDIDATE = re.compile(
    r"""(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*\w+\s*)?[:=]\s*(["'])([^"'\s]{8,})\2"""
)

# H3 (#1058 review): the old approach matched a credential WORD immediately followed by `\b` then
# required the operator (`:`/`=`) to appear right after it. That works for `api_key = "..."`
# (word IS the whole identifier) but silently misses every identifier where the credential word is
# only a SEGMENT of a longer name — `GITHUB_TOKEN`/`DB_PASSWORD`/`client_secret` (word is the LAST
# snake_case segment) and `tokenValue` (word is the FIRST camelCase segment) all have other
# identifier characters between the word and the operator, so a "word, then immediately the
# operator" pattern can never reach them — measured: the module's own docstring claimed all of
# these still matched; none of them did. Fixed by decoupling the two questions: match the WHOLE
# identifier first (`_ASSIGNMENT_CANDIDATE` above), THEN ask whether any of its snake_case/
# camelCase SEGMENTS is a credential word — a real identifier-segmentation check, not a boundary
# patched onto a substring search.
_CREDENTIAL_WORDS = frozenset({"secret", "secrets", "token", "tokens", "password", "passwords"})
# `api_key`/`access_key` are two-word combos — ported from sentrymcp's own sink_pattern, which
# only combines these two, not `secret_key` or `password_key` — so adjacent-segment pairing is
# checked only for these, not folded into `_CREDENTIAL_WORDS`.
_CREDENTIAL_WORD_PAIRS = frozenset({("api", "key"), ("api", "keys"), ("access", "key"), ("access", "keys")})
_CAMEL_SPLIT = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")


def _name_segments(name: str) -> list[str]:
    """Split an identifier into lowercase segments by `_`/`-` and camelCase/SCREAMING_CASE
    boundaries: `GITHUB_TOKEN` -> `["github", "token"]`, `tokenValue` -> `["token", "value"]`,
    `accessKey` -> `["access", "key"]`, `tokenize` -> `["tokenize"]` (one segment — no boundary
    inside it, so it is never confused with the standalone word `token`)."""
    segments: list[str] = []
    for part in re.split(r"[_-]+", name):
        segments.extend(m.group(0).lower() for m in _CAMEL_SPLIT.finditer(part))
    return segments


def _is_credential_shaped_name(name: str) -> bool:
    segments = _name_segments(name)
    if any(seg in _CREDENTIAL_WORDS for seg in segments):
        return True
    return any((a, b) in _CREDENTIAL_WORD_PAIRS for a, b in zip(segments, segments[1:], strict=False))

# An obvious placeholder value — sentrymcp's own source has no such exclusion, but shipping
# this unfiltered would flag the extremely common tutorial/scaffolding idiom as CRITICAL.
_PLACEHOLDER_VALUE = re.compile(
    r"^(?:your[_-]|<|\$\{)|xxx|changeme|example|placeholder|\btodo\b|\bfixme\b",
    re.IGNORECASE,
)

# H3 (#1058 review): a masked/redacted display value (`"********"`, `"***REDACTED***"`) or a
# key-NAME-shaped literal (`"access_token"`, `"auth-token-storage-key"` — a lookup key or a
# localStorage/config field name, not a secret VALUE) was firing CRITICAL alongside the existing
# `_PLACEHOLDER_VALUE` filter missing both shapes entirely. A real secret value, by contrast,
# reliably carries digits or mixed case (`sk-live-abc123def456`, `AKIAABCDEFGH12345678`) — this
# guard's own canary plants are deliberately built that way — so "all-lowercase words joined by `_`
# or `-`, no digits at all" is a safe shape to treat as a name rather than a value. Only the mask
# alternatives are case-insensitive: compiled whole with IGNORECASE, the key-name alternative also
# swallowed all-letter secrets with capitals (round-2 M1). An HTTP header NAME (`X-API-Key`,
# `Authorization`) is the other name-shaped value a credential-named constant routinely holds;
# header names are letter words, so a digit after `X-` keeps a token-shaped value firing.
_MASKED_OR_KEY_NAME_SHAPED_VALUE = re.compile(
    r"(?i:^[*#]+$|redacted)"
    r"|^[a-z_-]+$"
    r"|^[Xx]-[A-Za-z-]+$|^(?:Proxy-)?Authorization$"
)

# Round-2 H2 of the #1058 review: once any name SEGMENT counts, `TOKEN_URL`, `SECRET_ARN` and
# `PASSWORD_RESET_PATH` are credential-shaped names, and their values locate or date a secret
# rather than being one. Excluded: a URL with no userinfo (one carrying `user:pass@` still fires),
# an absolute path, an ARN, an ISO-8601 date, and an all-lowercase relative path or resource name
# (`projects/123/secrets/foo`). Mixed case keeps a base64 secret containing `/` firing.
_LOCATOR_VALUE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]*://(?![^/@]*@)"
    r"|^/"
    r"|^arn:"
    r"|^\d{4}-\d{2}-\d{2}(?:T|$)"
    r"|^[a-z0-9._-]*/[a-z0-9._/-]*$"
)


class McpHardcodedCredentialGuard(Guard):
    id = "mcp-hardcoded-credential"
    title = "MCP server source hardcodes a credential-shaped variable as a literal"
    area = "AI agent"
    # A name-plus-value-shape heuristic flags a line to confirm by hand; it cannot prove a secret
    # (round 3 of the #1058 review). See the module docstring's "Why a review signal".
    surfacing = True

    # mcp_server_config.py: API_KEY = "<literal>" -> fires
    # mcp-hardcoded-credential/hardcoded-credential-literal.
    # mcp_server_config.js: const accessKey = "<literal>"; -> same rule, JS/TS side.
    canary_plant = CanaryPlant(
        files={
            "mcp_server_config.py": (
                'API_KEY = "sk-live-CANARYKEYFORTESTINGONLY1234567890"\n'
            ),
            "mcp_server_config.js": (
                'const accessKey = "AKIACANARYKEYFORTESTINGONLY12345";\n'
            ),
        },
        expects=frozenset({"mcp-hardcoded-credential/hardcoded-credential-literal"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        if "mcp" not in profile.features:
            return False
        return bool({"python", "javascript", "typescript"} & profile.features)

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
                    text = read(f)
                    if pragma_present(_PRAGMA, text, dialect="python"):
                        continue
                    out.extend(self._scan(root, f, text, strip_python_line_comment))
        if {"javascript", "typescript"} & profile.features:
            for f in iter_files(root, (".js", ".jsx", ".ts", ".tsx")):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="js"):
                    continue
                out.extend(self._scan_js(root, f, text))
        return out

    def _scan(
        self, root: Path, path: Path, text: str, strip_comment: Callable[[str], str]
    ) -> list[Finding]:
        out: list[Finding] = []
        for lineno, raw_line in enumerate(text.splitlines(), 1):
            line = strip_comment(raw_line)
            if self._line_fires(line):
                out.append(self._finding(root, path, lineno))
        return out

    def _scan_js(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        for lineno, line in enumerate(strip_js_comments(text).splitlines(), 1):
            if self._line_fires(line):
                out.append(self._finding(root, path, lineno))
        return out

    @staticmethod
    def _line_fires(line: str) -> bool:
        for m in _ASSIGNMENT_CANDIDATE.finditer(line):
            name, value = m.group(1), m.group(3)
            if not _is_credential_shaped_name(name):
                continue
            if (
                _PLACEHOLDER_VALUE.search(value)
                or _MASKED_OR_KEY_NAME_SHAPED_VALUE.search(value)
                or _LOCATOR_VALUE.search(value)
            ):
                continue
            return True
        return False

    def _finding(self, root: Path, path: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            # MEDIUM (round 3 of the #1058 review; CRITICAL, then HIGH before that): the shape
            # filters above are heuristics, not proof, so the finding is a review signal that
            # must not fail a build on its own. The class declares `surfacing = True` to match.
            severity="medium",
            title=self.title,
            location=f"{rel(root, path)}:{lineno}",
            message=(
                "A variable, field, or key named like a credential (api_key/secret/token/"
                "password/access_key) is assigned a quoted string literal of 8+ characters "
                "directly in this MCP server's own source. This is a review signal: confirm "
                "whether the value is a real credential. If it is, it ships with every "
                "clone, fork, and deployed image of this repo, and is visible to anyone "
                "with read access to it."
            ),
            remediation=(
                "Read the credential from an environment variable or a secrets manager at "
                "startup; never commit a literal key/token/password value to source. "
                f"Suppress an audited case (e.g. a test fixture) with `# {_PRAGMA}`."
            ),
            rule="mcp-hardcoded-credential/hardcoded-credential-literal",
            standards=list(_STANDARDS),
        )
