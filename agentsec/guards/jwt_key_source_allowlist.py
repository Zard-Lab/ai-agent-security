"""Guard: JWT verification key sourced from an unverified token header (jku/x5u/jwk).

§2a of the checklist (ASVS 9.1.3): "JWT key-source headers (jku/x5u/jwk) validated
against an allowlist — never fetch verification keys from a token-supplied URL/key."

`jku` (JWK Set URL), `x5u` (X.509 URL), and `jwk` (an embedded JSON Web Key) are all
**attacker-controlled** — they live in the JWT header, which `jwt.get_unverified_header()`
/ `jose.jwt.get_unverified_header()` reads *before* any signature check. There is no
other legitimate use for these three field names outside sourcing a verification key:

1. **`jwk` embedded directly** — the token carries its own public key. If that key is
   used to verify the token's own signature, the attacker signs the token with a key
   they generated and hands verification "success" to themselves — a complete signature
   bypass with no network step at all (CVE-2018-0114-class).
2. **`jku`/`x5u` fetched from a URL** — the URL comes from the token itself, so an
   attacker can point it at a server they control, or at an internal address (SSRF)
   your own service can reach.

Both defeat the entire point of a JWT signature: verifying that the token was issued by
someone who holds a key **you already trust**, not a key the token brought with it.

**Detection.** Scoped to files that call `get_unverified_header(` (PyJWT or python-jose)
— the field only carries this meaning in that context, so this file-level anchor keeps
the check precise without needing full data-flow tracing. Within such a file, any
`["jku"]`/`.get("jku")` (same for `x5u`/`jwk`) access fires:

  * **CRITICAL** for `jwk` — no fetch needed, the attacker-embedded key does everything.
  * **HIGH** for `jku`/`x5u` — matches the checklist item's declared severity.

Suppress a reviewed exception (e.g. the header is checked against a real allowlist
before being used — this guard doesn't attempt to verify that check's correctness) with
`# security: allow-jwt-key-source-header` anywhere in the file.

**Fixed 2026-08-22 (Dean's review, High 2 + Low 1).** Neither the file-level anchor nor
the field-access regex was comment- or string-aware, so a `#`/`//` comment describing this
pattern in prose, or a log/diagnostic string mentioning `header['jku']` as text, fired a
HIGH finding on code with no real field access at all. Comment lines are now skipped
up front; a field-access match is only accepted when its quoted field name is the ENTIRE
content of its own quoted span, not a substring of a longer enclosing string (a log
message). Also fixed a dead pragma-check clause (`f"# {_PRAGMA}" in text or _PRAGMA in
text` — the second operand already subsumes the first).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-jwt-key-source-header"

_STANDARDS = ["OWASP:A02", "OWASP:A07", "ASVS:9.1.3"]

# PyJWT and python-jose both expose this exact name for reading the header before
# signature verification -- the anchor that scopes the rest of this guard to a file
# where jku/x5u/jwk actually mean what they mean in the JWS spec.
_UNVERIFIED_HEADER = re.compile(r"\bget_unverified_header\s*\(", re.I)

# `header["jku"]` / `header.get("jku")` (single or double quotes) -- same shape for
# x5u/jwk. Captures which field name matched so severity can be graded per field.
_KEY_SOURCE_ACCESS = re.compile(
    r"""\[\s*["'](?P<field1>jku|x5u|jwk)["']\s*\]|\.get\(\s*["'](?P<field2>jku|x5u|jwk)["']""",
    re.I,
)

# Fixed 2026-08-22 (Dean's review, High 2): the field-access regex above is not comment-
# or string-aware on its own, so `_KEY_SOURCE_ACCESS` matches equally well inside a `#`
# comment ("... read header[\"jku\"] one day") or inside a log/prose STRING that merely
# describes the code shape ("looked up header['jku'] for diagnostics") -- neither is a
# real field access. `_is_standalone_quoted_field` distinguishes the two: a REAL access's
# quoted field name is the ENTIRE content of its own quoted span (`"jku"`, 5 chars, nothing
# else). A field name mentioned inside a bigger string is only a SUBSTRING of that
# string's own (much longer) quoted span. Reuses the same span-matching shape as
# `guards/base.py::_QUOTED_SPAN` (kept local rather than imported since that name is a
# private module constant, not a shared helper).
_QUOTED_SPAN_LOCAL = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')

# An f-string literal (optionally combined with r/R, either order): `f"..."`, `rf'...'`,
# `Fr"..."`. The negative lookbehind keeps an ordinary identifier ending in "f" right
# before an unrelated string on the same line from being mistaken for a prefix (not a
# real Python shape, but cheap to rule out). Group 1 is the full quoted literal.
_FSTRING_SPAN = re.compile(r'(?<![A-Za-z0-9_])(?:[rR][fF]|[fF][rR]?)("(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')')
# A single-level `{...}` interpolation region inside an f-string (no nested braces, no
# newline) -- deliberately not a full expression parser, just enough to tell "this is
# live code" from "this is literal string text" for the one shape this guard cares about.
_BRACE_EXPR = re.compile(r"\{[^{}\n]*\}")


def _inside_fstring_interpolation(text: str, span_start: int, span_end: int) -> bool:
    """True when `text[span_start:span_end]` (a quote pair) lies inside a `{...}`
    interpolation region of an f-string -- that's live Python code, not opaque string
    content, even though a same-quote-type-only scan treats the WHOLE f-string as one
    opaque span (`_QUOTED_SPAN_LOCAL`'s `[^"\\n]` content class doesn't exclude `'`, so it
    swallows a nested `'jku'` straight through to the f-string's real closing `"`).
    Fixed #686 fix-commit round, High 3: `f"{h['jku']}"` was never recognized as a
    standalone (real) field access for exactly this reason.
    """
    for fm in _FSTRING_SPAN.finditer(text):
        f_start, f_end = fm.start(1), fm.end(1)
        if not (f_start <= span_start and span_end <= f_end):
            continue
        for bm in _BRACE_EXPR.finditer(text, f_start, f_end):
            if bm.start() <= span_start and span_end <= bm.end():
                return True
    return False


def _is_standalone_quoted_field(text: str, span_start: int, span_end: int) -> bool:
    if _inside_fstring_interpolation(text, span_start, span_end):
        return True
    for qm in _QUOTED_SPAN_LOCAL.finditer(text):
        if qm.start() <= span_start and span_end <= qm.end():
            return qm.start() == span_start and qm.end() == span_end
    return False


def _blank_comment_lines(text: str) -> str:
    """Blank (space-fill, preserving every line break and column offset) any line whose
    stripped content starts with `#`/`//` -- a comment describing this pattern in prose
    must not fire (Dean's review, High 2). Applied to the WHOLE text up front so the
    real access scan below can run over the full text at once (see `_scan`) instead of
    per physical line, which is what let a formatter-split access go undetected."""
    return "\n".join(
        " " * len(line) if line.lstrip().startswith(("#", "//")) else line
        for line in text.split("\n")
    )

_SEVERITY: dict[str, Severity] = {"jwk": "critical", "jku": "high", "x5u": "high"}

_TITLE = "JWT verification key sourced from an unverified token header (jku/x5u/jwk)"


class JwtKeySourceAllowlistGuard(Guard):
    id = "jwt-key-source-allowlist"
    title = _TITLE
    area = "Login & access"

    # auth_verify.py: get_unverified_header(...) + header["jku"] with no allowlist check
    # -> fires jwt-key-source-allowlist/untrusted-key-source (HIGH for jku).
    # Must NOT contain: allow-jwt-key-source-header pragma.
    canary_plant = CanaryPlant(
        files={
            "auth_verify.py": (
                "import jwt\n"
                "import requests\n"
                "\n"
                "\n"
                "def verify(token: str):\n"
                "    header = jwt.get_unverified_header(token)\n"
                "    jwk_url = header[\"jku\"]\n"
                "    key = requests.get(jwk_url).json()\n"
                "    return jwt.decode(token, key, algorithms=[\"RS256\"])\n"
            ),
        },
        expects=frozenset({"jwt-key-source-allowlist/untrusted-key-source"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f, read(f)))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        text = strip_python_strings(text)
        if not _UNVERIFIED_HEADER.search(text):
            return []
        # Dean's review, Low 1: `f"# {_PRAGMA}" in text or _PRAGMA in text` -- the second
        # operand already subsumes the first (any string containing "# {_PRAGMA}" also
        # contains "{_PRAGMA}"), so the first clause can never decide the branch. Matches
        # house convention (every sibling guard uses the bare `_PRAGMA in text` form).
        if pragma_present(_PRAGMA, text, dialect="python"):
            return []
        # Dean's review, High 2: blank comment lines FIRST, then scan the whole text in
        # one pass rather than per physical line. Scanning per-line (the original shape)
        # can't match `_KEY_SOURCE_ACCESS`'s `\s*` across a line break, so a formatter-
        # split access -- `h[\n    "jku"\n]` -- went undetected entirely (#686 fix-commit
        # round, High 2); a whole-text scan sees it the same as the single-line form.
        scan_text = _blank_comment_lines(text)
        out: list[Finding] = []
        seen_fields: set[str] = set()
        for m in _KEY_SOURCE_ACCESS.finditer(scan_text):
            group = "field1" if m.group("field1") else "field2"
            field = m.group(group).lower()
            # The quote chars immediately surround the captured field-name group
            # (guaranteed by _KEY_SOURCE_ACCESS's own pattern shape).
            span_start, span_end = m.start(group) - 1, m.end(group) + 1
            if not _is_standalone_quoted_field(scan_text, span_start, span_end):
                # The field name is only a SUBSTRING of a longer quoted string (a log
                # message or other prose that happens to contain the same bracket/
                # quote shape), and not inside a live f-string interpolation either --
                # not a real field access.
                continue
            lineno = scan_text.count("\n", 0, m.start()) + 1
            key = f"{field}:{lineno}"
            if key in seen_fields:
                continue
            seen_fields.add(key)
            out.append(self._finding(root, path, lineno, field))
        return out

    def _finding(self, root: Path, path: Path, lineno: int, field: str) -> Finding:
        if field == "jwk":
            message = (
                "The JWT header's `jwk` field is read before the signature is verified. "
                "`jwk` embeds a public key directly in the token itself -- if that key is "
                "then used to verify the token's own signature, an attacker can generate "
                "their own key pair, embed the public half in `jwk`, and sign the token "
                "with the matching private key. Verification then \"succeeds\" against a "
                "key the attacker controls, a complete signature bypass."
            )
            remediation = (
                "Never derive a verification key from the token's own `jwk` header. Use a "
                "fixed, server-side key (or a JWKS endpoint you configured, not one the "
                "token names) that the token issuer is already known to hold."
            )
        else:
            message = (
                f"The JWT header's `{field}` field is read before the signature is "
                f"verified, and its value (a URL) appears to source the verification key. "
                f"`{field}` is attacker-controlled -- a forged token can point it at a "
                "server the attacker runs, or at an internal address your service can "
                "reach (SSRF), and the fetched \"public key\" then verifies the attacker's "
                "own forged signature."
            )
            remediation = (
                f"Never fetch a verification key from a URL the token itself supplies. "
                f"If `{field}`-based key rotation is genuinely needed, validate the URL's "
                "host against a fixed allowlist BEFORE fetching, or better, use a "
                "server-configured JWKS endpoint and ignore the token's own claim entirely. "
                f"Suppress a reviewed exception with `# {_PRAGMA}`."
            )
        return Finding(
            check_id=self.id,
            severity=_SEVERITY[field],
            title=self.title,
            location=f"{rel(root, path)}:{lineno}",
            message=message,
            remediation=remediation,
            rule="jwt-key-source-allowlist/untrusted-key-source",
            standards=list(_STANDARDS),
        )
