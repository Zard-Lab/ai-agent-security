"""Guard: JWT signature verification must pin the algorithm (no `alg` confusion).

§2a of the checklist: "Algorithm explicitly hardcoded server-side — never trust
the `alg` header from the token." Two attack shapes this guard catches:

1. **Unpinned algorithms** — a signature-verifying `jwt.decode(token, key, …)`
   with no `algorithms=` pin. If the library accepts the token's own `alg`
   header, an attacker can mount the **RS256→HS256 confusion attack**: re-sign a
   forged token with HS256 using the *public* RS256 key as the HMAC secret, and
   it verifies. `algorithms=["HS256"]` (or the one real algorithm) closes it.
2. **The `none` algorithm** — `algorithms=[…, "none", …]` accepts unsigned
   tokens (`alg: none`), i.e. anyone can forge any claim.

**Scope (complementary, not duplicative).** The OSS Semgrep pack
(`agentsec-jwt-unverified-decode`) already owns *signature-disabled* decodes
(`verify_signature: False` / `verify=False`) — those are a different finding
(unverified, often a deliberate non-security metadata read). This guard
therefore **skips** verification-disabled calls and focuses on the algorithm
pin of calls that DO verify. Covers PyJWT and python-jose (`from jose import
jwt`), both of which expose `jwt.decode(...)`.

Suppress a reviewed exception (e.g. `algorithms` supplied via a trusted
constant the scan can't see is treated as pinned already; this pragma is for a
deliberately-unpinned read) with `# security: allow-unpinned-jwt` on the decode
line or the line above.

**Node `jsonwebtoken.verify()` disabled (codeql `js/jwt-missing-verification`,
`javascript/ql/src/Security/CWE-347/MissingJWTKeyVerification.ql`).** The Node
`jsonwebtoken` package has its own, unrelated footgun: passing the literal `false` as
the second argument (the secret/public key) to `jwt.verify(token, false, ...)`
disables signature verification entirely — not an algorithm-confusion issue like the
Python side above, but a complete bypass (any token, forged or not, verifies). Single-
line detection only (mirrors the `.ql` query's own scope: a literal boolean argument).
The call's `(` and the `false` must both be live code on the shared anchor mask
(`js_code_matches`, #1055): a `jwt.verify(token, false)` spelled out in a docs or log string does
not fire, while a call inside a `${...}` substitution still does.
Suppress with `// security: allow-jwt-verify-disabled` on the `verify` line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    js_anchor_is_code,
    js_code_matches,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_strings,
)

_JWT_DECODE = re.compile(r"\bjwt\.decode\s*\(", re.I)  # PyJWT and python-jose
_VERIFY_DISABLED = re.compile(
    r"""verify_signature["']?\s*[:=]\s*False|(?<![\w.])verify\s*=\s*False""", re.I
)
_ALGORITHMS_KW = re.compile(r"\balgorithms\s*=", re.I)
_ALG_NONE = re.compile(r"""algorithms\s*=\s*\[[^\]]*['"]none['"][^\]]*\]""", re.I)
_PRAGMA = "security: allow-unpinned-jwt"
_STANDARDS = ["OWASP:A02", "OWASP:A07"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_JWT_VERIFY_DISABLED = re.compile(r"""\bjwt\.verify\s*\(\s*[^,]+,\s*false\b""", re.I)


def _verify_paren(m: re.Match[str]) -> int:
    """The `(` of a `_JS_JWT_VERIFY_DISABLED` match's `jwt.verify(`, the anchor `js_code_matches` tests."""
    return m.start() + m.group().index("(")
_JS_PRAGMA = "security: allow-jwt-verify-disabled"


def _call_args(text: str, open_paren: int) -> str:
    """Return the argument text between the `(` at `open_paren` and its match.

    Paren-depth walk that ignores parens inside string literals. Total: returns
    the rest of the text if the call is unterminated (never raises)."""
    depth = 0
    quote = ""
    i = open_paren
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
        i += 1
    return text[open_paren + 1 :]


class JwtAlgGuard(Guard):
    id = "jwt-alg"
    title = "JWT decoded without a pinned algorithm (alg-confusion risk)"
    area = "Login & access"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `agent.py` and `jwt_handler.py`, each of which several guards trip at once, so those files stay in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    canary_plant = CanaryPlant(
        files={
            # express_jwt.js: jwt.verify(token, false) -> fires jwt-alg/js-verify-disabled.
            # Requires "express" (turned on via js-cors-wildcard's express_app.js package.json dep).
            "express_jwt.js": (
                "const jwt = require('jsonwebtoken');\n"
                "function checkAuth(token) {\n"
                "  return jwt.verify(token, false);\n"
                "}\n"
            ),
        },
        expects=frozenset({"jwt-alg/none-algorithm", "jwt-alg/js-verify-disabled"}),
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
                    out.extend(self._scan(root, f, read(f)))
        if "express" in profile.features:
            # M2 (the PR #905 review): scope to product code, matching this PR's
            # own sibling insecure_cookies.py — a critical js-verify-disabled finding must not
            # fire inside tests/fixtures.
            for f in iter_files(root, _JS_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan_js(root, f))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so a decode-call EXAMPLE in a
        # docstring (this guard's own module docstring self-matches, issue #424) doesn't fire.
        # Line numbers are preserved and single-line string args in real calls are unaffected;
        # finditer/_call_args/line-counting below all operate on this same stripped text.
        text = strip_python_strings(text, filename=path)
        pragma_lines = pragma_line_set(_PRAGMA, text, dialect="python")  # comment lines only (#424)
        for m in _JWT_DECODE.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            if lineno in pragma_lines or lineno - 1 in pragma_lines:  # this line, or the one above it
                continue
            args = _call_args(text, m.end() - 1)
            if _VERIFY_DISABLED.search(args):
                continue  # signature-disabled decode is the Semgrep pack's finding, not ours
            loc = f"{rel(root, path)}:{lineno}"
            if _ALG_NONE.search(args):
                out.append(self._finding(
                    "high", loc,
                    "`jwt.decode(...)` lists the `none` algorithm — it accepts unsigned tokens, so "
                    "anyone can forge any claim.",
                    "Remove `none` from `algorithms`; pin only the real signing algorithm "
                    '(e.g. `algorithms=["HS256"]`).',
                    "jwt-alg/none-algorithm",
                ))
            elif not _ALGORITHMS_KW.search(args):
                out.append(self._finding(
                    "medium", loc,
                    "`jwt.decode(...)` verifies the signature but pins no `algorithms=` — if the "
                    "library honors the token's own `alg` header, this enables the RS256→HS256 "
                    "algorithm-confusion attack.",
                    'Pass `algorithms=["HS256"]` (or the single real algorithm) so the `alg` header '
                    "is never trusted. If this is a deliberate unpinned read, add "
                    f"`# {_PRAGMA}`.",
                    "jwt-alg/unpinned-algorithms",
                ))
        return out

    def _scan_js(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        code = strip_js_comments(raw)
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        # Built on the first matching line only. The search stays per line: `[^,]+` also crosses
        # newlines, so a whole-file search is quadratic on comma-free `jwt.verify(` lines (#1157).
        mask_lines: list[str] | None = None
        for i, line in enumerate(code.splitlines(), start=1):
            if not _JS_JWT_VERIFY_DISABLED.search(line):
                continue
            if mask_lines is None:
                mask_lines = strip_js_comments(raw, strip_strings=True, keep_substitutions=True).splitlines()
            # Same layout as `code`; a missing line fails open in `js_anchor_is_code` (keeps the finding).
            mask_line = mask_lines[i - 1] if i - 1 < len(mask_lines) else ""
            # The call's `(` and the `false` (the match's last five characters) must be live code
            # (#1055): `log('jwt.verify(token, false) disables checks')` is not a call, and every
            # match is tried, so a quoted copy cannot hide a real call after it on the line.
            if not any(
                js_anchor_is_code(line, mask_line, m.end() - 5)
                for m in js_code_matches(_JS_JWT_VERIFY_DISABLED, line, mask_line, anchor=_verify_paren)
            ):
                continue
            line_text = view_lines[i - 1] if i - 1 < len(view_lines) else ""
            if _JS_PRAGMA in line_text:
                continue
            out.append(self._finding(
                "critical", f"{rel(root, f)}:{i}",
                "`jwt.verify(token, false, ...)` passes `false` as the secret/public key — this "
                "disables signature verification entirely in the `jsonwebtoken` package. Any "
                "token, forged or not, verifies.",
                "Pass the real secret or public key, never a literal `false`. If this is "
                f"deliberate (e.g. reading an untrusted claim without verifying), add "
                f"`// {_JS_PRAGMA}`.",
                "jwt-alg/js-verify-disabled",
            ))
        return out

    def _finding(self, sev: Severity, loc: str, msg: str, remediation: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity=sev, title=self.title, location=loc,
            message=msg, remediation=remediation, rule=rule, standards=list(_STANDARDS),
        )
