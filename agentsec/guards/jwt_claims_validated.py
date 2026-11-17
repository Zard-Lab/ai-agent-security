"""Guard: JWT decode must not disable claim verification (OWASP:A07, CWE-345).

§2a of the checklist: JWT claims — expiry, audience, issuer, and signature —
must all be verified on every decode. Passing `options={"verify_exp": False}` (or
any of the equivalent keys) to PyJWT's `jwt.decode()` silently disables one or more
of these checks, so an attacker can replay an expired token, a token issued for
another service, or a token from an untrusted issuer.

**Detection signal (Rule 1 — this guard):** Flag any `jwt.decode(` call where the
`options=` kwarg is present and contains at least one of:
  - `"verify_exp": False`   — expired tokens accepted
  - `"verify_aud": False`   — audience check skipped (token from another service accepted)
  - `"verify_iss": False`   — issuer check skipped (token from a rogue issuer accepted)
  - `"verify_signature": False` — signature check fully disabled (token forgeable)

**Detection signal (Rule 2 — NOT this guard):** Calls without `algorithms=` are
already covered by the `jwt-alg` guard. This guard does not duplicate that finding.

**Scope:** Spans the arguments across the entire `jwt.decode(` call (not just the
immediate line), so multi-line calls are caught correctly via the `_call_args`
paren-depth walker borrowed from the `jwt-alg` guard.

**Suppress** a reviewed exception repo-wide with `# security: allow-jwt-no-verify`
anywhere in the file (e.g. a test helper that intentionally reads unverified claims).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

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

_PRAGMA = "security: allow-jwt-no-verify"

_STANDARDS = ["OWASP:A07", "CWE-345"]

# Match jwt.decode( or PyJWT().decode( (case-insensitive for library aliases)
_JWT_DECODE = re.compile(r"\bjwt\.decode\s*\(|\bPyJWT\(\)\.decode\s*\(", re.I)

# Match any of the four claim-verification disable keys set to False inside options
_VERIFY_DISABLED = re.compile(
    r"""["'](?:verify_exp|verify_aud|verify_iss|verify_signature)["']\s*:\s*False""",
    re.I,
)

# options= kwarg presence — used to scope the check to calls that pass options
_OPTIONS_KW = re.compile(r"\boptions\s*=", re.I)


def _call_args(text: str, open_paren: int) -> str:
    """Return the argument text between the `(` at `open_paren` and its match.

    Paren-depth walk that ignores parens inside string literals. Returns the
    rest of the text if the call is unterminated (never raises).
    """
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


class JwtClaimsValidatedGuard(Guard):
    id = "jwt-claims-validated"
    title = "JWT decode disables a required claim check (exp/aud/iss/signature)"
    area = "Login & access"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `jwt_handler.py`, which several guards trip at once, so the file stays in `canary.py`'s base owned
    # by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # jwt_handler.py: jwt.decode(..., options={"verify_exp": False}) -> verify-disabled.
    canary_plant = CanaryPlant(expects=frozenset({"jwt-claims-validated/verify-disabled"}))

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
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring/template CONTENT so a decode-call-with-options
        # EXAMPLE in a docstring (this guard's own module docstring self-matches, issue #424)
        # doesn't fire. Line numbers preserved; finditer/_call_args below use this stripped text.
        text = strip_python_strings(text, filename=path)
        for m in _JWT_DECODE.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            args = _call_args(text, m.end() - 1)
            if not _OPTIONS_KW.search(args):
                continue  # no options= kwarg — nothing to flag here
            if not _VERIFY_DISABLED.search(args):
                continue  # options= present but all checks are enabled — safe
            # Determine which keys are disabled for a precise message
            disabled = [
                key
                for key in ("verify_exp", "verify_aud", "verify_iss", "verify_signature")
                if re.search(rf'["\']{key}["\']\s*:\s*False', args, re.I)
            ]
            disabled_str = ", ".join(f'"{k}"' for k in disabled)
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, path)}:{lineno}",
                message=(
                    f"`jwt.decode(...)` passes `options={{...}}` with "
                    f"{disabled_str} set to `False`. "
                    "Disabling these checks means the library accepts tokens that "
                    "are expired, issued for a different audience, signed by an "
                    "untrusted issuer, or entirely unsigned — enabling token replay, "
                    "cross-service privilege escalation, and token forgery."
                ),
                remediation=(
                    "Remove the `False` overrides from the `options` dict. "
                    "If you must read claims from an unverified token for non-security "
                    "purposes (e.g. a debug log), add "
                    "`# security: allow-jwt-no-verify` anywhere in the file and "
                    "document the justification in a code comment."
                ),
                rule="jwt-claims-validated/verify-disabled",
                standards=list(_STANDARDS),
            ))
        return out
