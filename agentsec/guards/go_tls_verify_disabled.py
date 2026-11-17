"""Guard: Go `crypto/tls` certificate verification disabled (InsecureSkipVerify: true).

    cfg := &tls.Config{InsecureSkipVerify: true}
    client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}

Go's `crypto/tls` package's `tls.Config` struct has an `InsecureSkipVerify` field. Setting
it `true` disables BOTH certificate chain validation and hostname verification on every
connection that uses that config — the client now trusts whatever server answers, with no
check that it's actually the intended host and no check that its certificate chains to a
trusted root. This is functionally identical in spirit to the Python-side
`requests.get(url, verify=False)` pattern this project already guards against
(`tls_verify_disabled.py`) — a textbook man-in-the-middle setup (CWE-295, Improper
Certificate Validation).

Fires HIGH on either of Go's two real idioms for setting the field:

  * The struct-literal form, `InsecureSkipVerify: true` (or `InsecureSkipVerify:true`,
    flexible whitespace around the colon) inside a `tls.Config{...}` literal — the common
    case, usually as part of constructing an `http.Transport`/`http.Client` or a gRPC/TLS
    dial config.
  * The post-construction field-assignment form, `cfg.InsecureSkipVerify = true`, on an
    already-constructed `*tls.Config` value — equally common, e.g. inside a function that
    takes a `*tls.Config` and mutates it before use.

Both forms are matched on the FIELD NAME ALONE, without anchoring to a nearby `tls.Config{`
token. `InsecureSkipVerify` is not a generic word — it is the literal, distinctive name Go's
standard library gives this one specific `tls.Config` field, and no other stdlib or common
third-party struct defines a field with this exact name for an unrelated purpose. A user's
own config type COULD in principle declare its own field also spelled `InsecureSkipVerify`,
but doing so is itself either (a) a wrapper that forwards straight into a real `tls.Config`
(the underlying risk is identical), or (b) a deliberately confusing name choice that invites
exactly the same misreading a reviewer would make of the real thing — trusting the name
carries negligible added false-positive risk relative to requiring proximity to `tls.Config{`,
which would also make the struct-literal case brittle against a config assembled across
multiple lines or built via a package-level helper/composite-literal-in-a-function-call where
`tls.Config{` and `InsecureSkipVerify` don't sit inside the same textual window. See the
design doc's "When NOT to flag" for the full reasoning and the case where this is judged safe.

Suppress an audited case (e.g. a deliberately self-signed internal CA a real Go app has no
other way to trust yet) with:

    cfg := &tls.Config{InsecureSkipVerify: true} // security: allow-go-tls-verify-disabled
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
    go_scan_dirs,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_go_comments,
)

_STANDARDS = ["CWE-295"]

# Struct-literal field form: `InsecureSkipVerify: true` / `InsecureSkipVerify:true`.
_INSECURE_SKIP_VERIFY_LITERAL = re.compile(r"\bInsecureSkipVerify\s*:\s*true\b")
# Post-construction field-assignment form: `cfg.InsecureSkipVerify = true`.
_INSECURE_SKIP_VERIFY_ASSIGN = re.compile(r"\bInsecureSkipVerify\s*=\s*true\b")

# Go has no `#` comment syntax — a plain substring check (mirrors hardcoded_llm_provider_key.py's
# _GO_PRAGMA convention) over the comment-only view honours it inside a `//` line comment.
_GO_PRAGMA = "security: allow-go-tls-verify-disabled"

_MESSAGE = (
    "InsecureSkipVerify: true disables BOTH TLS certificate chain validation and hostname "
    "verification for every connection using this tls.Config — the app trusts whatever "
    "server answers with no check that it's the intended host and no check that its "
    "certificate chains to a trusted root. A man-in-the-middle attacker anywhere on the "
    "network path can intercept and tamper with the connection undetected (CWE-295)."
)
_REMEDIATION = (
    "Remove InsecureSkipVerify (or set it false, the zero-value default) and fix the "
    "underlying certificate issue: use a correctly-chained certificate, or if a private "
    "internal CA is genuinely in play, set tls.Config.RootCAs to a certificate pool built "
    "from that CA instead of disabling verification entirely. Suppress with "
    "`// security: allow-go-tls-verify-disabled` only after confirming there is no "
    "alternative (e.g. a fully offline/internal-only connection)."
)


class GoTlsVerifyDisabledGuard(Guard):
    id = "go-tls-verify-disabled"
    title = "TLS certificate verification disabled (InsecureSkipVerify: true)"
    area = "Crypto & TLS"

    # go_tls.go: tls.Config{InsecureSkipVerify: true} -> fires
    # go-tls-verify-disabled/insecure-skip-verify.
    canary_plant = CanaryPlant(
        files={
            "go_tls.go": (
                'package main\n\nimport "crypto/tls"\n\n'
                "func insecureConfig() *tls.Config {\n\treturn &tls.Config{InsecureSkipVerify: true}\n}\n"
            ),
        },
        expects=frozenset({
            "go-tls-verify-disabled/insecure-skip-verify",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "go" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".go",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        # Two parallel views of the same file (mirrors hardcoded_llm_provider_key.py's
        # _scan_go): the pattern check runs against the COMMENT-STRIPPED line (a mention only
        # inside a `//` comment must not fire), while the pragma check runs against the
        # COMMENT-ONLY view of the line, since the pragma IS a comment by definition:
        # strip_go_comments would blank it, and a string quoting it must not count (#424).
        out: list[Finding] = []
        raw_text = read(f)
        stripped_text = strip_go_comments(raw_text)
        view_lines = comment_view(raw_text, "go").splitlines()  # same length: comments only (#424)
        stripped_lines = stripped_text.splitlines()
        # strict=True: strip_go_comments guarantees an identical splitlines() count (its own
        # tested invariant) — a mismatch would mean that guarantee broke, and silently
        # truncating to the shorter list would misalign every line number after the break.
        for lineno, (view_line, code) in enumerate(zip(view_lines, stripped_lines, strict=True), start=1):
            if not code.strip():
                continue
            if _GO_PRAGMA in view_line:
                continue
            if _INSECURE_SKIP_VERIFY_LITERAL.search(code) or _INSECURE_SKIP_VERIFY_ASSIGN.search(code):
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=_MESSAGE,
            remediation=_REMEDIATION,
            rule="go-tls-verify-disabled/insecure-skip-verify",
            standards=list(_STANDARDS),
        )
