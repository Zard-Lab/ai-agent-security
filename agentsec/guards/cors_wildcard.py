"""Guard: CORS wildcard origin in FastAPI setup (§6a of the security checklist).

A FastAPI app configured with `CORSMiddleware(allow_origins=["*"])` accepts
cross-origin requests from any website. In a multi-tenant SaaS with cookie or
token auth this means any malicious page can make authenticated API calls on
behalf of a logged-in user — a classic CSRF/CORS misconfiguration.

Fires HIGH when `allow_origins=["*"]` is detected in a FastAPI app. Suppress
a known-intentional wildcard (e.g. a fully public, unauthenticated endpoint)
with the inline pragma:

    app.add_middleware(CORSMiddleware, allow_origins=["*"])  # security: allow-cors-wildcard

Also fires HIGH on `allow_origin_regex` set to a catch-all pattern (`.*`, `.+`,
`^.*$`) — this is a distinct, currently-unmatched bypass of the literal-wildcard
check above: Starlette's `CORSMiddleware` treats a matching `allow_origin_regex`
the same as an explicit allow-list entry, so a catch-all regex is functionally
identical to `allow_origins=["*"]` without ever containing the literal string
`"*"`. Adapted from CodeQL's JS-specific "reflected Origin header" query
(`CorsMisconfigurationForCredentialsQuery`) — that exact check doesn't map to
FastAPI's declarative middleware config, so this targets the real analogous gap
in this stack instead of porting the JS pattern verbatim.
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
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

_CORS_MIDDLEWARE = re.compile(r"\bCORSMiddleware\b")
# `\s*` spans newlines, so this matches a multi-line origins list too
# (`allow_origins=[\n    "*",\n]`) when run over the whole file, not per line (issue #424).
_WILDCARD_ORIGINS = re.compile(r"""allow_origins\s*=\s*\[\s*['"]?\*['"]?\s*,?\s*\]""")
_PRAGMA = re.compile(r"#\s*security:\s*allow-cors-wildcard")

_ORIGIN_REGEX_ARG = re.compile(r"""allow_origin_regex\s*=\s*r?['"]([^'"]*)['"]""")
# A catch-all: with anchors/grouping stripped, the pattern is just ".*" or ".+"
# (optionally with a trailing/leading ".*)?" etc.) — matches everything.
_CATCHALL_BODY = re.compile(r"^\^?\(?\.[*+]\)?\??\$?$")


class CorsWildcardGuard(Guard):
    id = "cors-wildcard"
    title = "CORS wildcard origin"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `app.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "cors-wildcard/allow-origins-star",
            "cors-wildcard/origin-regex-catchall",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # Blank triple-quoted docstring CONTENT so the wildcard-origins EXAMPLE in
                # this guard's own module docstring doesn't self-match (issue #424).
                raw = read(f)
                text = strip_python_strings(raw, filename=f)
                if not _CORS_MIDDLEWARE.search(text):
                    continue
                # Both rules below skip a line whose pragma is a real comment, never the phrase
                # in a string there (#1040), numbered as each rule numbers its own lines: the
                # origin-regex loop walks `splitlines()` rows, the wildcard span counts "\n".
                # The two differ past a form feed (#1132), so each rule gets its own set.
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                span_pragmas = frozenset(
                    n for n, ln in enumerate(comment_view(text, "python").split("\n"), start=1)
                    if _PRAGMA.search(ln)
                )
                # Match against a comment-stripped copy. `_WILDCARD_ORIGINS` spans newlines with
                # `\s*`, which a `# TODO tighten this` line inside the origins list interrupts —
                # so an ordinary comment in the middle of a real wildcard list silenced the guard
                # entirely (#439 review). Stripping comments also removes a fully commented-out
                # occurrence, which is why the old `startswith("#")` skip is no longer needed:
                # such a line cannot produce a match at all. `strip_python_line_comment` only
                # truncates, so line COUNT is preserved and the line math below still holds.
                code = "\n".join(strip_python_line_comment(ln) for ln in text.split("\n"))
                for m in _WILDCARD_ORIGINS.finditer(code):
                    start_line = code[: m.start()].count("\n") + 1
                    end_line = code[: m.end()].count("\n") + 1
                    # A pragma comment on any line the match spans suppresses it.
                    if any(n in span_pragmas for n in range(start_line, end_line + 1)):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="CORS wildcard allows any origin",
                            location=f"{rel(root, f)}:{start_line}",
                            message=(
                                "`allow_origins=[\"*\"]` accepts requests from every website. "
                                "In an app with auth, any page can make authenticated API calls "
                                "on behalf of a logged-in user."
                            ),
                            remediation=(
                                "Set `allow_origins` to an explicit list of trusted domains "
                                "(e.g. `[\"https://app.example.com\"]`). "
                                "If this endpoint is intentionally public and unauthenticated, "
                                "suppress with `# security: allow-cors-wildcard`."
                            ),
                            rule="cors-wildcard/allow-origins-star",
                            standards=["OWASP:A05"],
                        )
                    )
                for i, line in enumerate(text.splitlines(), start=1):
                    # `rm`, not `m`: the wildcard-origins loop above already binds `m` as a
                    # non-Optional Match, so reusing the name here is a mypy narrowing clash
                    # (Match[str] | None assigned to Match[str]). Marconi predicted this exact
                    # collision — it existed only in the pre-v0.22 combination, so it appears in
                    # neither PR's diff and only surfaces when both land.
                    rm = _ORIGIN_REGEX_ARG.search(line)
                    if not rm or not _CATCHALL_BODY.match(rm.group(1)):
                        continue
                    if i in pragmas:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="CORS allow_origin_regex is a catch-all",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "`allow_origin_regex` matches every origin, so it is functionally "
                                "identical to `allow_origins=[\"*\"]` — Starlette treats a matching "
                                "regex the same as an explicit allow-list entry — without ever "
                                "containing the literal string that the wildcard check looks for."
                            ),
                            remediation=(
                                "Narrow `allow_origin_regex` to actually constrain the origin "
                                "(e.g. `r\"https://.*\\.example\\.com\"`), or switch to an explicit "
                                "`allow_origins` list. If intentionally public, suppress with "
                                "`# security: allow-cors-wildcard`."
                            ),
                            rule="cors-wildcard/origin-regex-catchall",
                            standards=["OWASP:A05"],
                        )
                    )
        return out
