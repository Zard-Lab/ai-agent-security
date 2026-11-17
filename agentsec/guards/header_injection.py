"""Guard: user-supplied input written into an outgoing HTTP response header (CWE-113).

A response-header write (`response.headers[name] = value`) where the header name or
value contains an unescaped newline lets an attacker who controls that input inject
additional headers or split the response — HTTP response splitting / header injection.
This is the OUTGOING-header direction; `log-injection` already covers the same taint
sources written INTO a log call, a distinct sink.

Example of the dangerous pattern (FastAPI / Flask):

  response.headers["X-Request-Id"] = request.headers["X-Client-Id"]

If the client sends `X-Client-Id: abc\\r\\nSet-Cookie: session=attacker`, the response
now carries an extra, attacker-chosen header.

Mined from CodeQL's `python/ql/src/Security/CWE-113/HeaderInjection.ql`, verified
against the real `HttpHeaderInjectionCustomizations.qll`: sink is any header write whose
name or value "allows newline"; the only recognized sanitizer is a `.replace("\\n", ...)`
call on the value.

**Detection scope:** Single-line co-occurrence only, same limitation class as
`log-injection` — a value first stored in a variable and written to a header on a later
line is NOT detected.

**Suppress:** `# security: allow-header-injection` anywhere in a file silences this
check for that file. Use only after confirming the header value is sanitized (e.g. via
`.replace("\\n", "")`) or is not attacker-influenced.
"""
from __future__ import annotations

import re
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
)

_PRAGMA = "security: allow-header-injection"

_STANDARDS = ["OWASP:A03", "CWE-113"]

# A response-header subscript ASSIGNMENT (not comparison — `(?!=)` excludes `==`).
_HEADER_WRITE = re.compile(r"""\.headers\[[^\]]*\]\s*=(?!=)""")

# Request-derived source vocabulary. `request.state` / `request.app` are TRUSTED, server-set
# attributes (request-scoped state the app itself populated — e.g. a trace ID set by middleware,
# or the ASGI app instance) — not attacker-controlled, so `request.` is excluded when immediately
# followed by either (review #395 M). The incoming-headers source is `request.headers[` — matched
# by the `request.` alternative; a BARE `headers[` is NOT a source (review #395 H3: an unanchored
# `headers[` false-matched an OUTGOING/default header dict on the RHS —
# `other_response.headers['X-Trace']`, `default_headers['content-type']`).
_USER_INPUT = re.compile(
    r"""(?:request\.(?!state\b|app\b)|(?<!\w)body(?!\w)|query_params|form\[)""",
)

# A `len(...)` wrapper yields an integer length, which cannot carry a CRLF — so a tainted token
# that appears only inside `len(...)` is NOT an injectable value (review #395 H3:
# `response.headers['X-Length'] = str(len(body))` is not header injection). Blanked before the
# taint check.
_LEN_CALL = re.compile(r"\blen\s*\((?:[^()]|\([^()]*\))*\)")

# The one sanitizer CodeQL's own HttpHeaderInjectionCustomizations.qll recognizes:
# a call to replace line breaks.
_REPLACE_SANITIZER = re.compile(r"""\.replace\s*\(\s*['"]\\n['"]""")


class HeaderInjectionGuard(Guard):
    id = "header-injection"
    title = "Request value written into a response header (HTTP header injection)"
    area = "Web setup"

    # response_headers.py: response.headers[name] = request.headers[...] (unescaped) ->
    # fires header-injection.
    canary_plant = CanaryPlant(
        files={
            "response_headers.py": (
                "def echo_trace_id(response, request):\n"
                "    response.headers['X-Trace-Id'] = request.headers['X-Client-Trace-Id']\n"
            ),
        },
        expects=frozenset({"header-injection/user-input-in-header"}),
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue  # don't scan test/fixture/migration files (review #395 H3)
                text = read(f)

                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                for lineno, line in enumerate(text.splitlines(), 1):
                    write_match = _HEADER_WRITE.search(line)
                    if not write_match:
                        continue
                    # Check only the ASSIGNED VALUE (text after the sink match) for a tainted
                    # source — the sink itself is a `.headers[...] =` write, which contains the
                    # literal substring "headers[" and would otherwise false-match `_USER_INPUT`
                    # against its own left-hand side regardless of what's actually assigned.
                    rhs = line[write_match.end():]
                    # A `len(...)`-wrapped source is an int (no CRLF) — blank it before the taint
                    # check so `str(len(body))` doesn't count `body` as tainted (review #395 H3).
                    if not _USER_INPUT.search(_LEN_CALL.sub(" ", rhs)):
                        continue
                    # The recognized sanitizer must be applied to the VALUE, not the header NAME —
                    # search the RHS only, so `headers[name.replace('\n','')] = request...` (name
                    # sanitized, value not) still fires (review #395 M5).
                    if _REPLACE_SANITIZER.search(rhs):
                        continue
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Request value written into a response header",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A request-derived value (headers, query params, body, or form "
                            "fields) is written directly into an outgoing response header. An "
                            "attacker who embeds a newline (\\r\\n) in that value can inject "
                            "additional headers or split the response."
                        ),
                        remediation=(
                            "Strip or escape newlines before writing the header (e.g. "
                            "`value.replace('\\n', '').replace('\\r', '')`), or validate the "
                            "value against an allowlist before use. Suppress with "
                            "'# security: allow-header-injection' only after confirming the "
                            "value is sanitized."
                        ),
                        rule="header-injection/user-input-in-header",
                        standards=list(_STANDARDS),
                    ))

        return out
