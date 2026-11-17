"""Guard: slowapi / limits rate limiter with no persistent (Redis) storage backend
(checklist §2c, OWASP:A04 — Insecure Design).

slowapi and the `limits` library it wraps default `storage_uri` to `memory://` — an
in-process counter — when the argument is omitted from the `Limiter(...)` call. A
production FastAPI deployment almost always runs more than one worker process
(gunicorn/uvicorn `--workers N`, or multiple container replicas behind a load
balancer): each worker gets its OWN in-memory counter, so a caller hammering an
endpoint is only rate-limited against whichever single worker happens to handle
each request, not against the limit as configured. A "5 requests/minute" limit
behind 4 workers is really "20 requests/minute" in practice, and every process
restart or redeploy silently resets every counter to zero. This is the same shape
of gap `rate-limit-no-user-key` closes for the *keying* dimension of rate limiting;
this guard closes it for the *storage* dimension.

This guard performs a cross-file check, scoped PER ``Limiter(...)`` instantiation (round-2 fix,
PR #732 review — an earlier version aggregated every ``storage_uri=`` project-wide and treated
ANY persistent one as clearing the whole project, so a single Redis-backed `Limiter` anywhere
silenced the finding for every OTHER, genuinely in-memory `Limiter` in the project; the same
project-wide-aggregate shape the `rate-limit-no-user-key` sibling also carries, not fixed here —
out of this PR's scope, flagged as its own follow-up):

1. If no file in the project imports from ``slowapi`` or ``limits``, the library is
   not in use and there is nothing to flag — return empty.
2. Otherwise, scan for all ``Limiter(...)`` instantiations — matched on each line with its ``#``
   comment stripped first, so a ``Limiter(`` that lives only in a comment is not an instance
   (#897: it was counted as a second instantiation and one ``Limiter`` was reported twice).
   For EACH one, independently:
   a. If its ``storage_uri=`` value is a *non-literal* expression (an env var lookup, a
      settings attribute, a variable) — benefit of the doubt for THIS instance only,
      cannot tell what backend it resolves to; skip it rather than false-positive.
   b. If its ``storage_uri=`` literal names a persistent backend (``redis://``,
      ``rediss://``, ``memcached://``, ``mongodb://``, ``etcd://``) — THIS instance is
      fine; skip it.
   c. Otherwise (no ``storage_uri=`` at all, or the literal is explicitly ``memory://``)
      — emit one LOW finding at THIS instance's own location:

      **`no-persistent-store`** (LOW): this rate limiter uses (or defaults to) the
      in-memory storage backend, so its limits are not shared across worker processes
      and reset on every restart.

A LOW severity is used because this is a correctness/robustness gap in the rate
limit itself, not a direct bypass on its own — it degrades an existing control
rather than removing it, and single-worker/dev deployments are entirely correct
with the in-memory default.

Checklist item: `2c-rate-limit-persisted`.

Suppress: `# security: allow-in-memory-rate-limit` anywhere in a file silences
this guard for that file. Use for a genuinely single-process deployment, or when
persistence is intentionally not required.
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
    strip_python_line_comment,
)

_PRAGMA = "security: allow-in-memory-rate-limit"

_STANDARDS = ["OWASP:A04"]

# Detects any import of the slowapi / limits rate-limiting libraries.
_SLOWAPI_IMPORT = re.compile(r"from slowapi|import slowapi|from limits|import limits")

# Detects a Limiter() constructor call. Word-anchored (\b) so it matches the slowapi/limits
# `Limiter(` (bare or dotted `slowapi.Limiter(`) but NOT a different class whose name merely ends
# in "Limiter" — fastapi-limiter's per-route `RateLimiter(` dependency, a `MyLimiter(` wrapper, or
# a `class FooLimiter(Limiter)` subclass def, none of which take slowapi's `storage_uri=` (PR #732
# round-2 review, Medium: the per-instance widening newly exposed this substring FP).
# Applied to the comment-STRIPPED line (`strip_python_line_comment`), never the raw one: a `Limiter(`
# inside a `#` comment above the real call was a second "instantiation" and the one Limiter was
# reported twice (#897). Docstring / string-literal mentions are out of this guard's scope.
_LIMITER_INIT = re.compile(r"\bLimiter\s*\(")

# Extracts the storage_uri= argument value (a quoted literal or a bare token).
_STORAGE_URI_VAL = re.compile(r"""storage_uri\s*=\s*(?:(["'])(.*?)\1|(\S+))""")

# Persistent-backend URI schemes recognized by the `limits` storage backend.
_PERSISTENT_SCHEME = re.compile(r"^(?:redis|rediss|memcached|mongodb|etcd)://", re.IGNORECASE)

# The explicit in-memory scheme (also the library default when storage_uri is omitted).
_MEMORY_SCHEME = re.compile(r"^memory://", re.IGNORECASE)

_JOIN_LINES = 10  # max continuation lines to join for a Limiter( call wrapped across lines


def _joined_call(lines: list[str], idx: int) -> str:
    """The call text starting at lines[idx], joined across continuation lines until
    its parens balance (capped at _JOIN_LINES extra lines). Comment-stripped first
    so a stray `)` or a `storage_uri=` mentioned only in a trailing comment can't
    end the join early or count as configured (mirrors rate_limit_no_user_key.py)."""
    parts = [strip_python_line_comment(lines[idx])]
    depth = parts[0].count("(") - parts[0].count(")")
    j = idx + 1
    while depth > 0 and j < len(lines) and j <= idx + _JOIN_LINES:
        code = strip_python_line_comment(lines[j])
        parts.append(code)
        depth += code.count("(") - code.count(")")
        j += 1
    return " ".join(p.strip() for p in parts)


class RateLimitNoPersistentStoreGuard(Guard):
    id = "rate-limit-no-persistent-store"
    title = "Rate limiter has no persistent (Redis) backend — resets/desyncs across workers"
    area = "Reliability"

    # limiter.py has one rate-limit-no-persistent-store plant:
    #   Limiter(key_func=get_remote_address) with no storage_uri= at all
    #   -> no-persistent-store (LOW).
    # Must NOT contain: allow-in-memory-rate-limit pragma, or a persistent storage_uri.
    canary_plant = CanaryPlant(
        files={
            "limiter.py": (
                "from slowapi import Limiter\n"
                "from slowapi.util import get_remote_address\n"
                "\n"
                "limiter = Limiter(key_func=get_remote_address)\n"
            ),
        },
        expects=frozenset({"rate-limit-no-persistent-store/no-persistent-store"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        all_files: list[Path] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f not in seen:
                    seen.add(f)
                    all_files.append(f)

        # Pass 1: check whether the library is used at all.
        lib_in_use = False
        for f in all_files:
            if _SLOWAPI_IMPORT.search(read(f)):
                lib_in_use = True
                break
        if not lib_in_use:
            return []

        # Pass 2: evaluate each Limiter() instantiation independently — a persistent or
        # non-literal storage_uri= on ONE instance must never silence a different, genuinely
        # in-memory Limiter() elsewhere in the project (round-2 fix, PR #732 review).
        out: list[Finding] = []
        any_limiter_found = False

        for f in all_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue
            lines = text.splitlines()
            for i, raw in enumerate(lines):
                # Match on the comment-stripped line (#897): a `Limiter(` that lives only in a `#`
                # comment is not an instantiation. The stripped line also feeds the single-line
                # call text (so a `storage_uri=` named only in a trailing comment can't count as
                # configured) and the paren-balance check (so a `(` in a trailing comment can't
                # start a bogus multi-line join). The pragma check above stays on the whole file
                # text, so the user's opt-out still sees every line (review-doctrine Rule 4).
                line = strip_python_line_comment(raw)
                if not _LIMITER_INIT.search(line):
                    continue
                any_limiter_found = True
                call_text = line
                if line.count("(") > line.count(")"):
                    call_text = _joined_call(lines, i)
                su_match = _STORAGE_URI_VAL.search(call_text)
                storage_uri = (
                    (su_match.group(2) if su_match.group(1) else su_match.group(3))
                    if su_match
                    else None
                )

                # Non-literal (env var / settings / variable) — can't tell what THIS
                # instance resolves to; benefit of the doubt, don't false-positive on it.
                if (
                    storage_uri is not None
                    and not _PERSISTENT_SCHEME.match(storage_uri)
                    and not _MEMORY_SCHEME.match(storage_uri)
                ):
                    continue
                # A literal persistent-backend URI — THIS instance is fine.
                if storage_uri is not None and _PERSISTENT_SCHEME.match(storage_uri):
                    continue

                # No storage_uri= at all, or an explicit memory:// literal.
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="low",
                        title=self.title,
                        location=f"{rel(root, f)}:{i + 1}",
                        message=(
                            "This `Limiter()` instantiation uses (or defaults to, when "
                            "`storage_uri` is omitted) the in-memory storage backend. A "
                            "production deployment running more than one worker process "
                            "or container replica gets one independent counter per "
                            "process for this limiter — the configured limit is not "
                            "enforced across the deployment as a whole, and every restart "
                            "resets it to zero."
                        ),
                        remediation=(
                            "Point this limiter at a shared store: "
                            "`Limiter(key_func=..., storage_uri='redis://<host>:6379')`. "
                            "Suppress with `# security: allow-in-memory-rate-limit` in the "
                            "file where this `Limiter` is defined when the deployment is "
                            "genuinely single-process."
                        ),
                        rule="rate-limit-no-persistent-store/no-persistent-store",
                        standards=list(_STANDARDS),
                    )
                )

        if not any_limiter_found:
            # No Limiter() instantiation found (library imported but unused here).
            return []
        return out
