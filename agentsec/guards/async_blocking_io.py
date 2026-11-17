"""Guard: blocking I/O call inside an async def (OWASP:A04 — Insecure Design).

FastAPI and other async Python frameworks run on an event loop. When a coroutine
calls a synchronous, blocking function — `requests.get()`, `time.sleep()`, or
`urllib.request.urlopen()` — the entire event loop is stalled for the duration of
that call. No other request can be handled until the blocking call returns.

An attacker who can trigger the offending endpoint with a slow or unresponsive
target (e.g. a long `requests.get` to a controlled server) can effectively make
the entire API unresponsive, constituting a Denial-of-Service (DoS) condition. In
high-traffic deployments the failure cascades: worker threads exhaust their
connection pool, timeouts compound, and the service crashes.

Detectable pattern (MEDIUM):

  **`sync-call-in-async-def`** — a Python file that contains an `async def`
  function whose body includes a call matching `requests.(get|post|put|delete|patch|head)(`,
  `time.sleep(`, or `urllib.request.urlopen(`. These are the most commonly misused
  blocking primitives in async FastAPI code.

**Why MEDIUM?** The call must be reachable via a request path and the attacker
needs sufficient control over timing to cause starvation. That said, a single
`requests.get()` inside a FastAPI route handler is a near-certain DoS vector in
production — it just requires a slow upstream. The severity would be HIGH if the
call is unconditional, but since static analysis cannot prove reachability, MEDIUM
is appropriate.

**False-negative scope:** Multi-line blocking patterns (e.g. calling a helper
function that internally calls `requests.get`) are NOT caught — they require
dataflow / call-graph analysis beyond line-level static detection. Monkey-patched
or aliased `requests` modules are also not caught.

**Suppress:** add `# security: allow-blocking-io` anywhere in a file to silence
this check for that file. Use only when the blocking call is intentional and safe
(e.g. a startup-only script, a management CLI, or a test helper — never a request
handler).
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
    strip_python_strings,
)

_PRAGMA = "security: allow-blocking-io"

_STANDARDS = ["OWASP:A04"]

# Script/tooling directories: blocking calls are expected and harmless there because
# no asyncio event loop is shared. Distinct from NONPRODUCT_DIR_ALT (tests/fixtures)
# which is handled by is_nonproduct_path; these are intentional-product but non-server dirs.
_SCRIPT_DIR = re.compile(
    r"(?:^|/)(?:scripts?|tools?|tasks?|cron|jobs?)(?:/|$)",
    re.IGNORECASE,
)

# Matches an `async def` definition line (any indentation level).
_ASYNC_DEF = re.compile(r"^(\s*)async\s+def\s+\w+")

# Blocking primitives that stall the event loop. `\brequests\.` is anchored so an
# unrelated module whose name merely ends in "requests" (`myrequests.get(`) does not match.
_BLOCKING_CALL = re.compile(
    r"\brequests\.(?:get|post|put|delete|patch|head)\("
    r"|time\.sleep\("
    r"|urllib\.request\.urlopen\("
)


class AsyncBlockingIoGuard(Guard):
    id = "async-blocking-io"
    title = "Blocking I/O call inside async def stalls the event loop"
    area = "Reliability"

    # async_io_handler.py: requests.get() inside async def -> fires async-blocking-io.
    # Must NOT contain: allow-blocking-io pragma.
    canary_plant = CanaryPlant(
        files={
            "async_io_handler.py": (
                "import requests\n"
                "from fastapi import APIRouter\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                '@router.get("/data")\n'
                "async def get_data():\n"
                '    result = requests.get("https://api.example.com/data")\n'
                "    return result.json()\n"
            ),
        },
        expects=frozenset({"async-blocking-io/sync-call-in-async-def"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features or "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: C901
        out: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                if _SCRIPT_DIR.search(r.replace("\\", "/")):
                    continue

                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                # Blank triple-quoted docstring/template CONTENT so a `requests.get(` EXAMPLE in
                # an async function's OWN docstring (which sits inside the tracked async region)
                # doesn't fire (issue #424). Blanking preserves newlines/indentation, so the
                # async-body tracking below is unaffected.
                lines = strip_python_strings(text, filename=f).splitlines()
                in_async = False
                async_indent: str = ""

                for lineno, line in enumerate(lines, 1):
                    m = _ASYNC_DEF.match(line)
                    if m:
                        in_async = True
                        async_indent = m.group(1)
                        continue

                    if in_async:
                        # A non-blank, non-indented-deeper line at the same or outer
                        # level as the `async def` means we have left the function body.
                        stripped = line.rstrip()
                        if stripped and not stripped[0].isspace():
                            # Top-level line — we have left any async def
                            in_async = False
                        elif stripped and len(line) - len(line.lstrip()) <= len(async_indent):
                            # Back to the same indentation as the `async def` header
                            # or less — body is over.
                            in_async = False
                            # Still check this line in case it starts a new async def
                            m2 = _ASYNC_DEF.match(line)
                            if m2:
                                in_async = True
                                async_indent = m2.group(1)
                                continue

                    if in_async and _BLOCKING_CALL.search(line):
                        call_match = _BLOCKING_CALL.search(line)
                        assert call_match is not None  # narrowing for type checker  # nosec B101
                        call_text = call_match.group(0).rstrip("(")
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="medium",
                                title=f"Blocking call `{call_text}()` inside async def stalls the event loop",
                                location=f"{rel(root, f)}:{lineno}",
                                message=(
                                    f"`{call_text}()` is a synchronous, blocking call. "
                                    "When invoked from an `async def` handler in FastAPI "
                                    "(or any asyncio-based framework), it blocks the entire "
                                    "event loop for the duration of the call — no other request "
                                    "can be served. An attacker who controls the upstream target "
                                    "or the sleep duration can stall the service, causing a "
                                    "Denial-of-Service condition."
                                ),
                                remediation=(
                                    "Replace the blocking call with an async equivalent: "
                                    "use `httpx.AsyncClient` (or `aiohttp`) instead of `requests`, "
                                    "and `await asyncio.sleep()` instead of `time.sleep()`. "
                                    "If you must call a blocking function, off-load it to a "
                                    "thread pool: `await asyncio.get_event_loop().run_in_executor("
                                    "None, blocking_fn, *args)`. "
                                    "Suppress intentional cases with "
                                    "`# security: allow-blocking-io` in the file."
                                ),
                                rule="async-blocking-io/sync-call-in-async-def",
                                standards=list(_STANDARDS),
                            )
                        )

        return out
