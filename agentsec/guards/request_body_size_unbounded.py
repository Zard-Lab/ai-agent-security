"""Guard: FastAPI route with a Pydantic-model request body and no size cap (checklist §3a).

`upload_no_size_limit.py` covers `UploadFile` routes specifically. A plain JSON/Pydantic request
body has the exact same memory-exhaustion shape and is NOT that guard's target (its own docstring
scopes it to `UploadFile` only): FastAPI buffers the entire request body in memory and parses it
into JSON *before* Pydantic validation ever runs, so an attacker can POST an arbitrarily large body
to any `POST`/`PUT`/`PATCH` route that takes a Pydantic model — no authentication required if the
endpoint is public — and exhaust the server's heap.

Detectable pattern (MEDIUM, same tier as `upload-no-size-limit`):

  **`request-body-size-unbounded/no-size-check`** — a route handler decorated with
  `@app.post/put/patch(...)` or `@router.post/put/patch(...)` whose signature contains a
  parameter annotated with a capitalized type that is neither a recognized non-body FastAPI/
  Starlette type (`UploadFile`, `Request`, `Response`, `BackgroundTasks`, `WebSocket`, …) nor a
  parameter-marker default (`Depends`/`Query`/`Path`/`Header`/`Cookie`/`Form`/`File`/`Security`) —
  i.e. a Pydantic request-body model — and whose function body (and the rest of the file, for
  middleware) contains none of `content_length`, `Content-Length`, `max_size`, `max_body`,
  `body_size`, `max_length`, or a `MAX_*SIZE*`-style constant, and no ASGI middleware whose class
  name mentions `size`/`limit` registered via `app.add_middleware(...)`.

**Why MEDIUM?** Same reasoning as `upload-no-size-limit`: the impact (DoS via memory exhaustion) is
real but requires an already-reachable endpoint, and the check is conservative — missing signals in
the scanned scope does not prove the absence of a cap enforced elsewhere (a reverse proxy, an ASGI
middleware in another file, a global body-size limit set at the framework/server layer).

**Deliberately out of scope:** a route whose only body-shaped parameter is `UploadFile` — that is
`upload-no-size-limit`'s target, a distinct, non-overlapping sink (`UploadFile` streams rather than
buffering the whole body as one parsed JSON object). This guard's capitalized-type heuristic
excludes `UploadFile` by name specifically so the two guards never double-report the same route.

**Known accepted heuristic gap (mirrors `upload_no_size_limit.py`'s own accepted gap):** the
`MAX_*SIZE*` naming-convention match and the middleware name-substring match are lexical, not
proof of an actual enforced byte cap — a `max_page_size` (pagination) constant or a
`RequestSizeLoggerMiddleware` (logs size, doesn't cap it) would also silence this guard. Accepted
for the same reason `upload_no_size_limit.py` accepts it: a real project can't be distinguished
from a look-alike lexically, and tightening this would reopen real gaps it exists to catch.

**Suppress:** add ``# security: allow-unbounded-request-body`` anywhere in a file to silence this
check for that file. Use only when the body size is capped at the infrastructure layer (reverse
proxy, WAF, cloud gateway, ASGI middleware in a different file) and that guarantee is documented.
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
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
)

_PRAGMA = "security: allow-unbounded-request-body"
_STANDARDS = ["OWASP:A04"]

# A route registered for a body-bearing HTTP verb — GET/DELETE deliberately excluded (no
# conventional request body).
_ROUTE_DECORATOR = re.compile(r"@\s*[\w.]+\.(?:post|put|patch)\s*\(", re.IGNORECASE)

# The function signature's opening paren, so its parameter list can be extracted with the shared
# `split_call_args` balanced-paren splitter.
_DEF_SIG = re.compile(r"(?:async\s+)?def\s+\w+\s*\(")

# One parameter: `name: annotation` optionally followed by `= default`. Non-greedy up to the first
# top-level `=` (same shape as request_model_extra_forbid.py's own param parser).
_PARAM = re.compile(r"^\s*\*{0,2}\w+\s*:\s*(.+?)(?:=(.*))?$", re.S)

# Capitalized identifiers inside an annotation (`Optional[CreateUser]` -> `Optional`, `CreateUser`).
_TYPE_REF = re.compile(r"\b([A-Z]\w*)\b")

# A param default carrying one of these markers is a non-body dependency, not a request body.
_NON_BODY_DEFAULT = re.compile(r"\b(?:Depends|Query|Path|Header|Cookie|Form|File|Security)\s*\(")

# Capitalized type names that are NOT a Pydantic request-body model: FastAPI/Starlette framework
# types, generic-wrapper/typing names (unwrapped to their inner type is out of scope — conservative
# by design, see module docstring), and UploadFile specifically (that guard's own target).
_NON_BODY_TYPE = frozenset({
    "UploadFile", "Request", "Response", "BackgroundTasks", "WebSocket", "HTTPException",
    "HTTPConnection", "Depends", "Query", "Path", "Header", "Cookie", "Form", "File", "Security",
    "Optional", "List", "Dict", "Union", "Any", "Annotated", "Literal", "Callable", "Tuple", "Set",
    "FrozenSet", "Type", "ClassVar", "Final", "None",
})

# Size-enforcement signals anywhere in the enclosing function (or, for middleware, the file).
_SIZE_CHECK = re.compile(
    r"content[-_]length|max_size|max_body|body_size|max_length|MAX_\w*SIZE\w*",
    re.IGNORECASE,
)

# Middleware-level enforcement applies to the whole file: an ASGI middleware class whose NAME
# mentions size/limit, registered via `app.add_middleware(...)`.
_MIDDLEWARE_SIZE = re.compile(r"add_middleware\s*\(\s*[\w.]*(?:size|limit)\w*", re.IGNORECASE)


def _has_body_model_param(block: str) -> bool:
    """True if `block`'s function signature has a parameter typed as a Pydantic request-body
    model — a capitalized annotation not in `_NON_BODY_TYPE` and not defaulted to a non-body
    FastAPI parameter marker."""
    m = _DEF_SIG.search(block)
    if m is None:
        return False
    params = split_call_args(block, m.end() - 1)
    if params is None:
        return False
    for param in params:
        pm = _PARAM.match(param)
        if not pm:
            continue
        anno, default = pm.group(1), pm.group(2) or ""
        if _NON_BODY_DEFAULT.search(default):
            continue
        types = [t for t in _TYPE_REF.findall(anno) if t not in _NON_BODY_TYPE]
        if types:
            return True
    return False


class RequestBodySizeUnboundedGuard(Guard):
    id = "request-body-size-unbounded"
    title = "Request body (Pydantic model) route without a size limit (memory-exhaustion DoS)"
    area = "Reliability"

    # unbounded_body.py: @router.post with a Pydantic `CreateUser` body param, no size-check
    # signal, no size-limiting middleware -> fires request-body-size-unbounded/no-size-check.
    canary_plant = CanaryPlant(
        files={
            "unbounded_body.py": (
                "from fastapi import APIRouter\n"
                "from pydantic import BaseModel\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                "class CreateUser(BaseModel):\n"
                "    name: str\n"
                "\n"
                "\n"
                "@router.post(\"/users\")\n"
                "async def create_user(body: CreateUser):\n"
                "    return {\"name\": body.name}\n"
            ),
        },
        expects=frozenset({"request-body-size-unbounded/no-size-check"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features and "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        out: list[Finding] = []
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
                # Middleware-level enforcement applies to every route in the file.
                if _MIDDLEWARE_SIZE.search(text):
                    continue
                out.extend(self._check_file(root, f, text))
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        for def_line, block in iter_functions(text, filename=f):
            if not _ROUTE_DECORATOR.search(block):
                continue
            if not _has_body_model_param(block):
                continue
            if _SIZE_CHECK.search(block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=(
                        "Request-body route has no size check — memory-exhaustion DoS possible"
                    ),
                    location=f"{rel(root, f)}:{def_line}",
                    message=(
                        "This route handler accepts a Pydantic request-body model but its scope "
                        "contains no size-enforcement signal (`content_length`, `max_size`, "
                        "`max_body`, `body_size`, `max_length`, a `MAX_*SIZE*`-style constant, or "
                        "a size/limit-named ASGI middleware). FastAPI buffers the entire request "
                        "body in memory and parses it into JSON before validation runs, so an "
                        "attacker can POST an arbitrarily large body and exhaust the server's "
                        "heap — an unauthenticated DoS if the endpoint is public."
                    ),
                    remediation=(
                        "Enforce a body-size cap before/while reading the request, e.g. check "
                        "`request.headers.get('content-length')` against a `MAX_BODY_SIZE` "
                        "constant and raise `HTTPException(413)`, or configure a global limit at "
                        "the ASGI middleware / reverse-proxy layer and document that guarantee. "
                        "Suppress with `# security: allow-unbounded-request-body` when the limit "
                        "is enforced at the infrastructure layer."
                    ),
                    rule="request-body-size-unbounded/no-size-check",
                    standards=list(_STANDARDS),
                )
            )
        return out
