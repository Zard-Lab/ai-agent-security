"""Guard: FastAPI UploadFile route without a size-limit check (OWASP:A04 — Insecure Design).

FastAPI passes file uploads directly as `UploadFile` objects. Unless the handler
(or a middleware in front of it) explicitly enforces a maximum file size, an attacker
can POST an arbitrarily large file. FastAPI will happily buffer the entire upload in
memory before the route handler runs, so even one concurrent large upload can exhaust
heap and crash the process — a trivial unauthenticated Denial-of-Service.

Detectable pattern (MEDIUM):

  **`upload-no-size-check`** — a Python function whose signature contains
  ``: UploadFile`` (a FastAPI file parameter) but whose next 30 lines contain none of
  the standard size-enforcement signals: ``content_length``, ``max_size``, ``MAX_FILE``,
  ``size_limit``, ``file_size``, a ``MAX_<name>_SIZE``-style constant (e.g.
  ``MAX_AVATAR_SIZE``), or a ``size_bytes``-named variable used in a comparison
  (``MAX_UPLOAD_SIZE_BYTES``, ``uploaded_size_bytes > MAX_SIZE_BYTES``).

**Middleware coverage (#472).** A route is also covered when a size-limiting middleware
(``ContentSizeLimitMiddleware``, ``MaxBytesMiddleware``) is *registered* in the route's app:
``add_middleware(...)``, a ``Middleware(...)`` entry of a ``middleware=[...]`` list, or a
``dispatch=`` keyword, resolved by ``base.py::registered_middleware_scopes``. The registration may
sit in any product file in the route's top-level directory (a root-level file such as ``main.py``
covers the whole tree), so the idiomatic layout, middleware in ``main.py`` and routes under
``routes/``, is not reported. A mere mention does not count: a comment, an import, a class
definition, a registration under an ``if``, or one in a non-product file (tests, examples).

**Why MEDIUM?** The impact (DoS via memory exhaustion) is real but the attacker needs
write access to the upload endpoint. The check is also conservative: missing signals in
the next 30 lines does not prove absence of a size check implemented upstream (e.g. in
a reverse proxy or a framework default), so a manual review step is still warranted.

**Known accepted heuristic gap (issue #324):** the ``MAX_<name>_SIZE`` naming-convention
match is a name pattern, not proof of an actual enforced cap — a ``max_image_size``
(pixel dimensions) or ``max_page_size`` (pagination) constant also silences this guard
even though it enforces nothing about upload byte size. This trade-off is accepted
because tightening it back to exact tokens would reopen the reported gap (a real
project can't be distinguished from a look-alike lexically); see
``.claude/issues/issue-324.md`` "Risks and Considerations".

**Known accepted false-positive gap (PR #327 review):** anchoring ``size_bytes`` to a
``max_``-prefix or a comparison context (to stop it matching a bare read-chunk buffer
variable) means a ``size_bytes``-named variable passed to a **custom-named** helper with
no inline comparison — e.g. ``size_bytes = len(data); validate_upload_size(size_bytes)``
— no longer silences the guard even when that helper enforces a real cap internally. This
is the same "guard can't see into a differently-named helper" limitation the guard already
has for any size-check helper outside its 5-name hardcoded list
(``upload_with_limit``/``read_upload_with_limit``/``read_with_limit``/``limit_upload``/
``max_upload``) — accepted rather than fixed here; see
``.claude/issues/issue-324.md`` "Risks and Considerations".

**Suppress:** add ``# security: allow-no-upload-size-limit`` anywhere in a file to
silence this check for that file. Use only when size limits are enforced at the
infrastructure layer (reverse proxy, WAF, cloud gateway) and that guarantee is
documented.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    MIDDLEWARE_PREFILTER,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    middleware_scope,
    pragma_present,
    python_scan_dirs,
    read,
    registered_middleware_scopes,
    rel,
)

_PRAGMA = "security: allow-no-upload-size-limit"

_STANDARDS = ["OWASP:A04"]

# Matches any parameter annotated as UploadFile (e.g. `file: UploadFile`).
_UPLOAD_PARAM = re.compile(r":\s*UploadFile\b")

# Signals that the handler (or a helper it calls) enforces a size limit.
# Named helpers like read_upload_with_limit() are common application-level wrappers
# that perform the check internally. `max_[a-z0-9_]*size` also matches project-specific
# constant names (MAX_AVATAR_SIZE, MAX_UPLOAD_SIZE, ...) that don't contain the literal
# substring "max_size" (issue #324). Known accepted trade-off: this also matches an
# unrelated `max_*_size` name (a pixel-dimension or pagination cap, not a byte-size cap) —
# same heuristic-name-vs-actual-mitigation trade-off as content_type_magic_bytes.py's
# validation-helper match; see .claude/issues/issue-324.md "Risks and Considerations".
# `size_bytes` is anchored to a `max_`-prefixed name or a comparison context (PR #327
# review) so it doesn't also match a bare streaming-read buffer-size var like
# `chunk_size_bytes` (used only as a read-chunk argument, enforcing no total cap).
_SIZE_CHECK = re.compile(
    r"content_length|max_size|max_file|size_limit|file_size|max_length"
    r"|max_[a-z0-9_]*size\b"
    r"|max_\w*size_bytes\b|[<>]=?\s*\w*size_bytes\b|\w*size_bytes\b\s*[<>]=?"
    r"|upload_with_limit|read_upload_with_limit|read_with_limit|limit_upload|max_upload",
    re.IGNORECASE,
)

# Size-limiting middleware, matched against the NAME a product file registers
# (`registered_middleware_scopes`), not the raw text: a registration covers every route in its
# app scope, wherever the route lives (#472), while a mention in a comment or an import covers
# nothing.
_MIDDLEWARE_SIZE = re.compile(
    r"ContentSizeLimitMiddleware|MaxBytesMiddleware",
    re.IGNORECASE,
)


class UploadNoSizeLimitGuard(Guard):
    id = "upload-no-size-limit"
    title = "UploadFile route without a file size limit (memory-exhaustion DoS)"
    area = "Files"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `upload.py` and `upload_handler.py`, each of which several guards trip at once, so those files stay
    # in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # upload.py: async def save(file: UploadFile) with no size-check signal in 30 lines ->
    # fires upload-no-size-check (MEDIUM). (upload.py was already in the canary for
    # unrestricted-file-upload; it doubles as the size-limit plant here.)
    canary_plant = CanaryPlant(expects=frozenset({"upload-no-size-limit/no-size-check"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features and "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        # CLAUDE.md rule 4: the pragma skip below gates only where a finding may be ANCHORED, not
        # what pass 1 reads, so a pragma'd `main.py` still contributes its middleware. A test or
        # example app's middleware never runs in front of the product's routes, so a non-product
        # file is no coverage source.
        sources: list[tuple[Path, str]] = []
        found: list[tuple[str, list[Finding]]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if MIDDLEWARE_PREFILTER.search(text):
                    sources.append((f, text))
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _UPLOAD_PARAM.search(text):
                    continue
                hits = self._check_file(root, f, text)
                if hits:
                    found.append((middleware_scope(root, f), hits))
        if not found:
            return []
        # Pass 1 runs only once pass 2 has a candidate, so a repo with no unbounded upload never
        # pays for its AST parse (#771). A size-limiting middleware registered in the route's
        # scope covers it, whether in the route's own file or in `main.py` (#472).
        covered = registered_middleware_scopes(root, sources, _MIDDLEWARE_SIZE)
        if "" in covered:
            return []
        return [hit for scope, hits in found if scope not in covered for hit in hits]

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Scan each function's REAL body (AST-delimited) rather than a fixed 30-line window:
        # the window used to bleed into a following function, so a size check there falsely
        # suppressed an unguarded route (FN) or the reverse (#423).
        #
        # `include_closures=False` because this guard is the one consumer of `iter_functions`
        # that decides "is this a route?" from a parameter ANNOTATION rather than a decorator.
        # A helper nested in a route body receives the route's `UploadFile` and so carries
        # `: UploadFile` itself, without being a route and without the enclosing route's size
        # check in ITS block — reporting a correctly-capped route as unguarded (#452 re-review).
        # A nested def carrying a REGISTRATION decorator (`@router.post`, `@app.websocket`, ...)
        # is still emitted, so a route registered inside a factory is still analysed on its own
        # (the true positive #452 added). An unrelated decorator on the helper (`@lru_cache`,
        # `@retry`) does NOT promote it — that was the re-broken form of the same FP.
        for def_line, block in iter_functions(text, include_closures=False, filename=f):
            if not _UPLOAD_PARAM.search(block):
                continue
            # We found an UploadFile parameter. Check the same function for a size signal.
            if _SIZE_CHECK.search(block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="UploadFile route has no file-size check — memory-exhaustion DoS possible",
                    location=f"{rel(root, f)}:{def_line}",
                    message=(
                        "This function accepts a FastAPI `UploadFile` parameter but its body "
                        "contains no size-enforcement signal "
                        "(`content_length`, `max_size`, `MAX_FILE`, `size_limit`, `file_size`, "
                        "a `MAX_<name>_SIZE`-style constant, or a compared `size_bytes`-named "
                        "variable). Without an explicit size limit, an attacker can POST an "
                        "arbitrarily large file that FastAPI buffers entirely in memory before "
                        "the handler runs, exhausting heap and crashing the process — a "
                        "trivial unauthenticated DoS."
                    ),
                    remediation=(
                        "Read and enforce a size cap before processing the file, e.g.: "
                        "`contents = await file.read(MAX_FILE_SIZE + 1); "
                        "if len(contents) > MAX_FILE_SIZE: raise HTTPException(413)`. "
                        "Alternatively, configure a global limit at the middleware/reverse-proxy "
                        "layer and document that guarantee. "
                        "Suppress with `# security: allow-no-upload-size-limit` "
                        "when limits are enforced at the infrastructure layer."
                    ),
                    rule="upload-no-size-limit/no-size-check",
                    standards=list(_STANDARDS),
                )
            )
        return out
