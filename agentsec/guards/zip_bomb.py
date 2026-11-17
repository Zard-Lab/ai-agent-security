"""Guard: unsafe archive extraction without decompression size or file-count limit (§3a).

A zip bomb (CWE-409) is a compressed archive crafted to expand to an enormous size on
extraction — the classic "42.zip" decompresses to petabytes. In a FastAPI service that
accepts archive uploads, a single malicious upload can exhaust disk space or main memory
in seconds, causing a denial-of-service with no other attack surface needed.

The attack is straightforward: craft a zip where each member is many gigabytes of null
bytes (easily compressible to kilobytes) and submit it to any endpoint that calls
``.extractall()`` without first checking the total uncompressed size or the member count.
Python's ``zipfile`` and ``tarfile`` modules enforce no limits by default.

This guard is the *size/count* companion to ``zip-slip`` (path-traversal). Together the
two guards cover both halves of checklist item ``3a-decompression-bomb-zip-slip``.

**What it detects:** a ``.extractall(`` call in a file that imports ``zipfile`` or
``tarfile``, where nothing from the START of the enclosing function through the call itself
(``enclosing_function_span()``) contains evidence of a size or count check. A call
with no enclosing function (module-level code) falls back to a 12-line look-back window. The
safe patterns recognised as evidence of a limit:

    - ``file_size`` — the zipfile member uncompressed-size attribute
    - ``member.size`` / ``m.size`` / ``.size`` — the tarfile member size attribute, in a
      size-accumulation context (matches any ``.size`` reference, regardless of the accumulator's name)
    - ``MAX_SIZE`` / ``SIZE_LIMIT`` / ``max_size`` / ``size_limit`` / ``MAX_EXTRACT``
    - ``total_size`` / ``uncompressed`` — size accumulation variable names
    - ``MAX_FILES`` / ``max_files`` / ``MAX_MEMBERS`` / ``max_members``

**Why HIGH?** A decompression bomb requires no authentication — any file-upload endpoint
is the attack surface. Exploitation causes immediate disk or memory exhaustion, equivalent
in impact to a hard DoS.

**Scope:** Python files only. A size/count check enforced in a DIFFERENT function the caller
invokes (not inlined into the enclosing function's own body) is still not detected — use the
pragma to suppress after review.

**Checklist item:** ``3a-decompression-bomb-zip-slip`` (companion to zip-slip; together
they flip this item from partial to covered).

**Suppress:** add ``# security: allow-zip-bomb`` anywhere in the file (typically on the
extractall line) to silence this check for that file.
"""
# security: allow-zip-extractall — this file's docstring/strings contain
# `.extractall(` as guard-pattern examples; the zip-slip finding is self-referential.
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-zip-bomb"

_STANDARDS = ["OWASP:A04", "ASVS:5.3.3", "CWE-409"]

# Requires at least one of zipfile or tarfile to be imported in the file.
_ARCHIVE_IMPORT = re.compile(r"\b(?:import\s+(?:zipfile|tarfile)|from\s+(?:zipfile|tarfile)\s+import)\b")

# A bare .extractall( call — matches both zipfile and tarfile usage.
_EXTRACTALL = re.compile(r"\.extractall\(")

# Patterns that indicate a size or count limit is enforced near the extractall call.
# `\.size\b` recognises the tarfile member-size idiom (`m.size` / `member.size`) regardless of the
# accumulator variable's name — the docstring promised it but the regex omitted it (PR #205 review).
# `compress_size` is intentionally NOT here: bounding the *compressed* size is no defense against a
# decompression bomb (compressed << uncompressed), so accepting it was an over-suppression.
_SAFE_PATTERNS = re.compile(
    r"file_size|\.size\b|MAX_SIZE|SIZE_LIMIT|max_size|size_limit|MAX_EXTRACT|max_extract"
    r"|total_size|uncompressed_size|uncompressed"
    r"|MAX_FILES|max_files|MAX_MEMBERS|max_members",
)

# Window size — wider than zip-slip's 5 lines because the size-check loop often
# precedes the extractall call by several lines.
_WINDOW = 12


class ZipBombGuard(Guard):
    id = "zip-bomb"
    title = "Unsafe archive extraction without size/count limit — Zip Bomb (CWE-409)"
    area = "Files"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted across the canary's shared
    # `zip_bomb_handler.py` and `zip_handler.py`, each of which several guards trip at once, so those files
    # stay in `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # zip_bomb_handler.py: tf.extractall(output_dir) without size/count limit -> no-size-limit.
    canary_plant = CanaryPlant(expects=frozenset({"zip-bomb/no-size-limit"}))

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
                if not _ARCHIVE_IMPORT.search(text):
                    continue
                findings = self._check_file(root, f, text)
                out.extend(findings)
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        # Computed once per file, not per match: enclosing_function_span() re-parses the AST on
        # every call otherwise, which measures ~900x slower over a many-function file (found in the
        # #685 review).
        funcs = iter_functions(text, filename=f)
        for i, line in enumerate(lines):
            if not _EXTRACTALL.search(line):
                continue
            # look back to the START of the enclosing function first (a check can sit
            # further away than any fixed window, or inside a same-function helper `iter_functions`
            # inlines), falling back to the fixed window only for module-level calls with no
            # enclosing def. Look-BACK only, never forward — a size/count check written AFTER
            # `.extractall()` has already run is not a mitigation, it's dead code.
            span = enclosing_function_span(text, i + 1, functions=funcs)
            if span is not None:
                scope_start, _scope_end = span
                scope = "\n".join(lines[scope_start - 1 : i + 1])
            else:
                window_start = max(0, i - _WINDOW)
                scope = "\n".join(lines[window_start : i + 1])
            if _SAFE_PATTERNS.search(scope):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Unsafe .extractall() without decompression size/count limit — Zip Bomb",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "This `.extractall()` call does not appear to check the total "
                        "uncompressed size or member count before extracting. A malicious "
                        "archive can expand to gigabytes (or petabytes) from a tiny "
                        "compressed payload, exhausting disk space or memory instantly — "
                        "a zip bomb (CWE-409). In a web service, any file-upload endpoint "
                        "that calls `.extractall()` without a size guard is a hard DoS vector."
                    ),
                    remediation=(
                        "Before calling `.extractall()`, sum member sizes and enforce a cap. "
                        "For zipfile: `total = sum(m.file_size for m in zf.infolist()); "
                        "if total > MAX_SIZE: raise ValueError(...)`. "
                        "For tarfile: iterate `tf.getmembers()` and accumulate `m.size`. "
                        "Also limit file count: `if len(members) > MAX_FILES: raise ValueError(...)`. "
                        "If this call is already guarded by a helper that enforces limits, "
                        "suppress with `# security: allow-zip-bomb` on the extractall line "
                        "or anywhere in the file."
                    ),
                    rule="zip-bomb/no-size-limit",
                    standards=list(_STANDARDS),
                )
            )
        return out
