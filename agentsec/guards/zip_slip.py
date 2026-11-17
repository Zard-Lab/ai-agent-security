"""Guard: unsafe use of .extractall() from zipfile or tarfile without path validation (§3a — Input Validation).

Zip Slip (CWE-22) is a class of path traversal attack that exploits archive extraction.
A malicious archive contains member paths like ``../../etc/cron.d/evil`` — when the
application calls ``.extractall()`` without verifying that each member resolves inside
the intended destination, the attacker can overwrite arbitrary files on the server.

The attack is straightforward: craft a zip or tar with a member whose name starts with
``../``, pass the archive to any endpoint that unpacks it, and arbitrary files outside
the target directory are written with the server's permissions. In a FastAPI / Django
service, that can mean overwriting ``~/.bashrc``, a Python package in
``site-packages``, or application source code itself — turning a file-upload endpoint
into remote code execution.

This guard detects the static pattern: a call to ``.extractall(`` that is not accompanied by
any of the safe extraction idioms anywhere from the start of the enclosing function through the
call itself (``enclosing_function_span()`` — a 5-line fallback window when no
enclosing function is found, e.g. module-level code). Specifically it looks for any of:

    - ``safe_extract`` — a named helper that validates each member before extraction
    - ``os.path.realpath`` — used to check the resolved path stays inside the target
    - ``os.path.commonpath`` — commonly used in the "if commonpath != target: raise" idiom
    - ``abspath`` — the ``os.path.abspath`` variant of the same check
    - ``secure_filename`` — werkzeug's sanitizer, also used as a guard name

If none of those identifiers appear in the enclosing function up through the ``.extractall(``
call, the line is flagged HIGH. Files can opt out of this check repo-wide by including
the pragma string ``security: allow-zip-extractall`` anywhere in the file body (typically
as a comment on the offending line).

**Why HIGH?** Successful Zip Slip gives the attacker write access to arbitrary server
paths, typically leading to remote code execution (overwriting a Python module, SSH
authorized_keys, or a cron job). It was a widespread real-world bug (SnakeYaml, multiple
npm packages, Gradle, Kibana).

**Scope:** Python files only. Multi-step patterns where member paths are validated in a
DIFFERENT function the caller invokes (not inlined into the enclosing function's own body) are
still not detected — this guard catches the same-function case. Code review should confirm any
suppressed case.

**Express/Node (codeql `js/zipslip`, `javascript/ql/src/Security/CWE-022/ZipSlip.ql`).**
The same bare-call-without-validation shape applies to `adm-zip`'s
``zip.extractAllTo(dest, overwrite)`` / ``.extractAll(dest, ...)`` and `node-stream-zip`'s
``.extractAllTo(dest)`` — a direct unpack-everything call with no per-member path check, the
JS analog of Python's bare ``.extractall()``. Deliberately NOT matched: `tar`'s own
`tar.extract({file, cwd})`, which validates member paths against the target dir internally
since a 2021 CVE fix, and manual per-entry extraction loops (`unzipper`/`yauzl` streaming),
which are a multi-step pattern outside this guard's single-call scope — same limitation the
Python side already documents. The bulk-unpack call and the safe idioms count only when they are
live code, tested on the shared anchor mask (`js_code_matches`, #1055): an idiom spelled out in a
log or error string no longer clears the finding, a call spelled out in a docs string no longer
fires, and code inside a `${...}` substitution still counts.

**Checklist item:** ``3a-decompression-bomb-zip-slip`` (flipped from not-covered to covered).

**Suppress:** add ``# security: allow-zip-extractall`` anywhere in the file (typically on
the extractall line) to silence this check for that file. JS/TS files use the equivalent
``// security: allow-zip-extractall`` line comment.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    enclosing_function_span,
    iter_files,
    iter_functions,
    js_code_matches,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-zip-extractall"

_STANDARDS = ["OWASP:A01", "CWE-22"]

# A bare .extractall( call — matches both zipfile and tarfile usage.
_EXTRACTALL = re.compile(r"\.extractall\(")

# Safe extraction idioms: if any of these appear in the 5 preceding lines (or the
# extractall line itself), the call is considered validated.
_SAFE_PATTERNS = re.compile(
    r"safe_extract|os\.path\.realpath|os\.path\.commonpath|abspath|secure_filename",
)
# PEP 706 tarfile extraction filter — `data`/`tar` are the path-safe stdlib filters (the
# recommended mitigation since Python 3.12). NOT `fully_trusted`, which disables it.
# Kept SEPARATE from `_SAFE_PATTERNS` because it is a per-call kwarg: it may only be matched
# on the extractall line itself, never across the preceding-lines window.
_EXTRACT_FILTER = re.compile(r"filter\s*=\s*[\"'](?:data|tar)[\"']")

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
# adm-zip / node-stream-zip's bulk-unpack call — the JS analog of Python's bare .extractall().
_JS_EXTRACTALL = re.compile(r"\.extractAllTo\(|\.extractAll\(")
# Safe-idiom window for the JS side: a resolved-path containment check, or a named helper.
_JS_SAFE_PATTERNS = re.compile(
    r"safeExtract|isPathInside|path\.resolve|\.startsWith\(",
)
_JS_PRAGMA_TEXT = "security: allow-zip-extractall"


class ZipSlipGuard(Guard):
    id = "zip-slip"
    title = "Unsafe .extractall() without path validation — Zip Slip (CWE-22)"
    area = "Files"

    # express_zip.js: zip.extractAllTo(dest, true) without path validation ->
    # fires zip-slip/unsafe-extractall on the JS/Express branch.
    # Must NOT contain: allow-zip-extractall pragma.
    # zip_handler.py: zf.extractall(extract_dir) without path check -> unsafe-extractall.
    canary_plant = CanaryPlant(
        files={
            "express_zip.js": (
                "const AdmZip = require('adm-zip');\n"
                "\n"
                "function extractUpload(zipPath, destDir) {\n"
                "  const zip = new AdmZip(zipPath);\n"
                "  zip.extractAllTo(destDir, true);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "zip-slip/unsafe-extractall",
        }),
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
                    text = read(f)
                    if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                        continue
                    out.extend(self._check_file(root, f, text))
        if "express" in profile.features:
            for f in iter_files(root, _JS_SUFFIXES):
                raw = read(f)
                if pragma_present(_JS_PRAGMA_TEXT, raw, dialect=comment_dialect_for(f)):
                    continue
                code = strip_js_comments(raw)
                if not _JS_EXTRACTALL.search(code):
                    continue
                mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
                out.extend(self._check_js_file(root, f, code, mask))
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        # Parsed lazily: computed once per file, but only after an unfiltered .extractall() anchor
        # is found. Most scanned files have no such call, and iter_functions() is a full
        # safe_ast_parse + strip_python_strings — pure waste on an anchor-free file (issue #771).
        # Memoized after the first parse so enclosing_function_span() doesn't re-parse per match
        # (~900x slower over a many-function file #685 review).
        funcs: list[tuple[int, str]] | None = None
        for i, line in enumerate(lines):
            if not _EXTRACTALL.search(line):
                continue
            # The tarfile extraction FILTER is a per-call keyword argument, so it can only
            # vouch for the call it is written on. Matching it over a 5-line preceding window
            # let one hardened call silence its neighbours — including `zipfile` calls, which
            # cannot accept a `filter=` kwarg at all, and a mere COMMENT mentioning
            # `filter="data"` within five lines (#447 review). Checked on this line only.
            if _EXTRACT_FILTER.search(line):
                continue
            # The path-validation idioms (realpath/commonpath/safe_extract/...) DO legitimately
            # sit on preceding lines — they validate the destination before extracting — so
            # those keep the window. look back to the START of the enclosing function
            # first (a validation idiom can sit further back than a fixed 5-line window reaches),
            # falling back to the fixed window only for module-level calls with no enclosing def.
            # Look-BACK only, never forward — a check written AFTER extractall() has already run
            # is not a mitigation.
            if funcs is None:
                funcs = iter_functions(text, filename=f)
            span = enclosing_function_span(text, i + 1, functions=funcs)
            if span is not None:
                scope_start, _scope_end = span
                window = "\n".join(lines[scope_start - 1 : i + 1])
            else:
                window_start = max(0, i - 5)
                window = "\n".join(lines[window_start : i + 1])
            if _SAFE_PATTERNS.search(window):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Unsafe .extractall() without path validation — Zip Slip",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "This call to `.extractall()` does not appear to validate that "
                        "extracted member paths resolve inside the target directory. A "
                        "malicious archive whose members use `../` prefixes can write "
                        "files to arbitrary server paths outside the intended extraction "
                        "directory — Zip Slip (CWE-22). In a web service this typically "
                        "leads to remote code execution via overwritten Python modules, "
                        "cron jobs, or SSH keys."
                    ),
                    remediation=(
                        "Validate every member path before extraction. The standard idiom: "
                        "`dest = os.path.realpath(os.path.join(target, member.name)); "
                        "if not dest.startswith(os.path.realpath(target)): raise ValueError`. "
                        "Alternatively, use a `safe_extract` helper (e.g. from the `zipfile` "
                        "docs or a trusted library). If this call is already safe and has been "
                        "reviewed, suppress with `# security: allow-zip-extractall` on the "
                        "line or add the pragma anywhere in the file."
                    ),
                    rule="zip-slip/unsafe-extractall",
                    standards=list(_STANDARDS),
                )
            )
        return out

    def _check_js_file(self, root: Path, f: Path, code: str, mask: str) -> list[Finding]:
        out: list[Finding] = []
        lines = code.splitlines()
        mask_lines = mask.splitlines()
        # The sink's `(` and the first character of a safe idiom must be live code on the anchor
        # mask (#1055): `log('TODO: path.resolve( the target')` no longer clears a real call, and a
        # `.extractAllTo(` spelled out in a docs string no longer fires. Code inside a `${...}` is
        # still code, and every match is tried, so a quoted copy cannot hide a real one after it.
        for i, (line, mask_line) in enumerate(zip(lines, mask_lines, strict=True)):
            if not any(js_code_matches(_JS_EXTRACTALL, line, mask_line, anchor=lambda m: m.end() - 1)):
                continue
            window_start = max(0, i - 5)
            window = "\n".join(lines[window_start : i + 1])
            mask_window = "\n".join(mask_lines[window_start : i + 1])
            if any(js_code_matches(_JS_SAFE_PATTERNS, window, mask_window, anchor=lambda m: m.start())):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Unsafe .extractAllTo() without path validation — Zip Slip",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "This call unpacks every archive member without validating that each "
                        "resolved path stays inside the target directory. A malicious archive "
                        "whose entry names use `../` prefixes can write files to arbitrary "
                        "server paths outside the intended extraction directory — Zip Slip "
                        "(CWE-22). In a web service this typically leads to remote code "
                        "execution via an overwritten module, config file, or startup script."
                    ),
                    remediation=(
                        "Validate every entry path before extraction: "
                        "`const dest = path.resolve(target, entry.entryName); "
                        "if (!dest.startsWith(path.resolve(target))) throw new Error(...)`. "
                        "If this call is already safe and has been reviewed, suppress with "
                        "`// security: allow-zip-extractall` on the line or add the pragma "
                        "anywhere in the file."
                    ),
                    rule="zip-slip/unsafe-extractall",
                    standards=list(_STANDARDS),
                )
            )
        return out
