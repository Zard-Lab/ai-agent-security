"""Guard: file upload trusts Content-Type header without magic-byte validation (checklist §3a).

A browser or HTTP client can send any `Content-Type` header it likes — the MIME type is
caller-controlled and meaningless for security decisions. Uploaded files must be validated
against their actual magic bytes (the first few bytes embedded in the file) to prevent:

  * Polyglot file attacks — a `.jpg` that is actually a PHP/HTML/SVG file with executable content.
  * Content-type bypass leading to stored XSS or RCE on serving infrastructure.
  * Upload filter bypass (upload forbidden extensions as allowed MIME types).

This guard detects FastAPI `UploadFile` handlers that check only `file.content_type` (the
header) without also importing a magic-byte library (`python-magic`, `filetype`, `imghdr`,
`sndhdr`, or reading raw bytes for manual signature checks) or calling a validation-named
helper (`validate_file_type(...)`, `scan_uploaded_file(...)`, etc. — a name-pattern heuristic,
not a cross-file follow of the helper's own imports). CWE-434 / OWASP:A03.

Suppress a reviewed case with `# security: allow-content-type-header-only`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-content-type-header-only"
_STANDARDS = ["OWASP:A03", "CWE-434"]

_UPLOAD_FILE = re.compile(r"\bUploadFile\b")
_CONTENT_TYPE_CHECK = re.compile(r"\bfile\.content_type\b|\bcontent_type\b")
_MAGIC_VALIDATION = re.compile(
    r"\bimport\s+magic\b"
    r"|\bimport\s+filetype\b"
    r"|\bimport\s+imghdr\b"
    r"|\bimport\s+sndhdr\b"
    r"|\bimport\s+puremagic\b"
    r"|\bfrom\s+magic\s+import\b"
    r"|\bfrom\s+filetype\s+import\b"
    r"|\bfrom\s+PIL\b"            # Pillow: Image.open(...).verify() parses real content (PR #206 review)
    r"|Image\.open\b"
    r"|\.verify\s*\("
    r"|\.read\s*\(\s*\d+\s*\)"    # any explicit byte count, not just a fixed list (PR #206 review)
    r"|file_signature"
    r"|magic_bytes"
    r"|header_bytes"
    # A call to a project-local validation helper whose NAME implies content
    # validation (e.g. validate_file_type(...), scan_uploaded_file(...)) — a
    # heuristic name-pattern match, not a cross-file follow of the helper's own
    # imports (out of scope for the guards' no-cross-file-import sandbox) (issue #324).
    r"|\b\w*(?:validate|verify|sniff|scan|detect)\w*(?:file|type|content|upload|magic)\w*\s*\("
)


class ContentTypeMagicBytesGuard(Guard):
    id = "content-type-magic-bytes"
    title = "File upload validates Content-Type header only — magic bytes not checked (CWE-434)"
    area = "Files"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `upload_handler.py`, which several guards trip at once, so the file stays in `canary.py`'s base
    # owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # upload_handler.py: content_type check only, no magic import -> header-only-check.
    canary_plant = CanaryPlant(expects=frozenset({"content-type-magic-bytes/header-only-check"}))

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features and "fastapi" in profile.features

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
                if not _UPLOAD_FILE.search(text):
                    continue
                if not _CONTENT_TYPE_CHECK.search(text):
                    continue
                if _MAGIC_VALIDATION.search(text):
                    continue
                lineno = self._content_type_lineno(text)
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title="UploadFile handler checks content_type header without magic-byte validation",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This file upload handler checks `file.content_type` (a caller-controlled "
                        "HTTP header) without also validating the file's actual magic bytes. "
                        "An attacker can upload a malicious file with any MIME type by forging "
                        "the Content-Type header, bypassing allow-list filters."
                    ),
                    remediation=(
                        "Read the first few bytes of the upload and verify against known magic "
                        "signatures before trusting content_type:\n"
                        "    header = await file.read(12)\n"
                        "    await file.seek(0)\n"
                        "    if not _is_allowed_signature(header):\n"
                        "        raise HTTPException(400, 'Invalid file type')\n"
                        "Use `python-magic` or `filetype` for broader signature coverage. "
                        "Suppress a reviewed case with `# security: allow-content-type-header-only`."
                    ),
                    rule="content-type-magic-bytes/header-only-check",
                    standards=list(_STANDARDS),
                ))
        return out

    def _content_type_lineno(self, text: str) -> int:
        for i, line in enumerate(text.splitlines(), 1):
            if _CONTENT_TYPE_CHECK.search(line):
                return i
        return 1
