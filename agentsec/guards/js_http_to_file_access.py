"""Guard: raw HTTP response data written directly to the filesystem (checklist §3a).

Sourced from GitHub CodeQL's `js/http-to-file-access` query
(`javascript/ql/src/Security/CWE-912/HttpToFileAccess.ql` +
`HttpToFileAccessQuery.qll`, verified against real fetched source, codeql
`@security-severity 6.3`).

Writing the body of an HTTP response straight to the filesystem — without validating
its content, size, or the path it lands at — is a classic "arbitrary file write /
backdoor" primitive: the remote server (or a MITM, or a redirect chain) fully
controls what ends up on disk. Two common Node shapes:

1. **Streaming**: `response.pipe(fs.createWriteStream(dest))` off an `http`/`https`
   `.get()`/`.request()` callback.
2. **Buffered**: `fs.writeFileSync(dest, response.data)` off an `axios`/`fetch`
   response.

CWE-912 (Hidden Functionality), CWE-434 (Unrestricted Upload of File with Dangerous
Type) — CodeQL's own dual mapping. OWASP:A08 (Software and Data Integrity Failures).

**Detection design.** File-scoped in two parts (mirrors `js-host-header-email-link`'s
shape — the HTTP call and the file write are typically separate statements):

1. File-level gate: an HTTP-client indicator (`axios`, `https.get(`/`https.request(`,
   `http.get(`/`http.request(`, or `fetch(`).
2. A line in that file matching either:
   - `.pipe(fs.createWriteStream(...))` — the streaming shape, OR
   - `fs.writeFile(Sync)?(..., <expr>.data)` / `...(..., <expr>.body)` — the
     buffered shape (`response.data` is axios's own response-body property name;
     `.body` covers `fetch`'s `Response.body`).

Fires HIGH per matching line:

    https.get(url, (response) => {
      response.pipe(fs.createWriteStream(dest));  // security: allow-js-http-to-file-access
    });

Suppress a reviewed exception (e.g. downloading from a pinned, trusted, checksum-
verified source) with `// security: allow-js-http-to-file-access` on the write line.
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
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-http-to-file-access"

_HTTP_CLIENT_INDICATOR = re.compile(
    r"""\baxios\b|\bhttps?\.get\s*\(|\bhttps?\.request\s*\(|\bfetch\s*\(""",
    re.IGNORECASE,
)
_PIPE_TO_FILE = re.compile(r"""\.pipe\s*\(\s*fs\.createWriteStream\s*\(""", re.IGNORECASE)
_RESPONSE_DATA_TO_FS_WRITE = re.compile(
    r"""\bfs\.(?:writeFile|writeFileSync)\s*\([^)]*\.(?:data|body)\b""", re.IGNORECASE
)


class JsHttpToFileAccessGuard(Guard):
    id = "js-http-to-file-access"
    title = "HTTP response data written directly to the filesystem"
    area = "Files"

    # express_download.js: HTTP response piped straight to fs.createWriteStream -> fires
    # js-http-to-file-access/response-to-filesystem. Requires "express" (turned on via
    # js-cors-wildcard's express_app.js package.json dep).
    canary_plant = CanaryPlant(
        files={
            "express_download.js": (
                "const https = require('https');\n"
                "const fs = require('fs');\n"
                "https.get(url, (response) => {\n"
                "  response.pipe(fs.createWriteStream(dest));\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-http-to-file-access/response-to-filesystem"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            if not _HTTP_CLIENT_INDICATOR.search(code):
                continue
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(code.splitlines(), start=1):
                if not (_PIPE_TO_FILE.search(line) or _RESPONSE_DATA_TO_FS_WRITE.search(line)):
                    continue
                line_text = view_lines[i - 1] if i - 1 < len(view_lines) else ""
                if _PRAGMA in line_text:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "An HTTP response body is written directly to the filesystem in "
                            "this file, with no visible validation of its content, size, or "
                            "the destination path. The remote server (or anyone on the network "
                            "path, or a redirect chain) fully controls what ends up on disk — "
                            "an arbitrary file write / backdoor primitive."
                        ),
                        remediation=(
                            "Validate the response before writing: check content-type/size "
                            "limits, verify a checksum or signature from a separately trusted "
                            "channel, and write to a fixed, non-attacker-influenced path."
                        ),
                        rule="js-http-to-file-access/response-to-filesystem",
                        standards=["OWASP:A08", "CWE-912"],
                    )
                )
        return out
