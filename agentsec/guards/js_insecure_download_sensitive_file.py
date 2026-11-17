"""Guard: HTTP/FTP download URL for an executable or other sensitive file type (checklist §5).

A literal `http://` or `ftp://` URL (not HTTPS) whose path ends in a dangerous file
extension — an executable, archive, or script — is a man-in-the-middle target: an
attacker on-path can substitute the downloaded file with malicious content before it
reaches the client. CWE-829 (Inclusion of Functionality from Untrusted Control
Sphere), OWASP:A08 (Software and Data Integrity Failures).

Sourced from GitHub CodeQL's `js/insecure-download` query
(`InsecureDownloadQuery.ql` + `Customizations.qll`, verified against real fetched
source) — the exact dangerous-extension list is copied from the upstream
`unsafeExtension()` predicate: `exe`, `dmg`, `pkg`, `tar.gz`, `zip`, `sh`, `bat`,
`cmd`, `app`, `apk`, `msi`, `js`, `py`, `jar`, `war` (archives included because they
often contain source code).

This is a new checklist item — agentsec had no "insecure download" concept before
(the existing supply-chain guards check dependency manifests/lockfiles, not literal
download URLs in application code).

Fires HIGH per match:

    const url = "http://cdn.example.com/installer.exe";  // security: allow-js-insecure-download-sensitive-file
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
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-insecure-download-sensitive-file"

_UNSAFE_EXT = r"(?:exe|dmg|pkg|tar\.gz|zip|sh|bat|cmd|app|apk|msi|js|py|jar|war)"
# A trailing `?query` or `#fragment` after the extension is allowed before the closing quote
# (review #395 Major finding: "http://cdn/installer.exe?v=2" and a `.tar.gz#sig` URL were missed
# because the old pattern required the extension immediately before the closing quote).
_PATTERN = re.compile(
    rf"""['"](?:http|ftp)://[^'"\s]+\.{_UNSAFE_EXT}(?:[?#][^'"\s]*)?['"]""", re.IGNORECASE
)


class JsInsecureDownloadSensitiveFileGuard(Guard):
    id = "js-insecure-download-sensitive-file"
    title = "HTTP/FTP download URL for an executable or other sensitive file type"
    area = "Dependencies"

    # installer_download.js: http:// URL ending in .exe -> fires js-insecure-download-sensitive-file.
    canary_plant = CanaryPlant(
        files={
            "installer_download.js": 'const url = "http://cdn.example.com/installer.exe";\n',
        },
        expects=frozenset({
            "js-insecure-download-sensitive-file/http-ftp-sensitive-extension",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # strip_js_comments blanks both `//` (whole-line AND trailing) and `/* */` block
            # comments, string/regex-literal aware, preserving line numbers — review #395 Minor
            # finding: the old whole-line-only `//` check missed a `/* */` block-comment FP.
            code = strip_js_comments(text)
            for i, line in enumerate(code.splitlines(), start=1):
                if not _PATTERN.search(line):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This literal URL downloads a sensitive file type (executable, "
                            "archive, or script) over plain HTTP/FTP, not HTTPS. An attacker "
                            "on-path can substitute the file with malicious content before "
                            "it reaches the client."
                        ),
                        remediation=(
                            "Use an HTTPS URL. If the source only offers HTTP/FTP, verify "
                            "the download's integrity with a checksum/signature fetched over "
                            "a separate trusted channel before using it."
                        ),
                        rule="js-insecure-download-sensitive-file/http-ftp-sensitive-extension",
                        standards=["OWASP:A08", "CWE-829"],
                    )
                )
                break  # one finding per file is enough
        return out
