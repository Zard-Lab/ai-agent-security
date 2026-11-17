"""Guard: no embedded JavaScript / auto-run action in a PDF file (checklist §3a, new item).

The PDF format allows a document to carry executable JavaScript and auto-triggered
actions: a `/JS` action runs script when the reader opens the document or a page
event fires, `/OpenAction` triggers automatically on open (frequently pointing at a
`/JS` action), and `/Launch` runs an external program/command. A PDF accepted as a
"just a document" upload (invoice, resume, agent-skill reference doc) can carry any
of these — Adobe Reader/Acrobat execute embedded JS by default, and `/Launch` is a
long-standing PDF RCE vector. CWE-95 (Improper Neutralization of Directives in
Dynamically Evaluated Code) / OWASP:A03.

Three literal marker patterns, matched anywhere in a `.pdf` file's raw bytes (PDF
object *dictionaries* — where these keys live — are never compressed even when a
page's content stream is; only the stream *data* is, so the markers survive a plain
text scan):

  * **`/JS`/`/JavaScript` action** (HIGH) — an embedded JavaScript action dictionary.
  * **`/Launch`** (HIGH) — an action that launches an external application/command.
  * **`/OpenAction`** — an action that runs automatically when the document opens.
    A bare `/OpenAction` is routinely benign: `/OpenAction [3 0 R /Fit]` (an
    initial-view zoom/page action) is standard LaTeX/hyperref/pandoc output. So a
    LONE `/OpenAction` is reported MEDIUM; it is escalated to HIGH only when the file
    ALSO carries a `/JS`/`/JavaScript` action (the dangerous "auto-run script on open"
    pairing).

Suppress an audited case (a trusted, intentionally interactive PDF form) by adding a
text object containing `security: allow-pdf-embedded-javascript` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, rel

_JS_ACTION = re.compile(r"/(?:JS|JavaScript)\b")
_OPEN_ACTION = re.compile(r"/OpenAction\b")
_LAUNCH_ACTION = re.compile(r"/Launch\b")
# A PDF (read as latin-1 bytes) has no comment syntax a view reads, so its pragma is matched on the raw text
# by contract (`dialect=None`, #1040 T5).
_PRAGMA = re.compile(r"security:\s*allow-pdf-embedded-javascript")

_STANDARDS = ["OWASP:A03", "CWE-95"]

# Read cap: `.pdf` bytes come from an untrusted repo, and an uncapped whole-file read
# is a memory DoS on the scanner (issue #419). Real document PDFs sit far below this;
# an oversize file is SKIPPED with a disclosed info finding, never silently dropped.
_MAX_PDF_BYTES = 50 * 1024 * 1024  # 50 MiB

_JS_DESC = "an embedded /JS or /JavaScript action"
_LAUNCH_DESC = "a /Launch action (external program execution)"
_OPEN_DESC_HIGH = "an /OpenAction that auto-runs on open alongside an embedded /JS action"
_OPEN_DESC_LOW = (
    "an /OpenAction that runs automatically on open (no embedded /JS detected — "
    "often a benign initial-view zoom/page action)"
)


class PdfEmbeddedJavascriptGuard(Guard):
    id = "pdf-embedded-javascript"
    title = "No embedded JavaScript / auto-run action in a PDF file"
    area = "Files"

    # invoice.pdf: /S /JavaScript /JS (...) action dictionary -> fires
    # pdf-embedded-javascript/js-action (HIGH). Must NOT contain: security:
    # allow-pdf-embedded-javascript pragma.
    canary_plant = CanaryPlant(
        files={
            "invoice.pdf": (
                "%PDF-1.7\n"
                "1 0 obj\n<< /S /JavaScript /JS (app.alert('pwned');) >>\nendobj\n"
                "%%EOF\n"
            ),
        },
        expects=frozenset({"pdf-embedded-javascript/js-action"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: PDF-as-attack-vector is a property of the file, not the stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".pdf",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        # PDF is a binary format: read latin-1 (a total 1:1 byte<->codepoint mapping that
        # never raises on non-UTF-8 bytes) rather than the shared UTF-8 `read()` helper, so
        # the ASCII object-dictionary markers survive intact next to compressed stream bytes.
        try:
            if f.stat().st_size > _MAX_PDF_BYTES:
                return [
                    Finding(
                        check_id=self.id,
                        severity="info",
                        title="Oversize PDF skipped — not scanned for embedded actions",
                        location=rel(root, f),
                        message=(
                            f"This PDF exceeds the {_MAX_PDF_BYTES // (1024 * 1024)} MiB scan cap "
                            "and was not read (an uncapped read of an untrusted binary is a "
                            "memory-DoS vector against the scanner). Its embedded-JavaScript / "
                            "auto-run status is unverified."
                        ),
                        remediation=(
                            "Inspect the file manually (e.g. `pdfid`/`peepdf`) or shrink it if it "
                            "is not meant to be that large."
                        ),
                        rule="pdf-embedded-javascript/oversize-skipped",
                        standards=list(_STANDARDS),
                    )
                ]
            text = f.read_text(encoding="latin-1", errors="ignore")
        except OSError:
            return []
        if pragma_present(_PRAGMA, text, dialect=None):
            return []
        has_js = bool(_JS_ACTION.search(text))
        # (pattern, rule, description, severity). A lone /OpenAction is MEDIUM (routinely a
        # benign initial-view action); it is HIGH only when an embedded /JS also appears.
        rules: list[tuple[re.Pattern[str], str, str, Severity]] = [
            (_JS_ACTION, "pdf-embedded-javascript/js-action", _JS_DESC, "high"),
            (_LAUNCH_ACTION, "pdf-embedded-javascript/launch-action", _LAUNCH_DESC, "high"),
            (
                _OPEN_ACTION,
                "pdf-embedded-javascript/open-action",
                _OPEN_DESC_HIGH if has_js else _OPEN_DESC_LOW,
                "high" if has_js else "medium",
            ),
        ]
        out: list[Finding] = []
        for pattern, rule, desc, severity in rules:
            m = pattern.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                out.append(self._finding(root, f, line, rule, desc, severity))
        return out

    def _finding(self, root: Path, f: Path, line: int, rule: str, desc: str, severity: Severity) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                f"This PDF file contains {desc}. Most PDF readers execute embedded "
                "JavaScript / auto-run actions by default — a file accepted as an "
                "ordinary document upload can carry executable behavior."
            ),
            remediation=(
                "Strip JavaScript/auto-run actions from untrusted PDFs before storing or "
                "serving them (a sanitizer, or re-render via a flattening/rasterization "
                "step), or reject uploads containing them outright. Never open an "
                "untrusted PDF with a reader configured to auto-execute embedded actions."
            ),
            rule=rule,
            standards=list(_STANDARDS),
        )
