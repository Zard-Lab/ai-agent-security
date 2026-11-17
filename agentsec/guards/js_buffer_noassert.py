"""Guard: Node.js Buffer read/write call passes noAssert=true (§7, CWE-119).

Node's `Buffer` read/write methods (`readUInt8`, `writeInt32LE`, ...) take an
optional final `noAssert` boolean. Node's own docs mark it deprecated for
exactly this reason: when `true`, the offset is never validated against the
buffer's bounds before the read/write happens. An attacker-influenced offset
combined with `noAssert: true` can read or write memory beyond the buffer's
allocated end — an out-of-bounds access (CWE-119, OWASP-Web:A6) that can leak
adjacent heap memory or corrupt it, depending on which direction is off.

Sourced from njsscan's `buffer_noassert.yaml` rule pack (`ajinabraham/njsscan`,
real Semgrep-syntax rule `buffer_noassert` — 26 pattern variants across every
read/write width and endianness, all mapped to one rule id), verified against
the real fetched source. Adapted from Semgrep AST matching to same-file regex
(agentsec has no JS AST engine).

Fires MEDIUM per call found:

    buf.readUInt32LE(offset, true);   // security: allow-js-buffer-noassert
    buf.writeInt8(value, offset, true);

Gated broadly on JavaScript/TypeScript language presence rather than a
specific framework feature — `Buffer` is a Node.js-only global, not tied to
Express or any particular framework, so the language check alone already
keeps false-positive risk low (this API simply doesn't exist in browser JS).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, pragma_present, read, rel, strip_js_comments

_PRAGMA = "security: allow-js-buffer-noassert"
_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# All 26 njsscan Buffer read/write method variants, all mapped to one upstream rule id.
_METHODS = (
    "readUInt8", "readUInt16LE", "readUInt16BE", "readUInt32LE", "readUInt32BE",
    "readInt8", "readInt16LE", "readInt16BE", "readInt32LE", "readInt32BE",
    "readFloatLE", "readFloatBE", "readDoubleLE", "readDoubleBE",
    "writeUInt8", "writeUInt16LE", "writeUInt16BE", "writeUInt32LE", "writeUInt32BE",
    "writeInt8", "writeInt16LE", "writeInt16BE", "writeInt32LE", "writeInt32BE",
    "writeFloatLE", "writeFloatBE", "writeDoubleLE", "writeDoubleBE",
)
_NOASSERT_CALL = re.compile(
    r"\.(?:" + "|".join(_METHODS) + r")\s*\([^)]*,\s*true\s*\)"
)

class JsBufferNoassertGuard(Guard):
    id = "js-buffer-noassert"
    title = "Buffer read/write call passes noAssert=true"
    area = "Files"

    # buffer_parse.js: buf.readUInt32LE(offset, true) -> fires js-buffer-noassert.
    # Gated broadly on JS/TS language presence (already on via the many other .js plants).
    canary_plant = CanaryPlant(
        files={
            "buffer_parse.js": (
                "function parseHeader(buf, offset) {\n"
                "  return buf.readUInt32LE(offset, true);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "js-buffer-noassert/noassert-true",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            # Blank `//`, `/* */` and JSDoc comments (string-aware) so a documented/commented-out
            # example of the vulnerable call can't false-fire; the pragma still lives in a comment,
            # so it's matched on the comment-only view, where a string quoting it is blank (#407, #424).
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(strip_js_comments(raw).splitlines(), start=1):
                if _PRAGMA in view_lines[i - 1]:
                    continue
                m = _NOASSERT_CALL.search(line)
                if not m:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Buffer read/write call passes noAssert=true",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This Buffer call passes `true` for the deprecated `noAssert` "
                            "argument, skipping bounds validation on the offset. An "
                            "attacker-influenced offset can read or write past the end of the "
                            "buffer."
                        ),
                        remediation=(
                            "Remove the `noAssert` argument (or pass `false`) so Node validates "
                            "the offset against the buffer's bounds before the read/write. "
                            "Suppress a reviewed, intentional case with "
                            "`// security: allow-js-buffer-noassert`."
                        ),
                        rule="js-buffer-noassert/noassert-true",
                        standards=["OWASP:A06", "CWE-119"],
                    )
                )
        return out
