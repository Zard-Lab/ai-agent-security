"""Guard: XML must be parsed with defusedxml, not stdlib xml/lxml (XXE).

Ported from donor `scripts/security/check_xxe_safe.py`. A python file is a
violation iff it imports an XXE-capable parser AND does not also import
`defusedxml` AND the import line carries no allow pragma (`# nosec B4xx` or
`# security: xml-...`).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

_UNSAFE_XML_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+"
    r"(?P<mod>xml\.(?:etree|dom|sax|parsers\.expat)|xml\.dom\.minidom|lxml(?:\.\w+)?)\b"
)
_ALLOW = re.compile(r"#\s*(?:nosec\s+B4\d\d|security:\s*xml-)", re.I)

# Parsing calls that can deserialize untrusted XML — these are the actual XXE risk.
_PARSE_CALL = re.compile(r"\b(?:parse|fromstring|iterparse|parseString|fromstringlist)\s*\(")
# Generation-only calls that BUILD xml output — no untrusted input deserialized.
_GENERATE_CALL = re.compile(
    r"\b(?:Element|SubElement|tostring|tostringlist|indent|dump|register_namespace|Comment|ProcessingInstruction)\s*\("
)


class XxeSafeGuard(Guard):
    id = "xxe-safe"
    title = "XML parsed without defusedxml (XXE risk)"
    area = "Code safety"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # Canary plant: EXPECTS-ONLY — no `files`. This guard's violation (the stdlib
    # `import xml.etree.ElementTree as ET`) is planted in the canary's `app.py`, a shared
    # scaffolding file that also carries the plants for api-docs-exposed, background-tasks,
    # cors-wildcard, security-headers and trusted-host-absent.
    #
    # THE OWNERSHIP RULE, because this is the exemplar to copy for every entangled case:
    # a plant file shared by several guards stays in `canary.py`'s base and is owned by NO
    # guard; each guard on it declares `expects` only. Do not try to tear a shared file apart
    # so each guard can own a piece — the plants are interdependent (one file must parse and
    # trip several `applies()` gates at once), and `_assemble()` rejects two sources declaring
    # the same path with different content precisely to stop that.
    canary_plant = CanaryPlant(expects=frozenset({"xxe-safe/unsafe-xml-import"}))

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
                if "defusedxml" in text:
                    continue  # file routes real parsing through defusedxml
                # Generation-only use: file builds XML output (Element/tostring) but never
                # calls a parsing function — no untrusted input is deserialized, not an XXE risk.
                if _GENERATE_CALL.search(text) and not _PARSE_CALL.search(text):
                    continue
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040).
                allowed = pragma_line_set(_ALLOW, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    m = _UNSAFE_XML_IMPORT.match(line)
                    if not m or i in allowed:
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rel(root, f)}:{i}",
                            message=f"Imports `{m.group('mod')}` (XXE/billion-laughs capable) without defusedxml.",
                            remediation=(
                                "Parse via `defusedxml` (e.g. `import defusedxml.ElementTree as ET`); "
                                "or if type-hints-only/trusted, annotate `# security: xml-<reason>`."
                            ),
                            rule="xxe-safe/unsafe-xml-import",
                            standards=["OWASP:A05", "OWASP-LLM:LLM03"],
                        )
                    )
        return out
