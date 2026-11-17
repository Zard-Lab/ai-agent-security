"""Guard: Java XML parser constructed without a hardened (disallow-DOCTYPE / external-entity-off)
feature set anywhere in the file (XXE), extending checklist item `3a-xxe-safe-parsing`.

Third sibling for the same checklist item alongside `xxe_safe.py` (Python: import-presence) and
`js_xxe_unsafe_parsing.py` (JS/TS: a single dominant unsafe option on `libxmljs.parseXml`). The
Java vulnerability shape is neither of those: Java's stdlib XML APIs (`javax.xml.parsers`,
`org.xml.sax`, `javax.xml.transform`) are **unsafe by default** — DOCTYPE processing and external
entity resolution are both ON unless the caller explicitly hardens the factory/builder before
parsing. So there is no single unsafe call/option to match; the guard instead looks for the
ABSENCE of a hardening call anywhere appropriate, which is what Find Security Bugs' own
`XxeDetector.java` does (rules `XXE_SAXPARSER`/`XXE_XMLREADER`/`XXE_DOCUMENT`/`XXE_XPATH`) via
dataflow this codebase has no equivalent for (no Java AST/dataflow engine here — see "Known
bypasses").

Fires HIGH when a file constructs one of:

    SAXParserFactory.newInstance() -> .newSAXParser()
    DocumentBuilderFactory.newInstance() -> .newDocumentBuilder()
    XMLReaderFactory.createXMLReader()
    TransformerFactory.newInstance()

and calls `.parse(...)` (the actual XML-consuming step) SOMEWHERE in the file, but the file
contains NONE of the recognized hardening calls anywhere:

    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");

**Detection scope — same-file presence/absence, not same-method/proximity.** A real Java dataflow
analysis (Find Security Bugs' own approach) would tie the hardening call to the SPECIFIC factory
instance it was invoked on, scoped to the enclosing method. This codebase has no Java AST, so
`base.py`'s AST-based `iter_functions`/`enclosing_function_span` (Python-only) cannot be ported
directly; reproducing method-body scoping in Java would mean hand-rolling a brace-matching Java
method boundary walker, which is a meaningfully bigger and more fragile undertaking than the
existing sibling guards' single-call/import scans. The pragmatic, HONESTLY SCOPED choice made here:
a file with a parser-construction-and-parse pattern is flagged UNLESS a hardening call appears
ANYWHERE EARLIER in the same file — coarser than function-precise, but still narrower than "the
hardening call exists in the codebase at all" (which would require cross-file reasoning this guard
also does not attempt). See the design doc for the full FP/FN tradeoff this implies.

Suppress an audited case (parser genuinely only consumes trusted, application-generated XML) with:

    builder = factory.newDocumentBuilder();  // security: allow-java-xxe
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
    java_scan_dirs,
    read,
    rel,
    strip_java_comments,
)

# Parser/builder/reader/transformer CONSTRUCTION call-sites — the moment an XXE-capable object is
# built. Matched on the factory-method name only, deliberately NOT requiring `newInstance()` and
# the follow-on call (`.newSAXParser()`/`.newDocumentBuilder()`) to be chained on one statement —
# real-world code routinely splits factory-construction and builder/parser-retrieval across two
# statements via an intermediate variable (`Factory f = X.newInstance(); Y y = f.newFoo();`), and a
# chained-call-only regex misses that entirely (see the self-test that caught this). Same
# textual-scope philosophy as every sibling XXE/weak-crypto Java guard in this codebase: match the
# distinctive method name, not a proven receiver/dataflow link.
_PARSER_CONSTRUCTED = re.compile(
    r"\b(?:"
    r"\.\s*newSAXParser\s*\(\s*\)"
    r"|\.\s*newDocumentBuilder\s*\(\s*\)"
    r"|XMLReaderFactory\s*\.\s*createXMLReader\s*\(\s*\)"
    r"|TransformerFactory\s*\.\s*newInstance\s*\(\s*\)"
    r")"
)
# The actual XML-consuming step — without a `.parse(...)` (or `.transform(...)` for the
# Transformer shape) call somewhere in the file, no untrusted XML is ever deserialized, so a
# constructed-but-unused parser is not itself a finding.
_PARSE_CALL = re.compile(r"\.\s*(?:parse|transform)\s*\(")
# Recognized hardening calls — any ONE of these anywhere earlier in the file is treated as
# sufficient (this guard does not try to prove it was called on the SAME factory instance; see
# the module docstring's "Detection scope" section).
_HARDENING_CALL = re.compile(
    r'setFeature\s*\(\s*"http://apache\.org/xml/features/disallow-doctype-decl"\s*,\s*true\s*\)'
    r'|setFeature\s*\(\s*"http://xml\.org/sax/features/external-general-entities"\s*,\s*false\s*\)'
    r'|setFeature\s*\(\s*"http://xml\.org/sax/features/external-parameter-entities"\s*,\s*false\s*\)'
    r"|setFeature\s*\(\s*XMLConstants\s*\.\s*FEATURE_SECURE_PROCESSING\s*,\s*true\s*\)"
    r"|setAttribute\s*\(\s*XMLConstants\s*\.\s*ACCESS_EXTERNAL_DTD\s*,\s*\"\"\s*\)"
    r"|setAttribute\s*\(\s*XMLConstants\s*\.\s*ACCESS_EXTERNAL_STYLESHEET\s*,\s*\"\"\s*\)"
    r"|setExpandEntityReferences\s*\(\s*false\s*\)"
)
_PRAGMA = "security: allow-java-xxe"


class JavaXxeUnsafeParsingGuard(Guard):
    id = "java-xxe-unsafe-parsing"
    title = "Java XML parser used without a hardened (XXE-safe) feature set"
    area = "Code safety"

    # UnsafeXxe.java: DocumentBuilderFactory -> newDocumentBuilder() -> .parse(...), no
    # disallow-doctype-decl (or equivalent) feature anywhere in the file ->
    # java-xxe-unsafe-parsing/doctype-decl-allowed.
    canary_plant = CanaryPlant(
        files={
            "UnsafeXxe.java": (
                "import javax.xml.parsers.DocumentBuilder;\n"
                "import javax.xml.parsers.DocumentBuilderFactory;\n"
                "import org.w3c.dom.Document;\n"
                "import java.io.File;\n\n"
                "class UnsafeXxe {\n"
                "    Document load(File f) throws Exception {\n"
                "        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
                "        DocumentBuilder builder = dbf.newDocumentBuilder();\n"
                "        return builder.parse(f);\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({"java-xxe-unsafe-parsing/doctype-decl-allowed"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "java" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in java_scan_dirs(root, profile):
            for f in iter_files(d, (".java",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        view_lines = comment_view(text, "java").splitlines()  # same length: comments only (#424)
        # `strip_java_comments` preserves length and splitlines() count exactly (tested, see
        # java_weak_crypto.py's identical reasoning), so the two line lists always pair up.
        code_lines = strip_java_comments(text).splitlines()
        code = "\n".join(code_lines)

        if not _PARSE_CALL.search(code):
            return []  # never actually consumes XML; a constructed-but-unused parser is not a hit
        if _HARDENING_CALL.search(code):
            return []  # a recognized hardening call exists SOMEWHERE in the file (see docstring)

        out: list[Finding] = []
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            if _PARSER_CONSTRUCTED.search(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "A Java XML parser/builder/reader/transformer is constructed and used to parse XML "
                "(a `.parse(...)`/`.transform(...)` call exists in this file), but no hardening "
                "feature (`disallow-doctype-decl`, external-entity-disabling, "
                "`FEATURE_SECURE_PROCESSING`, or `ACCESS_EXTERNAL_DTD`) is set anywhere in the file. "
                "Java's XML parsers process DOCTYPE declarations and resolve external entities by "
                "default, so an attacker-controlled XML document can read local files, reach "
                "internal network endpoints (SSRF), or exhaust memory via entity expansion "
                "(billion laughs)."
            ),
            remediation=(
                'Harden the factory before parsing, e.g. '
                '`factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);` '
                "(SAX/DOM) or set `XMLConstants.ACCESS_EXTERNAL_DTD`/`ACCESS_EXTERNAL_STYLESHEET` to "
                '`""` (Transformer/XPath). If this parser genuinely only consumes trusted, '
                "application-generated XML, suppress with `// security: allow-java-xxe`."
            ),
            rule="java-xxe-unsafe-parsing/doctype-decl-allowed",
            standards=["OWASP:A05", "OWASP-LLM:LLM03"],
        )
