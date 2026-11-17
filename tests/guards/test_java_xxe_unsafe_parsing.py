from __future__ import annotations

from agentsec.guards.java_xxe_unsafe_parsing import JavaXxeUnsafeParsingGuard
from tests.guards._common import *  # noqa: F401,F403


def test_java_xxe_flags_documentbuilder_no_hardening(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "  DocumentBuilder b = dbf.newDocumentBuilder();\n"
        "  b.parse(new java.io.File(\"x.xml\"));\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-xxe-unsafe-parsing/doctype-decl-allowed"
    assert findings[0].severity == "high"


def test_java_xxe_flags_saxparser_no_hardening(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  SAXParserFactory spf = SAXParserFactory.newInstance();\n"
        "  SAXParser sp = spf.newSAXParser();\n"
        "  sp.parse(new java.io.File(\"x.xml\"), handler);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-xxe-unsafe-parsing/doctype-decl-allowed"


def test_java_xxe_flags_xmlreaderfactory_no_hardening(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  XMLReader reader = XMLReaderFactory.createXMLReader();\n"
        "  reader.parse(new InputSource(new StringReader(xml)));\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-xxe-unsafe-parsing/doctype-decl-allowed"


def test_java_xxe_flags_transformerfactory_no_hardening(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  TransformerFactory tf = TransformerFactory.newInstance();\n"
        "  Transformer t = tf.newTransformer();\n"
        "  t.transform(source, result);\n"
        "} }\n",
        encoding="utf-8",
    )
    findings = JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "java-xxe-unsafe-parsing/doctype-decl-allowed"


def test_java_xxe_silent_when_hardening_present_elsewhere_in_file(tmp_path: Path) -> None:
    # FP-bait / proximity-scope proof: the disallow-doctype-decl feature is set several lines
    # away, in a DIFFERENT method than the one that parses — proves the guard's documented
    # same-FILE (not same-method) scope actually silences the finding.
    (tmp_path / "T.java").write_text(
        "class T {\n"
        "  void m() throws Exception {\n"
        "    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "    DocumentBuilder b = dbf.newDocumentBuilder();\n"
        "    b.parse(new java.io.File(\"x.xml\"));\n"
        "  }\n"
        "  void hardenElsewhere() throws Exception {\n"
        "    DocumentBuilderFactory f2 = DocumentBuilderFactory.newInstance();\n"
        '    f2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_silent_with_external_general_entities_false(tmp_path: Path) -> None:
    # FP-bait: the equivalent external-entity-disabling feature also silences it.
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  SAXParserFactory spf = SAXParserFactory.newInstance();\n"
        '  spf.setFeature("http://xml.org/sax/features/external-general-entities", false);\n'
        "  SAXParser sp = spf.newSAXParser();\n"
        "  sp.parse(f, handler);\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_silent_with_feature_secure_processing(tmp_path: Path) -> None:
    # FP-bait: FEATURE_SECURE_PROCESSING also silences it.
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "  dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
        "  DocumentBuilder b = dbf.newDocumentBuilder();\n"
        "  b.parse(f);\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "  DocumentBuilder b = dbf.newDocumentBuilder(); // security: allow-java-xxe\n"
        "  b.parse(f);\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_silent_in_line_comment(tmp_path: Path) -> None:
    # FP-bait: an example mentioned in a `//` comment must not fire.
    (tmp_path / "T.java").write_text(
        "class T { void m() {\n"
        "  // DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f); is bad\n"
        "  int real = 1;\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_silent_in_javadoc_block_comment(tmp_path: Path) -> None:
    # FP-bait for the /** */ handling in strip_java_comments: an example inside a real
    # Javadoc block comment must not fire.
    (tmp_path / "T.java").write_text(
        "/**\n"
        " * Example: DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(f);\n"
        " * do not do this without hardening.\n"
        " */\n"
        "class T { void m() { int real = 1; } }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_silent_when_constructed_but_never_parsed(tmp_path: Path) -> None:
    # FP-bait: a constructed-but-unused builder never deserializes untrusted XML.
    (tmp_path / "T.java").write_text(
        "class T { void m() throws Exception {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "  DocumentBuilder b = dbf.newDocumentBuilder();\n"
        "} }\n",
        encoding="utf-8",
    )
    assert JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path)) == []


def test_java_xxe_not_applicable_without_java() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert JavaXxeUnsafeParsingGuard().applies(prof) is False


def test_java_xxe_unsafe_parsing_skips_maven_test_tree(tmp_path: Path) -> None:
    # Narrowing gate (PR #839 review): Maven/Gradle put test sources under `src/test/java`, whose
    # `test` segment `is_nonproduct_path` reads as non-product. Both trees carry the SAME violation
    # in one run, so this pins the skip AND the direction traded against it — production code under
    # `src/main/java` must still fire.
    src = (
        "class T { void m() throws Exception {\n"
        "  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
        "  DocumentBuilder b = dbf.newDocumentBuilder();\n"
        '  b.parse(new java.io.File("x.xml"));\n'
        "} }\n"
    )
    for tree in ("main", "test"):
        d = tmp_path / "src" / tree / "java"
        d.mkdir(parents=True)
        (d / "T.java").write_text(src, encoding="utf-8")
    findings = JavaXxeUnsafeParsingGuard().run(tmp_path, _javaprof(tmp_path))
    assert findings
    assert {f.location.split(":")[0].replace("\\", "/") for f in findings} == {"src/main/java/T.java"}
