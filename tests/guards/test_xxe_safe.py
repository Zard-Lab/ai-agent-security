from __future__ import annotations

from agentsec.guards.xxe_safe import XxeSafeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_xxe_flags_stdlib_xml(tmp_path: Path) -> None:
    (tmp_path / "p.py").write_text("import xml.etree.ElementTree as ET\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = XxeSafeGuard().run(tmp_path, prof)
    assert len(findings) == 1 and "xml.etree" in findings[0].message

def test_xxe_passes_defusedxml_and_pragma(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("import defusedxml.ElementTree as ET\nimport xml.etree.ElementTree as S\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import lxml.etree  # security: xml-trusted-junit\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert XxeSafeGuard().run(tmp_path, prof) == []

def test_xxe_generation_only_silent(tmp_path: Path) -> None:
    # File that imports xml.etree but only uses Element()/tostring() for XML generation,
    # never calls parse()/fromstring() — no untrusted input deserialized, not an XXE risk.
    (tmp_path / "build_xml.py").write_text(
        "from xml.etree import ElementTree\n"
        "root = ElementTree.Element('root')\n"
        "child = ElementTree.SubElement(root, 'item')\n"
        "child.text = 'value'\n"
        "output = ElementTree.tostring(root)\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert XxeSafeGuard().run(tmp_path, prof) == []

def test_xxe_generation_with_parse_still_flags(tmp_path: Path) -> None:
    # File that generates AND parses XML — the parse() call is the XXE risk.
    (tmp_path / "roundtrip.py").write_text(
        "import xml.etree.ElementTree as ET\n"
        "root = ET.Element('r')\n"
        "data = ET.parse('file.xml')\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(XxeSafeGuard().run(tmp_path, prof)) == 1



def test_xxe_safe_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # Neither allow form counts when it is a string on the import line, only as a comment (#1040).
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    for note in ("neutral", "# nosec B405", "# security: xml-trusted"):
        (tmp_path / "p.py").write_text(f'import xml.etree.ElementTree as ET; _n = "{note}"\n', encoding="utf-8")
        findings = XxeSafeGuard().run(tmp_path, prof)
        assert len(findings) == 1 and findings[0].location.endswith("p.py:1"), note


def test_xxe_safe_nosec_comment_suppresses_only_its_own_import_line(tmp_path: Path) -> None:
    # The `# nosec B4xx` comment form still suppresses its own import line, and no other (#1040 reach).
    (tmp_path / "p.py").write_text(
        "import xml.etree.ElementTree as ET  # nosec B405\nimport xml.dom.minidom\n", encoding="utf-8"
    )
    findings = XxeSafeGuard().run(tmp_path, mkprofile(tmp_path, features={"python"}, python_dirs=["."]))
    assert [f.location.rsplit(":", 1)[1] for f in findings] == ["2"]
