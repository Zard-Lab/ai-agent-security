"""Tests for the pdf-embedded-javascript guard.

Covers:
  - pdf-embedded-javascript/js-action (HIGH)
  - pdf-embedded-javascript/open-action (MEDIUM alone; HIGH when co-occurring with /JS)
  - pdf-embedded-javascript/launch-action (HIGH)
"""
from __future__ import annotations

from agentsec.guards.pdf_embedded_javascript import PdfEmbeddedJavascriptGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_js_action(tmp_path: Path) -> None:
    (tmp_path / "invoice.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /S /JavaScript /JS (app.alert('pwned');) >>\nendobj\n"
        b"%%EOF\n"
    )
    findings = PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "pdf-embedded-javascript/js-action" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_lone_open_action_is_medium(tmp_path: Path) -> None:
    # A bare /OpenAction with no embedded /JS -- routinely benign (standard LaTeX/hyperref/
    # pandoc initial-view action). Still surfaced, but at MEDIUM, not HIGH.
    (tmp_path / "resume.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction [3 0 R /Fit] >>\nendobj\n"
        b"%%EOF\n"
    )
    findings = PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    open_findings = [f for f in findings if f.rule == "pdf-embedded-javascript/open-action"]
    assert open_findings
    assert all(f.severity == "medium" for f in open_findings)


def test_open_action_with_js_is_high(tmp_path: Path) -> None:
    # /OpenAction pointing at an embedded /JS action -- the dangerous auto-run-script-on-open
    # pairing -- escalates the open-action rule to HIGH.
    (tmp_path / "auto.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /S /JavaScript /JS (app.alert('pwned');) >>\nendobj\n"
        b"%%EOF\n"
    )
    findings = PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    open_findings = [f for f in findings if f.rule == "pdf-embedded-javascript/open-action"]
    assert open_findings
    assert all(f.severity == "high" for f in open_findings)


def test_fires_on_launch_action(tmp_path: Path) -> None:
    (tmp_path / "form.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /S /Launch /F (calc.exe) >>\nendobj\n"
        b"%%EOF\n"
    )
    findings = PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "pdf-embedded-javascript/launch-action" for f in findings)


def test_passes_plain_pdf(tmp_path: Path) -> None:
    (tmp_path / "plain.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"%%EOF\n"
    )
    assert PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_passes_non_pdf_file(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("/JavaScript /OpenAction /Launch\n", encoding="utf-8")
    assert PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "trusted.pdf").write_bytes(
        b"%PDF-1.7\n"
        b"% security: allow-pdf-embedded-javascript\n"
        b"1 0 obj\n<< /S /JavaScript /JS (app.alert('ok');) >>\nendobj\n"
        b"%%EOF\n"
    )
    assert PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []

def test_oversize_pdf_is_skipped_with_disclosed_info(tmp_path: Path) -> None:
    # Regression (issue #419): the guard read arbitrary `.pdf` binaries whole with no size
    # cap — a memory DoS from an untrusted repo. Oversize files are now skipped with a
    # disclosed info finding (never silently dropped).
    import os

    big = tmp_path / "big.pdf"
    big.write_bytes(b"%PDF-1.7\n<< /S /JavaScript /JS (app.alert(1);) >>\n")
    os.truncate(big, 51 * 1024 * 1024)  # sparse: st_size above the cap without a real 51 MiB write
    findings = PdfEmbeddedJavascriptGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["pdf-embedded-javascript/oversize-skipped"]
    assert findings[0].severity == "info"
