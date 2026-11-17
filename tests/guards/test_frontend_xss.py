from __future__ import annotations

from agentsec.guards.frontend_xss import FrontendXssGuard
from tests.guards._common import *  # noqa: F401,F403


def test_frontend_dangerous_html(tmp_path: Path) -> None:
    (tmp_path / "C.tsx").write_text("const x = <div dangerouslySetInnerHTML={{__html: y}} />\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    findings = FrontendXssGuard().run(tmp_path, prof)
    assert any(f.rule == "frontend-xss/dangerously-set-inner-html" for f in findings)

def test_frontend_dangerous_html_pragma_ok(tmp_path: Path) -> None:
    (tmp_path / "C.tsx").write_text(
        "// security: allow-dangerous-html (sanitized upstream)\n"
        "const x = <div dangerouslySetInnerHTML={{__html: clean}} />\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert FrontendXssGuard().run(tmp_path, prof) == []

def test_frontend_rehype_order(tmp_path: Path) -> None:
    (tmp_path / "M.tsx").write_text(
        "const p = <Markdown rehypePlugins={[rehypeSanitize, rehypeRaw]} />\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    findings = FrontendXssGuard().run(tmp_path, prof)
    assert any(f.rule == "frontend-xss/rehype-order" for f in findings)

def test_frontend_sri(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text('<script src="https://cdn.evil.com/x.js"></script>\n', encoding="utf-8")
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    findings = FrontendXssGuard(first_party=("example.com",)).run(tmp_path, prof)
    assert any(f.rule == "frontend-xss/script-no-sri" for f in findings)


def test_frontend_dangerous_html_pragma_quoted_in_a_string_above_does_not_opt_out(tmp_path: Path) -> None:
    # #424 E4: the line-or-line-above check reads `pragma_line_set` (comments only), so a string on
    # the line above that quotes the documented `// security: …` form is content, not a pragma.
    (tmp_path / "C.tsx").write_text(
        'const help = "opt out with // security: allow-dangerous-html";\n'
        "const x = <div dangerouslySetInnerHTML={{__html: raw}} />\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"frontend"}, frontend_dir=".")
    assert len(FrontendXssGuard().run(tmp_path, prof)) == 1
