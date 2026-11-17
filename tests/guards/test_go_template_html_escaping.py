from __future__ import annotations

from agentsec.guards.go_template_html_escaping import GoTemplateHtmlEscapingGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"go"}, go_dirs=["."])


def test_go_template_html_escaping_fires_on_text_template_with_response_writer(tmp_path: Path) -> None:
    (tmp_path / "handler.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "text/template"\n'
        ')\n'
        '\n'
        'func profileHandler(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := template.Must(template.New("profile").Parse(profileSrc))\n'
        '    tmpl.Execute(w, userData)\n'
        '}\n',
        encoding="utf-8",
    )
    findings = GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-template-html-escaping/text-template-http-response"
    assert findings[0].severity == "high"
    assert "CWE-79" in findings[0].standards


def test_go_template_html_escaping_fires_on_aliased_text_template_import(tmp_path: Path) -> None:
    (tmp_path / "handler.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    tt "text/template"\n'
        ')\n'
        '\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := tt.Must(tt.New("p").Parse(src))\n'
        '    tmpl.Execute(w, data)\n'
        '}\n',
        encoding="utf-8",
    )
    findings = GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-template-html-escaping/text-template-http-response"


def test_go_template_html_escaping_silent_on_html_template_correct_package(tmp_path: Path) -> None:
    # FP-bait: the CORRECT package (html/template) doing the exact same thing must stay silent.
    (tmp_path / "handler.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "html/template"\n'
        ')\n'
        '\n'
        'func profileHandler(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := template.Must(template.New("profile").Parse(profileSrc))\n'
        '    tmpl.Execute(w, userData)\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_silent_without_response_writer(tmp_path: Path) -> None:
    # FP-bait: text/template with NO http.ResponseWriter reference at all — a CLI tool or
    # config-file generator, the overwhelmingly common and totally safe use of text/template.
    (tmp_path / "gen.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "os"\n'
        '    "text/template"\n'
        ')\n'
        '\n'
        'func generateConfig() {\n'
        '    tmpl := template.Must(template.New("cfg").Parse(cfgSrc))\n'
        '    tmpl.Execute(os.Stdout, settings)\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_silent_when_both_packages_used_for_separate_purposes(
    tmp_path: Path,
) -> None:
    # FP-bait: BOTH text/template (for a non-HTML config generator) and html/template (for
    # actual page rendering) imported and each used for its own legitimate purpose, far apart
    # in the file and never crossing — must not false-fire on the text/template import alone,
    # and the chain-proximity heuristic (signal 2) must not coincidentally co-occur either.
    (tmp_path / "app.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "os"\n'
        '    texttemplate "text/template"\n'
        '    "html/template"\n'
        ')\n'
        '\n'
        '// writeConfigFile renders the on-disk config using text/template — plain text\n'
        '// output, never sent over HTTP, so no escaping is needed here.\n'
        'func writeConfigFile() {\n'
        '    cfgTmpl := texttemplate.Must(texttemplate.New("cfg").Parse(cfgSrc))\n'
        '    cfgTmpl.Execute(os.Stdout, settings)\n'
        '}\n'
        '\n'
        '// profileHandler renders the actual HTML page, correctly via html/template.\n'
        'func profileHandler(w http.ResponseWriter, r *http.Request) {\n'
        '    pageTmpl := template.Must(template.New("profile").Parse(profileSrc))\n'
        '    pageTmpl.Execute(w, userData)\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_fires_on_direct_chain_when_both_packages_imported(
    tmp_path: Path,
) -> None:
    # Signal 2: html/template IS also imported (so signal 1's exclusion applies), but the
    # SPECIFIC construction chain in view unambiguously resolves to text/template, is executed,
    # and writes to http.ResponseWriter right there — a real bug hiding behind the dual import.
    (tmp_path / "app.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    texttemplate "text/template"\n'
        '    "html/template"\n'
        ')\n'
        '\n'
        'func profileHandler(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := texttemplate.Must(texttemplate.New("profile").Parse(profileSrc))\n'
        '    tmpl.Execute(w, userData)\n'
        '}\n',
        encoding="utf-8",
    )
    findings = GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "go-template-html-escaping/text-template-execute-http-response"


def test_go_template_html_escaping_silent_on_pattern_only_in_comment(tmp_path: Path) -> None:
    # FP-bait: the pattern appearing only inside a `//` comment must not fire.
    (tmp_path / "handler.go").write_text(
        'package main\n'
        '\n'
        'import "net/http"\n'
        '\n'
        '// Old code used to do:\n'
        '//   import "text/template"\n'
        '//   tmpl := template.Must(template.New("p").Parse(src))\n'
        '//   tmpl.Execute(w, data)\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '    w.Write([]byte("ok"))\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "handler.go").write_text(
        '// security: allow-go-template-html-escaping\n'
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    "text/template"\n'
        ')\n'
        '\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := template.Must(template.New("p").Parse(src))\n'
        '    tmpl.Execute(w, data)\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_pragma_does_not_reach_a_different_handler(tmp_path: Path) -> None:
    # #565 review, Dean: a whole-file pragma check let one audited handler silence every other
    # handler in the same file. Two signal-2 chains (html/template also imported, so signal 1's
    # exclusion applies to both): handlerA is pragma'd inside its own function, handlerB is not.
    # handlerB must still fire.
    (tmp_path / "app.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    texttemplate "text/template"\n'
        '    "html/template"\n'
        ')\n'
        '\n'
        'func handlerA(w http.ResponseWriter, r *http.Request) {\n'
        '    // security: allow-go-template-html-escaping -- audited, fields are fixed constants\n'
        '    tmpl := texttemplate.Must(texttemplate.New("a").Parse(aSrc))\n'
        '    tmpl.Execute(w, aData)\n'
        '}\n'
        '\n'
        'func handlerB(w http.ResponseWriter, r *http.Request) {\n'
        '    tmpl := texttemplate.Must(texttemplate.New("b").Parse(bSrc))\n'
        '    tmpl.Execute(w, bData)\n'
        '}\n',
        encoding="utf-8",
    )
    findings = GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    # line 16 is handlerB's chain; handlerA's (line 11, pragma'd) must not appear
    assert findings[0].location.endswith(":16")
    assert findings[0].rule == "go-template-html-escaping/text-template-execute-http-response"


def test_go_template_html_escaping_pragma_still_suppresses_its_own_signal2_handler(
    tmp_path: Path,
) -> None:
    # The direction traded against the fix above: a pragma inside the SAME function it audits
    # must still work — narrowing the scope from file-wide to per-function must not also break
    # the case the scope is supposed to keep working.
    (tmp_path / "app.go").write_text(
        'package main\n'
        '\n'
        'import (\n'
        '    "net/http"\n'
        '    texttemplate "text/template"\n'
        '    "html/template"\n'
        ')\n'
        '\n'
        'func handlerA(w http.ResponseWriter, r *http.Request) {\n'
        '    // security: allow-go-template-html-escaping -- audited, fields are fixed constants\n'
        '    tmpl := texttemplate.Must(texttemplate.New("a").Parse(aSrc))\n'
        '    tmpl.Execute(w, aData)\n'
        '}\n',
        encoding="utf-8",
    )
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, _prof(tmp_path)) == []


def test_go_template_html_escaping_nonproduct_path_skipped(tmp_path: Path) -> None:
    # Independent review finding: run() never called is_nonproduct_path, so a project's own
    # test fixture demonstrating the insecure pattern would false-fire on every scan.
    tests_dir = tmp_path / "tests" / "fixtures"
    tests_dir.mkdir(parents=True)
    (tests_dir / "vulnerable_example.go").write_text(
        'package fixtures\n\nimport (\n\t"text/template"\n\t"net/http"\n)\n\n'
        'func h(w http.ResponseWriter, r *http.Request) {\n'
        '\tt := template.Must(template.New("x").Parse("{{.}}"))\n'
        "\tt.Execute(w, r.URL.Query())\n}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"go"}, go_dirs=["."])
    assert GoTemplateHtmlEscapingGuard().run(tmp_path, profile) == []


def test_go_template_html_escaping_not_applies_without_go(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert GoTemplateHtmlEscapingGuard().applies(profile) is False
