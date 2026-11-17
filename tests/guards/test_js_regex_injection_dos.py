from __future__ import annotations

from agentsec.guards.js_regex_injection_dos import JsRegexInjectionDosGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_regex_injection_dos_flags_direct_new_regexp(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/search', (req, res) => {\n"
        "  const re = new RegExp(req.query.pattern);\n"
        "  res.json({ match: re.test(req.query.text) });\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsRegexInjectionDosGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-regex-injection-dos/user-controlled-regex-sink"
    assert findings[0].severity == "high"


def test_js_regex_injection_dos_flags_indirect_via_variable(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/find', (req, res) => {\n"
        "  const term = req.body.term;\n"
        "  const idx = someString.search(term);\n"
        "  res.json({ idx });\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsRegexInjectionDosGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_js_regex_injection_dos_flags_direct_match(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/f/:x', (req, res) => {\n"
        "  const found = data.match(req.params.x);\n"
        "  res.json({ found });\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsRegexInjectionDosGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_js_regex_injection_dos_silent_with_literal_pattern(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/safe', (req, res) => {\n"
        "  const re = new RegExp('^[a-z]+[0-9]*$');\n"
        "  const parts = 'a,b,c'.split(',');\n"
        "  res.json({ ok: re.test(parts[0]) });\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsRegexInjectionDosGuard().run(tmp_path, profile) == []


def test_js_regex_injection_dos_silent_when_tainted_var_never_reaches_sink(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "app.get('/log', (req, res) => {\n"
        "  const term = req.query.q;\n"
        "  console.log('search term:', term);\n"
        "  res.json({ ok: true });\n"
        "});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsRegexInjectionDosGuard().run(tmp_path, profile) == []


def test_js_regex_injection_dos_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const re = new RegExp(req.query.pattern);  // security: allow-js-regex-injection-dos\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsRegexInjectionDosGuard().run(tmp_path, profile) == []


def test_js_regex_injection_dos_not_applies_without_feature(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const re = new RegExp(req.query.pattern);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features=set())
    assert not JsRegexInjectionDosGuard().applies(profile)


def test_js_regex_injection_dos_silent_on_req_substring_in_string(tmp_path: Path) -> None:
    # Regression (PR #407 review #2): the substring `req.` inside a hardcoded string literal is
    # NOT request input — a fully-hardcoded regex must stay silent.
    (tmp_path / "app.js").write_text(
        "const label = 'req.count: total';\n"
        "const re = new RegExp(label);\n",
        encoding="utf-8",
    )
    assert JsRegexInjectionDosGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_regex_injection_dos_silent_on_commented_taint(tmp_path: Path) -> None:
    # A `req.` in a comment is likewise not a real taint source.
    (tmp_path / "app.js").write_text(
        "// const p = req.query.x;\n"
        "const re = new RegExp('static');\n",
        encoding="utf-8",
    )
    assert JsRegexInjectionDosGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_regex_injection_dos_per_line_pragma_only_suppresses_its_line(tmp_path: Path) -> None:
    # #423: a per-line pragma suppresses only its own sink — a second, un-pragma'd sink still
    # fires (the file-level skip used to silence the whole file after any single pragma).
    (tmp_path / "app.js").write_text(
        "const a = new RegExp(req.query.p);  // security: allow-js-regex-injection-dos\n"
        "const b = new RegExp(req.query.q);\n",
        encoding="utf-8",
    )
    findings = JsRegexInjectionDosGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].location.endswith(":2")  # the un-pragma'd sink


def test_js_regex_injection_dos_route_regex_does_not_swallow_sink(tmp_path: Path) -> None:
    # Regression (PR #407 fixup review, CRITICAL): a route-matching regex literal must not blank the
    # rest of the line — a real `new RegExp(req.query.x)` on a later line still fires.
    (tmp_path / "app.js").write_text(
        "app.get(/^\\/api\\//, handler);\n"
        "const re = new RegExp(req.query.pattern);\n",
        encoding="utf-8",
    )
    findings = JsRegexInjectionDosGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_js_regex_injection_dos_flags_semicolon_free_assignment(tmp_path: Path) -> None:
    # Regression (#422): ASI-style JS/TS omits semicolons; the assignment must still mark the
    # variable as request-tainted, or every sink fed by it goes unreported.
    (tmp_path / "app.ts").write_text(
        "app.get('/find', (req, res) => {\n"
        "  const q = req.query.term\n"
        "  const re = new RegExp(q)\n"
        "  res.json({ ok: re.test('x') })\n"
        "})\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsRegexInjectionDosGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-regex-injection-dos/user-controlled-regex-sink"


def test_js_regex_injection_dos_semicolon_free_non_req_assignment_untainted(tmp_path: Path) -> None:
    # FP-bait for the widened assignment match: a semicolon-free assignment NOT from req must
    # not taint the variable.
    (tmp_path / "app.ts").write_text(
        "app.get('/find', (req, res) => {\n"
        "  const q = defaults.term\n"
        "  const idx = someString.search(q)\n"
        "  res.json({ idx })\n"
        "})\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsRegexInjectionDosGuard().run(tmp_path, profile) == []


def test_js_regex_injection_dos_semicolon_free_pragma_still_silences(tmp_path: Path) -> None:
    # FP-bait for the widening: the per-line opt-out must still work on the newly-detected
    # semicolon-free shape (a suppression that stops working is worse than the FP it removed).
    (tmp_path / "app.ts").write_text(
        "app.get('/find', (req, res) => {\n"
        "  const q = req.query.term\n"
        "  const re = new RegExp(q)  // security: allow-js-regex-injection-dos\n"
        "  res.json({ ok: re.test('x') })\n"
        "})\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsRegexInjectionDosGuard().run(tmp_path, profile) == []


# #543: a `{` in a regex inside a `${…}` used to shift the lexer's template frame. Alone it kept the
# template open, so a commented-out sink after it read as template text and fired; paired with a `}`
# in a later substitution it rebalanced, and a real sink between the two was blanked.
_HANDLER = (
    "app.get('/s', (req, res) => {\n  %sconst re = new RegExp(req.query.q);\n  res.json(re.test('x'));\n});\n"
)


def test_commented_sink_after_a_brace_in_a_substitution_regex_stays_silent(tmp_path: Path) -> None:
    opens = 'const s = `${ v.replace(/{/g, "") }`;\n'
    (tmp_path / "fp.js").write_text(opens + _HANDLER % "// ", encoding="utf-8")
    (tmp_path / "real.js").write_text(opens + _HANDLER % "", encoding="utf-8")   # rule 1: still fires
    profile = mkprofile(tmp_path, features={"express"})
    assert [f.location for f in JsRegexInjectionDosGuard().run(tmp_path, profile)] == ["real.js:3"]


def test_sink_between_two_brace_regex_substitutions_fires(tmp_path: Path) -> None:
    opens = "const t = `a ${ s.replace(/{/g, '') } b`;\n"
    closes = "const u = `a ${ s.replace(/}/g, '') } b`;\n"
    (tmp_path / "pair.js").write_text(opens + _HANDLER % "" + closes, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"express"})
    assert [f.location for f in JsRegexInjectionDosGuard().run(tmp_path, profile)] == ["pair.js:3"]
