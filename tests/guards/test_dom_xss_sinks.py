from __future__ import annotations

from typing import Any

import pytest

from agentsec.findings import Finding
from agentsec.guards.dom_xss_sinks import DomXssSinksGuard, _is_function_literal
from tests.guards._common import *  # noqa: F401,F403


def test_dom_xss_sinks_flags_inner_html(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("el.innerHTML = userInput;\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/unsafe-dom-write"
    assert findings[0].severity == "high"

def test_dom_xss_sinks_flags_insert_adjacent(tmp_path: Path) -> None:
    (tmp_path / "widget.ts").write_text(
        'div.insertAdjacentHTML("beforeend", rawHtml);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/unsafe-dom-write"

def test_dom_xss_sinks_flags_document_write(tmp_path: Path) -> None:
    (tmp_path / "legacy.jsx").write_text("document.write(template);\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/unsafe-dom-write"

def test_dom_xss_sinks_silent_static_string(tmp_path: Path) -> None:
    (tmp_path / "safe.js").write_text(
        'el.innerHTML = "<p>static</p>";\n'
        "el.textContent = userInput;\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []

def test_dom_xss_sinks_pragma_silences(tmp_path: Path) -> None:
    content = "el.innerHTML = userInput;\n// security: allow-dom-xss-sink\n"
    (tmp_path / "allowed.ts").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []

def test_dom_xss_sinks_not_applies_without_frontend() -> None:
    profile = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert DomXssSinksGuard().applies(profile) is False

def test_dom_xss_sinks_playwright_dir_silent(tmp_path: Path) -> None:
    # FP fix: browser automation scripts may use innerHTML as a control primitive — skip.
    pw = tmp_path / "playwright"
    pw.mkdir()
    (pw / "test_fill.js").write_text(
        "await page.evaluate(el => el.innerHTML = '<p>injected</p>', el);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []

def test_dom_xss_sinks_browser_harness_dir_silent(tmp_path: Path) -> None:
    bh = tmp_path / "browser-harness"
    bh.mkdir()
    (bh / "helpers.js").write_text("el.innerHTML = dynamicContent;\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []

def test_dom_xss_sinks_app_dir_still_fires(tmp_path: Path) -> None:
    app = tmp_path / "src"
    app.mkdir()
    (app / "render.js").write_text("el.innerHTML = userContent;\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert any(f.rule == "dom-xss-sinks/unsafe-dom-write" for f in findings)


def test_dom_xss_eval_fires(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text("eval(userCode);\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dom-xss-sinks/eval-sink"
    assert findings[0].severity == "critical"


def test_dom_xss_eval_member_access_fires(tmp_path: Path) -> None:
    # `\beval\s*\(` matches a whole-word `eval` member (this is how `window.eval` / `globalThis.eval`
    # are covered) — intentional. It is NARROW: a substring like `retrieval(` must NOT match.
    (tmp_path / "runner.js").write_text(
        "window.eval(userCode);\n"
        "const r = retrieval(payload);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    hits = [f for f in DomXssSinksGuard().run(tmp_path, profile)
            if f.rule == "dom-xss-sinks/eval-sink"]
    assert len(hits) == 1 and hits[0].severity == "critical"
    assert hits[0].location.endswith(":1")  # window.eval line, not the retrieval() line


def test_dom_xss_new_function_fires(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text("const fn = new Function(codeStr);\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "dom-xss-sinks/new-function-sink"
    assert findings[0].severity == "critical"


def test_dom_xss_eval_literal_safe(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text('eval("42");\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_dom_xss_new_function_literal_safe(tmp_path: Path) -> None:
    # A purely-literal new Function body must NOT fire — esp. the standard globalThis idiom.
    (tmp_path / "poly.js").write_text(
        'const g = (new Function("return this"))();\n'
        'const f = new Function("return 42");\n'
        "const e = new Function();\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    rules = {f.rule for f in DomXssSinksGuard().run(tmp_path, profile)}
    assert "dom-xss-sinks/new-function-sink" not in rules


def test_dom_xss_new_function_dynamic_fires_critical(tmp_path: Path) -> None:
    (tmp_path / "run.js").write_text("const fn = new Function(userCode);\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    hits = [f for f in DomXssSinksGuard().run(tmp_path, profile)
            if f.rule == "dom-xss-sinks/new-function-sink"]
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_dom_xss_eval_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        "// security: allow-dom-xss-sink\neval(userCode);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []

def test_dom_xss_sinks_flags_non_global_regex_tag_strip(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        "const clean = userInput.replace(/<script>/i, \"\");\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/incomplete-sanitization"
    assert findings[0].severity == "high"

def test_dom_xss_sinks_flags_string_literal_tag_strip(tmp_path: Path) -> None:
    (tmp_path / "sanitize.ts").write_text(
        'const clean = userInput.replace("<script>", "");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/incomplete-sanitization"

def test_dom_xss_sinks_silent_global_regex_tag_strip(tmp_path: Path) -> None:
    # The `g` flag removes every occurrence, not just the first — not the bug this catches.
    (tmp_path / "sanitize.js").write_text(
        "const clean = userInput.replace(/<script>/gi, \"\");\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []

def test_dom_xss_sinks_silent_replace_all(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        'const clean = userInput.replaceAll("<script>", "");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []

def test_dom_xss_sinks_silent_non_tag_replace(tmp_path: Path) -> None:
    (tmp_path / "format.js").write_text(
        'const clean = userInput.replace(",", "");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []

def test_dom_xss_sinks_silent_replace_non_empty_replacement(tmp_path: Path) -> None:
    (tmp_path / "sanitize.js").write_text(
        'const escaped = userInput.replace("<script>", "&lt;script&gt;");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []


def test_dom_xss_settimeout_string_concat_fires(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        'setTimeout("alert(" + x + ")", 100);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_dom_xss_settimeout_function_literal_safe(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        "setTimeout(() => alert(x), 100);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert all(f.rule != "dom-xss-sinks/settimeout-string-arg" for f in findings)


def test_dom_xss_setinterval_bare_identifier_safe(tmp_path: Path) -> None:
    # #395 C2: a bare identifier is indistinguishable from a named-callback function reference
    # (`setInterval(refreshTimer, 1000)`), so it must NOT fire — a positive string signal only.
    (tmp_path / "runner.js").write_text(
        "setInterval(userCode, 1000);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert all(f.rule != "dom-xss-sinks/settimeout-string-arg" for f in findings)


def test_dom_xss_settimeout_named_callback_safe(tmp_path: Path) -> None:
    # The headline #395 C2 false positive: a debounce/throttle-style named callback.
    (tmp_path / "runner.js").write_text(
        "setTimeout(handleClick, 300);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert all(f.rule != "dom-xss-sinks/settimeout-string-arg" for f in findings)


def test_dom_xss_settimeout_block_body_arrow_safe(tmp_path: Path) -> None:
    # FP-bait (round-2 §D.2/§G.1): a block-body arrow as the first argument is the SAFE form and
    # must never fire. This exact shape produced 3 criticals on a shipped frontend (Test-FE) and
    # 1 on remote-coding-agent. The positive string-signal (#395 C2) already excludes it; this
    # locks it in as a permanent negative fixture so it cannot regress.
    (tmp_path / "WorkflowLogs.tsx").write_text(
        "setTimeout(() => { doThing(); cleanup(); }, 6000);\n"
        "setInterval(() => { refresh(); }, 1000);\n"
        "setTimeout(() => {\n  multiLine();\n}, 500);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []


def test_dom_xss_settimeout_callback_containing_a_concatenation_is_safe(tmp_path: Path) -> None:
    # #479 review: the previous fixture used callback bodies with no string and no `+`, so it
    # passed while the FP class stayed live. A callback that BUILDS A STRING inside its body —
    # ordinary React — tripped the "`+` and a quote means a code string" heuristic and produced a
    # CRITICAL. The body is never re-parsed by the engine, so nothing in it is an eval sink.
    (tmp_path / "Toast.tsx").write_text(
        'setTimeout(() => { setMsg("Saved " + name); }, 3000);\n'
        'setInterval(function() { el.title = "count: " + n; }, 1000);\n'
        'setTimeout(async () => { await save("draft-" + id); }, 500);\n'
        'setTimeout(() => setMsg("Saved " + name), 3000);\n'
        'setTimeout(e => log("got " + e), 100);\n'
        'setTimeout(function named(a) { q("x" + a); }, 100);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_dom_xss_settimeout_string_concat_still_fires_after_the_callback_exclusion(
    tmp_path: Path,
) -> None:
    # The other direction: excluding function/arrow literals must not swallow the real sink. A
    # parenthesized string expression is NOT a zero-arg arrow and must still fire.
    (tmp_path / "danger.js").write_text(
        'setTimeout("run(" + x + ")", 100);\n'
        'setTimeout(("alert(" + y + ")"), 100);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) == 2
    assert all(f.severity == "critical" for f in findings)


def test_dom_xss_setimmediate_string_fires(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        'setImmediate("runTask()");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1


def test_dom_xss_settimeout_template_literal_fires(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        "setTimeout(`run(${x})`, 100);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1
    assert hits[0].severity == "critical"


def test_dom_xss_settimeout_multiline_concat_fires(tmp_path: Path) -> None:
    # The paren-depth walk sees the whole call even when it spans lines (#395 C2).
    (tmp_path / "runner.js").write_text(
        'setTimeout(\n  "alert(" + userInput + ")",\n  100\n);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1


def test_dom_xss_settimeout_url_not_hidden_by_comment_heuristic(tmp_path: Path) -> None:
    # #395 M: a URL literal earlier on the line must NOT be mistaken for a `//` comment that
    # hides a genuine string-first-arg sink (the old naive `line.find("//")` FN).
    (tmp_path / "runner.js").write_text(
        'const u = "http://x"; setTimeout("steal(" + u + ")", 1);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1


def test_dom_xss_settimeout_unbalanced_paren_in_string_fires(tmp_path: Path) -> None:
    # #395 RL-3: an unbalanced `(` inside the setTimeout string arg (as the file's last statement)
    # must not unbalance the paren walk and drop the finding.
    (tmp_path / "runner.js").write_text(
        'setTimeout("run(" + userInput, 100)\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    hits = [f for f in findings if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1


def test_dom_xss_sinks_silent_placeholder_token_replace(tmp_path: Path) -> None:
    # #395 M: `<placeholder>` is a template marker, not a real HTML tag — stripping it once is
    # benign and must NOT fire the broken-sanitizer rule.
    (tmp_path / "format.js").write_text(
        'const clean = tpl.replace("<placeholder>", "");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert findings == []


def test_dom_xss_settimeout_function_expression_safe(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        "setTimeout(function() { doStuff(); }, 100);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert all(f.rule != "dom-xss-sinks/settimeout-string-arg" for f in findings)


def test_dom_xss_settimeout_comment_silent(tmp_path: Path) -> None:
    (tmp_path / "notes.js").write_text(
        "// avoid patterns like setTimeout(str) in this codebase\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert all(f.rule != "dom-xss-sinks/settimeout-string-arg" for f in findings)


def test_dom_xss_settimeout_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "runner.js").write_text(
        "// security: allow-dom-xss-sink\nsetTimeout(userCode, 100);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_dom_xss_typescript_typed_and_generic_arrows_are_safe(tmp_path: Path) -> None:
    # #479 second-pass review: `_is_function_literal` only accepted `=>` IMMEDIATELY after the
    # matching close paren, so the two mainstream TypeScript shapes — an explicit return-type
    # annotation and a `.tsx` leading type-parameter list — fell through to the concatenation
    # heuristic and reopened the exact FP class this PR fixes.
    (tmp_path / "Typed.tsx").write_text(
        'setTimeout((x: string): void => { const s = "Saved " + x; setMsg(s); }, 3000);\n'
        'setTimeout(<T,>(x: T) => { const s = "Loaded " + String(x); log(s); }, 100);\n'
        'setTimeout((x: string): Promise<void> => { log("a" + x); }, 100);\n'
        'setInterval(async (x: number): void => { q("n" + x); }, 100);\n'
        'setTimeout(<T extends object>(x: T): void => { q("a" + x); }, 100);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


@pytest.mark.parametrize(
    ("arg", "expected"),
    [
        # Identifiers that merely START with "async" are not function literals. These returned False
        # under the bare strip too (the eaten remainder happened not to parse as one), so the
        # end-to-end verdict never changed — which is why this is pinned at the function level
        # instead of with a fixture that would pass either way.
        ("async", False),
        ("asyncHandler", False),
        ("async(x)", False),          # `async` used as a CALLEE, not a modifier
        # The one shape the bare `.startswith("async")` actually mis-classified: strip the prefix and
        # the remainder reads as `function () {}` (#479 review, B21).
        ("asyncfunction () {}", False),
        # ...and the modifier forms it must still accept.
        ("async () => {}", True),
        ("async function () {}", True),
        ("async()=>{}", True),
    ],
)
def test_dom_xss_async_modifier_strip_is_boundaried(arg: str, expected: bool) -> None:
    assert _is_function_literal(arg) is expected


def test_dom_xss_async_function_forms_are_still_safe(tmp_path: Path) -> None:
    # The other direction (F4): boundarying the strip must not lose the async forms it exists to
    # accept. The boundary is whitespace OR `(`, not whitespace alone — the compact `async()=>{}`
    # spelling carries no space, and requiring one would reopen the D.2 concatenation FP class on it.
    (tmp_path / "Async.tsx").write_text(
        'setTimeout(async () => { setMsg("Saved " + name); }, 3000);\n'
        'setTimeout(async function () { el.title = "n: " + n; }, 100);\n'
        'setTimeout(async()=>{ log("a" + x); }, 100);\n'
        'setTimeout(async function named(a) { q("x" + a); }, 100);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_dom_xss_string_sink_still_fires_after_the_typed_arrow_exclusion(tmp_path: Path) -> None:
    # The other direction: widening the arrow exclusion must not swallow a real code-string sink.
    (tmp_path / "danger.ts").write_text(
        'setTimeout("run(" + x + ")", 100);\nsetTimeout(("alert(" + y + ")"), 100);\n',
        encoding="utf-8",
    )
    findings = DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 2
    assert all(f.severity == "critical" for f in findings)


# --- #479 agentic gate (B31/B32): classify the VALUE, not a call-shaped prefix ------------------

@pytest.mark.parametrize(
    "arg",
    [
        'function(){ return "run(" + x + ")"; }()',
        'x => { return "run(" + x + ")"; }()',
        '(x) => { return "run(" + x + ")"; }()',
        '(x: string): string => { return "r(" + x + ")"; }()',
        '<T,>(x: T) => { return "run(" + String(x) + ")"; }()',
        # ...and the head shapes the structural body-location added (#479 fresh-eyes gate): each
        # carries a brace in its PARAMETER list or RETURN TYPE, so locating the body structurally
        # must not lose the "is it invoked?" verdict that the old first-brace search got right here
        # by accident.
        'function ({id}){ return "run(" + id + ")"; }()',
        'function (o = {a: 1}){ return "run(" + o + ")"; }()',
        'function named(){ return "run(" + x + ")"; }()',
        'function* gen(){ return "run(" + x + ")"; }()',
        'function (): string { return "run(" + x + ")"; }()',
        'function(){ return "run(" + x + ")"; }.call(null)',
        'function(){ return "run(" + x + ")"; }.bind(null)()',
        'function ({id}){ return "r(" + id + ")"; }.call(null)',
        '() => { q(1); }() + "run(" + x + ")"',
        # Found by fuzzing the structural fix itself: an invoked body followed by a brace group
        # that DOES run to the end of the argument. A body search that merely looks for "some
        # `{...}` block ending the text" accepts these and reopens the IIFE bypass.
        'function(){ return "r(" + x + ")"; }() || {}',
        'function ({id}){ return "r(" + id + ")"; }() || {}',
        'function (): string { return "r(" + x + ")"; }() || {}',
    ],
)
def test_immediately_invoked_function_is_not_a_function_literal(arg: str) -> None:
    # B31. `_is_function_literal` returned True the moment it recognized a function/arrow HEAD and
    # never checked what FOLLOWED it, so an IIFE read as a safe callback — but the value passed to
    # setTimeout is the invocation's RETURN VALUE, a built string, i.e. a live code-execution sink.
    # Confirmed a regression introduced by this PR: it fired correctly before the exclusion existed.
    assert _is_function_literal(arg) is False


def test_iife_sink_fires_end_to_end(tmp_path: Path) -> None:
    (tmp_path / "Danger.tsx").write_text(
        'setTimeout(function(){ return "run(" + x + ")"; }(), 100);\n'
        'setTimeout(x => { return "run(" + x + ")"; }(), 100);\n',
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 2 and all(h.severity == "critical" for h in hits)


def test_generic_type_param_head_does_not_desync_the_arg_splitter(tmp_path: Path) -> None:
    # B32. `_split_top_level_args` tracked depth only via `(`/`)`, so the comma inside the idiomatic
    # TSX `<T,>` head was read as the argument separator: `args[0]` became the fragment `"<T"` and the
    # real argument was never inspected. The `<T,>` support in `_is_function_literal` was therefore
    # DEAD CODE in the real pipeline, and any payload behind that head was hidden — no IIFE needed.
    from agentsec.guards.dom_xss_sinks import _split_top_level_args

    src = 'setTimeout(<T,>(x: T) => { q(1); }(), 100);'
    assert _split_top_level_args(src, src.index("(")) == ['<T,>(x: T) => { q(1); }()', ' 100']

    (tmp_path / "Danger.tsx").write_text(
        'setTimeout(<T,>("run(" + userInput + ")"), 100);\n', encoding="utf-8"
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_generic_arrow_callback_is_still_safe(tmp_path: Path) -> None:
    # The other direction: now that the `<T,>` head is actually parsed, the genuine generic-arrow
    # callback must still be excluded rather than newly firing.
    (tmp_path / "Safe.tsx").write_text(
        'setTimeout(<T,>(x: T) => { const s = "Loaded " + String(x); log(s); }, 100);\n'
        'setTimeout(<T extends object>(x: T): void => { q("a" + x); }, 100);\n',
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_sinks_silent_on_commented_sinks(tmp_path: Path) -> None:
    # FP-bait (#424): commented-out / JSDoc sink examples must not fire (strip_js_comments).
    (tmp_path / "app.js").write_text(
        "// el.innerHTML = userInput;\n"
        "/* document.write(x); eval(y); */\n"
        "const x = 1;\n",
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


# --- #479 fresh-eyes gate: locate the BODY structurally, never by the first brace ---------------

@pytest.mark.parametrize(
    "arg",
    [
        # (a) EXPRESSION bodies whose expression carries a brace. The first `{` in the tail is an
        # object literal INSIDE the expression, not the body — reading it as the body left a `)`
        # over, the literal was rejected, and the concatenation heuristic fired CRITICAL on the
        # single most common React timer.
        '() => toast.success("Saved " + n, { duration: 3000 })',
        '() => setState({ label: "Hi " + n })',
        '() => ({ msg: "Hi " + n })',
        'e => handle({ msg: "Hi " + e })',
        '(a, b) => log({ m: "Hi " + a }, b)',
        '(x: string): void => log({ m: "Hi " + x })',
        'async () => api.post({ body: "id=" + id })',
        'async (x) => ({ v: "a" + x })',
        '<T,>(x: T) => log({ m: "Hi " + String(x) })',
        # (b) brace-carrying PARAMETER lists — destructured, array-destructured, defaulted,
        # object-typed, rest — on BOTH the arrow and the `function` head. The body brace of a
        # `function` is the first `{` after the parameter list's MATCHING `)`.
        '({ id }) => log({ m: "Hi " + id })',
        '([a, b]) => log({ m: "Hi " + a })',
        '(o = { a: 1 }) => log("Hi " + o)',
        '(...rest) => log({ m: "Hi " + rest })',
        'function ({ id }) { log("Saved " + id); }',
        'function (o = { a: 1 }) { log("Saved " + o); }',
        'function (o: { a: string }) { log("Saved " + o); }',
        'function ([a, b]) { log("Saved " + a); }',
        'function named({ id }) { q("x" + id); }',
        'function* gen({ a }) { q("x" + a); }',
        'async function ({ id }) { q("x" + id); }',
        'function (o = { a: 1 }, b) { log("Saved " + b); }',
        # (c) brace-carrying RETURN-TYPE annotations — the third site of the same category error:
        # the annotation was bounded at the first `{`, which a type literal or a brace-carrying
        # generic puts inside the annotation itself.
        # The next two are deliberately UNIT-ONLY: end to end the splitter truncates such an
        # argument at the comma inside `Record<string, …>` and `_is_function_literal` never sees
        # it, so an end-to-end assertion here would pass for a different reason than the one being
        # pinned. That truncation is the documented mid-argument-generic FN — pinned separately, on
        # a shape that compiles, by `test_mid_argument_generic_comma_is_a_known_false_negative`.
        '(x): Record<string, {a: number}> => { log("Hi " + x); }',
        '(x): Record<string, {a: number}> => log("Hi " + x)',
        '(x): ((n: number) => void) => (n) => log("Hi " + x)',
        'function (): { a: string } { return { a: "x" + y }; }',
    ],
)
def test_expression_bodied_and_braced_head_callbacks_are_not_sinks(arg: str) -> None:
    # C1/C2/L3 — one category error at three sites. `text.find("{")` answers "where is the first
    # brace", which is NOT "where does the body start": a brace occurs inside a parameter list, a
    # return-type annotation and an expression body. The narrowing that closed the IIFE bypass
    # shipped only brace-BODY false-positive bait — the one shape it could not affect — so 3732
    # tests stayed green while a 16-line React component produced 3 CRITICALs.
    assert _is_function_literal(arg) is True


def test_ordinary_react_component_stays_silent(tmp_path: Path) -> None:
    # The end-to-end form of the same regression: zero real sinks, three CRITICALs. The guard
    # applies on any `frontend` profile and `critical` is above the default `--fail-on high`, so
    # this red-lights the CI gate of every downstream consumer on idiomatic React.
    (tmp_path / "Saver.tsx").write_text(
        'import { useState } from "react";\n'
        'import toast from "react-hot-toast";\n'
        "\n"
        "export function Saver({ name, id }) {\n"
        '  const [msg, setMsg] = useState("");\n'
        "  const onSave = () => {\n"
        '    setTimeout(() => toast.success("Saved " + name, { duration: 3000 }), 100);\n'
        '    setTimeout(() => setState({ label: "Hi " + name }), 200);\n'
        '    setTimeout(() => ({ msg: "Hi " + name }), 300);\n'
        '    setTimeout(function ({ id }) { log("Saved " + id); }, 400);\n'
        "    setTimeout(\n"
        '      () => setMsg("Saved " + name),\n'
        "      500\n"
        "    );\n"
        "  };\n"
        "  return <button onClick={onSave}>{msg}</button>;\n"
        "}\n",
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_generic_head_is_consumed_whatever_the_whitespace_layout(tmp_path: Path) -> None:
    # H1. "The start of an argument" is its first NON-WHITESPACE character. Gating on `not current`
    # required the `<` to be the immediate next byte, so the `<T,>` comma was read as the argument
    # separator again the moment prettier wrapped the call — which, for a call this long, is the
    # DEFAULT formatting, not an exotic one. The invariant is asserted at the splitter (both
    # layouts) and end to end on the payload the desync hides.
    from agentsec.guards.dom_xss_sinks import _split_top_level_args

    for src in (
        'setTimeout(<T,>(x: T) => { q(1); }(), 100);',
        'setTimeout(\n  <T,>(x: T) => { q(1); }(),\n  100\n);',
        'setTimeout(\t<T,>(x: T) => { q(1); }(),\t100);',
    ):
        args = _split_top_level_args(src, src.index("("))
        assert args is not None and len(args) == 2, src
        assert args[0].strip() == '<T,>(x: T) => { q(1); }()', src

    (tmp_path / "Danger.tsx").write_text(
        'setTimeout(\n  <T,>("run(" + userInput + ")"),\n  100\n);\n', encoding="utf-8"
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_generic_head_gate_does_not_widen_onto_comparisons(tmp_path: Path) -> None:
    # The direction H1's fix trades against: a `<` that is NOT the start of an argument is still a
    # comparison and must not swallow the argument separator. (An argument whose first
    # non-whitespace character IS `<` cannot be a comparison in JS — nothing may begin with `<` —
    # so widening the gate from "immediate next byte" to "first non-whitespace" is sound.)
    (tmp_path / "Safe.tsx").write_text(
        "setTimeout(() => cmp(a < b, c > d), 100);\n"
        "setTimeout(makeCb<A, B>(q), 100);\n"
        "setTimeout(\n  () => cmp(a < b, c > d),\n  100\n);\n"
        "setTimeout(\n  makeCb<A, B>(q),\n  100\n);\n"
        "setTimeout(a < b ? f : g, 100);\n",
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


# --- #479 re-gate: the argument BOUNDARY, one level up from the body ------------------------------

@pytest.mark.parametrize(
    "stmt",
    [
        "const opts = { a: 1, b: 2 };",          # object literal
        'const tags = ["x", "y"];',              # array literal
        "let x = 1, y = 2;",                     # two declarators
        "const { a, b } = obj;",                 # object destructuring
        "const [x, y] = pair;",                  # array destructuring
        "const m: Record<string, number> = {};",  # generic type annotation
        "const { a, b } = await import('m');",
        "log({ a: 1 }, b);",                     # a call taking two arguments
    ],
)
@pytest.mark.parametrize(
    "head",
    ["() =>", "async () =>", "(x: string): void =>", "function ()", "function named({ id })"],
)
def test_a_comma_in_the_callback_body_does_not_truncate_the_argument(
    tmp_path: Path, head: str, stmt: str
) -> None:
    # H1. The three sites fixed last round all live INSIDE `_is_function_literal`; this is the
    # fourth, upstream of every one of them. `_split_top_level_args` located the argument's end at
    # "the first comma at paren depth 1", so any top-level comma in the callback BODY truncated
    # `args[0]` mid-body — the literal was never classifiable, and the `+`-and-a-quote heuristic
    # fired CRITICAL on ordinary React. `test_ordinary_react_component_stays_silent` passes only
    # because none of its five bodies happens to contain one: add a single object literal and it
    # fails. Same class, same severity, same blast radius as the C1 this PR exists to close.
    (tmp_path / "T.tsx").write_text(
        f'setTimeout({head} {{\n  setMsg("Saved " + name);\n  {stmt}\n}}, 300);\n',
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_react_component_with_an_object_literal_in_the_callback_stays_silent(tmp_path: Path) -> None:
    # The end-to-end form: idiomatic, valid TSX, zero real sinks, 1 CRITICAL before the fix.
    (tmp_path / "Toast.tsx").write_text(
        'import { useState } from "react";\n'
        "\n"
        "export function Toast({ name }: Props) {\n"
        '  const [msg, setMsg] = useState("");\n'
        "  const onSave = () => {\n"
        "    setTimeout(() => {\n"
        '      setMsg("Saved " + name);\n'
        '      const opts = { duration: 3000, position: "top" };\n'
        "      show(opts);\n"
        "    }, 300);\n"
        "  };\n"
        "  return <button onClick={onSave}>{msg}</button>;\n"
        "}\n",
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


@pytest.mark.parametrize(
    "src",
    [
        'setTimeout("run(" + userInput + ")", 100);\n',              # the plain sink
        'setTimeout("show({" + userInput + "})", 300);\n',           # braces INSIDE the code string
        'setTimeout("go([" + userInput + "])", 100);\n',             # brackets inside the code string
        'setTimeout("open({" + userInput, 300);\n',                  # an UNBALANCED brace in it
        'setTimeout(function(){ return "r(" + x + ")"; }() || {}, 100);\n',  # IIFE, trailing group
    ],
)
def test_group_tracking_does_not_hide_a_real_timer_sink(tmp_path: Path, src: str) -> None:
    # The direction H1's fix trades against. Not splitting on a comma inside `{}`/`[]` is a
    # NARROWING, so the vulnerable cases have to be pinned firing: a code string carrying braces,
    # and — the one that could genuinely swallow the separator — a code string whose brace is
    # UNBALANCED, where `args[0]` now runs to the call's closing paren. It still fires, because a
    # first argument that STARTS with a quote is a code string whatever follows it.
    (tmp_path / "S.tsx").write_text(src, encoding="utf-8")
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1 and hits[0].severity == "critical", src


def test_group_tracking_is_off_for_the_raw_text_sanitizer_scan(tmp_path: Path) -> None:
    # `track_groups` is off here because the sanitizer scan only needs the top-level `.replace()`
    # args, NOT because raw text is unsafe to group-track. The splitter is now quote/string-aware
    # (#573/#574): a `{` inside a string literal is copied verbatim and never counted, so this
    # `"<script>{"` pattern fires whether group tracking is on or off. Both single-occurrence
    # tag-strips must fire.
    (tmp_path / "san.js").write_text(
        'const a = html.replace("<script>{", "");\n'
        'const b = html.replace("<script>", "");\n',
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/incomplete-sanitization"]
    assert len(hits) == 2


# --- #479 re-gate: the return-type annotation is walked, not searched ----------------------------

@pytest.mark.parametrize(
    "annotation",
    [
        "({ a: 1 })",                  # a parenthesised type literal — the paren-stop's blind spot
        "(A | { b: 1 })",              # ...and a parenthesised union carrying one
        "{ a: string }",               # a bare type literal
        "() => { a: string }",         # a function type RETURNING a type literal
        "T[]",
        "Promise<{ a: 1 }>",
        "void",
    ],
)
def test_return_type_annotation_does_not_make_a_callback_a_sink(
    tmp_path: Path, annotation: str
) -> None:
    # M1. The body used to be located by "some `{...}` block that runs to the end", with a
    # stop-at-the-first-paren heuristic keeping the `{…}() || {}` IIFE bypass closed. A paren
    # BETWEEN the annotation's own brace group and the body defeated the heuristic, so valid
    # sink-free TypeScript fired CRITICAL. The annotation is now walked structurally to its end,
    # which is the invariant the other two sites already obeyed.
    (tmp_path / "A.tsx").write_text(
        f'setTimeout(function (): {annotation} {{ log("Hi " + n); }}, 100);\n', encoding="utf-8"
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


@pytest.mark.parametrize(
    "annotation",
    ["T", "({ a: 1 })", "{ a: string }", "() => { a: string }"],
)
def test_annotated_iife_is_still_a_sink(tmp_path: Path, annotation: str) -> None:
    # The direction M1's fix trades against, and the reason the heuristic existed at all: an
    # IMMEDIATELY-INVOKED annotated function passes its return VALUE — here a built string — so it
    # must stay a sink however its annotation is shaped. Both the bare invocation and the
    # `|| {}` form (whose trailing group ends the argument) are pinned.
    for suffix in ("()", "() || {}"):
        (tmp_path / "I.tsx").write_text(
            f'setTimeout(function (): {annotation} {{ return "r(" + x + ")"; }}{suffix}, 100);\n',
            encoding="utf-8",
        )
        hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
                if f.rule == "dom-xss-sinks/settimeout-string-arg"]
        assert len(hits) == 1, f"{annotation} {suffix}"


@pytest.mark.parametrize(
    "arg",
    [
        'function (): Record<string, number> { return "r(" + x + ")"; }()',
        'function <T, U>(a: T) { return "r(" + x + ")"; }()',
    ],
)
def test_mid_argument_generic_comma_is_a_known_false_negative(tmp_path: Path, arg: str) -> None:
    # The documented FN, pinned so the design-doc row stays testable — and pinned on a shape that
    # COMPILES. The row's first spelling used an arrow IIFE (`(x): Record<…> => {…}()`), which is a
    # syntax error: an arrow function cannot be immediately invoked, so it described a mechanism
    # that was real with an instance that could never occur. The reachable instances are the
    # `function`-keyword forms below.
    #
    # Mechanism: a `<…>` head is consumed only where an argument STARTS. Mid-argument a `<` is
    # still a comparison, so the comma inside the generic splits the argument and the truncated
    # fragment carries no string signal. Consuming `<…>` mid-argument would swallow the separator
    # in `cmp(a < b, c > d)` — an FP on ordinary code, traded for this FN on a rare one.
    # If a future change closes this, THIS TEST SHOULD FAIL — replace it with a firing assertion.
    (tmp_path / "FN.tsx").write_text(f"setTimeout({arg}, 100);\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_match_bracket_honours_its_end_bound() -> None:
    # L1. An unbalanced `<`-initial argument used to run the angle search to END OF FILE, once per
    # timer match — measured on a 24 KB file of 800 such calls: 528 ms at both `6d0b0fd1` and
    # `fa380941`, and the tip newly reached that cost from a whitespace-led argument too (0.4 ms →
    # 77 ms at k=200). Bounding every inner scan at the call's own closing paren makes it 2.3 ms.
    # The bound is asserted here rather than by a wall-clock assertion, which would be flaky.
    from agentsec.guards.dom_xss_sinks import _match_bracket

    text = "<a<b>>tail"
    assert _match_bracket(text, 0, "<", ">") == 5          # unbounded: the real match
    assert _match_bracket(text, 0, "<", ">", end=4) == -1  # bounded before it: no match
    assert _match_bracket(text, 0, "<", ">", end=99) == 5  # a bound past the end is harmless
    # A literal that closes only past the bound is still open at it, so the match gives up (#909).
    assert _match_bracket('( ")" )', 0, "(", ")", end=3) == -1


def test_match_bracket_skips_literals_and_arrows() -> None:
    # #909: a bracket inside any of the three literal kinds is not structure, and `\` escapes the
    # delimiter. A literal still open at the bound gives up rather than guess.
    from agentsec.guards.dom_xss_sinks import _match_bracket

    assert _match_bracket('{ "}" }', 0, "{", "}") == 6
    assert _match_bracket("{ '}' }", 0, "{", "}") == 6
    assert _match_bracket("{ `}` }", 0, "{", "}") == 6
    assert _match_bracket('{ "\\"}" }', 0, "{", "}") == 8
    assert _match_bracket('{ "} }', 0, "{", "}") == -1
    # The `>` of `=>` is an arrow, not a generic close (main returned 15 here); a bare `>` closes.
    assert _match_bracket("<T extends () => void,>", 0, "<", ">") == 22
    assert _match_bracket('<T = "a>b",>', 0, "<", ">") == 11
    assert _match_bracket("<a<b>>", 0, "<", ">") == 5


def test_dom_xss_sinks_silent_on_innerhtml_comparison(tmp_path: Path) -> None:
    # #424: an equality COMPARISON (=== / ==) is not an assignment sink.
    (tmp_path / "app.js").write_text("if (el.innerHTML === expected) { ok(); }\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_sinks_silent_on_empty_eval(tmp_path: Path) -> None:
    # #424: an empty eval() injects nothing (the ) is excluded, mirroring new Function()).
    (tmp_path / "app.js").write_text("const noop = () => eval();\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_sinks_flags_inner_html_compound_assign(tmp_path: Path) -> None:
    # Regression (#422): `el.innerHTML += userInput` appends attacker HTML just like `=`.
    (tmp_path / "app.js").write_text("el.innerHTML += userInput;\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "dom-xss-sinks/unsafe-dom-write"


def test_dom_xss_sinks_silent_compound_assign_literal(tmp_path: Path) -> None:
    # FP-bait for the widening: a compound assignment of a string literal is static HTML.
    (tmp_path / "safe.js").write_text('el.innerHTML += "<b>static</b>";\n', encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


def test_dom_xss_sinks_silent_inner_html_inequality_comparison(tmp_path: Path) -> None:
    # FP-bait for the widening: the `+?` must not open a path back into a COMPARISON, the
    # false positive main's `(?!=)` closed (#424).
    (tmp_path / "cmp.js").write_text("if (el.innerHTML !== expected) { redraw(); }\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    assert DomXssSinksGuard().run(tmp_path, profile) == []


# --- #573 / #574: the arg splitter is self-sufficiently quote/string-aware ----------------------
# Two silent false negatives, one root cause: `_split_top_level_args` reasoned about `(){}[]`
# structure while treating string CONTENTS as code, so a bracket/comma living inside a string
# literal desynced the split. #573 (primary) — a `}` inside a string that #542's EOF un-blank
# restored VERBATIM decremented the track_groups counter early, a later `,` was read as the arg
# separator, args[0] was truncated, and the genuine IIFE-return-value string sink was dropped with
# a clean exit. #574 (consolidated) — a `(` inside a raw `.replace()` pattern desynced the
# quote-blind paren count. RCA: .claude/issues/issue-573.md.


def test_dom_xss_settimeout_sink_fires_despite_upstream_unterminated_template(tmp_path: Path) -> None:
    # #573 PRIMARY (missed-detection). The control (no template) is test_iife_sink_fires_end_to_end;
    # here the unterminated template on line 1 triggers the EOF un-blank, and the sink must STILL fire.
    (tmp_path / "b.tsx").write_text(
        "const broken = `unterminated template literal starts here and never closes\n"
        "export function evil({ userInput }) {\n"
        "  setTimeout(function(){\n"
        '    var label = "unexpected }";\n'
        '    var a = 1, b = ("run(" + userInput + ")");\n'
        "    return b;\n"
        "  }(), 100);\n"
        "}\n",
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_dom_xss_benign_timer_after_unterminated_template_stays_silent(tmp_path: Path) -> None:
    # #573 FP-bait (Rule 1, the widening direction): making the walk quote-aware must not NEWLY fire
    # on an ordinary arrow callback that sits after an unterminated template and carries a
    # comma-bearing string in its body. It is a function literal, never re-parsed as code.
    (tmp_path / "safe.tsx").write_text(
        "const broken = `unterminated and never closes\n"
        "setTimeout(() => { setMsg('x, y' + z); }, 100);\n",
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_generic_head_string_sink_fires_after_unterminated_template(tmp_path: Path) -> None:
    # #573: a `<T,>`-head + string-arg sink in the un-blanked tail must fire — and this fixture
    # DISCRIMINATES (verified against origin/main: it MISSES pre-fix, fires after). The single
    # unbalanced `(` inside the "run(" string defeats the old quote-blind `_match_bracket` call_close
    # (depth never returns to 0 → -1 → the split gives up → the sink is dropped); the quote-aware
    # `matching_close_paren` skips the in-string `(`. Also keeps the #479 type-parameter-head path
    # exercised through the rewrite. (An earlier draft used `"run(" + x + ")"`, whose two stray parens
    # net out under naive counting and so fired on the unfixed code too — proving nothing, #908 review.)
    (tmp_path / "g.tsx").write_text(
        "const broken = `unterminated and never closes\n"
        'setTimeout(<T,>("run(" + userInput), 100);\n',
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1 and hits[0].severity == "critical"


def test_dom_xss_broken_sanitizer_fires_with_paren_in_pattern(tmp_path: Path) -> None:
    # #574 (consolidated): a `(` inside the .replace() pattern string used to desync the quote-blind
    # paren count, call_close bailed (None), and the broken single-occurrence tag-strip was SILENTLY
    # missed. `matching_close_paren` skips the paren inside the string, so it fires like its
    # paren-free neighbours (`"<script>"`, `"<script>{"`), which stay green.
    (tmp_path / "sanitize.js").write_text(
        'const a = html.replace("(<script>", "");\n'
        'const b = html.replace("<script>", "");\n'
        'const c = html.replace("<script>{", "");\n',
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/incomplete-sanitization"]
    assert len(hits) == 3 and all(h.severity == "high" for h in hits)


def test_dom_xss_non_tag_paren_replace_stays_silent(tmp_path: Path) -> None:
    # #574 FP-bait (Rule 1): a `(`-bearing pattern that is NOT tag-shaped, with a non-empty
    # replacement, must stay silent — counting the paren correctly must not turn an ordinary
    # .replace() into a broken-sanitizer finding.
    (tmp_path / "safe.js").write_text('const a = s.replace("(a)", "b");\n', encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_split_honors_escaped_quote_in_replace_pattern(tmp_path: Path) -> None:
    # #573 escape edge: an escaped quote inside a .replace() pattern (`"a\")b"`) must NOT close the
    # string early — otherwise the `)` inside it reads as the call's close and the split truncates.
    # Asserted directly on the splitter; the finding stays silent (`a")b` is not tag-shaped).
    from agentsec.guards.dom_xss_sinks import _split_top_level_args

    src = 'html.replace("a\\")b", "")'
    assert _split_top_level_args(src, src.index("(")) == ['"a\\")b"', ' ""']
    (tmp_path / "esc.js").write_text(src + ";\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_dom_xss_broken_sanitizer_backtick_paren_pattern_fires(tmp_path: Path) -> None:
    # #909 site B, once pinned here as a known gap: `call_close` came from `matching_close_paren`,
    # which tracks `'`/`"` but not the backtick, while the splitter's walk tracks all three. The two
    # disagreed about where the template ends, the call "closed" on the `)` inside it, the walk fell
    # through to `None`, and the HIGH was dropped. Both now share `_match_bracket`'s literal model.
    # The apostrophe line is the same mechanism through the other door: the `'` inside the template
    # opened a phantom string for the backtick-blind finder.
    (tmp_path / "gap.js").write_text(
        "const a = html.replace(`<div title=odd) markup>`, \"\");\n"
        'const b = html.replace("<div title=odd) markup>", "");\n'    # control: fired before the fix too
        "const c = html.replace(`<p>it's</p>`, \"\");\n",
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/incomplete-sanitization"]
    # Pin WHICH lines fire, not just the count (#908 round-2).
    assert sorted(h.location for h in hits) == ["gap.js:1", "gap.js:2", "gap.js:3"]
    assert all(h.severity == "high" for h in hits)


def test_dom_xss_backtick_non_tag_replace_with_a_paren_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the site-B widening: a backtick pattern that now splits correctly is still judged
    # by `_is_broken_tag_sanitizer`, so a non-tag one stays silent.
    (tmp_path / "safe.js").write_text("const a = s.replace(`a) b`, \"\");\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_settimeout_sink_after_a_stray_template_opener_still_fires(tmp_path: Path) -> None:
    # #910: a missing closing backtick on an unrelated CSS-in-JS template earlier in the file paired
    # with the next template's opener inside the `strip_js_comments(strip_strings=True)` copy, and
    # the real timer sink between them was blanked before `_SET_TIMEOUT_CALL` ran — 0 findings,
    # clean exit, no skip (a silent CRITICAL false negative). The helper's parity cap now restores
    # the span. The control (same sink, template closed) fires the same single finding, so this is
    # the existing detection recovered, not a new one.
    timer = '  setTimeout("doSomething(" + userInput + ")", 100);\n'
    broken = ("const cardStyle = styled.div`\n  display: flex;\n  padding: 8px;\n\n"
              "export function scheduleRun(userInput) {\n" + timer + "}\n\n"
              "const tooltipStyle = styled.span`color: red;`;\n")
    control = broken.replace("  padding: 8px;\n", "  padding: 8px;\n`;\n")
    for src in (broken, control):
        (tmp_path / "Card.tsx").write_text(src, encoding="utf-8")
        hits = [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
                if f.rule == "dom-xss-sinks/settimeout-string-arg"]
        assert len(hits) == 1 and hits[0].severity == "critical", src


def test_settimeout_inside_a_closed_template_is_string_content(tmp_path: Path) -> None:
    # FP-bait for the #910 widening: the parity cap must not fire on VALID source. The template
    # closes on line 3, so this `setTimeout` is string content and stays silent — the RCA's
    # "even-count residual", pinned as correct behaviour rather than documented as a miss.
    (tmp_path / "Card.tsx").write_text(
        'const cardStyle = styled.div`\nsetTimeout("doSomething()", 100);\n`;\nconst label = `ready`;\n',
        encoding="utf-8",
    )
    assert DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_parity_cap_revive_inside_a_callback_body_no_longer_fires(tmp_path: Path) -> None:
    # Once pinned as the #910 parity cap's accepted trade at guard level (#912 review). On an
    # odd-parity file (a stray backtick, so not valid JS) the cap restores every closed template
    # verbatim, and a template carrying an unbalanced `{` inside a timer CALLBACK's body unbalanced
    # `_is_function_literal`'s quote-blind body walk: the callback was no longer recognised as a
    # literal and its own `"Saved " + name` read as a code string, a CRITICAL FP. `_match_bracket` now
    # skips literals itself (#909), so the revived brace is not structure. The cap is unchanged; the
    # guard simply stopped trusting it.
    body = ('export function Toast({ name }) {\n'
            '  const onSave = () => {\n'
            '    setTimeout(() => {\n'
            '      setMsg("Saved " + name + `{`);\n'
            '    }, 300);\n'
            '  };\n'
            '}\n')
    prof = mkprofile(tmp_path, features={"frontend"})
    (tmp_path / "Toast.tsx").write_text(body + "const stray = styled.div`\n", encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, prof) == []        # was the accepted CRITICAL FP
    # The even-parity control was always silent...
    (tmp_path / "Toast.tsx").write_text(body, encoding="utf-8")
    assert DomXssSinksGuard().run(tmp_path, prof) == []
    # ...and THE DIRECTION THIS TRADES AGAINST: a REAL code-string sink whose own arguments carry
    # such a template still fires exactly once on the odd-parity file.
    (tmp_path / "Toast.tsx").write_text(
        'function run(userInput) {\n'
        '  setTimeout("x(" + userInput + ")" + `{`, "100not", 100);\n'
        '}\n'
        'const stray = `never closed\n',
        encoding="utf-8",
    )
    hits = [f for f in DomXssSinksGuard().run(tmp_path, prof)
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]
    assert len(hits) == 1


# --- #909: literal-aware, `=>`-aware bracket matching; regex bodies blanked in the timer scan ------
# The timer and sanitizer walkers counted every `{ } ( ) < >` as code, trusting a scan copy whose
# literal contents were blanked. Regex bodies never were, and the #542 EOF cap and #910 parity cap
# restore literal text verbatim. So a brace or quote inside a literal flipped a callback into a
# CRITICAL FP, or made the split give up and silently drop a real CRITICAL/HIGH. The rows marked
# VALID need no broken file at all. RCA: .claude/issues/issue-909.md.

_UNTERMINATED = "const broken = `unterminated template literal starts here and never closes\n"


def _timer_hits(tmp_path: Path, name: str, src: str) -> list[Finding]:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return [f for f in DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
            if f.rule == "dom-xss-sinks/settimeout-string-arg"]


@pytest.mark.parametrize(
    "src",
    [
        # the issue's site-A repro: a `}` in a body string, restored verbatim by the #542 EOF cap
        _UNTERMINATED + 'setTimeout(function(){ var msg = "unexpected }"; '
                        'console.log("Elapsed: " + elapsed + "ms"); }, 100);\n',
        _UNTERMINATED + 'setTimeout(() => { var m = "}"; go("x" + m); }, 100);\n',
        # VALID: an unbalanced brace in a regex literal in the body, plus a concatenation
        'setTimeout(function(){ x.replace(/}/g, ""); go("x" + m); }, 100);\n',
        'setTimeout(function(){ x.replace(/{/g, ""); go("x" + m); }, 100);\n',
        'setTimeout(function(){ x.replace(/\\}/g, ""); go("x" + m); }, 100);\n',
        # VALID: the regex follows `=>`, which `strip_regex` must still blank
        'setTimeout(() => { list.filter(s => /}/.test(s)); go("x" + m); }, 100);\n',
    ],
)
def test_callback_with_a_brace_inside_a_literal_is_still_a_function_literal(
    tmp_path: Path, src: str
) -> None:
    # Narrowing (an FP fix). Each fired CRITICAL on main: the literal's brace closed the body early,
    # so `_body_consumes_rest` saw a tail and the body's own `"x" + m` read as a code string.
    assert _timer_hits(tmp_path, "a.js", src) == []


@pytest.mark.parametrize(
    "src",
    [
        # A8: the IIFE true positive, with a `}` in a body string, on the EOF path
        _UNTERMINATED + 'setTimeout(function(){ var l = "}"; return "r(" + x + ")"; }(), 100);\n',
        # VALID: an IIFE whose body carries a regex brace
        'setTimeout(function(){ return "r(" + x.replace(/}/g, "") + ")"; }(), 100);\n',
        # VALID: the `|| {}` bypass `_function_body_ends_argument` documents, with a regex brace
        'setTimeout(function(){ return "r(" + x.replace(/{/g, "") + ")"; }() || {}, 100);\n',
        # an arrow IIFE-shaped tail after a regex-brace body (the value passed is not the function)
        'setTimeout((() => { s.replace(/}/g, ""); return "r(" + x + ")"; })(), 100);\n',
    ],
)
def test_iife_with_a_brace_inside_a_literal_still_fires(tmp_path: Path, src: str) -> None:
    # Rule 1, the direction the narrowing above trades against: skipping literal braces must not
    # let an INVOKED function, whose value is the built string, pass as a callback literal.
    hits = _timer_hits(tmp_path, "a.js", src)
    assert len(hits) == 1 and hits[0].severity == "critical"


@pytest.mark.parametrize(
    ("name", "src"),
    [
        # R1, VALID: the classic legacy quote-escaping timer. The `'` in `/'/g` was kept as code,
        # opened a phantom string for the close-paren finder, and the whole call was skipped.
        ("a.js", 'setTimeout("run(" + x.replace(/\'/g, "") + ")", 0);\n'),
        ("a.js", 'setTimeout("alert(\'" + m.replace(/\'/g, "\\\\\'") + "\')");\n'),
        # C-arrow, VALID: the head's `<…>` match stopped at the `>` of `=>`, a top-level comma then
        # split the head, and `args[0]` was the fragment `<T extends () => void`.
        ("a.tsx", 'setTimeout(<T extends () => void,>("run(" + x), 100);\n'),
        # C2/C7, EOF path: the head's match stopped at the `>` inside the restored `"a>b"`.
        ("a.tsx", _UNTERMINATED + 'setTimeout(<T = "a>b",>("run(" + userInput), 100);\n'),
    ],
)
def test_string_timer_hidden_by_a_literal_or_an_arrow_now_fires(tmp_path: Path, name: str, src: str) -> None:
    # Widening (FN fixes): each was a silent CRITICAL miss on main, exit 0 and no skip.
    hits = _timer_hits(tmp_path, name, src)
    assert len(hits) == 1 and hits[0].severity == "critical"


@pytest.mark.parametrize(
    ("name", "src"),
    [
        # a quote-regex in a real callback: the split no longer gives up, so the body is classified
        ("a.js", 'setTimeout(() => { s = s.replace(/\'/g, ""); go("x" + s); }, 100);\n'),
        # generic-arrow callbacks whose head the widened matcher now consumes whole
        ("a.tsx", 'setTimeout(<T extends () => void,>(x: T) => { go("x" + x); }, 100);\n'),
        ("a.tsx", _UNTERMINATED + 'setTimeout(<T = "a>b",>(x: T) => { go("x" + x); }, 100);\n'),
        # division is not a regex, so nothing is blanked and the callback stays a literal
        ("a.js", 'setTimeout(() => { go(a / b / c + "px"); }, 100);\n'),
        # a brace inside a template substitution's string
        ("a.js", 'setTimeout(() => { go(`a ${ "}" } b` + x); }, 100);\n'),
    ],
)
def test_benign_neighbours_of_the_909_widening_stay_silent(tmp_path: Path, name: str, src: str) -> None:
    # Rule 1 FP-bait for the widening. Silent on main too, but there because the split gave up
    # before classifying anything; here each is classified and judged a function literal.
    assert _timer_hits(tmp_path, name, src) == []


@pytest.mark.parametrize(
    "src",
    [
        '<label>Name</label><button onClick={() => setTimeout("go(" + x + ")", 0)}>Go</button>\n',
        'if (ok) render(<A b="c" />, <button onClick={() => setTimeout("go(" + x + ")", 0)} />);\n',
        '<nav>/ {setTimeout("go(" + x + ")", 0)} / Docs</nav>\n',
    ],
)
def test_a_misread_jsx_regex_cannot_blank_a_timer_sink(tmp_path: Path, src: str) -> None:
    # The direction `strip_regex` trades against. In each line the lexer's heuristic reads a JSX `/`
    # as a regex START (after `<`, after a string close with a stale control-head flag, after a bare
    # `>`), and the "regex" runs to the next `/` on the line. Blanking its body deleted the CRITICAL
    # sink in between. All three fire on main; `_regex_body_may_blank` keeps them firing.
    hits = _timer_hits(tmp_path, "Form.jsx", src)
    assert len(hits) == 1 and hits[0].severity == "critical"


# --- #1055: a sink counts only when it is live code; `${...}` substitution code is live ------------


def _dom_run(tmp_path: Path, src: str) -> list[Finding]:
    (tmp_path / "app.js").write_text(src, encoding="utf-8")
    return DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))


@pytest.mark.parametrize(
    "src",
    [
        "log('do not eval(x) here');\n",
        "const help = \"set el.innerHTML = value only after DOMPurify\";\n",
        "throw new Error(`document.write(html) is disabled`);\n",
        "const doc = 'new Function(body) is banned';\n",
    ],
)
def test_dom_xss_sink_spelled_in_a_string_does_not_fire(tmp_path: Path, src: str) -> None:
    # The FP direction (#1055): a docs or error string is not a sink.
    assert _dom_run(tmp_path, src) == []


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        ("const s = `${eval(code)}`;\n", "dom-xss-sinks/eval-sink"),
        ("const s = `${el.innerHTML = html}`;\n", "dom-xss-sinks/unsafe-dom-write"),
        ("log('eval(x)'); eval(code);\n", "dom-xss-sinks/eval-sink"),
        ("log('el.innerHTML = x'); el.innerHTML = html;\n", "dom-xss-sinks/unsafe-dom-write"),
    ],
)
def test_dom_xss_real_sink_nested_or_after_a_quoted_copy_still_fires(
    tmp_path: Path, src: str, rule: str
) -> None:
    # A sink in a `${...}` is code (the shortcut-separating case), and a quoted copy first on the
    # line must not hide the real sink after it (first-match shadowing).
    assert [f.rule for f in _dom_run(tmp_path, src)] == [rule]


@pytest.mark.parametrize(
    ("first_arg", "fires"),
    [
        ("'run(' + x + ')'", True),       # the vulnerable form, nested in a substitution (#1055 FN)
        ("() => run(x)", False),          # FP bait: the same call with a function argument
    ],
)
def test_dom_xss_timer_nested_in_a_substitution_is_scanned(
    tmp_path: Path, first_arg: str, fires: bool
) -> None:
    # The timer scan used plain `strip_strings=True`, which blanked every `${...}`, so the nested call
    # never reached `_first_arg_is_code_string` at all. The two rows differ only in the argument, so the
    # silent row proves the bait now reaches the classifier and is rejected there, not skipped
    # earlier (a widening carries its FP bait, and the bait needs this mutation proof).
    findings = _dom_run(tmp_path, f"const s = `${{setTimeout({first_arg}, 10)}}`;\n")
    assert [f.rule for f in findings] == (["dom-xss-sinks/settimeout-string-arg"] if fires else [])


@pytest.mark.parametrize(
    "src",
    [
        "setTimeout(handler.bind(null, `${i + 1}`), 100);\n",
        "setTimeout(show(`Step ${step + 1}`), 100);\n",
        "setTimeout(poll(`/api?x=${a + 1}`), 5);\n",
        # The same shape nested in a substitution, which the timer scan now reads.
        "const s = `${setTimeout(show(`Step ${step + 1}`), 10)}`;\n",
        # A NESTED template in the argument (PR #1126 round-2 N1): the scan view blanks the `${`/`}`
        # delimiters, so a flat literal model cannot tell the inner template from the outer one.
        "setTimeout(render(`${items.map(i => `<li>${i + 1}</li>`).join('')}`), 100);\n",
        "setTimeout(show(`${a ? `x${n + 1}` : 'y'}`), 100);\n",
    ],
)
def test_dom_xss_timer_plus_inside_a_template_argument_is_not_a_concatenation(
    tmp_path: Path, src: str
) -> None:
    # FP bait for the #1055 timer-scan widening (PR #1126 round-1 M1). Keeping substitution code made
    # the `+` of `${i + 1}` visible, and the "a `+` plus a quote" heuristic read a function value as a
    # string-building concatenation: a CRITICAL on ordinary code. Only a `+` OUTSIDE every literal
    # builds a string.
    assert _dom_run(tmp_path, src) == []


@pytest.mark.parametrize(
    "src",
    [
        'setTimeout("run(" + x + ")", 100);\n',
        "setTimeout(`run(` + x + `)`, 100);\n",
        "setTimeout(prefix + `(${x})`, 100);\n",
        # These two reach the `+` test itself: neither argument starts with a quote (round-2 N3).
        'setTimeout(("run(" + x + ")"), 100);\n',
        "setTimeout(String('a' + x), 100);\n",
        "const s = `${setTimeout('run(' + x + ')', 10)}`;\n",
    ],
)
def test_dom_xss_timer_top_level_concatenation_still_fires(tmp_path: Path, src: str) -> None:
    # The direction the M1 fix trades against: a `+` between literals or values at the argument's top
    # level is still a string-building concatenation.
    assert [f.rule for f in _dom_run(tmp_path, src)] == ["dom-xss-sinks/settimeout-string-arg"]


def test_dom_xss_timer_outside_a_substitution_keeps_the_plain_view_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The invariant behind the #1055 timer-scan change (PR #1126 round-2 N1): keeping substitution
    # code may ADD calls that live inside a `${...}`, and must change nothing about a call outside
    # one. Differential over generated arguments: the real guard against a run whose views never
    # keep substitutions (the pre-#1055 view). Every argument shape is outside a substitution.
    import itertools

    import agentsec.guards.dom_xss_sinks as mod

    parts = [
        "x", "'a'", '"run("', "`t`", "`a${b}`", "`${i + 1}`", "`${f(`<li>${i + 1}</li>`)}`",
        "`${c ? `x${n + 1}` : 'y'}`", "f(", ")", " + ", "() => ", "g(`s ${h(1 + 2)}`)", "String(",
    ]
    args = [" ".join(c) for n in (1, 2, 3) for c in itertools.product(parts, repeat=n)]
    lines = [f"setTimeout({a}, 100);\n" for a in args]
    # 50-line files, not one 2,954-line file: the guard is quadratic on unbalanced `setTimeout(`
    # calls (#1138: each unclosed opener scans to EOF), so one file cost ~2.6s per run and this test
    # 5-7s. What chunking loses is any pairing (an unclosed opener matched to a later line) that
    # CROSSES a file boundary: measured, one file fires on 1,620 lines and one 50-line layout on 1,492
    # (#1145 review). So the corpus is laid out twice, the second time offset by 25 lines, and a
    # pairing spanning up to 25 lines sits inside one file in at least one layout. Every argument
    # shape is still generated and the invariant is judged per call in both layouts; the pre-#1055
    # mutant (`view = scan`) still fails here (measured 2026-10-23).
    roots = [tmp_path / "even", tmp_path / "offset"]
    for root, first in zip(roots, (50, 25), strict=True):
        root.mkdir()
        bounds = [0, *range(first, len(lines), 50), len(lines)]
        for k, (lo, hi) in enumerate(zip(bounds, bounds[1:], strict=False)):
            (root / f"app{k:05d}.js").write_text("".join(lines[lo:hi]), encoding="utf-8")

    def run() -> list[list[str]]:
        return [
            [f.location for f in DomXssSinksGuard().run(r, mkprofile(r, features={"frontend"}))]
            for r in roots
        ]

    real = run()
    plain_only = mod.strip_js_comments

    def no_substitutions(text: str, **kw: bool) -> str:
        return plain_only(text, **{**kw, "keep_substitutions": False})

    monkeypatch.setattr(mod, "strip_js_comments", no_substitutions)
    assert real == run()
    assert all(real)  # the corpus reaches the classifier in both layouts: some shapes do fire


# #543: a `{` in a regex inside a `${…}` used to shift the lexer's template frame. Alone it kept the
# template open, so a commented-out sink after it read as template text and fired; paired with a `}`
# in a later substitution it rebalanced, and a real timer sink between the two was blanked.
_SUBST_OPEN_BRACE = 'const s = `${ v.replace(/{/g, "") }`;\n'
_SUBST_PAIR = ("const t = `a ${ s.replace(/{/g, '') } b`;\n", "const u = `a ${ s.replace(/}/g, '') } b`;\n")
_TIMER_SINK = 'setTimeout("alert(" + location.hash + ")", 100);\n'


@pytest.mark.parametrize("sink", [_TIMER_SINK, "el.innerHTML = userInput;\n"])
def test_commented_sink_after_a_brace_in_a_substitution_regex_stays_silent(
    tmp_path: Path, sink: str
) -> None:
    (tmp_path / "fp.js").write_text(_SUBST_OPEN_BRACE + "// " + sink, encoding="utf-8")
    (tmp_path / "real.js").write_text(_SUBST_OPEN_BRACE + sink, encoding="utf-8")   # rule 1: still fires
    profile = mkprofile(tmp_path, features={"frontend"})
    assert [f.location for f in DomXssSinksGuard().run(tmp_path, profile)] == ["real.js:2"]


def test_timer_sink_between_two_brace_regex_substitutions_fires(tmp_path: Path) -> None:
    opens, closes = _SUBST_PAIR
    (tmp_path / "pair.js").write_text(opens + _TIMER_SINK + closes, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert [(f.location, f.rule) for f in findings] == [("pair.js:2", "dom-xss-sinks/settimeout-string-arg")]


def test_timer_sink_between_two_non_null_divisions_in_substitutions_fires(tmp_path: Path) -> None:
    # #1124 round 1, H2: `x! / 2` is a TypeScript non-null assertion followed by division. The
    # sub-lexer read the `/` after `!` as a regex opener, which ran to the next `/` on the line and
    # swallowed the substitution's `}` and closing backtick. Two such lines rebalanced the template
    # count, so neither restore cap fired and the critical timer sink between them was blanked.
    # The function bodies matter: with the three lines flat, the parity cap restored the file.
    line = "  const s = `${ el.offsetWidth! / 2 }px`; const q = a / b;\n"
    src = "function f() {\n" + line + "}\nfunction h() {\n  " + _TIMER_SINK + "}\nfunction g() {\n" + line + "}\n"
    (tmp_path / "App.tsx").write_text(src, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})
    findings = DomXssSinksGuard().run(tmp_path, profile)
    assert [(f.location, f.rule) for f in findings] == [("App.tsx:5", "dom-xss-sinks/settimeout-string-arg")]


# #1138: `_split_top_level_args` found every call's close with its own unbounded `_match_bracket`, so
# an unclosed `(` scanned to end of file once per regex match: 4,000 lines of `setTimeout(f(, 1);`
# took 14.2 s and `.replace(` took the same path through the sanitizer scan. One `_paren_closes` pass
# per view now answers every opener, which is an equivalence claim on a CRITICAL and a HIGH rule, so
# it is pinned three ways: growth class, the map against `_match_bracket`, and the guard's findings
# with the map against the guard's findings without it.
# The `prefix` cases put every opener inside a literal for a lexing started at the top of the file
# (the #542 EOF cap restores an unterminated literal verbatim): one stray quote kept a literal pass
# plus per-opener fallback quadratic, 54 s at 8,000 lines. The last layout alternates quote parity
# per line, so each opener is inside a literal for every lexing started before it: a pass per
# missed opener still took 11.3 s at 4,000 lines (#1149 review).
@pytest.mark.parametrize(
    ("line", "prefix"),
    [
        ("setTimeout(f(, 1);\n", ""),
        ("setTimeout(f(, 1);\n", "const t = `"),
        ("setTimeout(f(, 1);\n", "const t = '"),
        ("x.replace(f(, 1);\n", ""),
        ("x.replace(f(, 1);\n", "const t = `"),
        ("x.replace(f(, 1);\n", "const t = '"),
        ('x.replace("(\\"(\n', ""),
    ],
)
def test_dom_xss_unclosed_calls_scan_in_linear_time(tmp_path: Path, line: str, prefix: str) -> None:
    from tests._timing import assert_growth

    sizes = [1000, 2000, 4000, 8000]
    roots = {}
    for n in sizes:
        roots[n] = tmp_path / str(n)
        roots[n].mkdir()
        (roots[n] / "app.js").write_text(prefix + line * n, encoding="utf-8")

    def scan(n: int) -> None:
        DomXssSinksGuard().run(roots[n], mkprofile(roots[n], features={"frontend"}))

    assert_growth(scan, sizes, expected="linear")


def test_dom_xss_sink_after_thousands_of_unclosed_calls_still_fires(tmp_path: Path) -> None:
    # Both directions on the hostile layout: a real timer sink and a real broken sanitizer below the
    # unclosed openers still fire, and the benign neighbours beside them stay silent.
    (tmp_path / "app.js").write_text(
        "setTimeout(f(, 1);\nx.replace(f(, 1);\n" * 2000
        + 'setTimeout("run(" + location.hash + ")", 100);\n'
        + "setTimeout(() => run(location.hash), 100);\n"
        + 's = s.replace(/<script>/, "");\n'
        + 's = s.replace(/<script>/g, "");\n',
        encoding="utf-8",
    )
    found = DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert sorted((f.rule, f.location) for f in found) == [
        ("dom-xss-sinks/incomplete-sanitization", "app.js:4003"),
        ("dom-xss-sinks/settimeout-string-arg", "app.js:4001"),
    ]


def test_paren_closes_agrees_with_match_bracket_on_every_queried_opener() -> None:
    import random

    from agentsec.guards.dom_xss_sinks import _match_bracket, _paren_closes

    rng = random.Random(1138)
    alphabet = "(()),'\"`\\ x\n"
    checked = 0
    for _ in range(20000):
        text = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 40)))
        openers = [k for k, ch in enumerate(text) if ch == "("]
        # Any subset, as the caller's regex picks them: a query may sit inside a literal that an
        # earlier query's lexing opened, which is the case one forward pass cannot answer.
        keep = rng.choice((1.0, 0.5, 0.2))
        queried = [k for k in openers if rng.random() < keep]
        closes = _paren_closes(text, queried)
        for k in queried:
            assert closes[k] == _match_bracket(text, k, "(", ")"), (text, k)
            checked += 1
    assert checked > 30000  # 38,884 queried openers at seed 1138
    # The outcomes, named: a match, an unclosed opener, one left open by a literal that never
    # terminates, and one INSIDE an earlier query's literal, which its own lexing reads as code.
    assert _paren_closes("a(b)", [1]) == {1: 3}
    assert _paren_closes("f(g(x)", [1, 3]) == {1: -1, 3: 5}
    assert _paren_closes("f(x, 'oops", [1]) == {1: -1}
    assert _paren_closes("f('(x)')", [1, 3]) == {1: 7, 3: 5}


def test_dom_xss_findings_are_unchanged_by_the_paren_close_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The guard with the map against the guard with the map withheld (`closes=None`), which sends
    # every opener down the pre-#1138 per-call `_match_bracket` path. Lines mix firing and safe calls
    # with unclosed openers, quotes, templates, substitutions and regexes; some files end inside a
    # literal, the #542/#910 restored-verbatim text where a call sits inside an earlier one's literal.
    import random

    import agentsec.guards.dom_xss_sinks as mod

    rng = random.Random(1138)
    parts = [
        'setTimeout("run(" + u + ")", 1);', "setTimeout(() => go(u), 1);", "setTimeout(f(, 1);",
        "setInterval(`t${a + 1}`, 5);", "x.replace(/<b>/, '');", "x.replace('<i>', '');", "x.replace(f(, 1);",
        "s.replace(/<p>/g, '');", "const q = `a ${setTimeout('x' + y, 1)} b`;", "f(", ")", "'", '"', "`",
        "/'/g;", "{", "}", "// setTimeout('a' + b)", "setImmediate(g({, 1);", "\n",
    ]
    for k in range(60):
        (tmp_path / f"app{k:02d}.js").write_text(
            "\n".join(" ".join(rng.choice(parts) for _ in range(rng.randint(1, 4))) for _ in range(30)),
            encoding="utf-8",
        )
    # Plus one quote-free layout: in the random files a stray quote usually makes the raw-text
    # `.replace(` split give up, so the sanitizer rule would otherwise be compared only when silent.
    (tmp_path / "clean.js").write_text(
        'x.replace(f(, 1);\ns = s.replace(/<script>/, "");\ns = s.replace(/<script>/g, "");\n',
        encoding="utf-8",
    )

    def locations() -> list[tuple[str, str]]:
        found = DomXssSinksGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
        return sorted((f.rule, f.location) for f in found)

    real = locations()
    split = mod._split_top_level_args

    def per_call(text: str, open_idx: int, **kw: Any) -> list[str] | None:
        return split(text, open_idx, **{**kw, "closes": None})

    monkeypatch.setattr(mod, "_split_top_level_args", per_call)
    assert real == locations()
    assert any(r == "dom-xss-sinks/settimeout-string-arg" for r, _ in real)
    assert any(r == "dom-xss-sinks/incomplete-sanitization" for r, _ in real)
