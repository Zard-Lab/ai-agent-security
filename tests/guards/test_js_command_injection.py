from __future__ import annotations

import pytest

from agentsec.guards.js_command_injection import JsCommandInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_exec_template_literal_interpolation(tmp_path: Path) -> None:
    (tmp_path / "convert.js").write_text(
        "const { exec } = require('child_process');\n"
        "exec(`convert ${req.query.file} out.png`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].severity == "critical"


def test_flags_execsync_concatenation(tmp_path: Path) -> None:
    (tmp_path / "cleanup.ts").write_text(
        "import { execSync } from 'child_process';\n"
        'execSync("rm -rf " + userPath);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"


def test_flags_child_process_exec_prefixed(tmp_path: Path) -> None:
    (tmp_path / "run.js").write_text(
        "child_process.exec(`ping ${req.body.host}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsCommandInjectionGuard().run(tmp_path, profile)) == 1


def test_flags_spawn_shell_true_with_tainted_cmd_and_arg(tmp_path: Path) -> None:
    (tmp_path / "run.js").write_text(
        "const { spawn } = require('child_process');\n"
        "spawn(cmd, [userArg], {shell: true});\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/spawn-shell-true-tainted"


def test_flags_spawn_shell_true_with_tainted_array_element_only(tmp_path: Path) -> None:
    # literal command, but one array element is a bare (non-literal) variable
    (tmp_path / "run.js").write_text(
        "const { spawn } = require('child_process');\n"
        'spawn("sh", ["-c", userArg], {shell: true});\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsCommandInjectionGuard().run(tmp_path, profile)) == 1


def test_silent_on_fully_static_execsync(tmp_path: Path) -> None:
    # child_process IS bound, so this tests "static arg is safe" (not "unbound name is safe").
    (tmp_path / "list.js").write_text(
        "const { execSync } = require('child_process');\n"
        'execSync("ls -la");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_spawn_array_form_no_shell(tmp_path: Path) -> None:
    # the idiomatic safe form: no shell:true, literal array args
    (tmp_path / "status.js").write_text(
        "const { spawn } = require('child_process');\n"
        'spawn("git", ["status"]);\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_spawn_bare_cmd_without_shell_true(tmp_path: Path) -> None:
    # bare cmd variable but shell:true absent -> spawn's array form is inherently safe
    (tmp_path / "run.js").write_text(
        "const { spawn } = require('child_process');\n"
        "spawn(cmd, [userArg]);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "notes.js").write_text(
        "const { execSync } = require('child_process');\n"
        "// Never do: exec(`rm ${req.query.file}`)\n"
        'execSync("ls -la");\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "convert.js").write_text(
        "const { exec } = require('child_process');\n"
        "// security: allow-js-command-injection\n"
        "exec(`convert ${req.query.file} out.png`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsCommandInjectionGuard().applies(profile)


def test_applies_with_typescript(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsCommandInjectionGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        "const { exec } = require('child_process');\n"
        "exec(`convert ${req.query.file} out.png`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_js_command_injection_trailing_comment_sink_silent(tmp_path: Path) -> None:
    # #395 H1: a sink pattern in a TRAILING same-line comment must not fire.
    (tmp_path / "task.js").write_text(
        "const cmd = buildSafe();  // exec(`convert ${req.query.file} out.png`) - legacy path\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


# --- round-2 §D.1/§H.1: bind the sink to a child_process import (the 105-critical-FP fix) ----------

def test_silent_on_regexp_exec_no_child_process(tmp_path: Path) -> None:
    # FP-bait (§D.1, 21 critical FPs): `RegExp.prototype.exec()` is method-call string matching, not a
    # shell sink. The file does not import child_process, so nothing fires.
    (tmp_path / "parse.ts").write_text(
        "const re = /gitdir: (.+)\\/\\.git\\/worktrees\\//;\n"
        "const m = re.exec(content);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_mongoose_query_exec(tmp_path: Path) -> None:
    # FP-bait (§H.1, 84 critical FPs): a Mongoose query terminator `.exec()` on an ordinary model
    # receiver. No child_process import -> non-sink. (A receiver-name heuristic could not catch this.)
    (tmp_path / "roles.service.ts").write_text(
        "async findByRole(role) {\n"
        "  return this.roleModel.findOne({ role }).exec();\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_regex_exec_even_when_child_process_imported(tmp_path: Path) -> None:
    # The load-bearing binding case: a file that BOTH imports child_process for a real exec AND uses a
    # regex `.exec()`. Only the free bound `exec(...)` fires; the `re.exec(...)` method call does not.
    (tmp_path / "mixed.ts").write_text(
        "const { exec } = require('child_process');\n"
        "const re = /x(.+)/;\n"
        "const m = re.exec(userInput);\n"
        "exec(`rm -rf ${userInput}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].location.endswith("mixed.ts:4")  # the exec(`rm ...`) line, not the re.exec line


def test_flags_aliased_exec_import(tmp_path: Path) -> None:
    # An aliased named import (`exec as sh`) binds the local name `sh` to child_process.exec.
    (tmp_path / "run.ts").write_text(
        "import { exec as sh } from 'child_process';\n"
        "sh(`convert ${req.query.file} out.png`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"


def test_flags_namespace_module_exec(tmp_path: Path) -> None:
    # A namespace import (`import * as cp`) binds the module; `cp.exec(...)` is a member sink.
    (tmp_path / "run.ts").write_text(
        "import * as cp from 'child_process';\n"
        "cp.exec(`ping ${req.body.host}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert len(JsCommandInjectionGuard().run(tmp_path, profile)) == 1


def test_flags_inline_require_exec(tmp_path: Path) -> None:
    # `require('child_process').exec(...)` with no intermediate variable is still a real sink.
    (tmp_path / "run.js").write_text(
        "require('child_process').exec(`rm ${req.query.f}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsCommandInjectionGuard().run(tmp_path, profile)) == 1


@pytest.mark.parametrize(
    "quoted",
    [
        'const doc = "exec(`rm ${f}`)";',
        'const doc = "spawn(cmd, [arg], {shell: true})";',
    ],
    ids=["exec-in-a-string", "spawn-in-a-string"],
)
def test_silent_on_sink_spelled_out_in_a_string_literal(tmp_path: Path, quoted: str) -> None:
    # #749: a REAL binding of both names, then a string that only spells a sink out. The binder
    # mask always ignored strings, but the sink scan did not, so this fired CRITICAL. The sink's `(`
    # is string content in the anchor mask now.
    (tmp_path / "run.js").write_text(
        "const { exec, spawn } = require('child_process');\n" + quoted + "\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_flags_exec_nested_in_a_template_substitution(tmp_path: Path) -> None:
    # #749, the traded direction: a sink inside a `${...}` substitution is CODE. Anchoring against
    # plain `strip_strings=True` output (the binder mask) would blank it and drop this CRITICAL
    # silently, and no other test here would notice.
    (tmp_path / "run.js").write_text(
        "const { execSync } = require('child_process');\n"
        "res.send(`out: ${execSync(`ls ${req.query.d}`)}`);\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert [(f.location, f.rule) for f in findings] == [("run.js:2", "js-command-injection/tainted-exec")]


def test_quoted_sink_does_not_hide_a_real_one_on_the_same_line(tmp_path: Path) -> None:
    # #749: the quoted sink is skipped, not treated as the line's verdict, so the real one after it
    # is still examined.
    (tmp_path / "run.js").write_text(
        "const { exec } = require('child_process');\n"
        'log("exec(`rm ${f}`)"); exec(`convert ${req.query.file} out.png`);\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert [f.location for f in JsCommandInjectionGuard().run(tmp_path, profile)] == ["run.js:2"]


def test_sink_between_two_desyncing_substitutions_fires(tmp_path: Path) -> None:
    # #543, formerly the accepted trade #749 made (PR #1057 round-1 review): a `{` in a regex inside
    # one substitution opened a stray frame and a `}` in a later substitution closed it, so the file
    # ended balanced, neither restore cap fired, and the anchor mask dropped the real sink between
    # them (pair.js). The lexer now consumes a substitution's regexes and comments whole, so all three
    # placements fire. The lexer-level pin, in test_base.py, is
    # `test_strip_js_comments_anchor_mask_rebalancing_regex_pair_reads_as_code`.
    head = "const { execSync } = require('child_process');\n"
    opens = "const t = `a ${ s.replace(/{/g, '') } b`;\n"
    closes = "const u = `a ${ s.replace(/}/g, '') } b`;\n"
    sink = "execSync(`ls ${req.query.f}`);\n"
    (tmp_path / "pair.js").write_text(head + opens + sink + closes, encoding="utf-8")
    (tmp_path / "single.js").write_text(head + opens + sink, encoding="utf-8")
    (tmp_path / "after.js").write_text(head + opens + closes + sink, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"javascript"})
    locations = sorted(f.location for f in JsCommandInjectionGuard().run(tmp_path, profile))
    assert locations == ["after.js:4", "pair.js:3", "single.js:3"]


def test_silent_on_bare_exec_without_import(tmp_path: Path) -> None:
    # Documented false-negative trade-off (§H.1): a bare `exec(...)` whose name is NOT imported from
    # child_process is not proven to be the shell function, so it does not fire. This is the accepted
    # cost of removing 105 critical FPs — a real sink virtually always uses one of the import forms.
    (tmp_path / "run.js").write_text(
        "exec(`rm -rf ${userInput}`);\n", encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_silent_on_commented_out_import_binding(tmp_path: Path) -> None:
    # PR #480 review (FP regression): a commented-out `import { exec } from 'child_process'` must NOT
    # create a phantom binding that then fires on an unrelated later `exec(...)`. Bindings are resolved
    # from comment-stripped text.
    (tmp_path / "app.js").write_text(
        "// import { exec } from 'child_process';  // legacy, removed\n"
        "const exec = makeTemplateRenderer();\n"
        "exec(`<b>${userInput}</b>`);\n",  # a local `exec`, not child_process
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsCommandInjectionGuard().run(tmp_path, profile) == []


def test_flags_bare_spawnsync_shell_true(tmp_path: Path) -> None:
    # PR #480 review (FN): a bare-command `spawnSync(cmd, {shell:true})` on a bound spawnSync must fire
    # (spawnSync is a recognized sink family; `_BARE_SPAWN_CMD` matches spawnSync too).
    (tmp_path / "run.js").write_text(
        "const { spawnSync } = require('child_process');\n"
        "spawnSync(cmd, {shell: true});\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsCommandInjectionGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/spawn-shell-true-tainted"


def test_child_process_bindings_resolves_alias_and_module() -> None:
    # Direct unit test of the binding resolver (de-risks the import-parsing regexes).
    from agentsec.guards.js_command_injection import _child_process_bindings

    exec_names, spawn_names, module_names = _child_process_bindings(
        "import { exec as sh, spawnSync } from 'node:child_process';\n"
        "const cp = require('child_process');\n"
    )
    assert "sh" in exec_names
    assert "spawnSync" in spawn_names
    assert {"cp", "child_process"} <= module_names


# --- #480 review: binding shapes the resolver missed entirely -----------------------------------

@pytest.mark.parametrize(
    ("label", "source"),
    [
        # ESM lazy-loading — the mainstream Next.js / serverless form, and the headline miss.
        ("esm-dynamic-named", "const { exec } = await import('node:child_process');\n"),
        ("esm-dynamic-module", "const cp = await import('child_process');\n"),
        # TypeScript type annotation on the declarator.
        ("ts-annotated", "const cp: any = require('child_process');\n"),
        # A multi-declarator list — the binding is not adjacent to the `const`.
        ("multi-declarator", "const a = 1, cp = require('child_process');\n"),
        # Declare first, assign later.
        ("deferred", "let cp;\ncp = require('child_process');\n"),
    ],
)
def test_child_process_binding_shapes_all_resolve(tmp_path: Path, label: str, source: str) -> None:
    # Every one of these bound NOTHING before, so a tainted exec after them was reported 0 (#480
    # review). Named forms call `exec` free; module forms call it as a member.
    call = "exec(`ls ${req.query.d}`);\n" if "named" in label else "cp.exec(`ls ${req.query.d}`);\n"
    (tmp_path / f"{label}.ts").write_text(source + call, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert len(findings) == 1, label
    assert findings[0].rule == "js-command-injection/tainted-exec"


def test_optional_chained_module_call_resolves(tmp_path: Path) -> None:
    # `cp?.exec(...)` is the same sink as `cp.exec(...)`.
    (tmp_path / "run.js").write_text(
        "const cp = require('child_process');\ncp?.exec(`ls ${req.query.d}`);\n", encoding="utf-8"
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_widened_binders_keep_the_non_sink_exec_class_silent(tmp_path: Path) -> None:
    # The FP-bait direction: loosening the declaration keyword must NOT reopen the 105-FP class
    # this PR closed. None of these files import child_process at all.
    (tmp_path / "queries.js").write_text(
        "const m = /a(b)/.exec(`x ${y}`);\n"
        "const r = re.exec(`x ${y}`);\n"
        "const docs = await Model.find({ a: b }).exec(`${x}`);\n"
        "const { exec } = require('shelljs');\n"
        "exec(`ls ${req.query.d}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_string_literal_describing_the_wiring_does_not_bind(tmp_path: Path) -> None:
    # #480 second-pass review: dropping the `const|let|var` requirement (so deferred assignment and
    # multi-declarator lists bind) meant a string that merely DESCRIBES the wiring — a doc string, a
    # tutorial snippet — bound a real variable of the same name, producing a false CRITICAL on an
    # unrelated `cp.exec(...)`. Binder matches inside a string literal are now rejected.
    (tmp_path / "doc.ts").write_text(
        "const DOC = `const cp = require('child_process')`;\n"
        "const HINT = 'const cp = require(\"child_process\")';\n"
        "const cp = getSafeRunner();\n"
        "cp.exec(`ls ${req.query.d}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"})) == []


def test_stray_brace_does_not_hijack_the_destructure_binding(tmp_path: Path) -> None:
    # #480 second-pass review: `_NAMED_REQUIRE` was unanchored with an unbounded `{...}` capture, so
    # an earlier stray unmatched `{` — a regex literal like `/\{/`, common for template matching —
    # swallowed the text up to the real destructure and corrupted the binding. A genuinely dangerous
    # dynamic exec then reported ZERO.
    (tmp_path / "tpl.js").write_text(
        "const re = /\\{/;\n"
        "const { exec } = require('child_process');\n"
        "exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"


def test_multi_declarator_destructure_binds(tmp_path: Path) -> None:
    # #480 third-pass review: `_NAMED_REQUIRE`'s left anchor `(?:^|[;{}\n])` is a positive allowlist
    # of preceding punctuation, and a COMMA is not in it — so the second declarator of an ordinary
    # `const a = require('fs'), { exec } = require('child_process')` never bound and a real RCE sink
    # reported ZERO. The anchor is gone; `[^{}]*` alone carries the stray-brace fix.
    (tmp_path / "multi.js").write_text(
        "const fs = require('fs'), { exec } = require('child_process');\n"
        "exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].location == "multi.js:2"
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].severity == "critical"


def test_parenthesized_deferred_destructure_binds(tmp_path: Path) -> None:
    # #480 third-pass review: an OPEN PAREN was likewise missing from the anchor's allowlist, so the
    # parenthesized deferred destructure — the only legal way to write `{ x } = ...` as a statement —
    # never bound. Same silent CRITICAL.
    (tmp_path / "deferred.js").write_text(
        "let exec;\n"
        "({ exec } = require('child_process'));\n"
        "exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].location == "deferred.js:3"
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].severity == "critical"


def test_semicolon_separated_type_annotation_binds_the_declared_name(tmp_path: Path) -> None:
    # #480 review (Marconi). An inline TS object type separates members with `;`, and the un-anchored
    # binder's body excludes `;` (it must — that is what stops it running off the end of a statement).
    # So the body could not span the annotation, the engine advanced past it, and the LAST `ident:`
    # inside the annotation bound instead: measured `spawn`, not `cp`. The real RCE sink went
    # unreported on ORDINARY TypeScript, a detection `main` still makes. The declaration-anchored
    # binder owns this shape now; its body may span `;` and braces because `const` fixes the target.
    (tmp_path / "run.ts").write_text(
        "const cp: { exec: Function; spawn: Function } = require('child_process');\n"
        "cp.exec(`convert ${req.query.file} out.png`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert len(findings) == 1
    assert findings[0].location == "run.ts:2"
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].severity == "critical"


def test_semicolon_annotation_variants_bind(tmp_path: Path) -> None:
    # The same shape through `let` and through the `node:` specifier — both bound the annotation
    # member rather than the declared name before the split.
    (tmp_path / "a.ts").write_text(
        "let cp: { exec: Function; spawn: Function } = require('child_process');\n"
        "cp.exec(`ping ${req.query.host}`);\n",
        encoding="utf-8",
    )
    (tmp_path / "b.ts").write_text(
        "const cp: { a: 1; b: 2 } = require('node:child_process');\n"
        "cp.exec(`ping ${req.query.host}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert sorted(f.location for f in findings) == ["a.ts:2", "b.ts:2"]


def test_annotation_member_name_does_not_become_a_module_binding(tmp_path: Path) -> None:
    # FP bait, the OTHER direction of the same defect — it was wrong both ways from one cause. With
    # `spawn` mis-bound as the child_process module, an unrelated `spawn.exec(...)` elsewhere in the
    # file fired a false CRITICAL while the real sink two lines up stayed silent. Only the real sink
    # may fire here. Pins the `{}` exclusion on the un-anchored body: without it `spawn` binds again.
    (tmp_path / "app.ts").write_text(
        "const cp: { exec: Function; spawn: Function } = require('child_process');\n"
        "cp.exec(`convert ${req.query.file} out.png`);\n"
        "spawn.exec(`echo ${req.body.msg}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert [f.location for f in findings] == ["app.ts:2"]


def test_multi_declarator_with_brace_annotation_still_binds(tmp_path: Path) -> None:
    # Regression guard for the fix itself, not for the original defect. Excluding `{}` from the
    # un-anchored body is what stops it binding an annotation member — but on its own it also drops
    # `const a = 1, cp: { x: 1 } = require(...)`, which DID bind before. Measured before adopting.
    # That is why the anchored pattern accepts a leading `,` as well as `const|let|var`.
    (tmp_path / "multi.ts").write_text(
        "const a = 1, cp: { x: 1 } = require('child_process');\n"
        "cp.exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert len(findings) == 1
    assert findings[0].location == "multi.ts:2"


def test_string_literal_describing_the_destructure_does_not_bind(tmp_path: Path) -> None:
    # FP bait for the anchor removal. The anchor incidentally blocked a destructure spelled out
    # INSIDE a string (`= 'const { exec } = require("child_process")'`), and the mask check did not
    # catch it because it probed the first BODY character — which is a space in `{ exec }`, and a
    # space is indistinguishable from blanked string content. The check now probes the `{` delimiter.
    (tmp_path / "doc.js").write_text(
        "const DOC = `const { exec } = require('child_process')`;\n"
        "const HINT = 'const { exec } = require(\"child_process\")';\n"
        "const exec = getSafeRunner();\n"
        "exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_regex_literal_spelling_out_the_wiring_does_not_bind(tmp_path: Path) -> None:
    # FP bait for the anchor removal. `strip_js_comments` keeps a REGEX literal as code, so its
    # quotes never open a string and the mask cannot blank them — a codemod/linter regex that spells
    # the wiring out would otherwise bind. The specifier must be genuine string content (the
    # `_specifier_is_a_real_string` gate), which also covers the module-binder family.
    (tmp_path / "codemod.js").write_text(
        "const NAMED = /x{ exec } = require('child_process')/;\n"
        "const MODULE = /x cp = require('child_process')/;\n"
        "const exec = getSafeRunner();\n"
        "const cp = getSafeRunner();\n"
        "exec(`ls ${req.query.dir}`);\n"
        "cp.exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_object_literal_named_exec_does_not_bind(tmp_path: Path) -> None:
    # FP bait: a bare `{ exec }` object literal is NOT a destructure — the require on the next line
    # is a separate statement, so nothing may bind `exec` as a child_process function.
    (tmp_path / "opts.js").write_text(
        "const opts = { exec };\n"
        "const mod = require('child_process');\n"
        "const { exec: other } = require('shelljs');\n"
        "exec(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def _jci(tmp_path: Path, src: str, name: str = "a.jsx") -> int:
    (tmp_path / name).write_text(src, encoding="utf-8")
    return len(JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})))


def test_js_command_injection_jsx_text_does_not_bind_a_sink(tmp_path: Path) -> None:
    # The #480 gate's Major, measured 0 -> 1. This is valid JSX whose AST holds only a
    # JSXExpressionContainer and a sibling JSXText node — no AssignmentExpression, no ObjectPattern,
    # no require() call. It renders as text and never executes, yet it bound `exec` and made the
    # unrelated real `exec(cmd)` below report a CRITICAL RCE.
    src = "function U() {\n  return <pre>{ exec } = require('child_process')</pre>;\n}\nexec(cmd);\n"
    assert _jci(tmp_path, src) == 0


@pytest.mark.parametrize(
    ("label", "src"),
    [
        # THE TRADED-AGAINST DIRECTION, and the reason this is a pattern-POSITION test rather than a
        # re-added allowlist: the previous anchor `(?:^|[;{}\n])` omitted `,` and `(`, silently
        # dropping two ordinary shapes and missing real RCE sinks. Every legal position must bind.
        ("declaration", "const { exec } = require('child_process');\nexec(cmd);\n"),
        ("after a semicolon", "let a = 1; const { exec } = require('child_process');\nexec(cmd);\n"),
        ("multi-declarator", "const fs = require('fs'), { exec } = require('child_process');\nexec(cmd);\n"),
        ("parenthesized deferred", "let exec;\n({ exec } = require('child_process'));\nexec(cmd);\n"),
        # Conditionally live code IS a real assignment (a genuine ObjectPattern), unlike JSX text.
        ("ternary", "cond ? { exec } = require('child_process') : null;\nexec(cmd);\n"),
    ],
)
def test_js_command_injection_every_legal_pattern_position_still_binds(
    tmp_path: Path, label: str, src: str
) -> None:
    assert _jci(tmp_path, src) == 1, label


# --- #480 fresh-eyes gate F1: the MODULE-binder axis is reachable from JSX text too -------------

@pytest.mark.parametrize(
    ("label", "binder"),
    [
        # The gate's F1: `_MODULE_BINDERS[-1]` (`<name> [: Type] = <source>`) was deliberately
        # un-anchored and is reachable from JSX text. The pattern-position fix landed on one axis
        # only. The gate reported the first three; all SIX measure 1 (a false CRITICAL) at the
        # pre-fix tip. (It also believed the `import`-keyword binders could not appear in JSX text.
        # They can; see the #576 section at the end of this file.)
        ("require", "cp = require('child_process')"),
        ("await import", "cp = await import('child_process')"),
        ("node: prefix", "cp = require('node:child_process')"),
        ("ts annotation", "cp: any = require('child_process')"),
        ("nested element", "cp = require('child_process')"),
        # JSX text separated from the tag by whitespace/newlines only — same JSXText node.
        ("multi-line text", "\ncp = require('child_process')\n"),
    ],
)
def test_js_command_injection_jsx_text_does_not_bind_a_module_name(
    tmp_path: Path, label: str, binder: str
) -> None:
    # The module-binder analogue of `test_string_literal_describing_the_wiring_does_not_bind`:
    # JSX character data spelling out the wiring must not bind `cp`, so the unrelated real
    # `cp.exec(...)` below (a Mongoose-style connection pool, NOT child_process) stays silent.
    tag = "span" if label == "nested element" else "pre"
    src = (
        f"function U() {{\n  return <div><{tag}>{binder}</{tag}></div>;\n}}\n"
        "const cp = pool;\n"
        "cp.exec(`ls ${req.query.d}`);\n"
    )
    assert _jci(tmp_path, src) == 0, label


@pytest.mark.parametrize(
    ("label", "src"),
    [
        # THE TRADED-AGAINST DIRECTION for F1, and the reason this is a `>`-only test rather than a
        # reuse of `_opens_a_binding_pattern`: an assignment TARGET, unlike a destructuring PATTERN,
        # may legally follow a value. Built against a shadow variant that DOES reuse the pattern
        # predicate, 7 of these 9 go 1 -> 0 — seven silently missed RCE sinks. That is what makes
        # this parametrize load-bearing rather than decorative; keep it whenever the deny-set for
        # the module-binder axis is touched.
        ("brace-less if", "let cp;\nif (x) cp = require('child_process');\n"),
        ("brace-less else", "let cp;\nif (x) y(); else cp = require('child_process');\n"),
        ("brace-less for", "let cp;\nfor (const i of xs) cp = require('child_process');\n"),
        ("brace-less while", "let cp;\nwhile (x) cp = require('child_process');\n"),
        ("arrow expression body", "let cp;\nconst f = () => cp = require('child_process');\n"),
        # Mainstream semicolon-less style: ASI makes a bare identifier a legal predecessor.
        ("ASI after a bare let", "let cp\ncp = require('child_process')\n"),
        # `=>` is a `>` that MUST still admit the binder (the arrow carve-out).
        ("arrow across a newline", "let cp;\nconst f = () =>\n  cp = require('child_process');\n"),
        # A statement genuinely ending in `>` but terminated — the neighbour is `;`, not `>`.
        ("comparison then semicolon", "let cp;\nconst t = a > b;\ncp = require('child_process');\n"),
        ("JSX element then semicolon", "const el = <div>hi</div>;\nlet cp;\ncp = require('child_process');\n"),
    ],
)
def test_js_command_injection_every_legal_assignment_target_still_binds(
    tmp_path: Path, label: str, src: str
) -> None:
    assert _jci(tmp_path, src + "cp.exec(`ls ${req.query.d}`);\n") == 1, label


@pytest.mark.parametrize(
    "neighbour", [".", ":", ",", ";", "!", "?", "-", "*", "/", "%", "#", "@", "—", "é"]
)
def test_js_command_injection_jsx_prose_neighbour_is_an_accepted_fp(
    tmp_path: Path, neighbour: str
) -> None:
    # #480 gate F2, ACCEPTED and pinned rather than fixed (option (a)). JSX character data whose
    # destructure does NOT sit flush against the element's `>` still binds — `:`, `,` and `;` are
    # simultaneously legal JS pattern positions and ordinary prose punctuation, so no
    # character-position predicate can separate JSX character data from code. The only complete fix
    # is blanking JSX text spans, whose obvious implementation (tag-depth counting) collides with
    # `a < b` and TS generics and would silently suppress every real binder after one unbalanced
    # `<` — a missed-RCE mechanism strictly worse than this FP. Asserting 1 pins the residual class
    # as KNOWN: if a later change narrows it, this test fails loudly and gets updated deliberately
    # instead of the class quietly drifting.
    src = (
        f"function U() {{\n  return <pre>Usage{neighbour} {{ exec }} = require('child_process')</pre>;\n}}\n"
        "const exec = q.exec;\n"
        "exec(`ls ${req.query.d}`);\n"
    )
    assert _jci(tmp_path, src) == 1, neighbour


def test_js_command_injection_promisify_of_local_exec_shadow_is_an_accepted_fp(
    tmp_path: Path,
) -> None:
    # PR #915 review F2, ACCEPTED and pinned rather than narrowed. `_PROMISIFY_BARE` binds
    # `promisify(exec)`/`promisify(execSync)` by LITERAL token, deliberately bypassing the file's own
    # resolved `exec_names` -- that is what catches `exec` arriving via a wildcard/namespace import the
    # binder can't unpack (see the resolver docstring). The residual cost: a LOCAL function literally
    # named `exec` that is NOT child_process, once promisified and called with taint, fires a false
    # CRITICAL -- but only in a file that already imports child_process (the `_scan` gate). This is far
    # narrower than the 105-FP member-call class the file header eliminated, and narrowing the resolver
    # to resolve `exec` would re-open the wildcard/namespace-import gap it exists to close. Asserting 1
    # pins the residual as KNOWN: a later change that narrows it fails here and gets updated
    # deliberately instead of the class quietly drifting.
    src = (
        "const cp = require('child_process');\n"
        "function exec(query) { return db.run(query); }\n"
        "const execAsync = promisify(exec);\n"
        "execAsync(`report ${userInput}`);\n"
    )
    assert _jci(tmp_path, src, name="app.js") == 1


@pytest.mark.slow
def test_js_command_injection_module_binder_is_not_superlinear(tmp_path: Path) -> None:
    # #480 gate F3: the module binder was `({_IDENT})\s*(?::\s*[^=;\n]+?)?\s*=` — two `\s*` around an
    # optional group make the split of a whitespace run ambiguous, so every partition of it is tried:
    # O(n^2). Measured end-to-end on one ordinary `.js` file with a run of blank lines — 0.003s /
    # 0.096s / 1.42s / 22.4s at n = 10k / 40k / 160k against 0.003s / 0.011s / 0.042s pre-PR, a clean
    # 4x-per-doubling and a 533x regression that never crashes and never reports. `corpus-scan` clones
    # arbitrary public repos, so the input is untrusted. Folding the trailing `\s*` into the
    # annotation body makes it linear: 22.4s -> 0.13s.
    #
    # Actual <0.2s serial; 15.0s mirrors the open-redirect ceiling — headroom for
    # `-n auto`/CI contention, still far under the >20s a quadratic form takes at this n.
    import time

    n = 160_000
    (tmp_path / "big.js").write_text(
        "const cp = require('child_process')\nsomeIdentifier\n" + "\n" * n
        + "cp.exec(`ls ${req.query.d}`)\n",
        encoding="utf-8",
    )
    start = time.monotonic()
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert time.monotonic() - start < 15.0
    assert len(findings) == 1  # and it still finds the real sink


@pytest.mark.parametrize("kind", ["comma-object-map", "paren-call-list"])
def test_js_command_injection_many_colons_on_one_line_is_not_superlinear(
    tmp_path: Path, kind: str
) -> None:
    # The SECOND quadratic in this binder, on a different input shape from the blank-line one the
    # test above pins. The pattern anchors on the target identifier, so every `ident:` in the file is
    # a candidate, and an unbounded annotation body lets each run forward to the line's `;` hunting an
    # `=` that never comes. An ordinary generated one-line object map is enough - an i18n table, an
    # enum, a minified config - and it produces ZERO findings the whole time, so it reads as a clean
    # scan that merely takes forever. Measured 0.30 / 1.20 / 4.76 / 21.35 s at n = 2k / 4k / 8k / 16k
    # unbounded (a clean 4x per doubling) against 0.006 / 0.013 / 0.026 / 0.053 s bounded.
    #
    # The `(`-anchored binder added for parameter defaults (#906) reaches the SAME capped body from a
    # different anchor, so a `(`-dense call list is a parametrized input here rather than a redundant
    # second gate — it rides the same `_ANNOTATION_MAX` cap.
    #
    # A growth class, not a wall-clock ceiling (tests/_timing.py). This was one 15 s single shot at
    # n=32k, sized from a linux reading (~0.55 s); the self-hosted Windows leg runs the same scan in
    # 3.5 s idle, so the ceiling had ~4x of real room and the leg's own `-n 3` load spent it. A ratio
    # cancels machine speed. Measured on that host (2026-11-06): healthy 0.05-0.08 / 0.11-0.18 /
    # 0.22-0.37 / 0.45-0.77 s at n = 1k / 2k / 4k / 8k (linear); with `[^=\n]{0,200}` put back to
    # the unbounded `[^=\n]*`, 0.19-0.32 / 0.80-1.32 / 3.1-5.1 / 12.2-19.9 s, read as quadratic.
    from tests._timing import assert_growth

    def src(n: int) -> str:
        if kind == "comma-object-map":
            return "const MAP = {" + ",".join(f"k{i}:{i}" for i in range(n)) + "};\n// see the child_process docs\n"
        # paren-call-list — every `(` is a candidate for the `(`-anchored binder's capped body
        return "".join(f"f{i}(k{i}:{i});" for i in range(n)) + "\n// child_process docs\n"

    sizes = [1_000, 2_000, 4_000, 8_000]
    roots = {}
    for n in sizes:
        roots[n] = tmp_path / f"n{n}"
        roots[n].mkdir()
        (roots[n] / "map.js").write_text(src(n), encoding="utf-8")
    findings: dict[int, list[object]] = {}

    def scan(n: int) -> None:
        findings[n] = list(JsCommandInjectionGuard().run(roots[n], mkprofile(roots[n], features={"javascript"})))

    assert_growth(scan, sizes, expected="linear")
    # a candidate-dense line with no require() binds nothing
    assert all(findings[n] == [] for n in sizes), kind


@pytest.mark.parametrize(
    ("shape", "hijacked"),
    [
        ("() => any", "any"),                    # arrow at the end of the annotation
        ("{ a: () => 1, b: 2 }", "b"),           # arrow-typed member before a comma
    ],
)
def test_js_command_injection_arrow_annotation_binds_the_wrong_name(
    tmp_path: Path, shape: str, hijacked: str
) -> None:
    # #598, ACCEPTED and pinned rather than fixed here. `=>` carries the `=` that BOTH annotation
    # bodies stop at, so the declaration-anchored pattern fails on the real target and a later
    # identifier binds instead. Wrong in both directions from one cause, which is why it is pinned in
    # both: the real `cp.exec(...)` RCE sink is MISSED, and an unrelated call on the hijacked name
    # fires a false CRITICAL in its place.
    #
    # NOT #577/#578 despite the family resemblance — those attribute the root cause to the bare
    # binder's missing left anchor, and `080732f7` added exactly that anchor while these two shapes
    # survived it unchanged. A fix derived from either issue would not close this.
    #
    # The second shape is ordinary TypeScript (an option bag with one callback-typed member), so this
    # class is NOT confined to the contrived function-type-annotated require the first shape looks
    # like. Asserting the wrong behaviour pins it as KNOWN: when #598 is fixed this test fails loudly
    # and gets updated deliberately, instead of the class quietly drifting either way.
    src = (
        f"const cp: {shape} = require('child_process');\n"
        f"export function q(req) {{ return {hijacked}.exec(req.query.pattern); }}\n"
        "export function run(req) { return cp.exec(`convert ${req.query.file} out.png`); }\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    # Exactly one finding, and it is the WRONG one: line 2 (the unrelated call), not line 3 (the sink).
    assert [f.location.rsplit(":", 1)[-1] for f in findings] == ["2"]


def test_js_command_injection_over_cap_annotation_binds_the_wrong_name(tmp_path: Path) -> None:
    # #598's sibling, same family, also pinned rather than fixed. An annotation longer than
    # `_ANNOTATION_MAX` cannot be spanned by the body, so an identifier INSIDE the annotation binds
    # instead of the declared name. The comment at the regex said "will not bind" through five review
    # rounds; it is a mis-bind, not a plain miss, and it is wrong in both directions exactly like the
    # arrow shapes above. Accepted because reaching the cap takes a construction, not a codebase.
    annot = ", ".join(f"field{i}: string" for i in range(20))   # 328 chars, over the 200 cap
    assert len(annot) > 200, "fixture must actually exceed the cap or it proves nothing"
    src = (
        f"const cp: {{ {annot}, mode: Fn }} = require('child_process');\n"
        "export function q(req) { return field9.exec(req.query.pattern); }\n"
        "export function run(req) { return cp.exec(`convert ${req.query.file} out.png`); }\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert [f.location.rsplit(":", 1)[-1] for f in findings] == ["2"]   # the unrelated call, not the sink


def test_promisify_bare_exec_binding_fires(tmp_path: Path) -> None:
    # `promisify(exec)` — Node's idiomatic way to get a Promise-returning exec — was not
    # resolved at all before this fix, so `execAsync(userCmd)` never fired despite being exactly as
    # dangerous as `exec(userCmd, cb)`. This is the pattern apisec-inc/mcp-audit's own MCP-server
    # scanner was built specifically to catch (a real-world source found during this project's MCP
    # research, see research-queue.json id apisec-inc-mcp-audit).
    (tmp_path / "server.js").write_text(
        "const { exec } = require('child_process');\n"
        "const { promisify } = require('util');\n"
        "const execAsync = promisify(exec);\n"
        "async function runTool(args) {\n"
        "  return execAsync(`gh issue view ${args.issueId}`);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-command-injection/tainted-exec"
    assert findings[0].severity == "critical"
    assert findings[0].location == "server.js:5"


def test_promisify_execsync_bare_binding_fires(tmp_path: Path) -> None:
    (tmp_path / "server.ts").write_text(
        "import { execSync } from 'child_process';\n"
        "import { promisify } from 'util';\n"
        "const run = promisify(execSync);\n"
        "run(`echo ` + userInput);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"typescript"}))
    assert len(findings) == 1


def test_promisify_qualified_module_member_fires(tmp_path: Path) -> None:
    # `util.promisify(child_process.exec)` — the module-qualified form, not a destructured import.
    # The qualifier must resolve against this file's OWN `module_names` (a real child_process
    # binding), not just any identifier spelled `.exec` — see the FP-bait test below.
    (tmp_path / "server.js").write_text(
        "const cp = require('child_process');\n"
        "const util = require('util');\n"
        "const execAsync = util.promisify(cp.exec);\n"
        "execAsync(`convert ${req.query.file} out.png`);\n",
        encoding="utf-8",
    )
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].location == "server.js:4"


def test_promisify_unrelated_qualifier_does_not_bind(tmp_path: Path) -> None:
    # FP bait: `promisify(mongooseQuery.exec)` — `.exec` on a non-child_process object (the exact
    # Mongoose-query shape this whole guard's binding-resolution design exists to reject elsewhere)
    # must not become an exec sink just because it flows through promisify. The child_process import
    # is load-bearing: without it `_scan`'s whole-file gate returns before the resolver runs, and this
    # test passed with the `module_names` qualifier check deleted (measured 0 -> 0). With it, deleting
    # that check fires the false CRITICAL (0 -> 1), so the test now pins the check it names.
    (tmp_path / "app.js").write_text(
        "const cp = require('child_process');\n"
        "const util = require('util');\n"
        "const runQuery = util.promisify(mongooseQuery.exec);\n"
        "runQuery(`ls ${req.query.dir}`);\n",
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_promisify_bound_exec_with_static_arg_does_not_bind(tmp_path: Path) -> None:
    # FP bait: the promisified name IS a real exec sink, but a fully static call must still not
    # fire -- same "no interpolation, no fire" rule the guard already applies to bare exec/execSync.
    (tmp_path / "server.js").write_text(
        "const { exec } = require('child_process');\n"
        "const { promisify } = require('util');\n"
        "const execAsync = promisify(exec);\n"
        'execAsync("git status");\n',
        encoding="utf-8",
    )
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


# --- #577 / #578: an identifier label or property key + colon hijacked the un-anchored binder -------
# Root cause: `_MODULE_BINDERS[-1]` carried an optional, statement-spanning annotation group with no
# left anchor, so on `<a>: <b> = require('child_process')` finditer bound the leftmost `ident:` — a
# label or property key — and consumed the real target `<b>`. Dropping the group binds the identifier
# immediately left of `= <source>`, the true assignment target. Both directions are pinned here per
# review-doctrine Rule 1 (the FN must start firing AND the FP must go silent), and neither shape was
# test-pinned before this fix — only prose in the module docstring recorded the FN as a known miss.


@pytest.mark.parametrize(
    ("label", "prelude"),
    [
        # A `switch`/`case` arm — the issue's headline shape. The label `WIN` used to bind and the real
        # target `cp` was consumed, so the tainted `cp.exec(...)` below reported 0 (silent missed RCE).
        ("switch case label", "switch (process.platform) {\n  case WIN: cp = require('child_process'); break;\n}\n"),
        ("switch default label", "switch (k) {\n  default: cp = require('child_process');\n}\n"),
        ("labelled statement", "outer: cp = require('child_process');\n"),
        # A ternary whose else-branch is the assignment — `cp` sits after a `:` with no left anchor.
        ("ternary branch", "const v = f ? g : cp = require('child_process');\n"),
        # A string case label already worked (no bare `ident:` to hijack) — pinned as the control.
        ("string case label", "switch (k) {\n  case 'sh': cp = require('child_process');\n}\n"),
    ],
)
def test_js_command_injection_label_or_colon_does_not_hijack_the_binder(
    tmp_path: Path, label: str, prelude: str
) -> None:
    # #577 (narrowing / silent missed RCE). The bound name is `cp`; a tainted `cp.exec(...)` must fire.
    src = prelude + "export function run(req) { return cp.exec(`convert ${req.query.file} out.png`); }\n"
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1, label
    assert findings[0].rule == "js-command-injection/tainted-exec"


@pytest.mark.parametrize(
    ("label", "prelude", "key"),
    [
        # #578 (widening / false CRITICAL). The property KEY must NOT bind as a module name; only the
        # inner assignment target `cp` is child_process. A later `<key>.exec(...)` is an ordinary object
        # member call — a non-sink — so the guard must stay silent on it.
        ("object property key", "const o = { mode: cp = require('child_process') };\n", "mode"),
        ("object property key alt", "const o = { mod: cp = require('child_process') };\n", "mod"),
    ],
)
def test_js_command_injection_object_property_key_does_not_bind_as_module(
    tmp_path: Path, label: str, prelude: str, key: str
) -> None:
    src = prelude + "export function run(req) { return " + key + ".exec(`convert ${req.query.file} out.png`); }\n"
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == [], label


def test_js_command_injection_benign_object_key_is_not_a_false_positive(tmp_path: Path) -> None:
    # FP-bait neighbour to the #578 fix: an object entry whose value is NOT child_process must never
    # bind its key, regardless of the `key: target = call()` shape.
    src = (
        "const o = { mode: cfg = loadConfig() };\n"
        "export function run(req) { return mode.exec(`convert ${req.query.file} out.png`); }\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


@pytest.mark.parametrize(
    "annotation",
    [
        "any",                              # plain TS annotation on the declarator
        "Record<string, Array<number>>",    # nested generic — HIT on `main`, MISS in the reverted #480 rounds
        "Promise<Map<string, string>>",     # the other nested generic from the #480 revert trade table
    ],
)
def test_js_command_injection_annotated_declaration_still_binds(tmp_path: Path, annotation: str) -> None:
    # Regression guard for the #480 revert's win: dropping the un-anchored binder's annotation group
    # must not touch annotated DECLARATIONS, which the declaration-anchored binder owns. The nested
    # generics are the exact idiomatic-TS shapes the reverted rewrite rounds broke (HIT -> MISS).
    src = (
        f"const cp: {annotation} = require('child_process');\n"
        "export function run(req) { return cp.exec(`convert ${req.query.file} out.png`); }\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1, annotation
    assert findings[0].rule == "js-command-injection/tainted-exec"


@pytest.mark.parametrize(
    ("label", "signature"),
    [
        # A function/arrow PARAMETER default with a type annotation is `name: Type = init` — the same
        # shape as a declaration, but anchored by `(` (first param) or `,` (later param), not by
        # const|let|var. PR #906 review found that dropping the un-anchored binder's annotation group
        # regressed the FIRST/SOLE annotated parameter default HIT -> MISS (the un-anchored pattern then
        # binds the TYPE, `any`, not the param). The `(`-anchor on the declaration-anchored binder keeps
        # it a HIT. Narrowing-direction regression guard: the sole-annotated arrow, sole-annotated
        # fn-decl and nested-generic cases MISS (0 findings) against a binder without the `(` anchor, so
        # they discriminate; the later-annotated param (bound by the pre-existing `,` anchor) and the
        # sole param with no annotation (bound by the un-anchored pattern) are controls that HIT
        # regardless. A dependency-injection seam that shells out is real code.
        ("arrow, sole annotated param", "const run = (cp: any = require('child_process')) =>"),
        ("fn-decl, sole annotated param", "export function run(cp: any = require('child_process'))"),
        ("arrow, later annotated param", "const run = (req, cp: any = require('child_process')) =>"),
        ("arrow, sole param no annotation", "const run = (cp = require('child_process')) =>"),
        # A nested generic in the parameter's type must span the annotation body just like a declaration.
        ("fn-decl, nested-generic param", "export function run(cp: Map<string, string> = require('child_process'))"),
    ],
)
def test_js_command_injection_annotated_parameter_default_still_binds(
    tmp_path: Path, label: str, signature: str
) -> None:
    src = signature + " {\n  return cp.exec(`convert ${req.query.file} out.png`);\n}\n"
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1, label
    assert findings[0].rule == "js-command-injection/tainted-exec"


def test_js_command_injection_paren_anchor_does_not_bind_unrelated_names(tmp_path: Path) -> None:
    # FP-bait for the WIDENING direction of the `(` anchor (review-doctrine Rule 1). Binding the
    # parameter default `cp` must not leak to an UNRELATED sink: only `cp` receives child_process, so a
    # later `other.exec(tainted)` on a name the binder never saw stays silent. The `(` anchor can only
    # bind the identifier the concrete `require('child_process')` is actually assigned to, so it cannot
    # manufacture a false CRITICAL on ordinary parenthesized code.
    src = (
        "export function run(cp: any = require('child_process')) {\n"
        "  return other.exec(`convert ${req.query.file} out.png`);\n"
        "}\n"
    )
    (tmp_path / "app.ts").write_text(src, encoding="utf-8")
    assert JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


@pytest.mark.parametrize("annotation", ["", ": any"])
def test_js_command_injection_paren_in_jsx_text_is_an_accepted_fp(tmp_path: Path, annotation: str) -> None:
    # Accepted-FP pin, same class as `test_js_command_injection_jsx_prose_neighbour_is_an_accepted_fp`
    # (#480 gate F2): a parenthesized assignment inside JSX CHARACTER DATA is not flush against the
    # element's `>` (the `(` sits between), so no character-position predicate can tell it from code and
    # `_not_after_a_jsx_tag` cannot deny it. The non-annotated form has bound via the un-anchored binder
    # since before this PR; the annotated form is bound by the `(`-anchored declaration binder added for
    # the parameter-default fix. Both are the accepted residual, NOT a regression: the only complete fix
    # is blanking JSX text spans, which was judged worse (see the F2 pin's rationale). Pinned == 1 so a
    # later narrowing fails here loudly and is updated deliberately instead of drifting.
    src = (
        f"export function C() {{ return (<pre>(cp{annotation} = require('child_process'))</pre>); }}\n"
        "export function run(req) { return cp.exec(`convert ${req.query.file} out.png`); }\n"
    )
    (tmp_path / "app.tsx").write_text(src, encoding="utf-8")
    findings = JsCommandInjectionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1, annotation


# --- #576: JSX text spelling out an `import` or a declaration bound a phantom name ------------------
# The three `import`-keyword module binders, `_NAMED_IMPORT` and the declaration-anchored binder were
# exempt from every position test on the belief that JSX character data could not reach them. JSXText
# is any run of characters except `{ < > }`, so it can, and the un-anchored binder's identifier-level
# test passed whenever a keyword sat between the `>` and the name. Every binder is now tested at the
# statement's leading keyword (`_at_import_position` / `_assignment_can_bind`). All of the FP cases
# below measured 1 (a false CRITICAL) before the fix.

_JCI_POOL_SINK = "const cp = getPool();\ncp.exec(`SELECT ${req.query.q}`);\n"   # a DB pool, not child_process
_JCI_FREE_SINK = "exec(`ls ${req.query.d}`);\n"                                  # unbound unless a binder binds it
_JCI_MEMBER_SINK = "cp.exec(`ls ${req.query.d}`);\n"
_JCI_JSX_LAYOUTS = {
    "flush": "<pre>SNIPPET</pre>",
    "own line": "<pre>\n  SNIPPET\n</pre>",
    "prose before": "<pre>Run: SNIPPET</pre>",
    "word before": "<p>Add SNIPPET first</p>",
}


def _jci_in_jsx(snippet: str, layout: str) -> str:
    sink = _JCI_FREE_SINK if "{ exec }" in snippet else _JCI_POOL_SINK
    body = _JCI_JSX_LAYOUTS[layout].replace("SNIPPET", snippet)
    return "function U() {\n  return <div>" + body + "</div>;\n}\n" + sink


@pytest.mark.parametrize("layout", list(_JCI_JSX_LAYOUTS))
@pytest.mark.parametrize(
    "snippet",
    [
        "import * as cp from 'child_process'",
        "import cp from 'child_process'",
        "import cp = require('child_process')",    # TS; also matched by the un-anchored binder as `cp = ...`
        "import { exec } from 'child_process'",    # `_NAMED_IMPORT`
    ],
)
def test_js_command_injection_jsx_text_import_does_not_bind(tmp_path: Path, snippet: str, layout: str) -> None:
    # FP direction. An import is a module-level item, so its keyword may never follow a JSX tag's
    # `>`, and may follow a value only across a newline (ASI). That rejects all four layouts.
    assert _jci(tmp_path, _jci_in_jsx(snippet, layout), name="a.tsx") == 0, (snippet, layout)


@pytest.mark.parametrize("layout", ["flush", "own line"])
@pytest.mark.parametrize(
    "snippet",
    [
        "const cp = require('child_process')",
        "let cp = require('child_process')",
        "var cp = require('child_process')",
        "const cp = await import('node:child_process')",
        "const { exec } = require('child_process')",    # `_NAMED_REQUIRE` via the keyword branch
    ],
)
def test_js_command_injection_jsx_text_declaration_does_not_bind(
    tmp_path: Path, snippet: str, layout: str
) -> None:
    # FP direction, the branch the issue did not list and arguably the most natural snippet a docs page
    # renders. The `>` test now runs at the `const`/`let`/`var` keyword, not at the identifier or `{`
    # after it. Only these two layouts: with prose before the keyword this is the accepted F2 class
    # (an assignment may follow a value), pinned in `..._jsx_text_residual_is_an_accepted_fp` below.
    assert _jci(tmp_path, _jci_in_jsx(snippet, layout), name="a.tsx") == 0, (snippet, layout)


@pytest.mark.parametrize(
    ("label", "src"),
    [
        # THE TRADED-AGAINST DIRECTION for #576 (review-doctrine Rule 1). The fix narrows binding, so
        # every real module-level position must still bind. Before #576 the suite had no fixture for
        # `import cp from` or `import cp = require(...)` at all. Built against a shadow variant that
        # reuses `_opens_a_binding_pattern` for `import` (the issue's own suggestion; newline-blind),
        # 9 of these 19 go 1 -> 0: every semicolon-less row (after an import, `'use client'`, a call,
        # an array, a regex, a shebang, and the real component) plus `export import`. That is what
        # makes this parametrize load-bearing: keep it whenever `_at_import_position` changes.
        ("import default at column 0", "import cp from 'child_process';\n" + _JCI_MEMBER_SINK),
        ("import-equals at column 0", "import cp = require('child_process');\n" + _JCI_MEMBER_SINK),
        ("no-semicolon import after an import",
         "import fs from 'fs'\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("no-semicolon named import after an import",
         "import fs from 'fs'\nimport { exec } from 'child_process'\n" + _JCI_FREE_SINK),
        ("'use client' then import", "'use client'\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("import after a call", "dotenv.config()\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("import after an array", "const a = [1]\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("import after a regex literal", "const r = /re/g\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("import after a function", "function f() {}\nimport cp from 'child_process'\n" + _JCI_MEMBER_SINK),
        ("semicolon on the same line",
         "import fs from 'fs'; import cp from 'child_process';\n" + _JCI_MEMBER_SINK),
        ("after a block comment", "/* license */ import cp from 'child_process';\n" + _JCI_MEMBER_SINK),
        ("after a BOM", "\ufeffimport cp from 'child_process';\n" + _JCI_MEMBER_SINK),
        ("after a shebang", "#!/usr/bin/env node\nimport cp from 'child_process';\n" + _JCI_MEMBER_SINK),
        ("declare module body",
         "declare module 'x' {\n  import cp = require('child_process')\n  " + _JCI_MEMBER_SINK + "}\n"),
        ("export import-equals", "export import cp = require('child_process');\n" + _JCI_MEMBER_SINK),
        ("brace-less if var", "if (x) var cp = require('child_process');\n" + _JCI_MEMBER_SINK),
        ("const declaration", "const cp = require('child_process');\n" + _JCI_MEMBER_SINK),
        ("const destructure", "const { exec } = require('child_process');\n" + _JCI_FREE_SINK),
        ("a real .jsx component",
         "import React from 'react'\nimport { exec } from 'child_process'\n"
         "export function App({ q }) {\n  exec(`grep ${q}`)\n  return <pre>done</pre>\n}\n"),
    ],
)
def test_js_command_injection_every_legal_import_position_still_binds(
    tmp_path: Path, label: str, src: str
) -> None:
    assert _jci(tmp_path, src) == 1, label


@pytest.mark.parametrize(
    ("ending", "statement", "filename"),
    [
        ("TS generic", "type T = Array<string>", "a.ts"),
        ("self-closing JSX element", "const A = () => <div/>", "a.jsx"),
        ("closed JSX element", "const a = <div>x</div>", "a.jsx"),
    ],
)
@pytest.mark.parametrize(
    ("label", "binder", "sink"),
    [
        ("import", "import cp from 'child_process'\n", _JCI_MEMBER_SINK),
        ("named import", "import { exec } from 'child_process'\n", _JCI_FREE_SINK),
        ("const declaration", "const cp = require('child_process')\n", _JCI_MEMBER_SINK),
        ("const destructure", "const { exec } = require('child_process')\n", _JCI_FREE_SINK),
        ("bare assignment", "cp = require('child_process')\n", _JCI_MEMBER_SINK),
    ],
)
def test_js_command_injection_gt_ending_statement_then_asi_binder_is_an_accepted_fn(
    tmp_path: Path, ending: str, statement: str, filename: str, label: str, binder: str, sink: str
) -> None:
    # ACCEPTED FALSE NEGATIVE, widened by #576 and pinned rather than left silent. A statement that ENDS
    # in a `>` with no semicolon, a TS generic's or a JSX element's, followed under ASI by the binder on
    # the next line, no longer binds: a JSX opening tag, a child element's closing tag (JSX text follows
    # it inside a parent) and a type-argument list all close with `>`, and no character-position test
    # can separate them from a statement end. Before #576 this covered the bare `cp = require(...)` form
    # only (`_not_after_a_jsx_tag`); it now covers the import and declaration forms too. The JSX-element
    # rows went 1 -> 0 in #576 and were kept deliberately (#1060 round-1 review, R1-1): denying a closing
    # tag's `>` only on the same line recovers them but reopens the #576 FP for JSX text on its own line
    # after a child element (`<pre><b>x</b>` newline `const cp = require(...)`). It is a missed RCE, so
    # asserting 0 pins it as KNOWN and a later change has to adopt it deliberately.
    assert _jci(tmp_path, statement + "\n" + binder + sink, name=filename) == 0, (ending, label)
    # ...and a `;` after the `>` restores it.
    assert _jci(tmp_path, statement + ";\n" + binder + sink, name=filename) == 1, (ending, label)


@pytest.mark.parametrize(
    ("label", "jsx_text", "sink"),
    [
        # Text that starts after an expression container or an HTML entity: `}` and `;` are legal
        # predecessors of a real import.
        ("after an expression container", "<pre>{x}import cp from 'child_process'</pre>", _JCI_POOL_SINK),
        ("after an entity", "<pre>&nbsp;import cp from 'child_process'</pre>", _JCI_POOL_SINK),
        # An identifier then a newline then `import` is ASI-legal, so prose on the line above passes.
        ("prose on the line above", "<p>Add this\nimport cp from 'child_process'</p>", _JCI_POOL_SINK),
        # A declaration after prose: an assignment may follow a value, so only `>` is denied (F2).
        ("prose before a declaration", "<pre>Run: const cp = require('child_process')</pre>", _JCI_POOL_SINK),
        # `export` before a declaration keyword is not stepped over the way it is for `import`.
        ("export const", "<pre>export const cp = require('child_process')</pre>", _JCI_POOL_SINK),
    ],
)
def test_js_command_injection_jsx_text_residual_is_an_accepted_fp(
    tmp_path: Path, label: str, jsx_text: str, sink: str
) -> None:
    # ACCEPTED residual false positives after #576, the same structural limit as the F2 pin above: no
    # character-position predicate can tell these JSX text positions from code. Asserting 1 pins them as
    # KNOWN, so a later narrowing fails here and is adopted deliberately instead of drifting.
    src = "function U() {\n  return <div>" + jsx_text + "</div>;\n}\n" + sink
    assert _jci(tmp_path, src) == 1, label
