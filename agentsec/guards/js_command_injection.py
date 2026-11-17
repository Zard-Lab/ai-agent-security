"""Guard: no OS-command injection via a Node `child_process` shell sink (checklist §3b).

The JS/Node counterpart to agentsec's existing (Python-only) `command-injection` guard —
same requirement (a shell sink built from untrusted input is remote code execution), a
genuinely different code surface (Node's `child_process` module instead of `os`/`subprocess`),
so it extends the same `3b-command-injection` checklist item rather than duplicating it.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-078/CommandInjection.ql` +
`CommandInjectionCustomizations.qll` (verified against real fetched source): the sinks are
`child_process.exec()`/`exec()`/`execSync()` called with a command STRING built from
concatenation/template-literal interpolation, or `spawn(cmd, args, {shell: true})` where
`shell: true` turns `spawn`'s normally-safe array-argv form back into a shell command line —
`cmd`/an `args` element built the same way is exploitable the same way `exec` is.

The call must be an actual `child_process` function — resolved from the file's IMPORT BINDINGS, not
matched on the bare method name. Keying on `exec`/`spawn` alone flagged `regex.exec()` and Mongoose
`query.exec()` (105 critical FPs across two repos, none importing child_process); the only correct rule
(round-2 §D.1/§H.1) is: fire on a FREE call of a name imported from `child_process`/`node:child_process`
(`import { exec }`, `const { execSync: sh } = require(...)`), or a MEMBER call on a child_process MODULE
binding (`cp.exec(...)`, `child_process.exec(...)`, `require('child_process').exec(...)`). Every other
method-style `.exec(...)`/`.spawn(...)` is a non-sink. See `_child_process_bindings` / `_iter_sinks`.

Also resolves `promisify(exec)` / `util.promisify(child_process.exec)` bindings (both a bare-token
and a module-qualified form) as exec sinks — `const execAsync = promisify(exec); execAsync(userCmd)`
is exactly as dangerous as `exec(userCmd, cb)`. Added for the MCP-server population specifically
: a real MCP-server scanner (apisec-inc/mcp-audit) was built around this one pattern,
which this guard's binding resolver didn't cover despite already resolving every direct import form.
See `_PROMISIFY_BARE` / `_PROMISIFY_QUALIFIED`.

Fires CRITICAL on such a bound call when:

  * `exec`/`execSync` receives a **dynamic** command argument — a template-literal interpolation
    (`` `cmd ${x}` ``), a `+` concatenation, or a bare expression with no string literal at all
    (mirrors the precision philosophy of `command_injection.py`'s own `_is_dynamic`: it does not try to
    prove the specific value is request-derived, only that the command is NOT a fully static literal);
  * `spawn`/`spawnSync` sets `shell: true` AND whose command or an array-literal argument element is
    dynamic by the same test.

A fully static call — `execSync("ls -la")`, or `spawn("git", ["status"])` (no `shell: true`,
literal array args — the idiomatic safe form) — does NOT fire, nor does an unbound bare `exec(...)`
(a name not imported from child_process is not proven to be the shell function). The fix is array-form
spawn without a shell: `spawn("convert", [file, "out.png"])`.

Accepted false negatives (deliberate — the resolver handles the direct import/require forms a real sink
almost always uses; these rarer shapes are not resolved, PR #480 review): a mixed default+named import
(`import cp, { exec } from 'child_process'`), a default+namespace import, a two-step destructure
(`const cp = require('child_process'); const { exec } = cp;`), a property-assignment binding
(`const exec = require('child_process').exec;`), child_process reached through an intermediate variable
(`const cp2 = cp; cp2.exec(...)`), a dynamic `require(varName)`, and an optional-chaining call
(`exec?.(cmd)`). Extending the resolver to these is future work; a real shell sink virtually always uses
a direct form.

Two further accepted false negatives come from the BINDER-POSITION tests that keep JSX character data
from binding (`_opens_a_binding_pattern` / `_not_after_a_jsx_tag` / `_at_import_position`, #480 gate
and #576). Both are narrow, both were measured, and any ordinary formatting defeats them:

  * a destructure whose `{` directly follows a value — `)`, `]`, `>`, a quote, or a non-keyword
    identifier — is never bound. No such position is a legal destructuring-pattern site in JS, so this
    costs nothing on real code; it is listed because it IS the guard's contract, not an implementation
    detail.
  * a statement that ENDS in a `>` with no semicolon, a TypeScript generic's (`type T = Array<string>`,
    `let x: Map<K, V>`) or a JSX element's (`const A = () => <div/>`, `const a = <div>x</div>`),
    followed under ASI by a binder on the next line: a bare deferred `cp = require('child_process')`,
    and since #576 an `import` or a `const`/`let`/`var` declaration too (the `>` test now runs at the
    statement's keyword, so a keyword no longer restores it). A trailing `;` after the `>` does. A JSX
    opening tag, a child element's closing tag (JSX text follows it inside a parent) and a TS
    type-argument list all close with `>`, so no character-position test can separate them from a
    statement end. Denying a closing tag's `>` only on the same line was measured to recover the JSX
    rows and to reopen the #576 FP for JSX text on its own line after a child element, so the JSX form
    was kept as an accepted FN (#1060 review, R1-1). Pinned by
    `test_js_command_injection_gt_ending_statement_then_asi_binder_is_an_accepted_fn`.

Accepted FALSE POSITIVE (#480 gate F2 — documented, deliberately not fixed): JSX character data that
spells out a `require` destructure still binds when the text begins after ordinary PROSE PUNCTUATION —
`<pre>Usage. { exec } = require('child_process')</pre>`, and likewise for `: , ; ! ? - * / % # @` and
any non-ASCII neighbour. Only text flush against the element's `>` (or separated from it by whitespace
alone) is rejected. This is structural, not an oversight: `:`, `,` and `;` are simultaneously legal
JS pattern positions and ordinary prose punctuation, so NO character-position predicate can separate
JSX character data from code. The only complete fix is to blank JSX text spans the way string content
is blanked — and the obvious implementation (counting `<tag>`/`</tag>` depth) collides with `a < b`
and TS generics (`Map<string, string>`), where a single unbalanced `<` would silently suppress every
real binder in the rest of the file. That is a missed-RCE mechanism strictly worse than the false
positive it removes, so the class is accepted and pinned by
`test_js_command_injection_jsx_prose_neighbour_is_an_accepted_fp`.

#576 put every binder under a position test (the `import`-keyword binders, `_NAMED_IMPORT` and the
declaration forms had been exempt, so `<pre>import * as cp from 'child_process'</pre>` and
`<pre>const cp = require('child_process')</pre>` bound). The residual it leaves is the same structural
limit: JSX text that starts after an expression container or an HTML entity (`<pre>{x}import cp ...`,
`&nbsp;import cp ...`, since `}` and `;` legally precede an import), an `import` that begins a new line
under a line of prose (identifier ⏎ `import` is ASI-legal), and a declaration after prose or after
`export`. Pinned by `test_js_command_injection_jsx_text_residual_is_an_accepted_fp`. Suppress an
audited case with:

    execSync(cmd)  // security: allow-js-command-injection

Detection is deliberately single-line only (the call's opening paren and its dynamic
command/args must be on the same physical line) — matches the single-line-only convention
used by the other JS guards (`js-client-side-open-redirect`, `js-insecure-download-sensitive-file`)
to avoid the cross-statement bleed-through class of bug `js-system-prompt-injection` hit and
had to fix.
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
    js_anchor_is_code,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-command-injection"

# --- child_process binding resolution (round-2 §D.1/§H.1) -------------------------------------------
# The sink is a `child_process` shell function, NOT any method literally named exec/spawn. Keying on the
# bare method name matched `regex.exec()` and Mongoose `query.exec()` (105 critical FPs across two repos,
# none of which import child_process). So we resolve the file's child_process import bindings and fire
# ONLY on (a) a free call of a name imported from child_process, or (b) a member call on a binding of the
# child_process MODULE. Every other `.exec(...)`/`.spawn(...)` is a non-sink.
_MOD = r"['\"](?:node:)?child_process['\"]"
_IDENT = r"[A-Za-z_$][\w$]*"
_EXEC_TOKENS = frozenset({"exec", "execSync"})
_SPAWN_TOKENS = frozenset({"spawn", "spawnSync"})

# How a child_process value ARRIVES on the right-hand side of an assignment. Beyond `require`,
# ESM lazy-loading (`await import('node:child_process')`) is the mainstream Next.js / serverless
# form and bound nothing at all, so a tainted `exec(...)` after it went completely unreported
# (#480 review). The un-awaited `import(...)` is included too — it yields a Promise, so a direct
# member call on it is not real code, and firing there is the safe direction.
_CP_SOURCE = rf"(?:require|(?:await\s+)?import)\(\s*{_MOD}\s*\)"
# Module-binding forms:
#   `import * as cp from 'cp'` | `import cp from 'cp'` (default) | `import cp = require('cp')` (TS)
#   `<name> [: Type] = <source>` — deliberately WITHOUT requiring a `const|let|var` immediately
#   before the name, so it also covers a TS type annotation (`const cp: any = require(...)`), a
#   multi-declarator list (`const a = 1, cp = require(...)`), and deferred assignment
#   (`let cp;` … `cp = require(...)`). All four were silent (#480 review). The left lookbehind
#   keeps the name a whole identifier, not the tail of `obj.cp`.
#
# The annotation group's trailing `\s*` is FOLDED INTO the body, not written as
# `(?::\s*[^=;\n]+?)?\s*=` with a `\s*` on either side. Two `\s*` around an optional group make the
# split of a whitespace run ambiguous, so the engine tries every partition of it: O(n²) backtracking.
# Measured end-to-end `run()` on one ordinary `.js` file whose only unusual feature is a long run of
# blank lines: n=160,000 took 22.4 s (vs 0.04 s pre-PR — a 533x regression; 400 KB measured 136 s),
# and it never crashes and never reports — an audit that merely appears to hang. `corpus-scan` clones
# arbitrary public repos, so this input is untrusted. Folding the trailing `\s*` into the body makes
# the split unambiguous: 22.4 s → 0.12 s, byte-identical findings.
# Pinned by `test_js_command_injection_module_binder_is_not_superlinear` (#480 gate F3).
#
# The body is ALSO length-bounded, and that is a SECOND quadratic, on a different input shape. The
# pattern anchors on the TARGET identifier, so every `ident:` in the file is a candidate, and an
# unbounded `[^=;\n]*` lets each one run forward to the line's `;` hunting an `=` that never comes.
# An ordinary one-line object map — a generated i18n table, an enum, a minified config — is enough:
# `const MAP = {k0:0,k1:1,…}` measured 0.30 / 1.20 / 4.76 / 21.35 s at n = 2k / 4k / 8k / 16k, a
# clean 4x per doubling, producing ZERO findings the whole time. No blank-line run and no adversarial
# construction needed, so the F3 fix above does not cover it. Capping the body makes each candidate's
# scan constant and the pass linear: 0.006 / 0.013 / 0.026 / 0.053 s over the same range, and 0.23 s
# at n = 64k where the unbounded form does not finish in minutes. End to end, 22.01 s → 0.112 s.
#
# The cap does NOT change which names bind: output is byte-identical to the unbounded form on every
# shape in the suite plus plain/annotated/multi-declarator/deferred/nested-generic. That is the point
# of choosing a bound over a restructure — the binder's semantics were rewritten four times on this
# branch and reverted, so the cap deliberately changes only how far one quantifier may travel.
#
# Accepted defect, and it is a MIS-BIND rather than a plain miss (#598): when the annotation between
# the `:` and the `=` is longer than the cap, the body cannot span it, so the engine advances and an
# identifier INSIDE the annotation binds instead of the declared name. Measured with a 328-char
# annotation: `const cp: { field0: string, …, mode: Fn } = require('child_process')` binds `field9`,
# so the real `cp.exec(...)` sink is silently missed AND an unrelated `field9.exec(...)` fires a false
# CRITICAL. Wrong in both directions, like the `;` case below — accepted only because reaching the cap
# takes a construction, not a codebase, where the `;` and `=>` shapes are ordinary TypeScript.
# ("will not bind" is what this said through five review rounds; it understated its own behaviour.)
#
# The assignment binder is SPLIT IN TWO because one pattern cannot serve both jobs. An inline TS
# object type separates its members with `;` — `const cp: { exec: Function; spawn: Function } =
# require('child_process')` is ordinary TypeScript — and the un-anchored body excludes `;` (it has to:
# `;` is what stops the body running off the end of a statement, the second quadratic above). So the
# body could not span the annotation, the engine advanced past it, and the LAST `ident:` inside the
# annotation matched instead. Measured: it bound `spawn`, not `cp`.
#
# That is wrong in BOTH directions from one cause, which is why it is split rather than documented:
# the real `cp.exec(...)` RCE sink went unreported, AND an unrelated `spawn.exec(...)` elsewhere in the
# same file fired a false CRITICAL in its place. `main` reports the sink (it binds nothing at all,
# the same non-discrimination that produces the 105 critical FPs this PR removes), so shipping it
# would have traded a real detection away on ordinary input. #480 review (Marconi).
#
#   1. DECLARATION-ANCHORED, below. `const|let|var <name>`, `, <name>` for a later declarator in a
#      multi-declarator list, or `(<name>` for a function/arrow PARAMETER default. All three are the
#      same `name : Type = init` shape; the anchor makes the target unambiguous, so this body may
#      freely span `;` and braces (`[^=\n]`) without being able to bind something else.
#   2. UN-ANCHORED, bare assignment only (`let cp;` … `cp = require(...)`), where no keyword or
#      punctuation anchor precedes the name. It carries NO annotation group at all. A `: Type`
#      annotation before `=` occurs only in a binding position pattern 1 already owns — a declaration,
#      a later declarator, or a parameter default — never at bare-statement, object-literal or label
#      position, where `<a>: <b> = <source>` is a LABELLED STATEMENT or an object-literal entry. An
#      optional annotation group here (`(?::\s*[^=;\n{}]{0,N})?`) had no left anchor, so on that shape
#      finditer bound the leftmost `ident:` — the label or property key — and consumed the real target:
#      the silent missed RCE of #577 (`case WIN: cp = require(...)`) and its mirror false CRITICAL #578
#      (`{ mode: cp = require(...) }`). Dropping the group makes the pattern bind the identifier
#      immediately left of `= <source>`, which is always the true assignment target, so `case WIN:`,
#      the object-literal entry and `f ? g : cp = require(...)` all bind `cp` now (#577/#578 fix).
#
# The `,\s*` and `\(\s*` alternatives on the anchored pattern are load-bearing, not decoration: they
# bind a later annotated declarator (`const a = 1, cp: { x: 1 } = require(...)`) and an annotated first
# parameter default (`(cp: any = require(...)) => …`, a dependency-injection testability seam that
# shells out — PR #906 review found that dropping the group alone regressed this HIT → MISS), now that
# the un-anchored binder carries no annotation body. Measured; the shape matrix is in the test file.
#
# Cost: one extra linear pass. Measured on the one-line object map at n = 4k/16k/64k, 0.030/0.116/0.457 s
# before and 0.060/0.253/0.941 s after — 2.1x constant factor, still a clean 2x per doubling, and the
# n=32,000 gate passes in under a second against its 15 s ceiling.
#
# Accepted defect, unchanged by the split and by the #577/#578 fix, and tracked in its OWN issue
# (#598 — a DIFFERENT root cause: #577/#578 were the un-anchored binder's optional annotation group
# letting a label/key hijack the match, closed by dropping that group; #598 is `=>` inside a
# DECLARATION annotation, which pattern 1 owns). `=>` contains the `=` the anchored body stops at, so
# that pattern fails on the real target and the un-anchored binder then binds a later identifier:
#
#   const cp: () => any = require('child_process');            binds `any`, not `cp`
#   const cp: { a: () => 1, b: 2 } = require('child_process'); binds `b`,   not `cp`
#
# Wrong in both directions in both shapes — the real sink is missed AND an unrelated `any.exec(...)` /
# `b.exec(...)` fires a false CRITICAL. The second shape is ordinary TypeScript (an option bag with one
# callback-typed member), so this is NOT the contrived case the first shape looks like. Both are pinned
# as accepted defects in the test file rather than left silent. Admitting `=>` into the ANCHORED body
# alone was measured to close the second shape entirely and the first shape's missed sink, at parity on
# adversarial input — see #598 for the measurements and for what it does not close.
_ANNOTATION_MAX = 200
# The `import`-keyword binders get the import-statement position test, the assignment binders below
# get the assignment one (#576). Named rather than sliced by index so a tuple edit cannot silently move
# a binder from one test to the other.
_IMPORT_BINDERS = (
    re.compile(rf"import\s+\*\s+as\s+({_IDENT})\s+from\s+{_MOD}"),
    re.compile(rf"import\s+({_IDENT})\s+from\s+{_MOD}"),
    re.compile(rf"import\s+({_IDENT})\s*=\s*require\(\s*{_MOD}\s*\)"),
)
_MODULE_BINDERS = _IMPORT_BINDERS + (
    # 1. Declaration-anchored (incl. `(`-anchored parameter defaults) — body may span `;` and braces.
    re.compile(
        rf"(?:\b(?:const|let|var)\s+|,\s*|\(\s*)({_IDENT})\s*"
        rf"(?::\s*[^=\n]{{0,{_ANNOTATION_MAX}}})?=\s*{_CP_SOURCE}"
    ),
    # 2. Un-anchored — deferred assignment only; NO annotation group (a `: Type` annotation is a
    #    declaration's, owned by pattern 1; here it only let a label/key hijack the match, #577/#578).
    re.compile(rf"(?<![\w$.])({_IDENT})\s*=\s*{_CP_SOURCE}"),
)

# `const execAsync = promisify(exec)` / `util.promisify(child_process.exec)` — Node's idiomatic way
# to turn the callback-style exec into a Promise-returning function. The bound identifier is
# functionally an exec sink: `execAsync(userCmd)` shells out exactly like `exec(userCmd, cb)`, but
# none of the `_MODULE_BINDERS`/`_NAMED_IMPORT` forms above resolve it, since promisify's return
# value is not itself a child_process import. A real-world MCP-server scanner (apisec-inc/mcp-audit)
# was built specifically to catch this one pattern, which is what surfaced the gap here.
# Two argument shapes for promisify's own argument:
#   (a) a bare token — `promisify(exec)` / `promisify(execSync)` — resolved against `_EXEC_TOKENS`
#       directly, not against the file's own resolved `exec_names`, so it also catches the case
#       where `exec` arrived via a wildcard/namespace import this file's own binder can't unpack
#       (`import * as cp from 'child_process'; promisify(cp.exec)` is shape (b) below instead).
#   (b) a qualified member access — `promisify(child_process.exec)` / `promisify(cp.exec)` — the
#       qualifier is checked against the file's own resolved `module_names` before accepting it,
#       so an unrelated `promisify(someOtherThing.exec)` does not false-positive.
_PROMISIFY_BARE = re.compile(
    r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*=\s*(?:util\.)?promisify\s*\(\s*(exec|execSync)\s*\)"
)
_PROMISIFY_QUALIFIED = re.compile(
    r"\b(?:const|let|var)\s+(" + _IDENT + r")\s*=\s*(?:util\.)?promisify\s*\(\s*"
    r"(" + _IDENT + r")\.(exec|execSync)\s*\)"
)
# Named-binding forms: `import { ... } from 'cp'` | `const { ... } = require('cp')` |
# `const { exec } = await import('cp')` (DOTALL: multi-line). Same reasoning as above — the
# declaration keyword is optional so a deferred/multi-declarator destructure also binds.
_NAMED_IMPORT = re.compile(rf"import\s*\{{([^}}]*)\}}\s*from\s+{_MOD}", re.DOTALL)
# The brace body may not contain another `{`. With an unbounded `[^}]*` body, an earlier stray
# unmatched `{` — a regex literal like `/\{/`, common for template matching — swallowed the text
# up to the real destructure and corrupted the binding, so a genuinely dangerous dynamic `exec()`
# reported ZERO (#480 second-pass review). `[^{}]*` alone rules that whole class out: any hijack
# would have to swallow the real destructure's own `{`, which the body class forbids.
#
# There is deliberately NO left anchor. An allowlist of preceding punctuation
# (`(?:^|[;{}\n])`) is stricter than the hijack it was rebutting and silently dropped two
# ordinary JS shapes — a multi-declarator list (`const fs = require('fs'), { exec } =
# require('child_process')`, preceded by `,`) and a parenthesized deferred destructure
# (`({ exec } = require('child_process'))`, preceded by `(`) — so a real RCE sink reported ZERO
# (#480 third-pass review). A binder sitting inside a STRING literal is rejected by the
# `_in_string` mask check instead, which is the correct axis for that concern.
_NAMED_REQUIRE = re.compile(rf"\{{([^{{}}]*)\}}\s*=\s*{_CP_SOURCE}", re.DOTALL)
# Characters that END A VALUE. A `{` opening a destructuring PATTERN can never follow one: after an
# identifier, a `)`, a `]`, a string delimiter or a JSX `>`, the next `{` is a block, a JSX
# expression container, or nothing at all — never a binding.
#
# This is the deny side of the question the removed left anchor got wrong in both directions. The
# old allowlist `(?:^|[;{}\n])` omitted `,` and `(` and so dropped two ordinary JS shapes (a
# multi-declarator list and a parenthesized deferred destructure), silently missing real RCE sinks.
# Removing it entirely then let JSX TEXT bind: `<pre>{ exec } = require('child_process')</pre>` is
# valid JSX whose AST holds only a JSXExpressionContainer and a sibling JSXText node — no
# assignment, no require call, nothing executed — yet it bound `exec` and made a later real
# `exec(cmd)` report a CRITICAL (#480 gate).
#
# Enumerating what cannot precede a pattern is derivable from the grammar and complete in a way the
# allowlist was not: every construct that legally introduces one (statement start, `;`, `{`, `}`,
# `(`, `,`, `=`, `&&`, `||`, `?`, `:`, `return`, `const`/`let`/`var`) ends in a character outside
# this set.
_VALUE_ENDING = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$)]>'\"`")
# ...except that a DECLARATION KEYWORD also ends in identifier characters, and is the single most
# common thing to precede a pattern (`const { exec } = require(...)`). So an identifier-char
# neighbour is resolved to its whole WORD before deciding — the same rule, and for the same reason,
# as `guards/base.py`'s string-opener test: one character cannot tell `const {` from `foo {`.
_PATTERN_PRECEDING_KEYWORDS = frozenset({"const", "let", "var", "return", "yield", "await", "of", "in"})


def _opens_a_binding_pattern(text: str, brace: int) -> bool:
    """True if the `{` at `brace` can be the start of a destructuring pattern."""
    j = brace - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    if j < 0:
        return True  # start of input
    if text[j] not in _VALUE_ENDING:
        return True  # `;` `{` `}` `(` `,` `=` `&` `|` `?` `:` — all legal pattern positions
    if not (text[j].isalnum() or text[j] in "_$"):
        return False  # `)` `]` `>` or a quote: a value ended here, so this `{` is not a pattern
    word, start = _word_ending_at(text, j)
    # A keyword is the statement's first token, so the JSX test belongs on IT, not on the `{`:
    # `<pre>const { exec } = require('child_process')</pre>` passes the keyword check (#576).
    return word in _PATTERN_PRECEDING_KEYWORDS and _not_after_a_jsx_tag(text, start)


def _word_ending_at(text: str, j: int) -> tuple[str, int]:
    """The identifier-character run that ends at index `j` (inclusive), and its start index."""
    end = j + 1
    while j >= 0 and (text[j].isalnum() or text[j] in "_$"):
        j -= 1
    return text[j + 1:end], j + 1


def _not_after_a_jsx_tag(text: str, pos: int) -> bool:
    """True unless the token at `pos` directly follows a JSX tag's closing `>`.

    Applied at the bound identifier of a bare assignment, and at the KEYWORD when a declaration
    keyword precedes the identifier or the destructure's `{` (`_assignment_can_bind`,
    `_opens_a_binding_pattern`; #576): the keyword is the statement's first token, so it is the one
    JSX text sits flush against.

    The MODULE-binder axis (`cp = require('child_process')`, whose left anchor `ae8bfcdb` removed)
    is reachable from JSX character data exactly like `_NAMED_REQUIRE` was — `<pre>cp =
    require('child_process')</pre>` is a JSXText node, nothing executed — but it needs a MUCH weaker
    test than `_opens_a_binding_pattern`, and reusing that one here is a proven trap.

    An assignment TARGET, unlike a destructuring PATTERN, may legally follow a value: `if (x) cp =
    require(...)` follows `)`, the brace-less `else`/`for`/`while` bodies and an arrow expression
    body do too, and `let cp` ⏎ `cp = require(...)` (mainstream semicolon-less style) follows a bare
    identifier under ASI. Denying the whole `_VALUE_ENDING` set here was measured to kill six real
    RCE sinks 1 → 0 (#480 gate F1). Soundness on the `{` axis does not transfer to this one.

    The only character that can never precede an assignment target — `a > cp = ...` is not valid
    JS, `>` binds tighter than `=` so the target is invalid — but does precede JSX character data is
    a NON-ARROW `>`. `=>` is excluded because an arrow expression body is a real binder shape.

    Accepted false negative (narrow, deliberate): a statement that ENDS in a `>` with no semicolon,
    a TypeScript generic's (`type T = Array<X>` / `let x: Map<string, string>`) or a JSX element's
    (`const A = () => <div/>`), followed under ASI by a binder on the next line: a bare deferred
    `cp = require('child_process')`, and since #576 a `const`/`let`/`var` declaration or an `import`
    too. A JSX opening tag, a child element's closing tag and a TS type-argument list all close with
    `>`, and no character-position test can separate them from a statement end; the JSX-text FP is
    the common shape, and the ASI pair needs a semicolon-less file whose binder sits below such a
    statement. A `;` after the `>` restores it.
    """
    j = pos - 1
    while j >= 0 and text[j].isspace():
        j -= 1
    return not (j >= 0 and text[j] == ">" and not (j >= 1 and text[j - 1] == "="))


# ECMA-262 LineTerminator. ASI inserts a `;` only across one of these, which is what lets
# `_at_import_position` tell `foo()` ⏎ `import ...` (code) from `Run: import ...` on one line (prose).
_LINE_TERMINATORS = frozenset("\n\r\u2028\u2029")
_DECLARATION_KEYWORDS = frozenset({"const", "let", "var"})


def _prev_significant(text: str, pos: int) -> tuple[int, bool]:
    """Index of the last non-whitespace character before `pos` (-1 at start of input), and whether a
    line terminator lies between. A BOM counts as whitespace: `read()` keeps it, and `str.isspace()`
    is False for it, so a BOM-prefixed file would otherwise start with a non-space character."""
    j, newline = pos - 1, False
    while j >= 0 and (text[j].isspace() or text[j] == "\ufeff"):
        newline = newline or text[j] in _LINE_TERMINATORS
        j -= 1
    return j, newline


def _at_import_position(text: str, kw: int) -> bool:
    """True if the `import` keyword at `kw` can begin an import declaration (#576).

    JSX character data is any run of characters except `{ < > }`, so it can spell out `import`. The
    import binders were exempt from every position test on the opposite belief, so
    `<pre>import * as cp from 'child_process'</pre>` bound `cp` and made an unrelated `cp.exec(...)`
    fire CRITICAL. A static ImportDeclaration (and TS `import x = require(...)`) is a module-level
    item, so by ECMA-262 ASI rule 1 its keyword may follow only:
      * start of input, or `;` / `{` / `}` on any line (a `{` opens a TS `declare module` body);
      * the word `export` (`export import cp = require(...)`), itself tested the same way;
      * any other token ONLY ACROSS A NEWLINE. `foo()` ⏎ `import ...` is semicolon-less code, while
        `foo() import ...` on one line is a SyntaxError and so can only be prose;
    and never a non-arrow `>`, which is how JSX text begins both flush (`<pre>import`) and on its own
    line (`<pre>` ⏎ `import`). That `>` rule is `_not_after_a_jsx_tag`'s, with the same accepted
    false negative: a statement ending in a TS generic's or a JSX element's `>`, then the import
    under ASI.

    `_opens_a_binding_pattern` is NOT reusable here. It is newline-blind, and a shadow variant using it
    took 9 of the 19 rows in `test_js_command_injection_every_legal_import_position_still_binds` from
    1 to 0: every semicolon-less import (after another import, `'use client'`, a call, `[1]`, a regex
    literal, a shebang) and `export import`.
    """
    j, newline = _prev_significant(text, kw)
    if j < 0 or text[j] in ";{}":
        return True
    if text[j] == ">" and not (j >= 1 and text[j - 1] == "="):
        return False
    if text[j].isalnum() or text[j] in "_$":
        word, start = _word_ending_at(text, j)
        if word == "export":
            return _at_import_position(text, start)
    return newline


def _assignment_can_bind(text: str, ident: int) -> bool:
    """Position test for an assignment binder whose target identifier starts at `ident` (#576).

    `_not_after_a_jsx_tag` at the identifier sees only the token right before it. When that token is
    a declaration keyword (`<pre>const cp = require(...)</pre>`), or `import` (TS
    `<pre>import cp = require(...)</pre>`, which the un-anchored binder matches as
    `cp = require(...)`), the keyword is exactly what legitimately precedes a binding, so the test
    passed. It moves to the statement's first token, the keyword, instead. Every other neighbour
    (`,`, `(`, `else`, a bare identifier under ASI) keeps the identifier-level test it always had,
    so the accepted F2 classes are unchanged.
    """
    j, _ = _prev_significant(text, ident)
    if j >= 0 and (text[j].isalnum() or text[j] in "_$"):
        word, start = _word_ending_at(text, j)
        if word == "import":
            return _at_import_position(text, start)
        if word in _DECLARATION_KEYWORDS:
            return _not_after_a_jsx_tag(text, start)
    return _not_after_a_jsx_tag(text, ident)


# One destructured entry: `exec` | `exec as sh` (import) | `exec: sh` (require).
_ENTRY = re.compile(rf"({_IDENT})\s*(?:as|:)\s*({_IDENT})|({_IDENT})")

# A call site: an optional `<receiver>.` then a callee name then `(`. The negative lookbehind keeps a
# free `exec(` distinct from a method `foo.exec(` (group 1 present == member call) and stops a chained
# `x.y.exec(` / `q.findOne().exec()` from matching at all (the `.` before `exec` fails the lookbehind).
# `?.` is accepted alongside `.` so optional-chained `cp?.exec(...)` resolves like `cp.exec(...)`
# (#480 review).
_ANY_CALL = re.compile(rf"(?<![\w$.])(?:({_IDENT})\s*\??\.\s*)?({_IDENT})\s*\(")
# Inline `require('child_process').exec(...)` — a module member with no intermediate variable (the `.exec`
# is preceded by `)`, so `_ANY_CALL` cannot see it; matched separately).
_INLINE_REQUIRE_CALL = re.compile(rf"require\(\s*{_MOD}\s*\)\s*\.\s*({_IDENT})\s*\(")

_SHELL_TRUE = re.compile(r"\bshell\s*:\s*true\b")

# A template-literal argument that actually interpolates (`` `cmd ${x}` ``) — the JS analogue
# of the Python guard's f-string check.
_TEMPLATE_INTERP = re.compile(r"`[^`]*\$\{[^}]*\}[^`]*`")
# A string literal glued to something else via `+` — the JS analogue of the Python guard's
# concatenation check.
_CONCAT = re.compile(r"""['"`]\s*\+|\+\s*['"`]""")

# `spawn(<bare identifier>,` / `spawnSync(<bare identifier>,` — the command argument is a
# variable/expression, not a literal. Both spawn and spawnSync are recognized sink families, so this
# must match both (PR #480 review — a bare-cmd `spawnSync(cmd, {shell:true})` was otherwise missed).
_BARE_SPAWN_CMD = re.compile(r"\bspawn(?:Sync)?\s*\(\s*([A-Za-z_$][\w$.]*)\s*,")


def _child_process_bindings(
    text: str, mask: str | None = None
) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Resolve the file's `child_process` import bindings.

    Returns `(exec_names, spawn_names, module_names)`:
      * `exec_names`  — local names bound to child_process's exec/execSync FUNCTIONS
        (`import { exec } from 'child_process'`, `const { execSync: sh } = require('child_process')`).
      * `spawn_names` — likewise for spawn/spawnSync.
      * `module_names`— local names bound to the child_process MODULE (`import * as cp`, `import cp from`,
        `const cp = require(...)`) PLUS the literal `child_process` (its canonical receiver name, so a
        bare `child_process.exec(...)` still resolves without an explicit import binding).

    Parsed over the whole text so a multi-line import block is captured; the call scan stays single-line.
    """
    def _in_string(index: int) -> bool:
        # `strip_js_comments(..., strip_strings=True)` blanks string CONTENT to spaces while keeping
        # delimiters and layout, so a position that is a space in the mask but not in the source is
        # string content.
        return mask is not None and 0 <= index < len(mask) and mask[index] == " " and text[index] != " "

    def _specifier_is_a_real_string(m: re.Match[str]) -> bool:
        """The matched binder's `'child_process'` specifier must be genuine STRING content.

        A REGEX LITERAL that spells the wiring out — `/x{ exec } = require('child_process')/`, the
        kind of thing a codemod/linter/bundler carries — is code to `strip_js_comments`, not a
        string, so its quotes never open a string literal and the specifier stays unblanked in the
        mask. Requiring the specifier to be blanked rejects it while every genuine binder passes
        (verified against division-vs-regex ambiguity: `a / b`, `x.replace(/a/g, '')`, `url.split('/')`,
        `}`-then-`/`). The specifier is the LAST `child_process` in the match for every binder pattern.
        No mask ⇒ no evidence ⇒ accept."""
        if mask is None:
            return True
        return _in_string(m.start() + m.group(0).rindex("child_process"))

    exec_names: set[str] = set()
    spawn_names: set[str] = set()
    module_names: set[str] = {"child_process"}
    for binder in _MODULE_BINDERS:
        # EVERY binder is position-tested (#576). JSX character data is any run of characters except
        # `{ < > }`, so it spells out `import cp from 'child_process'` or `const cp = require(...)` as
        # easily as a bare `cp = require(...)`. An earlier exemption for the `import`-keyword and
        # declaration-anchored binders rested on the belief that they could not appear there, and
        # let all of those bind. Each binder kind gets the test its grammar allows, applied at the
        # statement's leading keyword rather than at the bound identifier: `_at_import_position` for
        # an import declaration, `_assignment_can_bind` (a `>`-only test, because an assignment TARGET
        # may legally follow a value; `_opens_a_binding_pattern` is unsound here) for the rest. The
        # declaration-anchored binder's `(` alternative in JSX prose stays the accepted F2 class (the
        # `(` sits between the `>` and the identifier; see
        # `test_js_command_injection_paren_in_jsx_text_is_an_accepted_fp`).
        imported = binder in _IMPORT_BINDERS
        for m in binder.finditer(text):
            if _in_string(m.start(1)) or not _specifier_is_a_real_string(m):
                continue
            if imported:
                in_code = _at_import_position(text, m.start())
            else:
                in_code = _assignment_can_bind(text, m.start(1))
            if in_code:
                module_names.add(m.group(1))
    for brace_re in (_NAMED_IMPORT, _NAMED_REQUIRE):
        for block in brace_re.finditer(text):
            # Test the destructure's opening `{` (group 1 is always preceded by it), NOT the first
            # body character: the body commonly opens with a space (`{ exec }`), and a space is
            # indistinguishable from blanked string content in the mask, so a `{` inside a string
            # would slip through. The `{` delimiter itself is unambiguous.
            if _in_string(block.start(1) - 1) or not _specifier_is_a_real_string(block):
                continue
            # `_NAMED_IMPORT` is position-tested like the other import binders (#576: JSX text can
            # spell out `import { exec } from 'child_process'`). The require form's `{` gets the
            # pattern-position test, which also tests what precedes a declaration keyword.
            if brace_re is _NAMED_IMPORT:
                if not _at_import_position(text, block.start()):
                    continue
            elif not _opens_a_binding_pattern(text, block.start(1) - 1):
                continue
            for entry in block.group(1).split(","):
                em = _ENTRY.search(entry.strip())
                if not em:
                    continue
                orig = em.group(1) or em.group(3)      # source name (exec/execSync/spawn/spawnSync)
                local = em.group(2) or em.group(3)     # local name (alias, or same as source)
                if orig in _EXEC_TOKENS:
                    exec_names.add(local)
                elif orig in _SPAWN_TOKENS:
                    spawn_names.add(local)
    for m in _PROMISIFY_BARE.finditer(text):
        if _in_string(m.start(1)):
            continue
        exec_names.add(m.group(1))
    for m in _PROMISIFY_QUALIFIED.finditer(text):
        if _in_string(m.start(1)) or m.group(2) not in module_names:
            continue
        exec_names.add(m.group(1))
    return frozenset(exec_names), frozenset(spawn_names), frozenset(module_names)


def _iter_sinks(
    line: str,
    exec_names: frozenset[str],
    spawn_names: frozenset[str],
    module_names: frozenset[str],
) -> list[tuple[str, int]]:
    """Yield `(family, paren_index)` for each real child_process sink call on `line`.

    `family` is `"exec"` or `"spawn"`; `paren_index` is the index of the call's opening `(`. A call is a
    sink only when it is a FREE call of a bound function name (`exec_names`/`spawn_names`) or a MEMBER
    call on a module binding (`module_names`). Any other `.exec(...)`/`.spawn(...)` (regex, ORM query) is
    skipped — that is the whole D.1/H.1 fix."""
    out: list[tuple[str, int]] = []
    for m in _ANY_CALL.finditer(line):
        receiver, callee = m.group(1), m.group(2)
        paren = m.end() - 1
        if receiver is None:
            if callee in exec_names:
                out.append(("exec", paren))
            elif callee in spawn_names:
                out.append(("spawn", paren))
        elif receiver in module_names:
            if callee in _EXEC_TOKENS:
                out.append(("exec", paren))
            elif callee in _SPAWN_TOKENS:
                out.append(("spawn", paren))
    for m in _INLINE_REQUIRE_CALL.finditer(line):
        callee = m.group(1)
        paren = m.end() - 1
        if callee in _EXEC_TOKENS:
            out.append(("exec", paren))
        elif callee in _SPAWN_TOKENS:
            out.append(("spawn", paren))
    return out


def _arg_after(line: str, paren: int) -> str:
    """Return the argument text from just after `paren` to the line end (trailing `)` trimmed).
    Good enough for the single-line calls this guard targets — mirrors command_injection.py."""
    return line[paren + 1:].rstrip().rstrip(")")


def _is_dynamic(arg: str) -> bool:
    """An argument is "dynamic" (not proven-static) if it is a template-literal interpolation,
    a `+` concatenation, or has no string literal at all (a bare variable/expression) — the
    same structural test `command_injection.py::_is_dynamic` uses for Python, translated to JS
    string syntax (`'`/`"`/`` ` ``)."""
    a = arg.strip()
    if not a:
        return False
    if _TEMPLATE_INTERP.search(a):
        return True
    if "'" not in a and '"' not in a and "`" not in a:
        return True
    return bool(_CONCAT.search(a))


def _spawn_args_tainted(line: str) -> bool:
    """True if `spawn`'s command argument or an array-literal argument ELEMENT is dynamic."""
    if _BARE_SPAWN_CMD.search(line):
        return True
    for m in re.finditer(r"\[([^\]]*)\]", line):
        for elem in m.group(1).split(","):
            if _is_dynamic(elem):
                return True
    return False


class JsCommandInjectionGuard(Guard):
    id = "js-command-injection"
    title = "No OS-command injection via a Node child_process shell sink"
    area = "Code safety"

    # js_command_exec.js: child_process.exec() with a template-literal command referencing
    # req.query -> fires js-command-injection.
    canary_plant = CanaryPlant(
        files={
            "js_command_exec.js": (
                "const { exec } = require('child_process');\n"
                "app.get('/convert', (req, res) => {\n"
                "  exec(`convert ${req.query.file} out.png`);\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-command-injection/tainted-exec"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        if "child_process" not in text:
            # No child_process mention ⇒ no shell sink and no bindings (the literal `child_process`
            # receiver can't appear either). Skips the whole §H.1 Mongoose `.exec()` cluster and every
            # regex-`.exec()` file before any per-line work.
            return out
        # strip_js_comments blanks a TRAILING `// ...` comment too (not just a whole-line one),
        # string/regex-literal aware — the old `^\s*//` check let a trailing comment mentioning a
        # sink false-fire (#395 H1). Resolve bindings from the STRIPPED text so a commented-out/JSDoc
        # `import { exec } from 'child_process'` cannot create a phantom binding that then fires on an
        # unrelated later `exec(...)` (PR #480 review). The comment-only view keeps the inline pragma visible.
        stripped = strip_js_comments(text)
        # The second argument is a string-blanked MASK used only to reject a binder match that
        # sits INSIDE a string literal. The binder patterns no longer require a `const|let|var` (so
        # deferred assignment and multi-declarator lists bind), which means a string that merely
        # DESCRIBES the wiring — a doc string, a tutorial snippet, an error message — bound a real
        # variable of the same name and produced a false CRITICAL on an unrelated `cp.exec(...)`
        # (#480 second-pass review). It has to be a MASK, not the scanned text: blanking strings
        # outright also erases the `'child_process'` module literal the patterns match on.
        exec_names, spawn_names, module_names = _child_process_bindings(
            stripped, strip_js_comments(text, strip_strings=True)
        )
        view_lines = comment_view(text, "js").splitlines()  # same length: comments only (#424)
        code_lines = stripped.splitlines()
        # The binder mask above is for binders only. Sinks get the anchor mask (#749), which keeps
        # `${...}` substitution code live: a sink spelled out in a string (`"exec(`rm ${f}`)"`) is
        # not a call, while `` `${execSync(cmd)}` `` is, and plain `strip_strings=True` would have
        # blanked that one too. Only the sink's `(` is tested, so the inline
        # `require('child_process').exec(...)` form still fires, and the argument checks below
        # still read the strings-intact `line`.
        mask_lines = strip_js_comments(text, strip_strings=True, keep_substitutions=True).splitlines()
        rows = zip(view_lines, code_lines, mask_lines, strict=True)
        for i, (view_line, line, mask_line) in enumerate(rows, start=1):
            if _PRAGMA in view_line:
                continue
            for family, paren in _iter_sinks(line, exec_names, spawn_names, module_names):
                if not js_anchor_is_code(line, mask_line, paren):
                    continue
                if family == "exec":
                    if _is_dynamic(_arg_after(line, paren)):
                        out.append(self._exec_finding(root, f, i))
                        break
                elif _SHELL_TRUE.search(line) and _spawn_args_tainted(line):
                    out.append(self._spawn_finding(root, f, i))
                    break
        return out

    def _exec_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This child_process exec/execSync call receives a command string built from "
                "template-literal interpolation or `+` concatenation. An attacker who controls "
                "the interpolated value controls the shell command (e.g. `; rm -rf /`), giving "
                "remote code execution on the host."
            ),
            remediation=(
                "Use array-form spawn/execFile without a shell: "
                '`spawn("convert", [file, "out.png"])` (no shell string, no `shell: true`). '
                "Never build a shell command string from request/model input. If this call is "
                "audited-safe, suppress with `// security: allow-js-command-injection`."
            ),
            rule="js-command-injection/tainted-exec",
            standards=["OWASP:A03", "CWE-78"],
        )

    def _spawn_finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This spawn() call sets `shell: true` and passes a non-literal command or "
                "argument. With a shell enabled, spawn joins its argv into a shell command line "
                "the same way exec does — an attacker-controlled argument can inject additional "
                "shell syntax."
            ),
            remediation=(
                'Drop `shell: true` and pass the command/args as array-form literals '
                '(`spawn("git", ["status"])`) — the default no-shell spawn never interprets '
                "shell metacharacters in an argument. If this call is audited-safe, suppress "
                "with `// security: allow-js-command-injection`."
            ),
            rule="js-command-injection/spawn-shell-true-tainted",
            standards=["OWASP:A03", "CWE-78"],
        )
