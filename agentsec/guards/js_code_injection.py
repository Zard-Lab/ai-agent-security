"""Guard: no code injection via a JS/Node dynamic-evaluation sink (checklist §3b, extends
`3b-eval-exec-injection`).

The JS/Node counterpart to agentsec's existing (Python-only) `code-injection-eval-exec` guard —
same requirement (a dynamic-evaluation sink fed attacker-influenceable content is arbitrary code
execution), a genuinely different code surface (JS's `eval`/`Function` constructor and Node's `vm`
module instead of Python's `eval`/`exec`), so it extends the same `3b-eval-exec-injection`
checklist item rather than duplicating it.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-094/CodeInjection.ql` +
`CodeInjectionCustomizations.qll` (445 lines, 20+ sink classes; verified against real fetched
source). This guard is **deliberately scoped to the core, highest-value, most-common sink shape**
— it does not attempt CodeQL's full sink library. Four sinks, all CWE-94/CWE-95:

  * `eval(...)` — the argument is the code that gets compiled and run.
  * `new Function(...)` — any argument to the constructor becomes function body/params, but the
    dominant real-world vulnerable shape is the LAST argument (the body), so — mirroring
    `js_command_injection.py`'s own precedent of picking the highest-value shape over exhaustive
    coverage — only the last argument is checked.
  * `vm.runInContext(...)` / `vm.runInNewContext(...)` / `vm.runInThisContext(...)` (Node's `vm`
    module) — the FIRST argument (the script text) is checked. Node's own docs are explicit that
    `vm` is not a security sandbox; a tainted script string here is direct code execution in the
    host process.
  * `require('node-serialize').unserialize(...)` — this specific package's `unserialize()` walks
    the payload for `_$$ND_FUNC$$_`-prefixed values and `eval()`s them, a well-documented RCE vector
    (the CVE-2017-5941 class) when the input is not trusted. Gated on the FILE containing a
    `node-serialize` import (`require('node-serialize')` or `from 'node-serialize'`), so an
    unrelated function that happens to be named `unserialize` does not fire.

**Explicitly out of scope**: CodeQL's server-side-template-injection sinks (`pug`/`handlebars`/
`mustache`/`hogan`/`eta`/`squirrelly`/`whiskers` `.render()`/`.compile()` fed a tainted TEMPLATE
STRING). That is a real, different, more involved sub-analysis — deferred to a future guard, not
an oversight. See "What this guard does NOT prove" in the design doc.

**Taint source** — the same file-scoped convention `js_regex_injection_dos.py` uses: a direct
`req.*`/`request.*` property access, OR a local variable assigned from one of those anywhere in
the same file (order-independent, file-scoped — a conservative simplification of real dataflow,
see that guard's docstring for the full justification). This is a DELIBERATE difference from
`js_command_injection.py`, which fires on any structurally-dynamic argument regardless of its
source: a code-execution sink is noisy enough (and eval-on-trusted-config a common enough
legitimate pattern) that gating on an actual taint source, not just "not a literal", is required
for acceptable precision here. `eval(JSON.stringify(safeConfig))` is dynamic-looking but not
request-derived, and must stay silent.

A finding requires the target argument to be BOTH structurally dynamic (a template-literal
interpolation, `+` concatenation, or a bare expression with no string literal at all — the same
`_is_dynamic` test `js_command_injection.py` uses) AND tainted (see above). Comments are blanked
before matching (`strip_js_comments`) so a comment mentioning the pattern never fires. String
CONTENTS are deliberately NOT blanked for the main scan (unlike `js_regex_injection_dos.py`'s
`strip_strings=True`): that would blank the interior of a template literal's `${...}` interpolation
too, which would erase the exact `` `code ${req.query.x}` `` shape this guard exists to catch.
Instead the sink call's `(` is tested against the anchor mask (`keep_substitutions=True`, #749),
which blanks string text but keeps substitution code: `eval(` quoted in a docs or error string does
not fire, a real `eval(` inside a `${...}` does, and every call on the line is tried, so a quoted
copy cannot hide a later real one (#1055). The assign-then-use taint pass reads the same mask. The
trade-off is a narrow, accepted false-positive residual: a dynamic
argument whose STATIC portion happens to literally contain the substring `req.`/`request.`
(e.g. `eval("do req.thing " + userExpr)`) reads as tainted even though the real dynamic part is
unrelated — see "Known bypasses".

**MCP tool-argument taint (sentrymcp-zaydmulani research-cycle batch).** A stdio/SDK-based
MCP tool server has no `req`/`request` object anywhere in the file — its handler receives tool
arguments directly (`async (args) => {...}`), so the `req.*`-only taint source above misses exactly
the shape sentrymcp's `MCPA-EVAL-JS-001`/`MCPA-EVAL-TS-001` target: a tool callback that does
``eval(`result = ${args.formula}`)``. Confirmed as a real, silent false-negative by reading
`_is_tainted`'s pre-fix body directly (its only taint source was `_REQ_TAINT`) and by the
before/after pair of tests below (`test_flags_eval_on_mcp_tool_argument` /
`test_silent_on_mcp_tool_argument_without_mcp_feature`). When `"mcp" in profile.features`,
`args.`/`params.`/`toolArgs.`/`input.` property access is ALSO
treated as tainted (sentrymcp's own vocabulary, `MCPA-EVAL-JS-001`'s `sink_pattern`) — gated on the
`mcp` feature specifically because those names are far too generic in ordinary (non-MCP) JS/TS code
to treat as an untrusted-input signal unconditionally; sentrymcp itself never needs this gate because
every repo it scans IS an MCP server by definition. Applied uniformly to all four sink checks (eval,
new Function, vm.run*, node-serialize unserialize) rather than only the two sinks sentrymcp's own
catalog names — the same "MCP tool argument reaches a dynamic-evaluation sink" risk applies equally
to any of them, and `_is_tainted` is one shared helper underneath all four.

Fires CRITICAL (this is arbitrary code execution, not a lesser injection class):

    eval(`result = ${req.query.formula}`)                       # template interpolation -> dynamic, tainted
    eval(userFormula)                                            # userFormula assigned from req.* earlier in file
    new Function(`return ${req.query.expr}`)                     # last-arg body, dynamic + tainted
    vm.runInContext(req.body.script, ctx)                        # first arg, dynamic + tainted
    require('node-serialize').unserialize(req.cookies.profile)   # dynamic + tainted, package imported

    eval("2 + 2")                                                 # static literal -> does NOT fire
    eval(JSON.stringify(safeConfig))                              # dynamic but NOT request-derived -> does NOT fire

Suppress an audited case with:

    eval(trustedExpr)  // security: allow-js-code-injection
"""
from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    split_call_args,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-code-injection"

# `(?<!\.)` so a method call like `someObj.eval(...)` is NOT matched — only the global
# `eval(...)` builtin sink (mirrors the Python sibling's method-call exclusion).
_EVAL_CALL = re.compile(r"(?<!\.)\beval\s*\(")
_NEW_FUNCTION_CALL = re.compile(r"\bnew\s+Function\s*\(")
# Matches `vm.runInContext(`, `runInNewContext(`, `someAlias.runInThisContext(`, etc. — an
# optional single-identifier receiver, since Node's `vm` module is commonly imported under an
# alias or destructured to a bare name.
_VM_RUN_CALL = re.compile(r"\b(?:[\w$]+\.)?runIn(?:Context|NewContext|ThisContext)\s*\(")
_UNSERIALIZE_CALL = re.compile(r"\bunserialize\s*\(")
_NODE_SERIALIZE_IMPORT = re.compile(
    r"""require\(\s*['"]node-serialize['"]\s*\)|from\s+['"]node-serialize['"]"""
)

# A template-literal argument that actually interpolates (`` `code ${x}` ``) — the JS analogue of
# the Python guard's f-string check.
_TEMPLATE_INTERP = re.compile(r"`[^`]*\$\{[^}]*\}[^`]*`")
# A string literal glued to something else via `+`.
_CONCAT = re.compile(r"""['"`]\s*\+|\+\s*['"`]""")

_REQ_TAINT = re.compile(r"\b(?:req|request)\.\w")
# MCP tool-call-argument taint, active only when "mcp" in profile.features (see module
# docstring) — sentrymcp's own MCPA-EVAL-JS-001/TS-001 vocabulary.
_MCP_ARG_TAINT = re.compile(r"\b(?:args|params|toolArgs|input)\.\w")
_IDENTIFIER = re.compile(r"^\s*(\w+)\s*$")
# const/let/var NAME = <expr containing req.*/request.*>; — same assign-then-use tracking
# `js_regex_injection_dos.py` uses, extended to also recognize `request.*`.
_ASSIGN_FROM_REQ = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=[^;\n]*\b(?:req|request)\.\w[^;\n]*;")

_STANDARDS = ["OWASP:A03", "CWE-95"]


def _is_dynamic(arg: str) -> bool:
    """An argument is "dynamic" (not proven-static) if it is a template-literal interpolation,
    a `+` concatenation, or has no string literal at all (a bare variable/expression) — the same
    structural test `js_command_injection.py::_is_dynamic` uses."""
    a = arg.strip()
    if not a:
        return False
    if _TEMPLATE_INTERP.search(a):
        return True
    if "'" not in a and '"' not in a and "`" not in a:
        return True
    return bool(_CONCAT.search(a))


def _is_tainted(arg: str, tainted_vars: set[str], mcp_arg_taint: bool) -> bool:
    """True if `arg` derives from `req.*`/`request.*` — directly, or as a bare identifier
    previously assigned from one anywhere in the same file (file-scoped, order-independent).
    When `mcp_arg_taint` ("mcp" in profile.features), `args.`/`params.`/`toolArgs.`/
    `input.` property access is ALSO a taint source — see module docstring."""
    if _REQ_TAINT.search(arg):
        return True
    if mcp_arg_taint and _MCP_ARG_TAINT.search(arg):
        return True
    m = _IDENTIFIER.match(arg)
    return m is not None and m.group(1) in tainted_vars


def _first_arg(line: str, open_paren: int) -> str | None:
    args = split_call_args(line, open_paren)
    return args[0] if args else None


def _last_arg(line: str, open_paren: int) -> str | None:
    args = split_call_args(line, open_paren)
    return args[-1] if args else None


def _has_tainted_call(
    pattern: re.Pattern[str],
    pick: Callable[[str, int], str | None],
    line: str,
    mask_line: str,
    tainted_vars: set[str],
    mcp_arg_taint: bool,
) -> bool:
    """True if some call of `pattern` on `line` is live code and its `pick`ed argument is dynamic and
    tainted. The call's `(` is tested on the anchor mask (#1055): `eval(` spelled out in a docs or
    error string is not a call, while one nested in a `${...}` substitution is. Every match is
    tried, so a quoted copy earlier on the line cannot hide the real call after it. The argument
    is still read from the strings-intact `line`, which is where the `${req.x}` interpolation lives."""
    for m in js_code_matches(pattern, line, mask_line, anchor=lambda m: m.end() - 1):
        arg = pick(line, m.end() - 1)
        if arg is not None and _is_dynamic(arg) and _is_tainted(arg, tainted_vars, mcp_arg_taint):
            return True
    return False


class JsCodeInjectionGuard(Guard):
    id = "js-code-injection"
    title = "No code injection via a JS/Node dynamic-evaluation sink fed request-derived content"
    area = "Code safety"

    # express_code_injection.js: eval() with a template-literal interpolation of req.query ->
    # fires js-code-injection/eval-dynamic.
    canary_plant = CanaryPlant(
        files={
            "express_code_injection.js": "eval(`result = ${req.query.formula}`);\n",
        },
        expects=frozenset({"js-code-injection/eval-dynamic"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        mcp_arg_taint = "mcp" in profile.features
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text, mcp_arg_taint))
        return out

    def _scan(self, root: Path, f: Path, text: str, mcp_arg_taint: bool) -> list[Finding]:
        out: list[Finding] = []
        view_lines = comment_view(text, "js").splitlines()  # same length: comments only (#424)
        # Comments blanked, strings/template literals PRESERVED — a `${req.x}` interpolation must
        # stay visible (see module docstring for why `strip_strings=True` cannot be used here).
        code_lines = strip_js_comments(text).splitlines()
        # The anchor mask (#749): string content and template text blanked, `${...}` substitution
        # code kept. It serves two jobs. The assign-then-use taint tracking reads it, so a hardcoded
        # label like `const s = "req.count: total";` is not mistaken for a request-derived
        # assignment (PR #407 review precedent), while `` const f = `${req.query.f}`; `` still is.
        # Plain `strip_strings=True`, used here before #1055, blanked that substitution and lost the
        # taint. The sink calls below are also tested against it.
        masked = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
        tainted_vars = {m.group(1) for m in _ASSIGN_FROM_REQ.finditer(masked)}
        has_node_serialize = _NODE_SERIALIZE_IMPORT.search(text) is not None
        mask_lines = masked.splitlines()

        rows = zip(view_lines, code_lines, mask_lines, strict=True)
        for i, (view_line, line, mask_line) in enumerate(rows, start=1):
            if _PRAGMA in view_line:
                continue

            if _has_tainted_call(_EVAL_CALL, _first_arg, line, mask_line, tainted_vars, mcp_arg_taint):
                out.append(self._finding(root, f, i, "eval-dynamic", self._eval_message()))
                continue

            if _has_tainted_call(_NEW_FUNCTION_CALL, _last_arg, line, mask_line, tainted_vars, mcp_arg_taint):
                out.append(self._finding(root, f, i, "new-function-dynamic", self._new_function_message()))
                continue

            if _has_tainted_call(_VM_RUN_CALL, _first_arg, line, mask_line, tainted_vars, mcp_arg_taint):
                out.append(self._finding(root, f, i, "vm-run-dynamic", self._vm_run_message()))
                continue

            if has_node_serialize and _has_tainted_call(
                _UNSERIALIZE_CALL, _first_arg, line, mask_line, tainted_vars, mcp_arg_taint
            ):
                out.append(
                    self._finding(root, f, i, "node-serialize-unserialize", self._unserialize_message())
                )
        return out

    @staticmethod
    def _eval_message() -> str:
        return (
            "eval() is called with content derived from request input (a template-literal "
            "interpolation, `+` concatenation, or a bare expression assigned from req./request. "
            "earlier in the file). An attacker who controls that value gets arbitrary JavaScript "
            "execution (CWE-95)."
        )

    @staticmethod
    def _new_function_message() -> str:
        return (
            "new Function(...) is constructed with a function body derived from request input. "
            "Like eval(), an attacker-controlled function body compiles and runs inside the "
            "process (CWE-95)."
        )

    @staticmethod
    def _vm_run_message() -> str:
        return (
            "This vm.runInContext/runInNewContext/runInThisContext call executes a script string "
            "derived from request input. Node's vm module is NOT a security sandbox — a tainted "
            "script here runs with the same privileges as the rest of the process (CWE-95)."
        )

    @staticmethod
    def _unserialize_message() -> str:
        return (
            "node-serialize's unserialize() is called on request-derived data. This package's "
            "unserialize() executes any function embedded in the serialized payload — a "
            "well-documented remote-code-execution vector when the input is not trusted (CWE-95)."
        )

    def _finding(self, root: Path, f: Path, line: int, rule_suffix: str, message: str) -> Finding:
        remediation = {
            "eval-dynamic": (
                "Never eval() attacker-influenceable input. Use JSON.parse() for data, a "
                "restricted expression parser, or an explicit allowlist of accepted operations "
                "instead. If this call is audited-safe, suppress with "
                "`// security: allow-js-code-injection`."
            ),
            "new-function-dynamic": (
                "Avoid constructing a Function from request-derived text. Use a data-only parser "
                "(JSON.parse) or a sandboxed, capability-limited evaluator instead of compiling "
                "attacker-controlled code. If audited-safe, suppress with "
                "`// security: allow-js-code-injection`."
            ),
            "vm-run-dynamic": (
                "Do not run untrusted script text through vm.runInContext/runInNewContext/"
                "runInThisContext — the vm module isolates globals, not security. Use a real "
                "sandbox (e.g. isolated-vm, a subprocess under OS-level restrictions) or avoid "
                "executing user-controlled code entirely."
            ),
            "node-serialize-unserialize": (
                "Never call node-serialize's unserialize() on untrusted input; it is a documented "
                "RCE sink. Use JSON.parse() instead — node-serialize exists only to also "
                "(de)serialize functions, which is precisely the dangerous feature."
            ),
        }[rule_suffix]
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=message,
            remediation=remediation,
            rule=f"js-code-injection/{rule_suffix}",
            standards=list(_STANDARDS),
        )
