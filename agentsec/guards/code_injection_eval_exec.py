"""Guard: no code injection via a bare eval()/exec() sink (checklist §3b, new item).

`eval()`/`exec()` on dynamic content lets an attacker who controls the string run
arbitrary Python: `eval(request.args.get("expr"))`, `exec(f"result = {user_formula}")`.
This is CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) —
the Python-source sibling of `command-injection`'s shell-sink check, but for the
interpreter itself rather than a subprocess.

The existing `llm-output-to-sink` guard already catches `eval`/`exec` fed by an LLM
call's result — but it's gated on the `llm` feature and only fires in files that
already contain an LLM call. A plain FastAPI endpoint with no LLM involvement at all
that does `eval(request.query_params.get("expr"))` is caught by neither guard; this
guard closes that gap with a broader, LLM-independent check.

Fires HIGH on an `eval(`/`exec(`/`compile(`/`__import__(` call whose argument is **dynamic**
(an f-string, `+`/`%`/`.format` concatenation, or a bare variable with no string literal at all):

    eval(user_input)                          # bare variable -> dynamic
    exec(f"x = {formula}")                    # f-string -> dynamic
    eval("2 + 2")                              # static literal -> does NOT fire

Suppress an audited case with:

    eval(trusted_constant)  # security: allow-eval-exec

**2026-09-22: `compile(`/`__import__(`/SymPy `parse_expr(` sinks added.**
Ported from `agent-audit-kit`'s real `AAK-MCP-TOOL-UNSAFE-EVAL-001` (fetched and read in
full), anchored on **CVE-2026-44717** (`mcp-calculate-server`, an MCP tool handler routing a
tool parameter through `sympy.parsing.sympy_parser.parse_expr()` with no `local_dict`/
`global_dict` pinning — SymPy's own docs call unpinned `parse_expr` on untrusted input
equivalent to `eval`). The bare `eval(`/`exec(` case on a tool-handler parameter was already
caught here regardless of MCP-decorator context (this guard has no decorator-awareness at
all, by design — a stricter, MCP-scoped check would be redundant); `compile(`/`__import__(`/
`parse_expr(` were the real, disclosed gap. `parse_expr(` fires unless BOTH `local_dict` and
`global_dict` are present on the same line (either one missing still fires) — present-but-empty
pinning (`local_dict={}`) is the documented-safe form and must not fire.

**2026-09-23 fix (Dean's review, agentic pre-review M-5):** this paragraph
previously said the fire condition was "BOTH absent," the opposite of what `_check_file`
actually implements (`not (_LOCAL_DICT.search(line) and _GLOBAL_DICT.search(line))` fires
unless both are present, not only when both are absent) — corrected to match the code, not
the other way around.

**2026-09-23 (Dean's review, agentic pre-review H-3, partial fix + disclosed
remaining gap):** `eval`/`exec` with a `globals`/`locals` dict argument restricting
`__builtins__` to `{}`/`None` (the documented sandboxed-eval/exec idiom) now stays silent —
fixed, see `_BUILTINS_SANDBOX` below. **Note (Dean's review):** `{"__builtins__": {}}` is
NOT a real sandbox — it is a well-known, well-documented Python escape (reachable through any
object's `__class__`/`__base__`/`__subclasses__`/`__mro__` chain with no `__builtins__` access
at all, e.g. `().__class__.__base__.__subclasses__()`). Silencing on it is recognizing that the
developer INTENDED to harden the call, not confirming the call is actually safe — the same
"marker of intent, not proof of safety" distinction every other suppression marker in this
codebase makes (a pragma, a mitigation-marker regex, a consent flag). **Not fixed, disclosed
rather than guessed:**
`compile(tree, '<ast>', 'exec')` where `tree` is an already-parsed AST object is syntactically
IDENTICAL to `compile(formula, '<formula>', 'eval')` where `formula` is a raw untrusted string
— both are a bare variable with no literal, this guard's own `_is_dynamic()` fire condition,
and the existing `test_fires_on_dynamic_compile` regression test locks in that the untrusted-
string shape must still fire. There is no reliable syntactic signal (short of real type/taint
tracking this guard does not do) to tell the two apart, so narrowing bare-variable `compile()`
calls to require stronger evidence would silence the guard's own anchor case
(CVE-2026-44717's shape), not just the benign one. Left as a known, accepted FP class rather
than a guessed narrowing that would reopen a real gap; `# security: allow-eval-exec` is the
correct suppression for a confirmed AST-codegen case. `__import__(name, ...)` was considered
for the same narrowing and rejected for a different reason: unlike eval(compile(...)), a
dynamic import has no downstream eval/exec call to independently catch the real vulnerable
case if this guard's own check were narrowed, so the same-shape ambiguity does not have an
equivalent safety net here either.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    split_call_args,
    strip_python_strings,
)

# `(?<!\.)` so a method call like `pandas.DataFrame.eval(...)` / `obj.exec(...)` is NOT matched —
# only the builtin `eval(...)`/`exec(...)`/`compile(...)`/`__import__(...)` sinks (a leading `.`
# means it's an attribute call). `compile(`/`__import__(` added for (CVE-2026-44717) —
# both are the same "dynamic content becomes running code" shape as eval/exec. Named group so
# the sandboxing check below can tell which sink matched (only eval/exec take a globals/locals
# argument at all).
_EVAL_EXEC = re.compile(r"(?<!\.)\b(?P<sink>eval|exec|compile|__import__)\s*\(")

# SymPy's `parse_expr(expr)` with NO `local_dict`/`global_dict` pinning is equivalent to
# eval() on the expression string (SymPy's own docs make this explicit) — a separate sink
# from the bare-builtin one above because its "safe" form isn't "static content," it's
# "pinned dicts present," checked on the same physical line (matching this guard's existing
# line-scoped design, not a multi-line call span). Deliberately NOT excluding a leading `.`
# the way `_EVAL_EXEC` does for `eval`/`exec` — the real vulnerable shape is the fully
# dotted `sympy.parsing.sympy_parser.parse_expr(...)` / `sympy_parser.parse_expr(...)` call,
# and `parse_expr` (unlike `eval`/`exec`) is not a builtin name any other attribute access
# could be confused with, so there is no equivalent false-positive to guard against.
_PARSE_EXPR = re.compile(r"\bparse_expr\s*\(")
_LOCAL_DICT = re.compile(r"\blocal_dict\s*=")
_GLOBAL_DICT = re.compile(r"\bglobal_dict\s*=")
_FSTRING = re.compile(r"(?:^|[\s(,=+])[rR]?[fF]['\"]")
_PCT = re.compile(r"%[sdrfeg]|['\"]\s*%|%\s*\(")
_CONCAT = re.compile(r"['\"]\s*\+|\+\s*['\"]")
_PRAGMA = re.compile(r"#\s*security:\s*allow-eval-exec")

# `eval`/`exec`'s own `globals`/`locals` dict argument restricting `__builtins__` to `{}`/`None`
# is the documented, real hardening idiom for a sandboxed eval/exec (Python's own docs describe
# it explicitly) — teams reach for this specifically to FIX an eval/exec finding, and firing on
# the resulting hardened call defeats the guard's own remediation advice (2026-09-23 fix, Dean's
# review, agentic pre-review H-3). `compile()` does NOT take a globals/locals
# argument at all (its own signature has no such parameter), so this marker never applies there.
# NOT a real sandbox (2026-09-24, Dean's review) — a well-known escape reaches the same
# builtins via any object's __class__/__base__/__subclasses__/__mro__ chain with no
# __builtins__ access needed. Silencing here recognizes developer INTENT to harden, not that
# the call is actually safe.
_BUILTINS_SANDBOX = re.compile(r"""['"]__builtins__['"]\s*:\s*(?:\{\s*\}|None\b)""")

# A `["key"]`/`['key']` dict/subscript access. A chain like `node["a"]["b"]` contains quotes
# only as the subscript KEYS — the extracted VALUE is still fully dynamic (CVE-2026-33017's
# `custom_params.pop("code")`-shaped extraction is the same class of access). Stripped out
# before the "no literal anywhere" bare-variable check, so `node["code"]` reads as dynamic
# instead of being mistaken for a static string literal just because a quote appears in it.
_SUBSCRIPT_KEY = re.compile(r"""\[\s*['"][^'"]*['"]\s*\]""")

# Also OWASP-ASI:ASI05 (Unexpected Code Execution, OWASP Top 10 for Agentic Applications 2026):
# dynamic content reaching a bare eval()/exec() sink is the canonical "content becomes running
# code" shape — see wiki/research/owasp-asi-2026.md.
_STANDARDS = ["OWASP:A03", "CWE-95", "OWASP-ASI:ASI05"]


def _is_dynamic(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _FSTRING.search(a):
        return True
    unsubscripted = _SUBSCRIPT_KEY.sub("", a)
    if "'" not in unsubscripted and '"' not in unsubscripted:
        return True  # no literal left once dict/subscript keys are stripped -> a variable/expression
    if ".format(" in a:
        return True
    if _PCT.search(a):
        return True
    return bool(_CONCAT.search(a))


def _first_arg_after(line: str, paren: int) -> str:
    """The sink call's FIRST argument only, quote- and balanced-bracket-aware (stops at the
    first top-level comma or unbalanced closer). Added because `compile(source, filename,
    mode)` and `exec(code, globals)` are common multi-argument forms where only the first
    argument is ever the actual evaluated content — the guard's original whole-tail-string
    check made `compile(formula, '<formula>', 'eval')` read as "has a literal somewhere"
    (the static `filename`/`mode` args) and silently masked a dynamic first argument, a
    real false negative caught by this guard's own test suite, not assumed. `eval`/`exec`'s
    own existing tests (a single dynamic first argument, or a dynamic first argument
    alongside a bare-variable second one) are unaffected — the dynamism they test for was
    already in the first argument specifically.

    **2026-09-23 fix (Dean's review):** the first cut of this function tracked
    bracket depth only, not string-literal quoting — so a comma INSIDE a string literal
    argument, e.g. `eval('a,b' + x)`, was read as a top-level argument separator and the
    function returned just `'a` (a broken fragment, not dynamic) instead of the real first
    argument `'a,b' + x` (a concatenation, genuinely dynamic) — a real regression against
    `eval('a,b' + x)`, which fired correctly on `main` before this change. Delegates to
    the shared `split_call_args` (quote- and escape-aware, already used by `weak_crypto` for
    the identical class of bug) instead of a second, narrower local reimplementation."""
    args = split_call_args(line, paren)
    if args:
        return args[0].strip()
    # Unbalanced on this line (a multi-line call) -- fall back to the naive whole-tail read,
    # matching this guard's pre-existing line-scoped design rather than guessing further.
    return line[paren + 1 :].rstrip().rstrip(")").strip()


class CodeInjectionEvalExecGuard(Guard):
    id = "code-injection-eval-exec"
    title = "No code injection via a bare eval()/exec() sink fed dynamic content"
    area = "Code safety"

    # eval() with a bare variable (no LLM call in this file) -> fires
    # code-injection-eval-exec/dynamic-content (HIGH).
    canary_plant = CanaryPlant(
        files={
            "eval_injection.py": (
                "def calculate(expr: str) -> object:\n"
                "    return eval(expr)\n"
            ),
        },
        expects=frozenset({
            "code-injection-eval-exec/dynamic-content",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        text = strip_python_strings(raw, filename=f)
        # The pragma counts only as a real comment on the line, never quoted in a string
        # there (#1040), numbered on the text walked below (a form feed in a docstring
        # shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for i, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or i in pragmas:
                continue
            m = _EVAL_EXEC.search(line)
            if (
                m
                and _is_dynamic(_first_arg_after(line, m.end() - 1))
                and not (m.group("sink") in ("eval", "exec") and _BUILTINS_SANDBOX.search(line))
            ):
                out.append(self._finding(root, f, i))
                continue
            pm = _PARSE_EXPR.search(line)
            if (
                pm
                and _is_dynamic(_first_arg_after(line, pm.end() - 1))
                and not (_LOCAL_DICT.search(line) and _GLOBAL_DICT.search(line))
            ):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "eval()/exec()/compile()/__import__()/SymPy parse_expr() is called with "
                "dynamic content (an f-string, concatenation, or a bare variable with no "
                "literal), and — for parse_expr() specifically — with no local_dict/"
                "global_dict pinning. If that content is influenceable by a caller, this is "
                "arbitrary code execution (CWE-95)."
            ),
            remediation=(
                "Never eval()/exec()/compile()/__import__() attacker-influenceable input. "
                "For SymPy expression parsing, always pass local_dict={} and global_dict={} "
                "(or a strict symbol allow-list) to parse_expr(). Use ast.literal_eval() for "
                "simple data, a restricted expression parser, or an explicit allowlist of "
                "accepted operations instead."
            ),
            rule="code-injection-eval-exec/dynamic-content",
            standards=list(_STANDARDS),
        )
