"""Guard: an unparameterized Supabase-py / PostgREST filter expression built from untrusted
input (checklist §3b).

**CVE-2026-77071** (n8n's Supabase node, Row Get Many / Delete / Update operations): filter
queries were built by concatenating an expression-bindable value directly into the PostgREST
filter STRING, without escaping. An attacker who controls that value can inject a condition that
widens the filter to match every row — turning an intended single-row operation into full-table
disclosure, deletion, or modification. This is a DISTINCT injection sink from raw SQL: every
existing SQL-injection guard in this codebase (`semgrep`'s rules, `js-sql-injection`,
`go-sql-injection`) targets literal SQL text or the Mongo-operator DSL. Supabase-py's own
filter-builder methods — a Python/postgrest-py client wrapping PostgREST's own mini
filter-language — are a third, unrelated DSL nothing here already covers.

**The safe vs. unsafe shape.** postgrest-py's per-column methods (``.eq(column, value)``,
``.neq(``, ``.gt(``, ``.lt(``, ``.like(``, ``.ilike(``, ``.is_(``, ``.in_(``) take the column name
and the value as SEPARATE arguments — the value never passes through PostgREST's filter-string
parser, so these are inherently safe and this guard never flags them. ``.or_(raw_filter_string)``
has NO safe multi-argument form at all — its entire API is a single raw filter-string argument
(e.g. ``"id.eq.1,status.eq.active"``), and PostgREST's own mini-language treats commas as
AND-joins and ``or(...)``/``and(...)`` as nesting operators — so an attacker-controlled value
concatenated into that string can inject additional clauses (``id.eq.1,or(id.neq.0)``) to widen
or bypass the intended filter entirely. ``.filter(column, operator, value)``'s 3-argument form is
equally safe (the value is separate); its rarer single-argument form takes a raw filter string
and shares ``.or_()``'s exact risk.

**Detection (AST, whole-file — no route-scoping needed, the sink is unconditionally unsafe
wherever it's built this way):** a call to ``.or_(``, ``.not_.or_(``, or single-argument
``.filter(`` whose sole argument is built from untrusted input rather than a static literal —
an f-string (``ast.JoinedStr``) with any interpolated value, a ``+``/``%`` string
concatenation/formatting with a non-constant operand, or a ``"...".format(...)`` call. A plain
string literal (``.or_("id.eq.1,status.eq.active")``) is a static, non-injectable filter and
never fires.

Fires **CRITICAL** — the same severity class as raw SQL injection (`3b-sql-parameterized`): a
successful injection here reaches the exact same PostgREST-fronted table, with the exact same
full-table blast radius. Suppress an audited case with `# security: allow-supabase-filter-concat`.

**Checklist item:** new — `3b-supabase-filter-parameterized`, a distinct DSL from
`3b-sql-parameterized` (confirmed via grep of checklist.json before starting: nothing already
covers Supabase-py's own filter-builder methods as an injection sink).
"""
from __future__ import annotations

import ast
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-supabase-filter-concat"
_STANDARDS = ["OWASP:A03", "OWASP-LLM:LLM08"]

# The unsafe sink methods: `.or_(` always takes a single raw filter string (no safe multi-arg
# form exists); `.filter(` is only unsafe in its rarer single-argument form (the 3-arg
# column/operator/value form is inherently safe and is excluded by the arg-count check below).
_UNSAFE_METHODS = frozenset({"or_", "filter"})


def _is_untrusted_string_build(node: ast.expr) -> bool:
    """True if `node` is a STRING built from non-constant input — an f-string with any
    interpolated value, a `+`/`%` concatenation/formatting with a non-constant operand, or a
    `"...".format(...)` call. A plain string literal (`ast.Constant`) is NOT untrusted — it is
    static and cannot be injected into. Total: never raises."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        left_const = isinstance(node.left, ast.Constant)
        right_const = isinstance(node.right, ast.Constant)
        return not (left_const and right_const)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and isinstance(node.func.value, ast.Constant)
    )


def _find_unsafe_filter_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """(lineno, method-name) pairs for every `.or_(`/single-arg `.filter(` call whose sole
    argument is built from untrusted input."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        method = node.func.attr
        if method not in _UNSAFE_METHODS:
            continue
        # `.filter(column, operator, value)` (2-3 args) is the inherently-safe form — only the
        # rarer single-argument raw-filter-string form shares `.or_()`'s risk.
        if method == "filter" and len(node.args) != 1:
            continue
        if not node.args:
            continue
        if _is_untrusted_string_build(node.args[0]):
            out.append((node.lineno, method))
    return out


class SupabaseFilterInjectionGuard(Guard):
    id = "supabase-filter-injection"
    title = "Unparameterized Supabase/PostgREST filter built from untrusted input"
    area = "Code safety"  # injection family, same bucket as sqlalchemy-text-parameterized/ldap-injection

    # a raw .or_() filter string built via f-string interpolation -> fires
    # supabase-filter-injection/unparameterized-filter.
    canary_plant = CanaryPlant(
        files={
            "orders_api.py": (
                "def get_order(supabase, order_id, user_id):\n"
                "    return (\n"
                "        supabase.table('orders')\n"
                "        .select('*')\n"
                "        .or_(f'id.eq.{order_id},user_id.eq.{user_id}')\n"
                "        .execute()\n"
                "    )\n"
            ),
        },
        expects=frozenset({"supabase-filter-injection/unparameterized-filter"}),
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
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan_file(root, f, text))
        return out

    def _scan_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            return []
        return [
            self._finding(root, f, lineno, method)
            for lineno, method in _find_unsafe_filter_calls(tree)
        ]

    def _finding(self, root: Path, f: Path, lineno: int, method: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"`.{method}(...)` is called with a filter STRING built from untrusted input "
                "(an f-string, string concatenation, or `.format()` call) rather than a static "
                "literal. PostgREST's filter mini-language treats commas as AND-joins and "
                "`or(...)`/`and(...)` as nesting operators, so an attacker-controlled value can "
                "inject additional clauses that widen or bypass the intended filter — turning a "
                "single-row lookup into full-table disclosure, deletion, or modification "
                "(CVE-2026-77071's exact shape, n8n's Supabase node)."
            ),
            remediation=(
                "Use the per-column parameterized methods instead, where the value never enters "
                "the filter-string parser: `.eq(\"id\", order_id)` / `.neq(` / `.gt(` / `.in_(` "
                "etc. If a genuinely combined OR condition is needed, build it only from "
                "hardcoded column/operator names, never from request-controlled values. Suppress "
                f"an audited case with `# {_PRAGMA}`."
            ),
            rule="supabase-filter-injection/unparameterized-filter",
            standards=list(_STANDARDS),
        )
