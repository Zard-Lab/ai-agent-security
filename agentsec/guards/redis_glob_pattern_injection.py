"""Guard: a Redis `KEYS`/`SCAN` glob pattern built from untrusted input, unescaped (checklist §3a).

**CVE-2026-78378** (Ransomlook): an endpoint resolved a caller-supplied name to a known group,
and on resolution failure fell back to using the attacker-controlled value DIRECTLY in a Redis
`SCAN ... MATCH` pattern. Redis glob metacharacters (`*`, `?`, `[`, `]`) in that value let an
unauthenticated attacker broaden the scan far beyond the intended scope — `GET /api/health/*`
enumerated health data belonging to every group, including private ones. The same unsafe
interpolation pattern was present in a second read endpoint and in a delete function, where a
crafted key containing glob metacharacters could match (and act on) keys belonging to a
DIFFERENT resource than the one requested — a potentially destructive sink, not just a read one.

No guard or stack-detection signal for Redis existed in this codebase at all before this — grepped
`agentsec/detect.py` for `redis` and found nothing; `detect.py` gained a `redis` feature (matching
the `mcp`/`electron` pattern: a real dependency declaration via `_declares_py_dep`/`_js_dep`, plus
a real Python import) as a prerequisite for this guard to have anything to gate on.

**Detection (AST, whole-file — no route-scoping needed, the sink is unconditionally unsafe
wherever it's built this way):** a call to redis-py's `.keys(`/`.scan(`/`.scan_iter(`/`.hscan(`/
`.sscan(`/`.zscan(` whose PATTERN argument (the sole positional argument for `.keys(`; the
`match=` keyword — or the 1st positional after `cursor` — for the `scan*` family) is built from
untrusted input rather than a static literal: an f-string with any interpolated value, a `+`/`%`
concatenation/formatting with a non-constant operand, or a `"...".format(...)` call. Mirrors
`supabase_filter_injection.py`'s own untrusted-string-build detection (the same shape of bug —
an unescaped value flowing into a mini pattern-language — one guard file per distinct sink DSL,
matching this project's existing per-DSL guard boundaries).

Fires **HIGH** (Ransomlook's own real-world impact: unauthenticated cross-tenant data enumeration,
plus a destructive variant on the delete path — scored below the `critical` SQL/PostgREST
injection guards since Redis glob-widening enumerates/matches KEYS, a narrower blast radius than
a full-table SQL/PostgREST injection). Suppress an audited case with
`# security: allow-redis-glob-concat`.

**Checklist item:** new — `3a-redis-glob-pattern-safe`, no existing item covers Redis
KEYS/SCAN pattern construction (confirmed via grep of checklist.json before starting).
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

_PRAGMA = "security: allow-redis-glob-concat"
_STANDARDS = ["OWASP:A03"]

# `.keys(pattern)` takes the pattern as its sole positional argument. The `scan*` family takes an
# optional `cursor` first, then `match=` (keyword, the documented spelling) as the pattern.
_KEYS_METHODS = frozenset({"keys"})
_SCAN_METHODS = frozenset({"scan", "scan_iter", "hscan", "sscan", "zscan"})


def _is_untrusted_string_build(node: ast.expr) -> bool:
    """True if `node` is a STRING built from non-constant input. Mirrors
    `supabase_filter_injection.py`'s identically-named helper — the same shape of bug (an
    unescaped value flowing into a mini pattern-language), duplicated per this project's
    per-DSL guard-file boundary rather than shared, to keep each guard self-contained."""
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


def _pattern_arg(call: ast.Call, method: str) -> ast.expr | None:
    """The pattern-carrying argument of a `.keys(`/`.scan*(` call, or `None` if it doesn't have
    one in a recognizable position."""
    if method in _KEYS_METHODS:
        return call.args[0] if call.args else None
    for kw in call.keywords:
        if kw.arg == "match":
            return kw.value
    # Positional `match` — `.scan(cursor, pattern)` — the 2nd positional argument.
    if len(call.args) >= 2:
        return call.args[1]
    return None


def _find_unsafe_pattern_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """(lineno, method-name) pairs for every `.keys(`/`.scan*(` call whose pattern argument is
    built from untrusted input."""
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
            continue
        method = node.func.attr
        if method not in _KEYS_METHODS and method not in _SCAN_METHODS:
            continue
        arg = _pattern_arg(node, method)
        if arg is not None and _is_untrusted_string_build(arg):
            out.append((node.lineno, method))
    return out


class RedisGlobInjectionGuard(Guard):
    id = "redis-glob-pattern-injection"
    title = "Redis KEYS/SCAN glob pattern built from untrusted input"
    area = "Code safety"  # injection family, same bucket as sqlalchemy-text-parameterized/ldap-injection

    # a SCAN MATCH pattern built via f-string interpolation, no glob-escaping -> fires
    # redis-glob-pattern-injection/unescaped-glob-pattern.
    canary_plant = CanaryPlant(
        files={
            "health_api.py": (
                "def get_group_health(redis_client, group_name):\n"
                "    keys = redis_client.scan_iter(match=f'health:{group_name}:*')\n"
                "    return [redis_client.get(k) for k in keys]\n"
            ),
        },
        expects=frozenset({"redis-glob-pattern-injection/unescaped-glob-pattern"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "redis" in profile.features

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
            for lineno, method in _find_unsafe_pattern_calls(tree)
        ]

    def _finding(self, root: Path, f: Path, lineno: int, method: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"`.{method}(...)`'s glob pattern is built from untrusted input (an f-string, "
                "string concatenation, or `.format()` call) with no escaping. Redis glob "
                "metacharacters (`*`, `?`, `[`, `]`) in that value let an attacker broaden the "
                "match far beyond the intended scope — enumerating or matching keys belonging to "
                "a different resource than the one requested (CVE-2026-78378's exact shape)."
            ),
            remediation=(
                "Escape glob metacharacters in the untrusted portion before building the pattern "
                "(wrap each `*`/`?`/`[`/`]` with a preceding `[` `]` pair, or reject any input "
                "containing them outright if the value is expected to be a plain identifier). "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="redis-glob-pattern-injection/unescaped-glob-pattern",
            standards=list(_STANDARDS),
        )
