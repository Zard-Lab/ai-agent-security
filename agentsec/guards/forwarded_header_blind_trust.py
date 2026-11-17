"""Guard: X-Forwarded-For / X-Real-IP used in a security decision without proxy validation (OWASP:A04).

The ``X-Forwarded-For`` and ``X-Real-IP`` HTTP headers are set by reverse proxies and
load balancers to carry the original client IP. They are **fully client-controlled** when
the application sits behind no proxy, or behind a proxy that forwards the client's own
``X-Forwarded-For`` value without stripping or validating it first.

When application code reads one of these headers and feeds the value into a security
decision — IP rate-limiting, IP allowlisting, ban enforcement, or throttle logic — an
attacker who controls the header can trivially spoof any IP address and bypass those
controls. This is a well-known bypass for IP-based rate limiters.

A proxy-aware application signals its awareness by using ``ProxyHeadersMiddleware``,
setting ``forwarded_allow_ips``, or using ``TrustedHostMiddleware``. When any of those
are present in a file the file is treated as proxy-hardened and skipped.

Detectable pattern (MEDIUM):

  **``xff-in-security-context``** — a line that accesses ``X-Forwarded-For`` or
  ``X-Real-IP`` via ``headers.get()`` or ``headers[...]``, where the value actually
  FLOWS into a security-context keyword (``rate_limit``, ``limiter``, ``ip_addr``,
  ``client_ip``, ``allow_list``, ``ban``, ``throttle``) — not merely sits near one
  (the enclosing function's own span; a 5-line fallback window when no enclosing
  function is found). When the header value is assigned to a variable, that SAME
  variable — or a ONE-HOP binding DERIVED from it — must be referenced on the line carrying
  the security-context keyword, anywhere in the enclosing function (a check via a
  same-function helper is no longer invisible just because it sits more than 5 lines away).

  "Derived" is resolved from the **AST**, not a line regex (#772): a binding is a one-hop
  alias when its value is a *receiver-rooted chain* on the header variable — the canonical
  ``ip = raw.split(",")[0].strip()``, an annotated ``ip: str = raw``, a parenthesised or
  multi-line right-hand side, or a trailing ``# comment`` — so how the rename is spelled is
  not a detection boundary. It is scoped, ordered, and liveness-aware, because the AST rewrite
  opened three axes a text regex never had to reason about:
    - **Scope.** Only assignments in the SAME function scope as the header read alias it, and a
      name that is LOCAL to a nested ``def``/``lambda`` — its parameter, or a name that scope
      assigns — is masked from the sink check on lines inside that scope, because Python makes
      it a local there, not the header value. A *closure* over the header name (bound by
      neither) still counts: that is real flow, which is why this is name-level masking rather
      than excluding the whole nested span. A comprehension (``denied = [ip for ip in ...]``) is
      not a receiver-rooted chain, so it cannot alias the header var it shadows.
    - **Order.** Only aliases and sinks that appear AFTER the header read count; an alias and
      its sink sitting entirely before the read are unrelated code.
    - **Liveness.** Reassigning a tracked name to a value that is NOT header-derived — a
      sanitizer (``client = trusted_client_ip(request, client)``, including via a walrus
      ``ip := sanitize(ip)``) or the safe branch of a hand-rolled proxy check — kills the taint
      on that name: a scanner that fires on the remediation is worse than one that misses the
      bug. Only the reassigned name is dropped from that line's sink check, so a genuine sink of
      a different still-live name on the same physical line is not masked.
  Membership is tested against the header's OWN binding, never against names already added,
  so a second rename (``ip2 = ip``) stays a disclosed, accepted gap and the hop count cannot
  grow. When the header value is used inline (no assignment captured), the security-context
  keyword must appear on the same line/statement — a keyword merely nearby in unrelated code
  is no longer enough. An unparseable module degrades to a bare one-hop-rename text scan.

**Why MEDIUM?** The bypass is trivial once the pattern is identified (add a header in
``curl``), but the attacker needs to know a rate limit or allowlist is in play and where
to target. An unauthenticated public endpoint with IP rate-limiting is the highest-risk
case; an internal admin endpoint with IP allowlisting is equally critical.

**Suppress:** add ``# security: allow-forwarded-header-trust`` anywhere in a file when
the proxy configuration is validated out-of-band and trusted-proxy enforcement is done
at the infrastructure layer.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import NamedTuple

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-forwarded-header-trust"

_STANDARDS = ["OWASP:A04"]

# Matches header access for X-Forwarded-For or X-Real-IP.
_XFF = re.compile(
    r"""headers\.get\(\s*['"]X-(?:Forwarded-For|Real-IP)['"]\s*[,)]|headers\[['"]X-(?:Forwarded-For|Real-IP)['"]\]""",
    re.IGNORECASE,
)

# Security-context keywords that indicate the header value feeds a security decision.
_SEC_CTX = re.compile(r"rate.?limit|limiter|ip_addr|client_ip|allow.?list|ban\b|throttle", re.IGNORECASE)

# Files that contain these signals are proxy-aware — skip them.
_PROXY_AWARE = re.compile(r"ProxyHeadersMiddleware|forwarded_allow_ips|TrustedHostMiddleware")

_CTX_WINDOW = 5  # fallback lines before/after the XFF access when no enclosing function is found

# A simple assignment target: `<name> = <header access>`. Used to recover the variable the
# header value is bound to, so the security-context keyword can be required to co-occur with an
# actual REFERENCE to that value rather than just sitting somewhere nearby (removes the
# proximity-coincidence false positive the fixed window carried).
_ASSIGN_LHS = re.compile(r"^\s*([A-Za-z_]\w*)\s*=")

# A bare-rename alias: `<new> = <existing>` with nothing else on the RHS (no call, no
# expression) -- `ip = raw`. Deliberately ONE-HOP only (matched against the header's ORIGINAL
# variable specifically, never chained through an already-discovered alias): Dean's own
# suggested scope for this fix (#685 fix-commit round, High 3). Without it, `ip = raw` followed
# by `apply_rate_limit(ip)` went silent -- the sink search only ever looked for `raw`, the
# header's original binding, and never saw the renamed reference the security-context keyword
# actually co-occurs with.
_ALIAS_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$")


def _root_name(value: ast.expr) -> str | None:
    """The base variable a value is *derived from* by attribute access, subscripting, or a method
    call chain rooted at that variable — or ``None`` when the value is not such a chain.

    ``raw`` -> ``"raw"``; ``raw.split(",")[0].strip()`` -> ``"raw"`` (the header value, normalized);
    ``(raw)`` -> ``"raw"`` (parentheses are not an AST node). But a *function* call whose result is
    bound — ``trusted_client_ip(request, raw)`` — returns ``None``: the tracked value is an argument
    the callee consumes, not the receiver the result flows from, so the binding is a sanitization
    boundary, not a rename (#772 High 2). A comprehension, a literal, or a ``BinOp`` likewise return
    ``None`` — which is also why a shadowing ``denied = [ip for ip in ...]`` cannot alias the header
    var ``ip`` it re-binds inside itself (#772 High 1, the comprehension half): a comprehension is
    not a receiver-rooted chain, so it is never a derivation regardless of what Name it contains.
    """
    cur: ast.expr = value
    while True:
        if isinstance(cur, ast.Name):
            return cur.id
        if isinstance(cur, (ast.Attribute, ast.Subscript, ast.Starred)):
            cur = cur.value
        elif isinstance(cur, ast.Call) and isinstance(cur.func, ast.Attribute):
            cur = cur.func.value  # a method call: the receiver is the chain root
        else:
            return None


class _AssignInfo(NamedTuple):
    lineno: int
    scope: ast.AST | None  # innermost enclosing FunctionDef/AsyncFunctionDef, or None (module level)
    names: tuple[str, ...]  # the simple Name targets this assignment binds
    root: str | None  # `_root_name` of the value — the var this binding is derived from, if any


class _FuncSpan(NamedTuple):
    node: ast.AST
    start: int
    end: int


class _InnerScope(NamedTuple):
    """A nested `def`/`async def`/`lambda`, with the names it binds by PARAMETER. Its locally
    *assigned* names are recovered separately from the assignment list (they carry their own
    scope). Together those are the names local to this scope — which, on a line inside it, are NOT
    the outer header value and must be masked from the sink check (#772 fix-round Issue 1)."""

    node: ast.AST
    start: int
    end: int
    params: frozenset[str]


def _param_names(args: ast.arguments) -> frozenset[str]:
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg is not None:
        names.append(args.vararg.arg)
    if args.kwarg is not None:
        names.append(args.kwarg.arg)
    return frozenset(names)


class _ScopeCollector(ast.NodeVisitor):
    """One tree pass per file: record every simple assignment with its innermost function scope,
    plus every function/lambda's line span and parameter names. The per-header analysis then needs
    no further tree walk, which is what keeps the alias resolution once-per-file rather than
    once-per-header-match (#772 Medium 2 — the reverted fix walked the whole module on every match,
    9.5x on a header-dense module)."""

    def __init__(self) -> None:
        self._scope: list[ast.AST | None] = [None]
        self.assigns: list[_AssignInfo] = []
        self.funcs: list[_FuncSpan] = []  # def / async def only — candidates for the ENCLOSING scope
        self.scopes: list[_InnerScope] = []  # def / async def / lambda — for shadow masking

    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        end = node.end_lineno or node.lineno
        self.funcs.append(_FuncSpan(node, node.lineno, end))
        self.scopes.append(_InnerScope(node, node.lineno, end, _param_names(node.args)))
        self._scope.append(node)
        self.generic_visit(node)
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_func(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # A lambda opens a scope but holds no statements, so it never OWNS an assignment and is
        # never the enclosing scope of a header read (that is an assignment) — hence not in
        # `funcs`. It contributes only its parameter shadow, so its body reference to a shadowed
        # header name is not credited as an outer-scope sink (#772 fix-round Issue 1).
        self.scopes.append(
            _InnerScope(node, node.lineno, node.end_lineno or node.lineno, _param_names(node.args))
        )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        names = tuple(t.id for t in node.targets if isinstance(t, ast.Name))
        self.assigns.append(_AssignInfo(node.lineno, self._scope[-1], names, _root_name(node.value)))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            names = (node.target.id,) if isinstance(node.target, ast.Name) else ()
            self.assigns.append(
                _AssignInfo(node.lineno, self._scope[-1], names, _root_name(node.value))
            )
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # Walrus (`ip := sanitize(ip)`) is a reassignment like any other, so it must feed the
        # liveness kill / derivation logic; its target is always a Name (#772 fix-round Issue 3).
        self.assigns.append(
            _AssignInfo(node.lineno, self._scope[-1], (node.target.id,), _root_name(node.value))
        )
        self.generic_visit(node)


def _enclosing(
    funcs: list[_FuncSpan], header_line: int, n_lines: int
) -> tuple[ast.AST | None, int, int]:
    """The (scope-node, scope-start, scope-end) for a header read at `header_line`. The scope node
    is the innermost function enclosing the read (``None`` for module-level code, which falls back
    to the ±``_CTX_WINDOW`` line window)."""
    enclosers = [fs for fs in funcs if fs.start <= header_line <= fs.end]
    if not enclosers:
        return None, max(1, header_line - _CTX_WINDOW), min(n_lines, header_line + _CTX_WINDOW)
    e = max(enclosers, key=lambda fs: fs.start)  # innermost = the one that opens latest
    return e.node, e.start, e.end


def _refs_any(line: str, names: set[str]) -> bool:
    """True when `line` mentions any of `names` as a whole word."""
    return any(re.search(r"\b" + re.escape(n) + r"\b", line) for n in names)


class ForwardedHeaderBlindTrustGuard(Guard):
    id = "forwarded-header-blind-trust"
    title = "X-Forwarded-For / X-Real-IP trusted in a security decision without proxy validation"
    area = "Network requests"

    # xff_rate_limiter.py: X-Forwarded-For read inside a rate_limit context (keyword within 5
    # lines) -> fires forwarded-header-blind-trust/xff-in-security-context (MEDIUM).
    # Must NOT contain: ProxyHeadersMiddleware, forwarded_allow_ips (proxy-aware silencers).
    # Must NOT contain: security: allow-forwarded-header-trust (pragma silences file).
    canary_plant = CanaryPlant(
        files={
            "xff_rate_limiter.py": (
                "from fastapi import Request\n"
                "\n"
                "\n"
                "def check_rate_limit(request: Request) -> bool:\n"
                "    client_ip = request.headers.get('X-Forwarded-For')\n"
                "    return apply_rate_limit(client_ip)\n"
                "\n"
                "\n"
                "def apply_rate_limit(ip: str) -> bool:\n"
                "    return True\n"
            ),
        },
        expects=frozenset({"forwarded-header-blind-trust/xff-in-security-context"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if _PROXY_AWARE.search(text):
                    continue
                if not _XFF.search(text):
                    continue
                out.extend(self._check_file(root, f, text))
        return out

    def _check_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        lines = text.splitlines()
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            # Unparseable module: degrade to the bare one-hop-rename text scan rather than go
            # silent (#772 Low — the fallback is pinned by a test).
            return self._check_file_text(root, f, text, lines)

        collector = _ScopeCollector()
        collector.visit(tree)  # once per file (#772 Medium 2): assignments + function spans.

        out: list[Finding] = []
        for i, line in enumerate(lines):
            header_match = _XFF.search(line)
            if not header_match:
                continue
            header_line = i + 1
            assign_m = _ASSIGN_LHS.match(line)
            var = assign_m.group(1) if assign_m else None

            if var is None:
                # No assignment captured — the header read is used inline (passed directly as a
                # call argument). Without a named variable the only real-flow signal is
                # co-occurrence on the SAME statement; a keyword elsewhere is coincidence.
                if not _SEC_CTX.search(line):
                    continue
            else:
                scope_node, scope_start, scope_end = _enclosing(
                    collector.funcs, header_line, len(lines)
                )
                if not self._live_sink_exists(
                    var, header_line, scope_node, scope_start, scope_end,
                    collector.assigns, collector.scopes, lines,
                ):
                    continue
            out.append(self._finding(root, f, i, header_match))
        return out

    def _live_sink_exists(
        self,
        var: str,
        header_line: int,
        scope_node: ast.AST | None,
        scope_start: int,
        scope_end: int,
        assigns: list[_AssignInfo],
        scopes: list[_InnerScope],
        lines: list[str],
    ) -> bool:
        """Does a security-context sink referencing a *still-live* header-derived value exist
        AFTER the header read, in the header read's OWN scope?

        A forward, source-order sweep over the enclosing scope, starting after the header read
        (#772 Medium 1, ordering). `live` is the set of names currently holding the header value:
        it starts as the header's own binding and grows by one-hop derivations (`root == var`,
        never chaining through an already-added name, so the two-hop gap cannot grow) and shrinks
        when a tracked name is rebound to a non-derivation (#772 High 2, liveness).

        Two per-line adjustments keep the sink check honest without over-suppressing:
        - **`killed_here`**: only the specific names a line rebinds to a non-derivation are removed
          from that line's sink check (a sanitizer like `client = trusted_client_ip(request,
          client)`), so a genuine sink of a *different* still-live name on the same physical line
          is not masked (#772 fix-round Issue 2 — the earlier whole-line suppression was a
          missed-detection regression).
        - **`shadowed`**: a name that is local to a nested scope (a `def`/`lambda` parameter, or a
          name that scope assigns) is not the outer header value on lines inside that scope, so it
          is masked there. A closure over the outer name (bound by neither) still counts — that is
          real flow, and the reason this is name-level masking rather than excluding the whole
          nested span (#772 fix-round Issue 1)."""
        by_line: dict[int, list[_AssignInfo]] = {}
        for a in assigns:
            if a.scope is scope_node and header_line < a.lineno <= scope_end and scope_start <= a.lineno:
                by_line.setdefault(a.lineno, []).append(a)

        # Names each nested scope binds by assignment (its parameters come from `_InnerScope`).
        bound_in: dict[ast.AST, set[str]] = {}
        for a in assigns:
            if a.scope is not None and a.scope is not scope_node:
                bound_in.setdefault(a.scope, set()).update(a.names)
        inner = [
            s
            for s in scopes
            if s.node is not scope_node
            and (scope_node is None or (scope_start <= s.start and s.end <= scope_end))
        ]

        live = {var}
        for ln in range(header_line + 1, scope_end + 1):
            text_ln = lines[ln - 1] if 0 <= ln - 1 < len(lines) else ""
            here = by_line.get(ln, [])
            killed_here = {n for a in here if a.root != var for n in a.names if n in live}
            shadowed: set[str] = set()
            for s in inner:
                if s.start <= ln <= s.end:
                    shadowed |= s.params
                    shadowed |= bound_in.get(s.node, set())
            effective = live - killed_here - shadowed
            if effective and _SEC_CTX.search(text_ln) and _refs_any(text_ln, effective):
                return True
            for a in here:
                if a.root == var:
                    live |= set(a.names)  # one-hop header derivation
                else:
                    live -= set(a.names)  # rebound to a non-header value: taint is dead
        return False

    def _check_file_text(
        self, root: Path, f: Path, text: str, lines: list[str]
    ) -> list[Finding]:
        """Bare one-hop-rename text scan — the pre-#772 behavior, kept ONLY as the fallback for a
        module `ast` cannot parse. No scope/order/liveness reasoning (that needs the AST)."""
        out: list[Finding] = []
        funcs = iter_functions(text, filename=f)
        for i, line in enumerate(lines):
            header_match = _XFF.search(line)
            if not header_match:
                continue
            span = enclosing_function_span(text, i + 1, functions=funcs)
            if span is not None:
                scope_start, scope_end = span
            else:
                scope_start = max(1, i + 1 - _CTX_WINDOW)
                scope_end = min(len(lines), i + 1 + _CTX_WINDOW)
            assign_m = _ASSIGN_LHS.match(line)
            var = assign_m.group(1) if assign_m else None
            if var is not None:
                tracked = {var}
                for j in range(scope_start - 1, scope_end):
                    if j == i or not (0 <= j < len(lines)):
                        continue
                    alias_m = _ALIAS_RE.match(lines[j])
                    if alias_m and alias_m.group(2) == var:
                        tracked.add(alias_m.group(1))
                var_re = re.compile(r"\b(?:" + "|".join(re.escape(v) for v in tracked) + r")\b")
                sink_found = False
                for j in range(scope_start - 1, scope_end):
                    if j == i or not (0 <= j < len(lines)):
                        continue
                    candidate = lines[j]
                    if _SEC_CTX.search(candidate) and var_re.search(candidate):
                        sink_found = True
                        break
                if not sink_found:
                    continue
            elif not _SEC_CTX.search(line):
                continue
            out.append(self._finding(root, f, i, header_match))
        return out

    def _finding(self, root: Path, f: Path, i: int, header_match: re.Match[str]) -> Finding:
        header_name = "X-Real-IP" if "Real-IP" in header_match.group(0) else "X-Forwarded-For"
        return Finding(
            check_id=self.id,
            severity="medium",
            title=f"`{header_name}` used in a security decision without proxy validation",
            location=f"{rel(root, f)}:{i + 1}",
            message=(
                f"The value of `{header_name}` is read from the request headers and "
                "appears within a security-sensitive context (rate limiting, IP allowlisting, "
                "ban, or throttle logic). This header is fully attacker-controlled when "
                "the application is not behind a validated reverse proxy. An attacker "
                "can spoof any IP address by sending `X-Forwarded-For: <trusted-ip>` and "
                "bypass per-IP rate limits or allowlists entirely."
            ),
            remediation=(
                "Use a proxy-aware middleware such as Uvicorn's `ProxyHeadersMiddleware` "
                "with an explicit `forwarded_allow_ips` allowlist, or Starlette's "
                "`TrustedHostMiddleware`, so the framework only trusts the forwarded IP "
                "when it arrives from a known proxy address. "
                "Derive the authoritative client IP from `request.client.host` (set by "
                "the validated middleware layer) rather than from the raw header. "
                "Suppress with `# security: allow-forwarded-header-trust` "
                "when proxy validation is confirmed at the infrastructure layer."
            ),
            rule="forwarded-header-blind-trust/xff-in-security-context",
            standards=list(_STANDARDS),
        )
