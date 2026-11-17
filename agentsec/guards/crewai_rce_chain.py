"""Guard: CrewAI tool usage matching the 2026-04-02 CrewAI exploit chain (CVE-2026-2275/2285/2286,
CERT/CC VU#221883) — checklist §4, new item; agent-audit-kit's `crewai_rce_chain.py`
AAK-CREWAI-CHAIN-2026-04-001.

ThaiCERT and CERT/CC disclosed a chain through CrewAI 0.x that turns an untrusted prompt into
host remote code execution, combining three tool-level primitives:

  1. `CodeInterpreterTool(unsafe_mode=True)` — runs LLM-generated code directly on the host with
     no Docker sandbox at all (CVE-2026-2275).
  2. `JSONSearchTool`/`JSONLoader` given a dynamic (non-literal) file path — path traversal
     reading arbitrary host files (CVE-2026-2285).
  3. `RagTool`/`WebsiteSearchTool` given a dynamic (non-literal) URL — SSRF, no allow-list
     (CVE-2026-2286).

**Deliberately not ported: the chain's 4th component** (CVE-2026-2287 — the CodeInterpreterTool
sandbox silently falling back to unsandboxed host execution when the Docker daemon is
unreachable, with no liveness check). That is a defect inside the `crewai_tools` package's OWN
implementation, not a pattern an application's source code exhibits — no source-level rule can
detect "did the library's internal Docker-availability check run." Closing that gap is a
version-floor entry (a minimum patched `crewai`/`crewai-tools` version), which this project adds
only after independently verifying the CVE-to-fixed-version mapping against the real GitHub
Advisory/PyPI data (tracked as a separate, not-yet-done task) — not fabricated here.

Three rules, all Python, all fired on the class name + a non-literal (dynamic) argument:

  - **`unsafe-code-interpreter`** (CRITICAL): `CodeInterpreterTool(...)` with `unsafe_mode=True`
    (or the string `"True"`) anywhere in its call — direct host execution, no sandbox.
  - **`json-tool-path-traversal`** (HIGH): `JSONSearchTool(...)`/`JSONLoader(...)` with at least
    one non-literal argument — the file path is not fixed and not visibly validated.
  - **`rag-tool-dynamic-url-ssrf`** (HIGH): `RagTool(...)`/`WebsiteSearchTool(...)` with at least
    one non-literal argument — the URL is not fixed and not visibly allow-listed.

"Non-literal" means neither a literal nor a trusted configuration value: a module-level ALL_CAPS
constant, a read off a module-level `settings`/`config` object, or a pure path/string build over
those (`os.path.join(BASE_DIR, "catalog.json")`) is the normal way to configure these tools and
does not fire. A function parameter (even one shadowing `settings`), a local, or any other call
does.

Suppress an audited case with:

    # security: allow-crewai-rce-chain
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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

_PRAGMA = re.compile(r"#\s*security:\s*allow-crewai-rce-chain")

_JSON_TOOL_NAMES = frozenset({"JSONSearchTool", "JSONLoader"})
_RAG_TOOL_NAMES = frozenset({"RagTool", "WebsiteSearchTool"})

_STD_CODE_EXEC = ["CWE-94", "OWASP-ASI:ASI04"]
_STD_PATH_TRAVERSAL = ["CWE-22"]
_STD_SSRF = ["CWE-918", "OWASP:A10"]


_CONST_NAME_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|__file__)$")
_SETTINGS_ROOTS = frozenset({"settings", "config", "cfg", "conf"})
# Pure path/string builders: their result is only as untrusted as their inputs.
_PURE_FUNCS = frozenset({
    "Path", "PurePath", "str", "dict", "os.path.join", "os.path.abspath", "os.path.normpath",
    "os.path.realpath", "os.path.expanduser", "os.path.dirname", "pathlib.Path",
})
_PURE_METHODS = frozenset({
    "joinpath", "resolve", "absolute", "as_posix", "expanduser", "format", "rstrip", "lstrip", "strip",
})


def _module_bound_names(tree: ast.AST) -> frozenset[str]:
    """Names bound at MODULE level (imports and assignments): the constants / settings objects an
    application configures its tools from."""
    names: set[str] = set()
    for stmt in tree.body if isinstance(tree, ast.Module) else ():
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in stmt.names)
        elif isinstance(stmt, ast.Assign):
            names.update(n.id for t in stmt.targets for n in ast.walk(t) if isinstance(n, ast.Name))
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            names.add(stmt.target.id)
    return frozenset(names)


def _dotted(func: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
        return ".".join(reversed(parts))
    return ""


def _is_trusted(arg: ast.expr, module_names: frozenset[str], params: frozenset[str]) -> bool:
    """True when `arg` is a literal, a module-level ALL_CAPS constant, a read of a module-level
    `settings`/`config` object, or a pure path/string build over those. A function parameter, a
    local, or any other call stays UNtrusted (it may carry LLM/caller-supplied data)."""

    def ok(node: ast.expr) -> bool:
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, int, float, bool))
        if isinstance(node, ast.Name):
            return (
                node.id in module_names or node.id == "__file__"
            ) and node.id not in params and bool(_CONST_NAME_RE.match(node.id))
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value  # type: ignore[assignment]
            if isinstance(root, ast.Name) and root.id in _SETTINGS_ROOTS:
                return root.id in module_names and root.id not in params
            return ok(node.value)  # `BASE_DIR.parent`, `Path(...).parent`
        if isinstance(node, ast.JoinedStr):
            return all(
                isinstance(v, ast.Constant) or (isinstance(v, ast.FormattedValue) and ok(v.value))
                for v in node.values
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div, ast.Mod)):
            return ok(node.left) and ok(node.right)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(ok(e) for e in node.elts)
        if isinstance(node, ast.Dict):
            return all(k is not None and ok(k) and ok(v) for k, v in zip(node.keys, node.values, strict=True))
        if isinstance(node, ast.Call):
            args_ok = all(ok(a) for a in node.args) and all(
                kw.arg is not None and ok(kw.value) for kw in node.keywords
            )
            if not args_ok:
                return False
            if isinstance(node.func, ast.Attribute) and node.func.attr in _PURE_METHODS:
                return ok(node.func.value)
            return _dotted(node.func) in _PURE_FUNCS
        return False

    return ok(arg)


def _has_dynamic_arg(call: ast.Call, module_names: frozenset[str], params: frozenset[str]) -> bool:
    if any(not _is_trusted(a, module_names, params) for a in call.args):
        return True
    return any(
        kw.value is not None and not _is_trusted(kw.value, module_names, params)
        for kw in call.keywords
    )


def _calls_with_params(tree: ast.AST) -> list[tuple[ast.Call, frozenset[str]]]:
    """Every `ast.Call` paired with the parameter names of its enclosing function(s)."""
    out: list[tuple[ast.Call, frozenset[str]]] = []

    def visit(node: ast.AST, params: frozenset[str]) -> None:
        for child in ast.iter_child_nodes(node):
            inner = params
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                a = child.args
                names = {x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs)}
                names.update(x.arg for x in (a.vararg, a.kwarg) if x is not None)
                inner = params | names
            if isinstance(child, ast.Call):
                out.append((child, params))
            visit(child, inner)

    visit(tree, frozenset())
    return out


def _unsafe_mode_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg != "unsafe_mode":
            continue
        if isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
        if isinstance(kw.value, ast.Constant) and str(kw.value.value).lower() == "true":
            return True
    return False


class CrewaiRceChainGuard(Guard):
    id = "crewai-rce-chain"
    title = "CrewAI tool usage matches the 2026-04-02 exploit chain (unsafe code exec, path traversal, or SSRF)"
    area = "AI agent"

    # crew_tools.py: CodeInterpreterTool(unsafe_mode=True) -> fires
    # crewai-rce-chain/unsafe-code-interpreter.
    canary_plant = CanaryPlant(
        files={
            "crew_tools.py": (
                "from crewai_tools import CodeInterpreterTool\n\n"
                "interpreter = CodeInterpreterTool(unsafe_mode=True)\n"
            ),
        },
        expects=frozenset({
            "crewai-rce-chain/unsafe-code-interpreter",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features and "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                raw = read(f)
                if not raw or pragma_present(_PRAGMA, raw, dialect="python"):
                    continue
                out.extend(self._scan(r, raw))
        return out

    def _scan(self, r: str, raw: str) -> list[Finding]:
        tree = safe_ast_parse(raw, r)
        if tree is None:
            return []
        out: list[Finding] = []
        module_names = _module_bound_names(tree)
        for node, params in _calls_with_params(tree):
            if not isinstance(node.func, ast.Name):
                continue
            name = node.func.id
            if name == "CodeInterpreterTool" and _unsafe_mode_true(node):
                out.append(self._finding(
                    r, node.lineno, "unsafe-code-interpreter", "critical", _STD_CODE_EXEC,
                    "CodeInterpreterTool is instantiated with unsafe_mode=True — LLM-generated "
                    "code runs directly on the host with no Docker sandbox at all "
                    "(CVE-2026-2275 class).",
                    "Remove unsafe_mode=True (the default, sandboxed mode uses Docker). If a "
                    "sandboxed interpreter is genuinely unavailable, do not fall back to "
                    "unsandboxed execution — fail closed instead.",
                ))
            elif name in _JSON_TOOL_NAMES and _has_dynamic_arg(node, module_names, params):
                out.append(self._finding(
                    r, node.lineno, "json-tool-path-traversal", "high", _STD_PATH_TRAVERSAL,
                    f"{name} is instantiated with a non-literal (dynamic) argument — if this "
                    "value can be influenced by LLM/agent-tool output or a caller, it can read "
                    "arbitrary host files via path traversal (CVE-2026-2285 class).",
                    "Validate and canonicalize the path against an allow-listed base directory "
                    "before passing it to this tool; never pass an unvalidated LLM/agent-tool "
                    "argument directly as a file path.",
                ))
            elif name in _RAG_TOOL_NAMES and _has_dynamic_arg(node, module_names, params):
                out.append(self._finding(
                    r, node.lineno, "rag-tool-dynamic-url-ssrf", "high", _STD_SSRF,
                    f"{name} is instantiated with a non-literal (dynamic) argument — if this "
                    "value can be influenced by LLM/agent-tool output or a caller, it is SSRF: "
                    "the tool fetches whatever URL it's given, including internal/metadata "
                    "endpoints (CVE-2026-2286 class).",
                    "Validate the URL against an allow-list of permitted hosts/schemes before "
                    "passing it to this tool, and block loopback/link-local/metadata-endpoint "
                    "targets.",
                ))
        return out

    def _finding(
        self, r: str, lineno: int, rule_suffix: str, severity: Severity,
        standards: list[str], message: str, remediation: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{r}:{lineno}",
            message=message,
            remediation=remediation,
            rule=f"crewai-rce-chain/{rule_suffix}",
            standards=list(standards),
        )
