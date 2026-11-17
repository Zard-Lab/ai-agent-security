"""Guard: setup.py performs a network call at module top level (checklist §8, new item).

`setup.py` runs on every `pip install`/`python setup.py build` from source, with no
confirmation, before the package's own code has been reviewed or even installed — the same
install-time-execution class `npm-install-script-network` already covers for npm's
`preinstall`/`install`/`postinstall`/`prepare` lifecycle scripts, applied here to Python's
equivalent surface. A module-level call runs unconditionally the moment the file is
imported/executed. A call inside a function or class body runs only when something calls it,
and for one shape that something is setuptools itself: the `run()` of a command class passed
through `cmdclass=`, which the second rule below covers. Ported from `rakshit-737/warden-supply-chain-security`'s
`warden-python.yml` semgrep rule (`warden.install_time_execution.setup-network-call`, fetched
and read in full).

  **`setup-py-network-call` (HIGH):** a `setup.py` (anywhere in the repo, matching the
  source's own `"setup.py"`/`"**/setup.py"` path scope) contains a network call
  (`urllib`/`urllib2`'s `urlopen`/`urlretrieve`, `requests`'s or `httpx`'s HTTP verb methods,
  `http.client.HTTPConnection`/`HTTPSConnection`, or `socket.create_connection`/
  `getaddrinfo`/`gethostbyname`) OUTSIDE any function or class definition — i.e. a call that
  runs the instant the file is executed, not one that waits for an explicit invocation.

  **`setup-cmdclass-network-call` (HIGH, fixed miss):** the classic
  malicious-`setup.py` shape this guard originally missed entirely: a custom command class
  passed via `setup(cmdclass={"install": CustomInstall})` whose own `run()` method makes a
  network call. `_iter_module_level_calls` deliberately does not descend into a class/function
  body (a call that only runs when the function is actually invoked is out of scope for the
  top-level rule above) — but setuptools itself invokes `cmdclass`'s `run()` during
  `pip install`, so a network call there is exactly as install-time-unconditional as a bare
  module-level call, just one layer of indirection away. Detected by resolving every class name
  referenced as a `cmdclass={...}` dict VALUE back to its `ClassDef`, then checking that
  class's own `run` method body for one of the same network calls above.

**Deliberately simpler than the source:** the source's own `pattern-either` also matches a raw
`socket.socket(...).connect(...)` chain and a bare `$SOCK.connect(...)` where `$SOCK` was
assigned from `socket.socket(...)` earlier — tracking that assignment chain needs real AST
dataflow. Dropped here as the noisiest, lowest-marginal-value sub-pattern (the fixed-function
calls above already cover the overwhelming majority of real `setup.py` network fetches), the
same kind of trim this project's other ported rule sets make (see `download-execute-chain`'s
own disclosed drops).

Fires when `python` is detected. Suppress an audited case (a vendored build step with a
genuinely reviewed, pinned fetch) with:

    # security: allow-setup-network-call
"""
from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files_named, pragma_present, read, rel

_PRAGMA = "security: allow-setup-network-call"
_STANDARDS = ["OWASP:A08", "CWE-829", "CWE-494"]

_NETWORK_DOTTED_CALLS = frozenset({
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "urllib.urlopen", "urllib.urlretrieve", "urllib2.urlopen",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.head", "httpx.options",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname",
})


def _dotted_name(node: ast.expr) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _iter_module_level_calls(node: ast.AST) -> Iterator[ast.Call]:
    """Yield every `ast.Call` reachable from `node` WITHOUT descending into a function, async
    function, class, or lambda body -- those only run when actually invoked, not at import
    time, so a network call inside one is out of scope for this guard."""
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    if isinstance(node, ast.Call):
        yield node
    for child in ast.iter_child_nodes(node):
        yield from _iter_module_level_calls(child)


def _cmdclass_names(tree: ast.Module) -> set[str]:
    """Every class name referenced as a `cmdclass={...}` dict VALUE in a `setup(...)` call
    anywhere in the module -- these are the classes setuptools itself will instantiate and
    invoke during `pip install`/`python setup.py build`."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _dotted_name(node.func) in ("setup", "setuptools.setup")):
            continue
        for kw in node.keywords:
            if kw.arg == "cmdclass" and isinstance(kw.value, ast.Dict):
                for value in kw.value.values:
                    if isinstance(value, ast.Name):
                        names.add(value.id)
    return names


def _find_run_method(cls: ast.ClassDef) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for item in cls.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "run":
            return item
    return None


def _first_network_call(node: ast.AST) -> ast.Call | None:
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and _dotted_name(child.func) in _NETWORK_DOTTED_CALLS:
            return child
    return None


class SetupNetworkCallGuard(Guard):
    id = "setup-network-call"
    title = "setup.py performs a network call at module top level"
    area = "Dependencies"

    # setup.py: urllib.request.urlopen(...) called at module top level -> fires
    # setup-network-call/setup-py-network-call (HIGH).
    canary_plant = CanaryPlant(
        files={
            "setup.py": (
                "import urllib.request\n"
                "urllib.request.urlopen('https://example.com/prebuilt.tar.gz')\n"
            ),
        },
        expects=frozenset({"setup-network-call/setup-py-network-call"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "setup.py"):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="python"):
                continue
            tree = safe_ast_parse(text, filename=f)
            if not isinstance(tree, ast.Module):
                continue
            for stmt in tree.body:
                for call in _iter_module_level_calls(stmt):
                    name = _dotted_name(call.func)
                    if name in _NETWORK_DOTTED_CALLS:
                        out.append(self._finding(root, f, call.lineno, name, "setup-py-network-call"))

            classes = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)}
            for cname in _cmdclass_names(tree):
                cls = classes.get(cname)
                run_method = _find_run_method(cls) if cls is not None else None
                if run_method is None:
                    continue
                net_call = _first_network_call(run_method)
                if net_call is not None:
                    name = _dotted_name(net_call.func) or "<network call>"
                    out.append(self._finding(root, f, net_call.lineno, name, "setup-cmdclass-network-call"))
        return out

    def _finding(self, root: Path, f: Path, lineno: int, call_name: str, rule_suffix: str) -> Finding:
        if rule_suffix == "setup-cmdclass-network-call":
            message = (
                f"This `setup.py` registers a custom command class via `cmdclass=` whose "
                f"`run()` method calls `{call_name}(...)`. setuptools invokes that `run()` "
                "during `pip install`/`python setup.py build`, before the package's own code "
                "has been reviewed or even installed -- the same install-time-unconditional "
                "exposure as a bare module-level call, one layer of indirection away."
            )
        else:
            message = (
                f"This `setup.py` calls `{call_name}(...)` at module top level, outside any "
                "function. It runs on every `pip install`/`python setup.py build` from "
                "source, before the package's own code has been reviewed or even installed."
            )
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=(
                "Remove the network call from setup.py's top level entirely. If a build step "
                "genuinely needs to fetch something, have it run explicitly (a documented "
                f"post-install command), never automatically on install. Suppress with `# "
                f"{_PRAGMA}` for an audited, pinned fetch."
            ),
            rule=f"setup-network-call/{rule_suffix}",
            standards=list(_STANDARDS),
        )
