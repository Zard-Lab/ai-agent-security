"""G5 verification: `agentsec/net.py` is the ONLY module under `agentsec/` that imports a
network module. This is the inverse of the guard-sandbox import scan — it relocates G5's
"no surprise egress" auditability to one file rather than losing it.

If this fails, some module imported `urllib`/`socket`/`http`/… directly instead of routing
through `agentsec/net.py` (the chokepoint). Fix the module, don't add it to the allowlist.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Egress-performing import paths no module except net.py may use. (NOT `urllib.parse` /
# `urllib.error` — those are URL string-handling, they don't touch the network.)
_EGRESS_PREFIXES = (
    "urllib.request", "socket", "http.client", "urllib3", "requests", "httpx", "aiohttp",
)
# The single sanctioned egress boundary.
_ALLOWED = {"net.py"}
_AGENTSEC = Path(__file__).resolve().parents[1] / "agentsec"


def _is_egress(dotted: str) -> bool:
    return any(dotted == p or dotted.startswith(p + ".") for p in _EGRESS_PREFIXES)


def _egress_imports(source: str) -> set[str]:
    """Egress import paths in one module (handles `import urllib.request`,
    `from urllib.request import …`, and `from urllib import request`)."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names if _is_egress(a.name)}
        elif isinstance(node, ast.ImportFrom) and node.module:
            if _is_egress(node.module):
                found.add(node.module)
            else:  # `from urllib import request` → urllib.request
                found |= {f"{node.module}.{a.name}" for a in node.names if _is_egress(f"{node.module}.{a.name}")}
    return found


def test_only_net_py_imports_a_network_module() -> None:
    offenders: list[str] = []
    for py in sorted(_AGENTSEC.rglob("*.py")):
        if py.name in _ALLOWED:
            continue
        # Shipped CI template scripts (installed INTO a user's repo) are data, not agentsec
        # runtime code — they legitimately use the network in the user's project.
        if "/ci/components/" in py.as_posix() and "/files/" in py.as_posix():
            continue
        imps = _egress_imports(py.read_text(encoding="utf-8"))
        if imps:
            offenders.append(f"{py.relative_to(_AGENTSEC.parent)} imports {sorted(imps)}")
    assert not offenders, (
        "network module imported outside agentsec/net.py — route it through the net.py chokepoint:\n  "
        + "\n  ".join(offenders)
    )


def test_net_py_is_the_boundary() -> None:
    # sanity: net.py itself DOES import the egress stack (it's the one allowed to)
    assert _egress_imports((_AGENTSEC / "net.py").read_text(encoding="utf-8"))
