"""Cross-module import reachability — the robust, name-independent signal for the exclude advisor.

The exclude advisor's hardest question is *"is this directory actually non-product?"* — a name
like `evals/` is a weak hint (a repo could **serve** an `evals` endpoint). The strong answer is
reachability: **a directory whose Python modules are never imported by the app's served entrypoints
is almost certainly not product code.**

This module builds a forward import-closure from the detected entrypoints (FastAPI app / `main.py` /
`app.py`) over a cheap, stdlib `ast` import graph (no execution, no third-party deps), then reports the
directories that fall outside it. It is intentionally a **signal, not an oracle**: dynamic imports,
plugin registries, and CLI-only entrypoints can make a genuinely-used module look unreachable, so the
advisor only ever *combines* this with other axes and *suggests* (never auto-excludes).

Bounded: at most `_MAX_FILES` modules are parsed (mirrors `detect._MAX_PY_SCAN`) so a huge repo stays
fast. A file that fails to parse is skipped (total — never raises).
"""
from __future__ import annotations

import ast
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.walk import walk_files

_MAX_FILES = 2000  # cap the closure so it stays fast on big monorepos

# Names that mark a file as a served entrypoint even without an explicit app object.
_ENTRYPOINT_NAMES = frozenset({"main.py", "app.py", "asgi.py", "wsgi.py", "manage.py", "server.py"})
# Substrings that mark app/router construction (the served surface). Detection markers, not a
# real app instance — the trailing pragma opts the literal below out of the api-docs guard.
_APP_MARKERS = ("FastAPI(", "APIRouter(", "Flask(", "Starlette(", "create_app(")  # security: allow-api-docs


def _read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _source_roots(root: Path, profile: StackProfile) -> list[Path]:
    """The import roots to resolve absolute dotted names against — the repo root plus each
    detected top-level python dir (so `from app.routes import x` resolves under `backend/` too)."""
    roots = [root]
    for d in profile.python_dirs:
        if d and d != ".":
            p = root / d
            if p.is_dir():
                roots.append(p)
    # de-dupe, preserve order
    seen: set[Path] = set()
    out: list[Path] = []
    for r in roots:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _module_names(file: Path, source_roots: list[Path]) -> set[str]:
    """Every dotted module name `file` could be imported as, relative to each source root
    (`backend/app/routes.py` -> {`app.routes`, `backend.app.routes`}). `__init__.py` maps to its package."""
    names: set[str] = set()
    for sr in source_roots:
        try:
            rel = file.relative_to(sr)
        except ValueError:
            continue
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1][:-3]  # strip ".py"
        if parts:
            names.add(".".join(parts))
    return names


def _resolve_relative(file: Path, node: ast.ImportFrom, file_set: set[Path]) -> set[Path]:
    """Resolve a relative import (`from .mod import x`, `from .. import y`) to local files by path."""
    base = file.parent
    for _ in range(node.level - 1):  # one dot = current package (file.parent); each extra = up one
        base = base.parent
    out: set[Path] = set()

    def _add(target: Path) -> None:
        for cand in (target.with_suffix(".py"), target / "__init__.py"):
            if cand in file_set:
                out.add(cand)

    if node.module:
        _add(base / Path(*node.module.split(".")))
    else:
        # `from . import a, b` — each name is a submodule/subpackage in `base`
        for alias in node.names:
            _add(base / alias.name)
    return out


def _imports(file: Path, text: str, module_map: dict[str, Path], file_set: set[Path]) -> set[Path]:
    """The set of local files `file` imports (absolute names via `module_map`, relative via path)."""
    tree = safe_ast_parse(text, filename=file)
    if tree is None:
        return set()
    targets: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in module_map:
                    targets.add(module_map[alias.name])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                targets |= _resolve_relative(file, node, file_set)
            elif node.module:
                if node.module in module_map:
                    targets.add(module_map[node.module])
                # `from pkg import submod` where submod is itself a module/package
                for alias in node.names:
                    sub = f"{node.module}.{alias.name}"
                    if sub in module_map:
                        targets.add(module_map[sub])
    return targets


def _is_entrypoint(file: Path, text: str) -> bool:
    return file.name in _ENTRYPOINT_NAMES or any(m in text for m in _APP_MARKERS)


def app_reachable_files(root: Path, profile: StackProfile) -> set[Path]:
    """The set of `.py` files reachable (via a forward import-closure) from the app's served
    entrypoints. Empty if no entrypoint is found (caller treats "no closure" as "no signal")."""
    files = walk_files(root, suffixes=(".py",))[:_MAX_FILES]
    if not files:
        return set()
    file_set = set(files)
    source_roots = _source_roots(root, profile)
    texts = {f: _read(f) for f in files}

    module_map: dict[str, Path] = {}
    for f in files:
        for name in _module_names(f, source_roots):
            # first writer wins is fine; collisions across roots are rare and either resolves the import
            module_map.setdefault(name, f)

    entrypoints = [f for f in files if _is_entrypoint(f, texts[f])]
    if not entrypoints:
        return set()

    # BFS forward closure over the import edges.
    reachable: set[Path] = set(entrypoints)
    queue: list[Path] = list(entrypoints)
    while queue:
        cur = queue.pop()
        for tgt in _imports(cur, texts[cur], module_map, file_set):
            if tgt not in reachable:
                reachable.add(tgt)
                queue.append(tgt)
    return reachable


def unreachable_dirs(root: Path, profile: StackProfile) -> set[str]:
    """Repo-relative directories whose `.py` files are **all** outside the app import-closure — the
    name-independent "looks non-product" signal. Empty when no entrypoint is found (no signal). A dir
    is reported only if it actually contains `.py` files and none of them are reachable.

    Reported at the granularity of every directory that holds `.py` files (so `backend/evals` and
    `backend/evals/cases` are distinct candidates); the advisor rolls these up / scores them."""
    reachable = app_reachable_files(root, profile)
    if not reachable:
        return set()
    files = walk_files(root, suffixes=(".py",))[:_MAX_FILES]
    by_dir: dict[str, list[Path]] = {}
    for f in files:
        rel = f.relative_to(root).parent.as_posix()
        by_dir.setdefault(rel, []).append(f)
    out: set[str] = set()
    for d, members in by_dir.items():
        if d in (".", "") or not members:
            continue
        if all(m not in reachable for m in members):
            out.add(d)
    return out
