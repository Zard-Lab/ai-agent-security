"""Guard: install/skill-setup code resolves an executable from a workspace-controlled
source with no absolute-path pin or allowlist — CVE-2026-53819 (checklist §8, new item;
agent-audit-kit's `skill_untrusted_exec_path.py` AAK-SKILL-UNTRUSTED-EXEC-PATH, CWE-426).

Per NVD, "OpenClaw before 2026.5.27 contains an arbitrary code execution vulnerability in
skill install flows where workspace `.env` files can override the Homebrew executable
selection ... execute unintended Homebrew-compatible executables during skill setup to
compromise the system" (CVSS 8.7). The system then executes whatever binary the workspace
points at instead of the intended one.

Fires HIGH when, in an install/skill-setup-context file (named `install`/`setup`/
`bootstrap`/`provision`/`postinstall`/`skill`, or content mentioning `SKILL.md`/
`load_dotenv`/`homebrew`/`brew`), a subprocess/exec sink's command resolves from an
untrusted source with no absolute-path pin:

  - a `.env`/dotenv-sourced variable (`load_dotenv()` then `os.environ.get(...)`/
    `os.getenv(...)`/`dotenv_values(...)[...]`) used as the command;
  - a `PATH` prepended with a non-absolute/workspace directory
    (`os.environ["PATH"] = os.getcwd() + os.pathsep + ...`);
  - `shutil.which(...)` resolved over such a tainted `PATH`. A `PATH` is tainted by
    `load_dotenv(override=True)`, `os.environ.update(dotenv_values(...))`, or a dotenv-derived
    `env=` passed to the spawn. A bare `load_dotenv()` does not taint it (the default
    `override=False` never replaces an existing PATH), and a `$HOME/...:$PATH` shell prepend
    is the standard per-user install idiom, so neither fires;
  - a bare binary name (no path separator) resolved over a tainted `PATH`.

Shell install scripts are checked with a parallel, narrower regex path: a `PATH` prepend
with a non-absolute element or a sourced `.env`, followed by a bare `brew`/`npm`/`node`/
`pip`/`python`/`uv` invocation.

FP guards: an absolute-path-pinned binary, an `os.path.isabs`/allowlist check anywhere in
the file, or a file with no install/skill-setup context at all all pass clean.

Suppress an audited case with:

    # security: allow-skill-untrusted-exec-path
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-skill-untrusted-exec-path")

_INSTALL_NAME_RE = re.compile(r"install|setup|bootstrap|provision|post[_-]?install|skill", re.IGNORECASE)
_INSTALL_CONTENT_RE = re.compile(
    r"SKILL\.md|skill[_\s-]*install|post[_-]?install|load_dotenv|dotenv_values|homebrew|\bbrew\b|HOMEBREW",
    re.IGNORECASE,
)

_EXEC_ATTRS = {"run", "popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
_OS_EXEC_ATTRS = {"system", "popen", "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe", "spawnv", "spawnl"}
_PIN_RE = re.compile(r"os\.path\.isabs|allow[_-]?list|allowlist|ALLOWED_(?:BINARIES|EXECUTABLES|PATHS)")

_SH_TAINT_PATH_RE = re.compile(
    # A `$HOME/...` or `~/...` prepend is the standard uv/pipx/cargo install idiom: a per-user
    # directory, not a workspace-controlled one.
    r"export\s+PATH=(?![\"']?(?:/|~|\$HOME\b|\$\{HOME\}))[^\n]*:\$PATH|PATH=\.[:/]|export\s+PATH=\$\(pwd\)|export\s+PATH=\$PWD"
)
_SH_SOURCE_ENV_RE = re.compile(r"(?:^|\s)(?:source|\.)\s+\.?/?\.env\b", re.MULTILINE)
_SH_BREW_EXEC_RE = re.compile(r"(?<![/\w])(?:brew|npm|node|pip|python|uv)\b")

_PY_SUFFIXES = (".py",)
_SH_SUFFIXES = (".sh", ".bash")

_STANDARDS = ["CWE-426", "OWASP-ASI:ASI04"]


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_env_source(value: ast.AST) -> bool:
    for sub in ast.walk(value):
        if isinstance(sub, ast.Call) and _attr_chain(sub.func) in ("os.environ.get", "os.getenv", "getenv", "dotenv_values"):
            return True
        if isinstance(sub, ast.Subscript) and _attr_chain(sub.value) in ("os.environ", "environ"):
            return True
    return False


def _is_shutil_which(value: ast.AST) -> bool:
    return any(isinstance(sub, ast.Call) and _attr_chain(sub.func) in ("shutil.which", "which") for sub in ast.walk(value))


def _expr_has_abs_literal(value: ast.AST) -> bool:
    for sub in ast.walk(value):
        if (
            isinstance(sub, ast.Constant)
            and isinstance(sub.value, str)
            and (sub.value.startswith("/") or re.match(r"^[A-Za-z]:\\", sub.value))
        ):
            return True
    return False


def _has_dotenv_values(value: ast.AST) -> bool:
    return any(
        isinstance(s, ast.Call) and _attr_chain(s.func) in ("dotenv_values", "dotenv.dotenv_values")
        for s in ast.walk(value)
    )


def _path_is_tainted(tree: ast.AST, dotenv_names: set[str]) -> bool:
    """True when a workspace `.env` can actually change the PATH a later spawn resolves over.

    `load_dotenv()` alone does NOT: python-dotenv's default `override=False` never replaces a
    variable already in the environment, and PATH always is. So a bare `load_dotenv()` no longer
    taints the file. What does: `load_dotenv(override=True)`, `os.environ.update(<dotenv
    values>)`, or an explicit non-absolute assignment to `os.environ["PATH"]`."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            if chain in ("load_dotenv", "dotenv.load_dotenv"):
                override = next((k.value for k in node.keywords if k.arg == "override"), None)
                if override is not None and not (isinstance(override, ast.Constant) and override.value is False):
                    return True
            if chain in ("os.environ.update", "environ.update") and any(
                _has_dotenv_values(a) or any(isinstance(s, ast.Name) and s.id in dotenv_names for s in ast.walk(a))
                for a in node.args
            ):
                return True
        if isinstance(node, ast.Assign):
            for tgt in node.targets:
                if isinstance(tgt, ast.Subscript):
                    base = _attr_chain(tgt.value)
                    key = tgt.slice
                    keyval = key.value if isinstance(key, ast.Constant) else None
                    if (
                        base in ("os.environ", "environ")
                        and keyval == "PATH"
                        and (
                            not _expr_has_abs_literal(node.value)
                            or any(isinstance(s, (ast.Name, ast.Call)) for s in ast.walk(node.value))
                        )
                    ):
                        return True
    return False


def _command_expr(call: ast.Call) -> ast.AST | None:
    if call.args:
        first = call.args[0]
        if isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            return first.elts[0]
        return first
    for kw in call.keywords:
        if kw.arg == "executable":
            return kw.value
    return None


def _scan_python(text: str, path: Path) -> int | None:
    tree = safe_ast_parse(text, filename=path)
    if tree is None:
        return None
    if _PIN_RE.search(text):
        return None

    env_bins: set[str] = set()
    which_bins: set[str] = set()
    dotenv_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            tgt = node.targets[0]
            if not isinstance(tgt, ast.Name):
                continue
            if _has_dotenv_values(node.value):
                dotenv_names.add(tgt.id)
            if _expr_has_abs_literal(node.value):
                continue
            if _is_env_source(node.value):
                env_bins.add(tgt.id)
            elif _is_shutil_which(node.value):
                which_bins.add(tgt.id)

    path_tainted = _path_is_tainted(tree, dotenv_names)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fname = _attr_chain(node.func)
        is_sink = (
            (fname.split(".")[-1] in _EXEC_ATTRS and "subprocess" in fname)
            or fname in {f"os.{a}" for a in _OS_EXEC_ATTRS}
            or fname in ("os.system", "os.popen")
        )
        if not is_sink:
            continue
        cmd = _command_expr(node)
        if cmd is None or _expr_has_abs_literal(cmd):
            continue
        names = {s.id for s in ast.walk(cmd) if isinstance(s, ast.Name)}
        # A dotenv-derived `env=` handed to the spawn lets the workspace `.env` set PATH for it.
        spawn_env_tainted = any(
            kw.arg == "env" and (
                _has_dotenv_values(kw.value)
                or any(isinstance(s, ast.Name) and s.id in dotenv_names for s in ast.walk(kw.value))
            )
            for kw in node.keywords
        )
        if names & env_bins:
            return node.lineno
        if (names & which_bins or _is_shutil_which(cmd)) and (path_tainted or spawn_env_tainted):
            return node.lineno
        if _is_env_source(cmd):
            return node.lineno
        if (path_tainted or spawn_env_tainted) and isinstance(cmd, ast.Constant) and isinstance(cmd.value, str) and "/" not in cmd.value and cmd.value:
            return node.lineno
    return None


def _scan_shell(text: str) -> int | None:
    if _PIN_RE.search(text):
        return None
    tainted = bool(_SH_TAINT_PATH_RE.search(text) or _SH_SOURCE_ENV_RE.search(text))
    if not tainted:
        return None
    m = _SH_BREW_EXEC_RE.search(text)
    return (text.count("\n", 0, m.start()) + 1) if m else None


def _in_install_context(path: Path, text: str) -> bool:
    return bool(_INSTALL_NAME_RE.search(path.name) or _INSTALL_CONTENT_RE.search(text))


class SkillUntrustedExecPathGuard(Guard):
    id = "skill-untrusted-exec-path"
    title = "Install/skill-setup code resolves an executable from a workspace-controlled source"
    area = "AI agent"

    # skill_install.py: PATH tainted via load_dotenv(override=True), then a bare 'brew' name is
    # resolved via shutil.which over it -> fires
    # skill-untrusted-exec-path/untrusted-search-path.
    canary_plant = CanaryPlant(
        files={
            "skill_install.py": (
                "import os, shutil\n"
                "from dotenv import load_dotenv\n\n"
                "load_dotenv(override=True)\n"
                "brew_path = shutil.which('brew')\n"
                "os.system(brew_path)\n"
            ),
        },
        expects=frozenset({
            "skill-untrusted-exec-path/untrusted-search-path",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _PY_SUFFIXES + _SH_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or not _in_install_context(f, text):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            line = _scan_python(text, f) if f.suffix in _PY_SUFFIXES else _scan_shell(text)
            if line is not None:
                out.append(self._finding(f"{r}:{line}"))
        return out

    def _finding(self, location: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=location,
            message=(
                "Install/skill-setup code resolves an executable, interpreter, or "
                "build tool from a workspace-controlled source (a `.env`-sourced "
                "var, an env-overridden/non-absolute `PATH`, `shutil.which()` over a "
                "tainted PATH, or a bare binary name resolved over a tainted PATH) "
                "and runs it without an absolute-path pin — a workspace `.env` can "
                "override which binary executes during setup (CVE-2026-53819, "
                "CWE-426 Untrusted Search Path)."
            ),
            remediation=(
                "Pin the executable to an absolute, known-good path, or validate the "
                "resolved binary against an explicit allowlist before invoking it. "
                "Never let a workspace-controlled `.env`/`PATH` influence which "
                "binary a skill-setup step executes."
            ),
            rule="skill-untrusted-exec-path/untrusted-search-path",
            standards=list(_STANDARDS),
        )
