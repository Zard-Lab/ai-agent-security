"""Guard: an MCP server declares the upstream SDK and exposes a STDIO transport with no
argv sanitizer, allow-list, or documented opt-out anywhere in the repo (checklist §4, new
item; agent-audit-kit's `mcp_sdk_hardening.py` AAK-ANTHROPIC-SDK-001).

Anthropic declined to CVE the MCP STDIO transport design itself (OX Security, 2026-04-15):
the upstream SDKs pass configuration to the OS as command execution BY DESIGN — that is
what STDIO transport means. The obligation this leaves on every downstream server is to
add its own argv sanitizer; a server that uses the SDK's STDIO primitives and adds nothing
of its own inherits an unpatchable-by-design risk with no compensating control.

Fires MEDIUM (a structural, repo-wide gap — not a single-line bug) when, across the whole
repo:
  1. a dependency manifest declares the upstream MCP SDK — Python (`mcp`,
     `modelcontextprotocol`), TypeScript (`@modelcontextprotocol/sdk`, `@anthropic-ai/mcp`,
     `@anthropic-ai/claude-agent-sdk`), Java (`io.modelcontextprotocol` in
     `pom.xml`/`build.gradle`), or Rust (`mcp`/`modelcontextprotocol` in `Cargo.toml`);
  2. at least one repo file uses a STDIO-transport API from that SDK
     (`StdioServerTransport`, `StdioClientTransport`, `stdio_server`, `StdioServer`,
     `stdio_client`, `StdioClient`); AND
  3. none of the following opt-outs are present ANYWHERE in the repo: a `shlex.quote`/
     `shlex.split` call (Python) or `execFile([...])` (Node) — real argv sanitization; an
     allow-list-shaped identifier (`ALLOWED_*`, `WHITELIST_*`, `VALID_TOOLS`/
     `VALID_COMMANDS`); `ProcessBuilder(List.of(...)/Arrays.asList(...)/[...])` (Java) or
     `std::process::Command::new(...).arg(...)` (Rust); a config opt-out
     (`transports=['http'|'sse'|'streamable-http']` / `stdio_disabled: true`); or the
     inline pragma below (this project's substitute for the real source's bespoke
     `.agent-audit-kit.yml` risk-acceptance file, which agentsec has no equivalent
     convention for).

     "Anywhere" is literal: every source file in the project is searched, not only the
     STDIO-using ones, so a shared sanitizer helper module counts. A "project" is the tree
     under a manifest that declares the SDK (item 1): the whole repo for a single-package
     repo, one package for a monorepo, where a sanitizer in one package does not vouch for
     another (the deepest declaring manifest owns a STDIO file). The pragma and the config
     opt-outs are also read from test/example paths and from YAML/TOML/JSON/INI config files;
     the sanitizer and allow-list identifiers are read from product source only. Web-server
     allow-lists (`ALLOWED_HOSTS`, `ALLOWED_ORIGINS`, CORS/redirect/extension lists) are not an
     argv control and do not count.

Suppress an audited/accepted case with:

    # security: allow-mcp-stdio-no-sanitizer
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-stdio-no-sanitizer"

_PY_SDK_NAMES = ("mcp", "modelcontextprotocol", "model-context-protocol")
_TS_SDK_NAMES = ("@modelcontextprotocol/sdk", "@anthropic-ai/mcp", "@anthropic-ai/claude-agent-sdk")
_JAVA_SDK_TOKEN = "io.modelcontextprotocol"  # nosec B105 (a package-name string, not a credential)
_RUST_SDK_TOKENS = ("mcp", "modelcontextprotocol")

_STDIO_MARKERS = (
    "StdioServerTransport", "StdioClientTransport", "StdioTransport",
    "stdio_server", "StdioServer", "stdio_client", "StdioClient",
)

# The side that LAUNCHES a configured command (the OX Security design issue this guard cites:
# "the SDK passes configuration to the OS as command execution"). `StdioServerTransport`/
# `stdio_server`/`StdioServer` are the SERVER side -- reading JSON-RPC from stdin, spawning
# nothing. `StdioTransport` is ambiguous across SDKs and kept on the launcher side (the safer
# direction for a false negative). `StdioServerParameters` is a CLIENT-side config object
# despite its name: it describes how a client should launch a downstream server.
_LAUNCHER_STDIO_MARKERS = (
    "StdioClientTransport", "StdioTransport", "stdio_client", "StdioClient", "StdioServerParameters",
)
_SPAWN_CALL_RE = re.compile(
    r"\bsubprocess\.|child_process|\bspawn\s*\(|\bexecFile\s*\(|\bPopen\s*\(|\bexecSync\s*\("
)

_STDIO_OPT_OUT_RE = re.compile(
    r"""
    (?:
        transports\s*=\s*\[\s*['"](?:http|sse|streamable-http)['"]
      | transport\s*[:=]\s*['"](?:http|sse|streamable-http)['"]
      | stdio_disabled\s*[:=]\s*(?:true|True|1)
    )
    """,
    re.VERBOSE,
)

_WEB_ALLOWLIST = (
    r"(?:HOSTS?|ORIGINS?|METHODS|HEADERS|EXTENSIONS?|IPS?|DOMAINS?|URLS?|MIME\w*|FILE\w*"
    r"|HTTP\w*|REDIRECT\w*|CORS\w*)"
)

_SANITIZER_HINTS = (
    re.compile(r"\bshlex\.(?:quote|split)\s*\("),
    re.compile(r"\bexecFile\s*\(\s*[^,]+,\s*\["),
    # Whole-repo scanning makes this identifier broad: web-server allow-lists (`ALLOWED_HOSTS`,
    # `ALLOWED_ORIGINS`, CORS/redirect/extension lists) are NOT an argv control, so they are excluded.
    re.compile(
        r"\b(?:(?:ALLOWED|WHITELIST)_(?!" + _WEB_ALLOWLIST + r"(?![A-Z0-9]))[A-Z_]+"
        r"|VALID_(?:TOOLS|COMMANDS))\b"
    ),
    re.compile(r"\bProcessBuilder\s*\(\s*(?:List\.of|Arrays\.asList|\[)"),
    re.compile(r"\bstd::process::Command::new\s*\([^)]+\)\s*\.\s*arg\s*\("),
)

_LANG_EXTS_FOR_STDIO_MARKERS = (".py", ".ts", ".tsx", ".js", ".mjs", ".java", ".kt", ".rs")
# Config files are searched for the opt-outs and the pragma only (never for sanitizer identifiers).
_CONFIG_EXTS_FOR_OPT_OUT = (".yaml", ".yml", ".toml", ".json", ".cfg", ".ini")

_MANIFEST_GLOBS = (
    "pyproject.toml", "requirements*.txt", "package.json",
    "pom.xml", "build.gradle", "build.gradle.kts", "Cargo.toml",
)

_STANDARDS = ["CWE-78", "OWASP-ASI:ASI04"]


def _manifest_declares_sdk(f: Path) -> bool:
    """True if the manifest `f` declares the upstream MCP SDK (dispatch on the manifest's name)."""
    name = f.name
    text = read(f)
    if not text:
        return False
    if name == "pyproject.toml":
        return any(f'"{n}"' in text or f"'{n}'" in text for n in _PY_SDK_NAMES)
    if name.startswith("requirements") and name.endswith(".txt"):
        for line in text.splitlines():
            dep = line.split("#", 1)[0].strip().split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip()
            if dep in _PY_SDK_NAMES:
                return True
        return False
    if name == "package.json":
        try:
            data = json.loads(text)
        except (ValueError, RecursionError):  # hostile deep nesting: not a usable manifest
            return False
        if not isinstance(data, dict):
            return False
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(section) or {}
            if isinstance(deps, dict) and any(n in deps for n in _TS_SDK_NAMES):
                return True
        return False
    if name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        return _JAVA_SDK_TOKEN in text
    if name == "Cargo.toml":
        return any(re.search(rf"^\s*{re.escape(tok)}\s*=", text, re.MULTILINE) for tok in _RUST_SDK_TOKENS)
    return False


def _declaring_dirs(root: Path, profile: StackProfile) -> list[Path]:
    """Every directory whose manifest declares the SDK, deepest first: the "projects" the
    STDIO-transport check runs on. A single-package repo has exactly one, the repo root. In a
    monorepo each package is its own project, so a sanitizer in one package does not vouch for
    another; manifests under test/example/fixture paths do not create a project."""
    dirs: set[Path] = set()
    for f in iter_files_named(root, *_MANIFEST_GLOBS):
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue
        if _manifest_declares_sdk(f):
            dirs.add(f.parent)
    return sorted(dirs, key=lambda d: len(d.parts), reverse=True)


def _uses_stdio(root: Path) -> list[Path]:
    hits: list[Path] = []
    for f in iter_files(root, _LANG_EXTS_FOR_STDIO_MARKERS):
        text = read(f)
        if any(m in text for m in _STDIO_MARKERS):
            hits.append(f)
    return hits


def _project_has_launcher_evidence(project: Path, root: Path, profile: StackProfile) -> bool:
    """True when `project` shows evidence it LAUNCHES a subprocess: a client-side STDIO API
    (`_LAUNCHER_STDIO_MARKERS`) or a direct process-spawn call in its product source (test and
    example paths are skipped: `modelcontextprotocol/servers` launches its server-only packages
    from `__tests__/` harnesses, which gave 2 findings on packages that spawn nothing). A server-only
    project (`StdioServerTransport`/`stdio_server`/`StdioServer`, no spawn call at all) reads
    JSON-RPC from stdin and builds no argv -- the OX Security design issue this guard cites is
    about the side that launches a configured command, not the side that answers on it. Without
    this gate, the per-package sanitizer scoping (a real fix: a sanitizer in one package no
    longer vouches for an unrelated one) took a real corpus's server-only reference
    implementations from 0 findings to 7, none of which spawns anything."""
    for f in iter_files(project, _LANG_EXTS_FOR_STDIO_MARKERS):
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue  # a test harness that launches the server is not the product launching one
        text = read(f)
        if any(m in text for m in _LAUNCHER_STDIO_MARKERS) or _SPAWN_CALL_RE.search(text):
            return True
    return False


def _has_sanitizer_or_optout(root: Path, project: Path, profile: StackProfile) -> bool:
    """True if a sanitizer, allow-list or opt-out exists ANYWHERE in `project` (the directory of
    the manifest that declares the SDK: the whole repo for a single-package repo).

    The pragma and the config opt-outs (`stdio_disabled: true`, `transports=['http']`) are read from
    EVERY scanned file, including tests/examples and config files: a user's own opt-out must not be
    voided by a path skip (CLAUDE.md rule 4). The sanitizer/allow-list identifiers are read from
    product source only, so a `shlex.split` in a test or example does not vouch for production code.
    (This used to look only at the STDIO-using files, so a `shlex.quote` in a shared helper module
    imported by the server still fired.)
    """
    for f in iter_files(project, _LANG_EXTS_FOR_STDIO_MARKERS + _CONFIG_EXTS_FOR_OPT_OUT):
        if f.name.endswith("lock.json"):
            continue  # a lockfile is machine output, never an opt-out, and can be megabytes
        text = read(f)
        if not text:
            continue
        if _STDIO_OPT_OUT_RE.search(text) or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return True
        if (
            f.suffix in _LANG_EXTS_FOR_STDIO_MARKERS
            and not is_nonproduct_path(rel(root, f), profile.archive_segments)
            and any(pat.search(text) for pat in _SANITIZER_HINTS)
        ):
            return True
    return False


def _first_stdio_line(text: str) -> int:
    """1-based line of the first STDIO-transport marker in `text` (1 if none)."""
    first = min((i for m in _STDIO_MARKERS if (i := text.find(m)) >= 0), default=0)
    return text.count("\n", 0, first) + 1


class McpStdioNoSanitizerGuard(Guard):
    id = "mcp-stdio-no-sanitizer"
    title = "MCP server uses the SDK's STDIO transport with no argv sanitizer anywhere"
    area = "AI agent"

    # mcp_stdio_pkg/pyproject.toml declares `mcp`; mcp_stdio_pkg/mcp_stdio_server.py uses
    # StdioServerTransport with no shlex/allow-list anywhere in that package -> fires
    # mcp-stdio-no-sanitizer/no-sanitizer. The plant is its OWN project directory because the
    # sanitizer/opt-out search covers the whole project tree, and the shared canary repo holds other
    # guards' plants that legitimately carry an HTTP transport and an `ALLOWED_TOOLS` allow-list.
    canary_plant = CanaryPlant(
        files={
            "mcp_stdio_pkg/pyproject.toml": (
                "[project]\nname = \"canary-mcp-server\"\ndependencies = [\"mcp\"]\n"
            ),
            "mcp_stdio_pkg/mcp_stdio_server.py": (
                "import subprocess\n"
                "from mcp.server.stdio import StdioServerTransport\n\n"
                "def run_tool(cmd):\n"
                "    transport = StdioServerTransport()\n"
                "    transport.serve()\n"
                "    subprocess.run(cmd)\n"
            ),
        },
        expects=frozenset({
            "mcp-stdio-no-sanitizer/no-sanitizer",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        projects = _declaring_dirs(root, profile)
        if not projects:
            return []

        stdio_files = _uses_stdio(root)
        if not stdio_files:
            return []

        covered: dict[Path, bool] = {}
        launches: dict[Path, bool] = {}
        out: list[Finding] = []
        for f in stdio_files:
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            # The deepest project whose manifest declares the SDK owns this file.
            owner = next((d for d in projects if d == f.parent or d in f.parents), None)
            if owner is None:
                continue
            if owner not in launches:
                launches[owner] = _project_has_launcher_evidence(owner, root, profile)
            if not launches[owner]:
                continue
            if owner not in covered:
                covered[owner] = _has_sanitizer_or_optout(root, owner, profile)
            if covered[owner]:
                continue
            out.append(self._finding(r, _first_stdio_line(read(f))))
        return out

    def _finding(self, r: str, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                "The upstream MCP SDK is declared and this file exposes a STDIO "
                "transport, but no argv sanitizer, allow-list, or documented opt-out is "
                "present anywhere in the repo. Anthropic declined to CVE the STDIO "
                "design itself (OX Security, 2026-04-15) — the SDK passes configuration "
                "to the OS as command execution BY DESIGN, so every downstream server "
                "must add its own compensating control."
            ),
            remediation=(
                "Add explicit argv sanitization (`shlex.quote`/`shlex.split` in Python, "
                "`execFile([...])` with a literal argv array in Node) or an allow-list of "
                "permitted commands/tools before any STDIO-transported argument reaches "
                "process execution."
            ),
            rule="mcp-stdio-no-sanitizer/no-sanitizer",
            standards=list(_STANDARDS),
        )
