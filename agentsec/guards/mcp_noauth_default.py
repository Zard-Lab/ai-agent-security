"""Guard: an MCP server ships an auth check that fails open, or is unauthenticated by
default (checklist §4, new item; agent-audit-kit's `mcp_noauth_default.py`
AAK-MCP-NOAUTH-DEFAULT).

Distinct from `mcp-transport-no-auth` (which flags a transport with NO auth configured at
all) and `mcp-transport-session-unauth` (which flags an outbound credential mistaken for
an inbound one): this guard flags an MCP server that SHIPS an auth check which does not
actually enforce anything. CVE-2026-48814 (Network-AI, CVSS 9.1) is the anchor — an
*incomplete fix* of a prior CVE where the newly-added auth gate still admitted requests
when the secret was unset.

Fires HIGH/CRITICAL on any of three shapes:
  (a) **fail-open-auth**: an `is_authorized`/`verify_token`/`check_auth`/... function whose
      body returns a truthy value when the secret/token is empty or unset
      (`if not SECRET: return True`).
  (b) **placeholder-secret**: a secret-named variable assigned a literal
      `""`/`"changeme"`/`"secret"`/`"admin"`/... default, or
      `os.environ.get("X_SECRET", "")` with an empty-string default (ships unauthed until
      an operator changes it).
  (c) **warn-only-auth-gate**: a secret-emptiness check that only logs/warns and continues
      (no `raise`/`return`/`sys.exit`) while the server binds a non-loopback interface.
  (d) **auth-disabled-config**: an MCP config (JSON/YAML/TOML/env) that switches
      authentication off by flag (`auth.enabled: false` / `disable_auth: true`) while
      binding a non-loopback interface — CVE-2026-90898 (Bifrost) shipped exactly this
      default.

FP guards: a required secret (`os.environ["X"]`, no empty default), a non-empty literal, an
auth function that returns `token == SECRET`, and a loopback bind all pass clean.

Suppress an audited case with:

    # security: allow-mcp-noauth-default
"""
from __future__ import annotations

import ast
import json
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
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-mcp-noauth-default")

_MCP_HINT_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|FastMCP|McpServer|mcpServers|\bServer\s*\(",
    re.IGNORECASE,
)
_SECRET_NAME_RE = re.compile(
    r"secret|token|api[_-]?key|apikey|password|passwd|auth[_-]?key|auth_token",
    re.IGNORECASE,
)
_AUTH_FN_RE = re.compile(
    r"^_?(?:is_?authori[sz]ed|authori[sz]e|check_?auth|verify_?token|verify_?auth"
    r"|require_?auth|validate_?token|validate_?auth|authenticate)$",
    re.IGNORECASE,
)
_WEAK_SECRET_VALUES = frozenset({
    "", "changeme", "change-me", "change_me", "secret", "password", "passwd",
    "admin", "default", "token", "test", "placeholder", "xxx", "none",
    "your-secret-here", "your_secret_here", "your-token-here", "example",
})
_WARN_CALL_RE = re.compile(r"warn|warning|getLogger|logger|print|console\.warn", re.IGNORECASE)
_BIND_NONLOOPBACK_RE = re.compile(r"0\.0\.0\.0|\[::\]|[\"']::[\"']")
# A JSON SCHEMA document (a meta-file describing what fields a config CAN have) is not a live
# runtime config, so a "secret": "secret" pair inside its own `"examples"` / `"default"`
# subtrees is an illustrative placeholder, not a deployed credential. Confirmed on fastmcp's
# docs/assets/schemas/mcp_server_config/v1.json: `"API_KEY": "secret"` sits inside an
# `"examples"` block documenting the env-var dict's SHAPE.
#
# The exclusion is scoped to those subtrees of a document that IS itself a schema
# (`_is_schema_document`). It used to drop any file merely containing `"$schema"`, which also
# silenced real configs: ordinary configs carry `"$schema"` for editor autocompletion
# (schemastore-backed files, VS Code / Claude Code settings), and such a config must still fire.
_SCHEMA_STRUCTURE_KEYS = ("properties", "$defs", "definitions")
_SCHEMA_ILLUSTRATIVE_KEYS = frozenset({"examples", "example", "default"})
_SCHEMA_MAP_KEYS = frozenset({"properties", "$defs", "definitions", "patternProperties"})

_STANDARDS = ["OWASP:A07", "CWE-306", "CWE-862"]


def _is_emptiness_test(test: ast.AST) -> bool:
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _refs_secret(test.operand)
    if isinstance(test, ast.Compare) and _refs_secret(test.left):
        for op, comp in zip(test.ops, test.comparators, strict=True):
            if isinstance(op, (ast.Eq, ast.Is, ast.In)):
                if isinstance(comp, ast.Constant) and (comp.value in ("", None)):
                    return True
                if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                    return True
    return False


def _refs_secret(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and _SECRET_NAME_RE.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and _SECRET_NAME_RE.search(sub.attr):
            return True
    return False


def _returns_truthy(body: list[ast.stmt]) -> bool:
    for stmt in body:
        if (
            isinstance(stmt, ast.Return)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value not in (False, None, "", 0)
        ):
            return True
    return False


def _body_is_warn_only(body: list[ast.stmt]) -> bool:
    saw_warn = False
    for stmt in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(stmt, (ast.Raise, ast.Return)):
            return False
        if isinstance(stmt, ast.Call):
            name = ast.unparse(stmt.func) if hasattr(ast, "unparse") else ""
            if "exit" in name or "abort" in name:
                return False
            if _WARN_CALL_RE.search(name):
                saw_warn = True
    return saw_warn


def _scan_python(text: str, path: Path) -> list[tuple[int, str]]:
    if not _MCP_HINT_RE.search(text):
        return []
    tree = safe_ast_parse(text, path)
    if tree is None:
        return []

    hits: list[tuple[int, str]] = []
    bind_nonloopback = bool(_BIND_NONLOOPBACK_RE.search(text))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _AUTH_FN_RE.match(node.name):
            for inner in ast.walk(node):
                if isinstance(inner, ast.If) and _is_emptiness_test(inner.test) and _returns_truthy(inner.body):
                    hits.append((inner.lineno, "fail-open-auth"))
                    break

    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        if value is None:
            continue
        names = [t.id for t in targets if isinstance(t, ast.Name)]
        if not any(_SECRET_NAME_RE.search(n) for n in names):
            continue
        lineno = getattr(node, "lineno", 0)
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            if value.value.strip().lower() in _WEAK_SECRET_VALUES:
                hits.append((lineno, "placeholder-secret"))
        elif isinstance(value, ast.Call):
            fn = ast.unparse(value.func) if hasattr(ast, "unparse") else ""
            if fn in ("os.environ.get", "os.getenv") and len(value.args) >= 2:
                default = value.args[1]
                if isinstance(default, ast.Constant) and default.value == "":
                    hits.append((lineno, "empty-default-secret"))

    if bind_nonloopback:
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.If)
                and _is_emptiness_test(node.test)
                and _body_is_warn_only(node.body)
            ):
                hits.append((node.lineno, "warn-only-auth-gate"))

    return hits


_WEAK_CFG_WORDS = (
    r"changeme|change-me|change_me|secret|password|admin|default|placeholder"
    r"|xxx|example|token|test"
)
# `(?<![\w-])` pins each attempt to the start of a word: without it every position inside a long
# `[\w-]` run re-scanned the run to its end (quadratic on a long token with no secret keyword).
_CFG_SECRET_KV_RE = re.compile(
    r"(?<![\w-])[\"']?[\w-]*(?:secret|token|api[_-]?key|apikey|password|auth[_-]?key)[\w-]*[\"']?"
    r"[ \t]*[:=][ \t]*"
    r"(?:"
    rf"[\"'](?:{_WEAK_CFG_WORDS}|)[\"']"
    rf"|(?:{_WEAK_CFG_WORDS})(?=[\s,}}\]]|$)"
    r")",
    re.IGNORECASE | re.MULTILINE,
)
# Both branches allow an optional closing quote after the keyword, so quoted JSON keys
# (`"disable_auth": true`, `"auth": {"enabled": false}`) match like their YAML/TOML/env
# spellings. There is deliberately NO lazy prefix before the keyword: `\b` already anchors it,
# and the old `[\s"'.\w-]*?` prefix made the scan quadratic on a long near-miss run
# (`auth_something_unrelated ...`). Every gap is bounded. The look-through to `enabled` cannot
# cross a brace, so a sibling object's `"enabled": false` is not attributed to `auth`.
_CFG_AUTH_DISABLED_RE = re.compile(
    r"""
    (?:
        \b(?:auth|authentication|authorization|auth_config|require_auth|
             requireauth|security|governance)\b
        [\w."'\-]{0,40}
        \s{0,40}[:=]\s{0,40}
        \{?\s{0,40}
        (?:[^{}]{0,120}?\b(?:is_enabled|enabled|required|require)\b["']?\s{0,40}[:=]\s{0,40})?
        ["']?(?:false|0|no|off|disabled)\b["']?
      |
        \b(?:disable_auth|no_auth|auth_disabled|skip_auth|allow_anonymous)\b["']?
        \s{0,40}[:=]\s{0,40}["']?(?:true|1|yes|on)\b["']?
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _is_schema_document(doc: object) -> bool:
    """True when ``doc`` (parsed JSON) is itself a JSON Schema, not a config that cites one.

    A schema describes fields (`properties` / `$defs` / `definitions` at the top) AND identifies
    as one (`$schema` pointing at a json-schema.org meta-schema, or its own `$defs` / `$id`). A
    config with only `"$schema": "https://json.schemastore.org/..."` is neither.
    """
    if not isinstance(doc, dict):
        return False
    if not any(k in doc for k in _SCHEMA_STRUCTURE_KEYS):
        return False
    meta = doc.get("$schema")
    if isinstance(meta, str) and "json-schema.org" in meta:
        return True
    return "$defs" in doc or "$id" in doc


def _strip_illustrative(node: object, in_map: bool = False) -> object:
    """Copy of a schema tree without its `examples` / `example` / `default` subtrees.

    A property literally NAMED `default` (a child of a `properties`-style map) is a field
    definition, not an illustrative value, so it is kept.
    """
    if isinstance(node, dict):
        return {
            k: _strip_illustrative(v, k in _SCHEMA_MAP_KEYS)
            for k, v in node.items()
            if in_map or k not in _SCHEMA_ILLUSTRATIVE_KEYS
        }
    if isinstance(node, list):
        return [_strip_illustrative(v) for v in node]
    return node


def _live_config_text(text: str, path: Path) -> str:
    """The text worth scanning: a schema document loses its illustrative subtrees; anything
    else (including a real config that merely carries `$schema`) is scanned whole."""
    if path.suffix.lower() != ".json" or "$" not in text:
        return text
    try:
        doc = json.loads(text)
        if not _is_schema_document(doc):
            return text
        # Re-serialised, so a finding's line number is relative to the stripped copy.
        return json.dumps(_strip_illustrative(doc), indent=2)
    except (ValueError, RecursionError):  # hostile deep nesting: scan the raw text, don't zero the guard
        return text


def _scan_config(text: str) -> list[tuple[int, str]]:
    if not _MCP_HINT_RE.search(text):
        return []
    if not _BIND_NONLOOPBACK_RE.search(text):
        return []
    m = _CFG_SECRET_KV_RE.search(text)
    if m:
        return [(text.count("\n", 0, m.start()) + 1, "placeholder-secret-config")]
    disabled = _CFG_AUTH_DISABLED_RE.search(text)
    if disabled:
        return [(text.count("\n", 0, disabled.start()) + 1, "auth-disabled-config")]
    return []


_EVIDENCE = {
    "fail-open-auth": (
        "Auth function returns a truthy/allow value when the secret or token is empty or "
        "unset — the gate fails open, admitting unauthenticated callers"
    ),
    "placeholder-secret": (
        "A secret/token is hard-coded to a default/placeholder value — the server ships "
        "effectively unauthenticated until an operator changes it"
    ),
    "empty-default-secret": (
        "A secret/token is read from the environment with an empty-string default — when "
        "the env var is unset the server runs with no credential"
    ),
    "warn-only-auth-gate": (
        "Missing-secret check only logs a warning and continues, while the server binds a "
        "non-loopback interface — unauthenticated network access"
    ),
    "auth-disabled-config": (
        "MCP config switches authentication off by flag (`auth.enabled: false` / "
        "`is_enabled: false` / `disable_auth: true`) while binding a non-loopback "
        "interface — every caller is an administrator (CVE-2026-90898, Bifrost)"
    ),
    "placeholder-secret-config": (
        "MCP config sets a secret/token to a default/placeholder (or empty) value while "
        "binding a non-loopback interface — unauthenticated by default"
    ),
}

_CONFIG_SUFFIXES = (".json", ".yaml", ".yml", ".env", ".toml")


class McpNoauthDefaultGuard(Guard):
    id = "mcp-noauth-default"
    title = "MCP server ships an auth check that fails open, or is unauthenticated by default"
    area = "AI agent"

    # server.py: an is_authorized() function that returns True when SECRET is unset ->
    # fires mcp-noauth-default/fail-open-auth.
    canary_plant = CanaryPlant(
        files={
            "server.py": (
                "from mcp.server import Server\n"
                "import os\n\n"
                "SECRET = os.environ.get('MCP_SECRET')\n\n"
                "def is_authorized(token):\n"
                "    if not SECRET:\n"
                "        return True\n"
                "    return token == SECRET\n"
            ),
        },
        expects=frozenset({
            "mcp-noauth-default/fail-open-auth",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                hits = _scan_python(text, f)
                out.extend(self._findings(r, hits))

        for f in _config_files(root):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            hits = _scan_config(_live_config_text(text, f))
            out.extend(self._findings(r, hits))
        return out

    def _findings(self, r: str, hits: list[tuple[int, str]]) -> list[Finding]:
        out: list[Finding] = []
        seen: set[str] = set()
        for line, arm in hits:
            if arm in seen:
                continue
            seen.add(arm)
            out.append(Finding(
                check_id=self.id,
                severity="critical" if arm in ("fail-open-auth", "auth-disabled-config") else "high",
                title=self.title,
                location=f"{r}:{line}",
                message=f"{_EVIDENCE[arm]} (CVE-2026-48814/CVE-2026-90898 class, CWE-306/862).",
                remediation=(
                    "Require the secret/token to be set (fail closed on empty, not open); "
                    "never ship a default/placeholder secret value; and bind loopback-only "
                    "unless network exposure is genuinely required."
                ),
                rule=f"mcp-noauth-default/{arm}",
                standards=list(_STANDARDS),
            ))
        return out


def _config_files(root: Path) -> list[Path]:
    return iter_files(root, _CONFIG_SUFFIXES)
