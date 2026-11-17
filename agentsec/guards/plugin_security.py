"""Guard: LLM tool/plugin definition missing security controls (per-rule OWASP tags below).

LLM-callable tools (functions decorated with @tool or @agent.tool, and plugin/tool manifests)
are the primary attack amplifiers in agentic systems. Without security controls at the tool
definition boundary, a successful prompt injection or confused-deputy attack gains direct access
to databases, filesystems, external APIs, and arbitrary data.

Four statically detectable patterns:

  1. **PLG003 — `tool-no-auth-check`** (HIGH): An @tool or @agent.tool decorated function
     makes a sensitive call (DB query, file I/O, HTTP request) without an auth parameter in its
     signature. The LLM controls the tool's arguments — if the tool itself does not verify
     caller identity, any user (or a prompt-injected agent) can read or write arbitrary data.
     A "confused deputy" attack: the tool acts on behalf of whoever invoked the LLM, not
     necessarily the authenticated end-user.

  2. **PLG001 — `tool-unvalidated-input`** (MEDIUM): An @tool decorated function accepts a
     `dict` or `Any` typed parameter, or a parameter with no type annotation. LLMs can supply
     arbitrary JSON structures as tool arguments. Without a Pydantic schema, malformed or
     adversarial tool arguments bypass expected constraints and reach downstream sinks
     without structural validation.

  3. **PLG005 — `wildcard-capabilities`** (HIGH): A plugin/tool manifest JSON or YAML file
     declares a "capabilities", "permissions", "access", or "scopes" key with the value `"*"`,
     `"all"`, `["*"]`, or `["all"]`. Wildcard capabilities violate least-privilege and enable
     capability abuse via prompt injection.

  4. **PLG007 — `tool-data-overexposure`** (MEDIUM): An @tool decorated function returns
     `.dict()` or `.model_dump()` (the Pydantic/ORM export forms) on what appears to be an
     ORM/Pydantic model without field filtering (no `exclude=` or `include=` argument). ORM
     models often contain sensitive fields (hashed passwords, API keys, internal IDs) that
     should not be exposed to the model context. (`.json()` is intentionally excluded — it is
     the universal `response.json()` HTTP idiom, not a model export.)

  5. **PLG008 — `tool-shared-service-identity`** (HIGH): An @tool decorated function makes a
     sensitive call — a DB/file/OS operation on the SERVICE's OWN backing store, `open()`
     included — AND carries an auth-named parameter (`api_key`, `token`, `user_id`, ...) — so
     PLG003 stays silent — but that parameter's OWN default value is a hardcoded/shared SERVICE
     credential (a bare `SCREAMING_SNAKE_CASE` module constant, or an `os.getenv(...)` /
     `os.environ[...]` env lookup) rather than a per-request injection (`Depends(...)`,
     `Header(...)`, `Security(...)`). The parameter's NAME satisfies PLG003's auth check, but its
     BINDING never varies with the caller — the tool always authenticates its downstream call as
     the same static service principal, which is the narrower, statically-provable slice of the
     confused-deputy pattern PLG003's own name check cannot see (reading a signature's default
     literal needs no dataflow tracing — it is visible in source text). Deliberately does NOT
     count a generic outbound `requests.*`/`httpx.*` call as the qualifying sensitive call here
     (unlike PLG003's broader gate): an @tool calling a THIRD-PARTY provider API with its own
     env-sourced or module-constant key (Brave Search, Stripe, ...) is this rule's own documented
     safe pattern, not a confused deputy — F2 needs the downstream resource to enforce
     per-principal authorization across multiple callers with differing entitlements, which an
     arbitrary external API called with a static provider key does not establish.

**Relationship to other guards:**
  * `agent-tool-overpermission`: fires on PythonREPLTool, ShellTool, allow_dangerous_requests,
    and subprocess in @agent.tool. This guard is ORTHOGONAL — it fires on missing auth
    parameters, unvalidated inputs, wildcard manifest capabilities, and unfiltered output.
  * `mcp-tool-unverified`: fires when MCP servers are auto-loaded without trust verification.
    This guard targets @tool-decorated Python functions and JSON/YAML manifest files.

**Suppress:** `# security: allow-plugin-security` in any file silences all plugin-security
checks in that file.

**Checklist items:**
  * `4-agent-identity-propagation` (PLG003 + PLG008: tool auth verification / confused-deputy)
  * `2b-excessive-data-exposure` (PLG007: tool output must not expose full ORM models)
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    _bracket_delta,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-plugin-security"

# Per-rule standards. The five rules target different weaknesses, so they do not share a tag set.
# PLG003/PLG008 also carry OWASP-ASI:ASI03 (Identity & Privilege Abuse, OWASP Top 10 for Agentic
# Applications 2026): an agent tool acting under a shared, long-lived service identity rather than
# the end-user's own scope. Checklist item 4-agent-identity-propagation stays `partial` (same
# confused-deputy gap the checklist item records) — see wiki/research/owasp-asi-2026.md.
_STD_NO_AUTH = ["OWASP-LLM:LLM06", "OWASP:A01", "OWASP-ASI:ASI03"]       # PLG003: confused deputy / excessive agency
_STD_UNVALIDATED = ["OWASP-LLM:LLM01", "OWASP:A03"]   # PLG001: adversarial tool args / input validation
_STD_WILDCARD = ["OWASP-LLM:LLM06", "OWASP:A01"]      # PLG005: excessive agency / least-privilege
_STD_OVEREXPOSURE = ["OWASP-LLM:LLM02", "OWASP:A01"]  # PLG007: sensitive information disclosure
_STD_SHARED_IDENTITY = ["OWASP-LLM:LLM06", "OWASP:A01", "OWASP-ASI:ASI03"]  # PLG008: same confused-deputy axis as PLG003

# Matches @tool or @anything.tool decorator (at the end of a line or followed by '(')
_TOOL_DECORATOR = re.compile(
    r"@(?:\w+\.)*tool\s*(?:\(|$)",
    re.MULTILINE,
)

# Sensitive calls that indicate resource access. NB: `os.path.*` is deliberately NOT here —
# path *construction* (os.path.join/dirname/exists) is not resource access; only actual
# filesystem operations are.
_SENSITIVE_CALL = re.compile(
    r"\b(?:db|session|conn|cursor)\.(?:query|execute|get|filter|all|first|one)\s*\("
    r"|\bopen\s*\("
    r"|\bos\.(?:open|remove|unlink|rename|replace|mkdir|makedirs|rmdir|listdir|scandir|walk)\s*\("
    r"|\brequests\.[gpdh]\w*\s*\("
    r"|\bhttpx\.[gpdh]\w*\s*\(",
    re.IGNORECASE,
)

# Sensitive calls that indicate a downstream resource where a per-caller identity plausibly
# matters (PLG008 only) — DB/file/OS access on the SERVICE's OWN backing store, where a hardcoded
# credential really does mean "every caller shares one principal" for row/file-level scoping.
# Deliberately excludes generic outbound `requests.*`/`httpx.*` calls: an @tool that calls a
# THIRD-PARTY provider API (Brave Search, Stripe, ...) with its own env-sourced or module-constant
# key is the guard's own documented safe pattern ("reserve module-level constants and env vars for
# the service's OWN infrastructure credentials"), not a confused deputy — F2 needs the downstream
# resource to enforce PER-PRINCIPAL authorization across multiple callers with differing
# entitlements, which an arbitrary external API called with a static provider key does not
# establish (review H4). `_SENSITIVE_CALL` (PLG003, above) is unchanged: a tool with NO auth
# parameter at all making an outbound HTTP call is still worth flagging under that separate
# question.
_SENSITIVE_CALL_SHARED_IDENTITY = re.compile(
    r"\b(?:db|session|conn|cursor)\.(?:query|execute|get|filter|all|first|one)\s*\("
    r"|\bopen\s*\("
    r"|\bos\.(?:open|remove|unlink|rename|replace|mkdir|makedirs|rmdir|listdir|scandir|walk)\s*\(",
    re.IGNORECASE,
)

# Auth parameter names that indicate caller identity verification
_AUTH_PARAM = re.compile(
    r"\b(?:current_user|user_id|user|auth|token|api_key|requester)\b",
    re.IGNORECASE,
)

# Function definition — captures the parameter list
_FUNC_DEF = re.compile(
    r"(?:async\s+)?def\s+\w+\s*\(([^)]*)\)",
    re.MULTILINE,
)

# A def line whose parameter list may continue on later lines (black-wrapped signature)
_DEF_OPEN = re.compile(r"(?:async\s+)?\bdef\s+\w+\s*\(")

_SIG_JOIN_LINES = 10  # max lines to join when flattening a wrapped signature

# dict / Dict / Any annotation in parameter list (typing.Dict is still common in older code)
_UNVALIDATED_PARAM = re.compile(r"\bdict\b|\bDict\b|\bAny\b")

# Parameters to ignore (self, cls, ctx, context, *args, **kwargs)
_IGNORED_PARAMS = frozenset({"self", "cls", "args", "kwargs", "ctx", "context"})

# Wildcard value in a capabilities/permissions/access/scopes key — JSON *and* YAML.
# Boundaries are deliberate: quoted "all" must be exact and bare YAML `all` must end the
# value, so `"all_users"` / `access_level:` do not false-fire.
_WILDCARD_CAP = re.compile(
    r"""
    \b(?:capabilities|permissions|access|scopes)\b ["']? \s*:\s*
    (?:
        ["']? \* ["']?                      # *   "*"   '*'
      | ["'] all ["']                       # "all"  'all'   (quoted, exact)
      | \[ \s* ["']? \* ["']? \s* \]        # [*]  ["*"]  ['*']
      | \[ \s* ["']? all ["']? \s* \]       # [all]  ["all"]  ['all']
      | all (?= \s* (?: \# | $ ) )          # bare YAML `all` at end of value
    )
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)

# File name patterns for plugin/tool manifests
_MANIFEST_NAME = re.compile(
    r"(?:plugin[^/]*\.(?:json|ya?ml)|tool[s-][^/]*\.(?:json|ya?ml)"
    r"|tool-manifest[^/]*\.(?:json|ya?ml)|ai-plugin\.(?:json|ya?ml)"
    r"|openapi[^/]*\.(?:json|ya?ml)|api-spec[^/]*\.(?:json|ya?ml))$",
    re.IGNORECASE,
)

# Unfiltered model serialisation. NB: `.json()` is deliberately NOT matched — `response.json()`
# (requests/httpx/aiohttp body parsing) is the universal HTTP idiom, not ORM/Pydantic export.
# Only the Pydantic/ORM `.dict()` / `.model_dump()` forms signal a model dump.
_MODEL_DUMP = re.compile(
    r"\.(?:dict|model_dump)\s*\(\s*\)",
    re.IGNORECASE,
)

# Filtered variant — has exclude= or include= argument
_FILTERED_DUMP = re.compile(
    r"\.(?:dict|model_dump)\s*\(\s*(?:exclude|include)\s*=",
    re.IGNORECASE,
)

_CONTEXT_LINES = 20  # lines to examine in the function body after def

# --- PLG008: auth-named parameter bound to a hardcoded/shared service credential ---

# A default wrapped in one of these is per-request dependency injection, not a baked-in service
# identity — the FastAPI/pydantic-ai idiom for "give me THIS caller's identity". Must stay silent.
_PER_REQUEST_DEFAULT = re.compile(r"\b(?:Depends|Header|Security)\s*\(", re.IGNORECASE)

# A bare SCREAMING_SNAKE_CASE identifier reference — the constant-naming convention for a
# hardcoded/shared secret (SERVICE_API_KEY, ADMIN_TOKEN, SYSTEM_KEY). Anchored to the WHOLE
# default expression (not a substring search) so a call like `SomeFactory()` or an attribute
# access like `settings.SERVICE_KEY` (a per-instance config object, not a bare module constant)
# do not match — only an unadorned all-caps name standing alone as the default.
_ALLCAPS_CONSTANT_DEFAULT = re.compile(r"^[A-Z][A-Z0-9_]{2,}$")

# An env-sourced default, evaluated once at import/def time (module load) — NOT per request.
_ENV_SOURCED_DEFAULT = re.compile(r"^os\.(?:environ\.get|environ\s*\[|getenv)\s*[(\[]")


def _split_top_level_commas(sig: str) -> list[str]:
    """Split a parameter list on top-level commas only — quote- and bracket-depth-aware.

    Unlike the naive `sig.split(",")` used elsewhere in this module, this does not break on a
    comma inside a nested call's arguments or a string literal: `token: str =
    os.getenv("ADMIN_TOKEN", "fallback,with,commas")` must stay ONE parameter, not four."""
    parts: list[str] = []
    depth = 0
    quote: str | None = None
    current: list[str] = []
    i = 0
    n = len(sig)
    while i < n:
        ch = sig[i]
        if quote:
            current.append(ch)
            if ch == "\\" and i + 1 < n:
                i += 1
                current.append(sig[i])
            elif ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


def _param_name_and_default(param: str) -> tuple[str, str | None]:
    """Bracket/quote-aware split of one already-top-level-split parameter into
    `(bare_name, default_expr)`. `default_expr` is None when the parameter has no default.

    Finds the first top-level `:` (start of the annotation) and the first top-level `=` (start
    of the default) — both skipped while inside a string or a nested bracket, so an annotation
    like `dict[str, int]` or a default like `os.getenv("X", "a=b")` cannot confuse the split."""
    depth = 0
    quote: str | None = None
    colon_idx: int | None = None
    eq_idx: int | None = None
    i = 0
    n = len(param)
    while i < n:
        ch = param[i]
        if quote:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and ch == ":" and colon_idx is None and eq_idx is None:
            colon_idx = i
        elif depth == 0 and ch == "=":
            eq_idx = i
            break
        i += 1
    name_end = colon_idx if colon_idx is not None else (eq_idx if eq_idx is not None else n)
    bare_name = param[:name_end].strip().lstrip("*").strip()
    default_expr = param[eq_idx + 1:].strip() if eq_idx is not None else None
    return bare_name, default_expr


def _joined_signature(lines: list[str], start: int) -> str:
    """Flatten a possibly-wrapped def signature starting at lines[start] (0-based).

    Accumulates lines until the def's parentheses balance, capped at
    _SIG_JOIN_LINES lines, and returns the signature joined into one string.
    Comment- AND string-stripped per line (via the shared `_bracket_delta`) so neither a
    stray `)` in a `#` comment nor one inside a string DEFAULT ends the join early. The
    string case truncated the signature mid-way — `label: str = 'weird)paren'` dropped the
    closing `):` and every parameter after it (#437 review)."""
    parts: list[str] = []
    depth = 0
    for line in lines[start: start + _SIG_JOIN_LINES]:
        code = strip_python_line_comment(line)
        parts.append(code.strip())
        depth -= _bracket_delta(line)   # closes-minus-opens, string- and comment-safe
        if depth <= 0:
            break
    return " ".join(parts)


def _find_tool_functions(text: str) -> list[tuple[int, int, str]]:
    """Return list of (decorator_lineno, func_def_lineno, param_string) for each @tool.

    decorator_lineno and func_def_lineno are 1-based. param_string is the raw
    content between the parentheses of the def, with a black-wrapped signature
    flattened onto one line first (the reported lineno stays the def line)."""
    lines = text.splitlines()
    results: list[tuple[int, int, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if _TOOL_DECORATOR.search(line):
            dec_lineno = i + 1
            # Find the next def statement (within 5 lines)
            for j in range(i + 1, min(i + 6, len(lines))):
                m = _FUNC_DEF.search(lines[j])
                if m is None and _DEF_OPEN.search(lines[j]):
                    # Wrapped signature: the closing paren is on a later line
                    m = _FUNC_DEF.search(_joined_signature(lines, j))
                if m:
                    results.append((dec_lineno, j + 1, m.group(1)))
                    i = j  # advance past the def line
                    break
        i += 1
    return results


def _tool_body(lines: list[str], func_lineno: int) -> str:
    """Body text of the @tool function whose `def` is at func_lineno (1-based).

    Bounded at the next same-or-outer-indent statement so a sibling helper's sinks
    (`db.query`, `model_dump()`) defined right after a short tool are not attributed to
    the tool — capped at _CONTEXT_LINES lines as a safety bound."""
    def_line = lines[func_lineno - 1]
    func_indent = len(def_line) - len(def_line.lstrip())
    # Skip past a wrapped signature: the body starts after the def's parens balance
    # (for a single-line def this leaves start at func_lineno, the line after the def).
    start = func_lineno
    depth = 0
    for k in range(func_lineno - 1, min(func_lineno - 1 + _SIG_JOIN_LINES, len(lines))):
        # Same string-safe counting as `_joined_signature` — a `)` in a string default
        # otherwise ends the signature early and starts the body scan on the wrong line.
        depth -= _bracket_delta(lines[k])
        start = k + 1
        if depth <= 0:
            break
    body: list[str] = []
    for line in lines[start: start + _CONTEXT_LINES]:
        stripped = line.strip()
        if not stripped:
            body.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= func_indent:
            break  # dedent back to the def's level — end of this function
        body.append(line)
    return "\n".join(body)


class PluginSecurityGuard(Guard):
    id = "plugin-security"
    title = "LLM tool/plugin definition missing security controls"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `plugin_tools.py` (which `agent-tool-audit-log` also trips), so that file stays in
    # `canary.py`'s base owned by no guard. The ownership rule this follows is documented on
    # `xxe_safe.py`.
    # NOTE: in the ASSEMBLED canary this guard reports `chained_tools.py`, not the plant file named
    # below. `_tool_no_auth_check` returns on its FIRST match and `chained_tools.py` (planted for
    # tool-chaining-exfil) sorts first, so plugin_tools.py never gets reported even though it fires
    # on its own. Both files trip the rule in isolation — measured. A location-based ownership
    # probe therefore shows this guard on chained_tools.py; that is the probe's blind spot, not a
    # wrong comment.
    # plugin_tools.py: @agent.tool with cursor.execute but no auth param in signature ->
    # fires tool-no-auth-check (HIGH).
    #
    # plugin_shared_identity.py (this guard's own plant): @agent.tool with cursor.execute AND an
    # auth-named `api_key` param (so PLG003 stays silent) whose default is a bare SCREAMING_SNAKE
    # module constant (SERVICE_API_KEY) -> fires tool-shared-service-identity (HIGH).
    # Must NOT contain: security: allow-plugin-security (pragma silences the guard).
    # Must NOT wrap the default in Depends(/Header(/Security( (would silence PLG008 as per-request).
    canary_plant = CanaryPlant(
        files={
            "plugin_shared_identity.py": (
                "from pydantic_ai import Agent\n"
                "\n"
                "SERVICE_API_KEY = 'canary-service-key'\n"
                "\n"
                "agent = Agent('openai:gpt-4o')\n"
                "\n"
                "\n"
                "@agent.tool\n"
                "def get_records(query: str, api_key: str = SERVICE_API_KEY) -> list:\n"
                '    """Return records matching the query."""\n'
                "    return cursor.execute(query).fetchall()\n"
            ),
        },
        expects=frozenset({
            "plugin-security/tool-no-auth-check",
            "plugin-security/tool-shared-service-identity",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []

        # --- Python scan (PLG003, PLG001, PLG007) ---
        py_files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                py_files.append((f, read(f)))

        out += self._check_tool_no_auth(root, py_files, profile)
        out += self._check_tool_shared_service_identity(root, py_files, profile)
        out += self._check_tool_unvalidated_input(root, py_files, profile)
        out += self._check_tool_data_overexposure(root, py_files, profile)

        # --- Manifest scan (PLG005) ---
        manifest_files: list[Path] = []
        manifest_seen: set[Path] = set()
        for f in iter_files(root, (".json", ".yaml", ".yml")):
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            if _MANIFEST_NAME.search(f.name) and f not in manifest_seen:
                manifest_seen.add(f)
                manifest_files.append(f)

        out += self._check_wildcard_capabilities(root, manifest_files)

        return out

    # --- PLG003: @tool without auth parameter ---

    def _check_tool_no_auth(
        self,
        root: Path,
        files: list[tuple[Path, str]],
        profile: StackProfile,
    ) -> list[Finding]:
        # One finding per offending @tool, every file (#425): returning the first capped the
        # rule at one finding repo-wide, so an exception on it hid every other unauthenticated tool.
        out: list[Finding] = []
        for f, text in files:
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _TOOL_DECORATOR.search(text):
                continue

            lines = text.splitlines()
            for dec_lineno, func_lineno, sig in _find_tool_functions(text):
                # Skip if there is an auth param in the signature
                if _AUTH_PARAM.search(sig):
                    continue
                # Check the function body for sensitive calls
                body = _tool_body(lines, func_lineno)
                if _SENSITIVE_CALL.search(body):
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rp}:{dec_lineno}",
                        message=(
                            "@tool function accesses database/filesystem/network without an auth "
                            "parameter. The LLM controls tool arguments — without auth verification, "
                            "any user (or a prompt-injected agent) can read or write arbitrary data."
                        ),
                        remediation=(
                            "Add a user identity parameter: "
                            "def my_tool(query: str, current_user: User = Depends(get_current_user)). "
                            "Scope all data access to the authenticated user."
                        ),
                        rule="plugin-security/tool-no-auth-check",
                        standards=list(_STD_NO_AUTH),
                    ))

        return out

    # --- PLG008: auth-named parameter bound to a hardcoded/shared service credential ---

    def _check_tool_shared_service_identity(
        self,
        root: Path,
        files: list[tuple[Path, str]],
        profile: StackProfile,
    ) -> list[Finding]:
        # One finding per offending @tool, every file (#425); see _check_tool_no_auth.
        out: list[Finding] = []
        for f, text in files:
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _TOOL_DECORATOR.search(text):
                continue

            lines = text.splitlines()
            for dec_lineno, func_lineno, sig in _find_tool_functions(text):
                # Narrower than PLG003's gate: only a DB/file/OS call counts here, not a generic
                # outbound HTTP call (see `_SENSITIVE_CALL_SHARED_IDENTITY`'s own docstring, H4).
                body = _tool_body(lines, func_lineno)
                if not _SENSITIVE_CALL_SHARED_IDENTITY.search(body):
                    continue

                for param in _split_top_level_commas(sig):
                    bare_name, default_expr = _param_name_and_default(param)
                    if not bare_name or not _AUTH_PARAM.search(bare_name):
                        continue
                    if default_expr is None:
                        continue
                    # Per-request DI (Depends/Header/Security) is exactly the safe pattern PLG003
                    # already asks for — never flag it, regardless of what it wraps.
                    if _PER_REQUEST_DEFAULT.search(default_expr):
                        continue
                    if not (
                        _ALLCAPS_CONSTANT_DEFAULT.match(default_expr)
                        or _ENV_SOURCED_DEFAULT.match(default_expr)
                    ):
                        continue
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rp}:{dec_lineno}",
                        message=(
                            f"@tool's `{bare_name}` parameter is bound to a hardcoded/shared "
                            "credential (an env var or a module-level constant), not a "
                            "per-request end-user identity. The parameter's NAME satisfies an "
                            "auth check, but its value never varies with the caller — the tool "
                            "will always authenticate its downstream call as the same static "
                            "service principal, regardless of who invoked it (confused deputy)."
                        ),
                        remediation=(
                            "Inject the caller's own identity per request instead of a fixed "
                            "default: def get_data(query: str, current_user: User = "
                            "Depends(get_current_user)). Reserve module-level constants and env "
                            "vars for the service's OWN infrastructure credentials (DB DSN, "
                            "upstream provider API keys) — never as a stand-in for the "
                            "authenticated end-user's identity."
                        ),
                        rule="plugin-security/tool-shared-service-identity",
                        standards=list(_STD_SHARED_IDENTITY),
                    ))
                    break  # one finding per tool: the anchor is the tool, not the param

        return out

    # --- PLG001: @tool with unvalidated dict/Any input ---

    def _check_tool_unvalidated_input(
        self,
        root: Path,
        files: list[tuple[Path, str]],
        profile: StackProfile,
    ) -> list[Finding]:
        # One finding per offending @tool, every file (#425); see _check_tool_no_auth.
        out: list[Finding] = []
        for f, text in files:
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _TOOL_DECORATOR.search(text):
                continue

            for dec_lineno, _func_lineno, sig in _find_tool_functions(text):
                # Check for dict or Any annotation
                if _UNVALIDATED_PARAM.search(sig):
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rp}:{dec_lineno}",
                        message=(
                            "@tool function accepts dict or untyped input without Pydantic "
                            "validation. LLMs can supply arbitrary JSON structures — without "
                            "schema validation, malformed or adversarial tool arguments bypass "
                            "expected constraints."
                        ),
                        remediation=(
                            "Define a Pydantic model for tool inputs: "
                            "class SearchInput(BaseModel): query: str; "
                            "def search(input: SearchInput): ..."
                        ),
                        rule="plugin-security/tool-unvalidated-input",
                        standards=list(_STD_UNVALIDATED),
                    ))
                    # One finding per tool: skip the bare-param pass below, which would
                    # otherwise add a second finding at the same anchor.
                    continue

                # Check for bare parameters (no type annotation)
                params = [p.strip() for p in sig.split(",") if p.strip()]
                for param in params:
                    bare_name = param.lstrip("*").split("=")[0].strip()
                    if bare_name in _IGNORED_PARAMS:
                        continue
                    # Skip the keyword-only `*` and positional-only `/` separators — they
                    # carry no annotation but are not real parameters.
                    if bare_name in ("", "/"):
                        continue
                    # A typed param has a colon: name: type
                    if ":" not in param:
                        out.append(Finding(
                            check_id=self.id,
                            severity="medium",
                            title=self.title,
                            location=f"{rp}:{dec_lineno}",
                            message=(
                                "@tool function accepts dict or untyped input without Pydantic "
                                "validation. LLMs can supply arbitrary JSON structures — without "
                                "schema validation, malformed or adversarial tool arguments bypass "
                                "expected constraints."
                            ),
                            remediation=(
                                "Define a Pydantic model for tool inputs: "
                                "class SearchInput(BaseModel): query: str; "
                                "def search(input: SearchInput): ..."
                            ),
                            rule="plugin-security/tool-unvalidated-input",
                            standards=list(_STD_UNVALIDATED),
                        ))
                        break  # one finding per tool, however many bare params it has

        return out

    # --- PLG005: wildcard capabilities in manifests ---

    def _check_wildcard_capabilities(
        self,
        root: Path,
        files: list[Path],
    ) -> list[Finding]:
        # One finding per offending manifest file (#425); see _check_tool_no_auth.
        out: list[Finding] = []
        for f in files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if _WILDCARD_CAP.search(text):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=rel(root, f),
                    message=(
                        "Plugin/tool manifest declares wildcard capabilities ('*' or 'all'). "
                        "Unrestricted capabilities mean the plugin can perform any action without "
                        "scope limits, violating least-privilege and enabling capability abuse "
                        "via prompt injection."
                    ),
                    remediation=(
                        "Enumerate specific required capabilities instead of wildcards: "
                        "{ 'capabilities': ['read_documents'] }"
                    ),
                    rule="plugin-security/wildcard-capabilities",
                    standards=list(_STD_WILDCARD),
                ))

        return out

    # --- PLG007: @tool returning unfiltered model dump ---

    def _check_tool_data_overexposure(
        self,
        root: Path,
        files: list[tuple[Path, str]],
        profile: StackProfile,
    ) -> list[Finding]:
        # One finding per offending @tool, every file (#425); see _check_tool_no_auth.
        out: list[Finding] = []
        for f, text in files:
            rp = rel(root, f)
            if is_nonproduct_path(rp, profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _TOOL_DECORATOR.search(text):
                continue

            lines = text.splitlines()
            for dec_lineno, func_lineno, _sig in _find_tool_functions(text):
                body = _tool_body(lines, func_lineno)

                if _MODEL_DUMP.search(body) and not _FILTERED_DUMP.search(body):
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rp}:{dec_lineno}",
                        message=(
                            "@tool function returns a complete model dump to the LLM. ORM models "
                            "often contain sensitive fields (hashed passwords, API keys, internal IDs) "
                            "that should not be exposed to the model context."
                        ),
                        remediation=(
                            "Return only the fields the LLM needs: return {'id': user.id, 'name': user.name}. "
                            "Use model_dump(include={'id', 'name'}) or define a dedicated response schema."
                        ),
                        rule="plugin-security/tool-data-overexposure",
                        standards=list(_STD_OVEREXPOSURE),
                    ))

        return out
