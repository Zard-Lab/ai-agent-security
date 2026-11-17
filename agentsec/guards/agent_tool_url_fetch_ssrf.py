"""Guard: agent tool wraps a URL-fetching sink with an unvalidated, non-literal URL
(OWASP:A10 SSRF / OWASP-LLM:LLM06 Excessive Agency).

`WebBaseLoader` (`langchain_community.document_loaders.WebBaseLoader`) issues a
server-side HTTP GET against whatever URL it is constructed with. When it is used
inside a fixed RAG-ingestion script with a hardcoded URL, that's a normal, safe
pattern. The risk appears when `WebBaseLoader` is wrapped as an agent-callable
**tool** (`@tool`, `Tool(name=...)`, `StructuredTool.from_function(...)`, a
`BaseTool` subclass) and the URL it fetches is NOT a literal — it is a tool
parameter, a variable, or any other value the LLM controls at call time. A prompt
injection (from a retrieved document, a user message, or a poisoned tool result)
can then instruct the agent to fetch an internal service, a cloud metadata
endpoint (`http://169.254.169.254/`), or encode sensitive data into the URL of an
attacker-controlled host for exfiltration — the same SSRF/data-exfiltration
pattern external agent-framework analyzers (e.g. static tool-risk registries used
by tools like agentic-radar) catalogue against `WebBaseLoader` specifically.

**Pattern (HIGH): `agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url`** — the
same Python file has BOTH a tool-registration marker AND a `WebBaseLoader(...)`
(or an aliased import of it) construction whose URL argument is not a pure string
literal, with no allowlist/validation marker anywhere in the file. Co-occurrence
detection, mirroring `agent-tool-overpermission`'s `subprocess-in-agent-tool` rule:
the file must show both signals; a `WebBaseLoader` used outside any tool-wrapping
context (a plain ingestion script) is a different, much lower-risk pattern and is
not flagged.

**Pattern (HIGH): `agent-tool-url-fetch-ssrf/http-client-dynamic-url`** — same
co-occurrence shape, widened to sibling server-side-fetch sinks that are
functionally identical SSRF vectors but a different call shape:
`requests.get/post/put/delete/head/patch/options/request(...)`, the same set on
`httpx.*`, `urllib.request.urlopen(...)` (or a bare `urlopen(...)`), and the
sibling LangChain URL loaders `AsyncHtmlLoader`, `SeleniumURLLoader`,
`PlaywrightURLLoader` (and their tracked import aliases). This closes the gap
that a bare-tool-parameter `requests.get(url)` inside an `@tool` function fell
through BOTH this guard (only recognized `WebBaseLoader`) and `ssrf-general`
(deliberately does not fire on a bare-variable URL argument, to stay low-FP for
ordinary backend code) — the exact LLM-controlled-URL scenario this checklist
item (`3a-ssrf-guard`, "SSRF guard on all URL-accepting endpoints") targets.
For the `requests.*`/`httpx.*`/`urlopen` sinks specifically, only the URL
argument itself is inspected — the first positional argument, or an explicit
`url=` keyword — never unrelated kwargs (`json=`, `params=`, `headers=`, `data=`,
...) that are common and often legitimately dynamic on general-purpose HTTP
clients (the #423 benign-kwarg lesson, extended: a dynamic kwarg must not make an
otherwise-literal URL argument look dynamic). An f-string URL whose interpolation
braces fall only AFTER a literal `scheme://host/` prefix (e.g.
`f"https://api.example.com/resource/{resource_id}"`) is treated as a dynamic
*path segment* on an otherwise-fixed, developer-controlled host, and is NOT
flagged; an interpolation in the host position itself (`f"http://{host}/status"`,
or no literal scheme+host prefix at all) is still dynamic. The loader sinks
(`AsyncHtmlLoader`/`SeleniumURLLoader`/`PlaywrightURLLoader`) are judged the same
way `WebBaseLoader` already is (whole-argument literal check), since their
typical kwargs mirror `WebBaseLoader`'s own (scalar, not payload-shaped).

**Relationship to other guards:**
  * `ssrf-general`: fires on `requests.*`/`httpx.*`/`urlopen(...)` sinks whose URL
    argument shows an f-string/concat/`request.`-object signal, but deliberately
    stays silent on a bare-variable URL argument to avoid FP noise in ordinary
    backend code. This guard's `http-client-dynamic-url` rule covers exactly that
    bare-variable, tool-registration-context case instead — the two guards are
    complementary (co-occurrence + tool-context vs. general-purpose, no
    tool-context requirement), not overlapping in what they flag.
  * `agent-tool-overpermission`: flags dangerous *tool classes* (ShellTool,
    PythonREPLTool, subprocess-in-tool, unscoped toolkit loads). None of this
    guard's sinks are code-execution primitives, so they are out of that guard's
    scope; this guard adds the SSRF-specific URL-fetch vector.

**When NOT to flag:**
  * `WebBaseLoader("https://docs.example.com/page")` — a literal URL (or a list
    of only literal URLs) stays silent regardless of tool-registration context;
    same for the widened sinks (`requests.post(SLACK_WEBHOOK_URL, json=payload)`
    style calls where the URL argument itself is literal and only an unrelated
    kwarg is dynamic);
  * any sink used in a file with no tool-registration marker at all (a plain
    ingestion/backend script loading a known, developer-chosen URL);
  * any file containing an allowlist/validation marker (`allowed_domains`,
    `allowlist`, `allow_list`, `whitelist`, `urlparse`, `netloc`, `validate_url`,
    `is_allowed_domain`, `ALLOWED_HOSTS`, `allowed_hosts`) — a domain check may
    gate the fetch even though this guard cannot verify it prevents SSRF.

**Known bypass:** the allowlist-marker check is a whole-file text search, not a
control-flow proof that the marker actually gates the URL before the fetch — a
file with an unused `ALLOWED_HOSTS` constant elsewhere silences a genuinely
unguarded call. Multi-file wrapping (the `@tool` function lives in one module,
the sink in another) is also not caught — same-file co-occurrence only. A
module-level constant assigned a literal URL elsewhere in the file
(`SLACK_WEBHOOK_URL = "https://..."`, referenced later as a bare name) is
textually indistinguishable from a tool parameter, so it is judged dynamic like
any other bare identifier — same accepted limitation `WebBaseLoader`'s own bare-
variable case already documents (no cross-line dataflow tracking).

Suppress a reviewed, intentional pattern with the inline pragma:

    # security: allow-tool-url-fetch-ssrf
"""
from __future__ import annotations

import re
from pathlib import Path

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
    strip_python_line_comment,
)

_PRAGMA = "security: allow-tool-url-fetch-ssrf"

_STANDARDS = ["OWASP:A10", "OWASP-LLM:LLM06"]

# Tool registration markers — same shape as agent_tool_overpermission._TOOL_REGISTRATION,
# kept local per the project's self-contained-guard convention. `@\w+\.tool\b` covers the
# pydantic-ai/mcp style (`@agent.tool`, `@mcp.tool`); `@\s*tool\b` separately covers
# LangChain's own bare decorator (`from langchain_core.tools import tool` then `@tool` with
# no dot-prefix) — since this guard's whole subject is a LangChain class (`WebBaseLoader`),
# missing LangChain's own primary tool-registration convention would be a real blind spot.
_TOOL_REGISTRATION = re.compile(
    r"@\w+\.tool\b|"
    r"@\s*tool\b|"
    r"\bclass\s+\w+\s*\(\s*BaseTool\s*\)|"
    r"\bTool\s*\(\s*name\s*=|"
    r"\bStructuredTool\.from_function\s*\(",
    re.IGNORECASE,
)

# `from ... import WebBaseLoader as Alias` — tracks the common rename-on-import
# bypass so `Alias(url)` is still recognised as the same loader.
_WEBBASELOADER_ALIAS_IMPORT = re.compile(r"\bWebBaseLoader\s+as\s+(\w+)")

# Sibling LangChain URL-fetching loaders — same SSRF shape as WebBaseLoader, judged the
# same way (whole-argument literal check), just a different class name.
_URL_LOADER_NAMES = ("AsyncHtmlLoader", "SeleniumURLLoader", "PlaywrightURLLoader")
_URL_LOADER_ALIAS_IMPORT = re.compile(
    r"\b(?:" + "|".join(_URL_LOADER_NAMES) + r")\s+as\s+(\w+)"
)

# General-purpose HTTP-client sinks (requests/httpx/urlopen) — a widened sink list closing
# the gap that a bare-tool-parameter `requests.get(url)` fell through both this guard (only
# recognized WebBaseLoader) and ssrf-general (deliberately silent on a bare-variable arg).
_HTTP_CLIENT_CALL = re.compile(
    r"\b(?:requests\.(?:get|post|put|delete|head|patch|options|request)|"
    r"httpx\.(?:get|post|put|delete|head|patch|options|request)|"
    r"(?:urllib\.request\.)?urlopen)\s*\("
    r"([^()]*(?:\([^()]*\)[^()]*)*)\)",
    re.DOTALL,
)

# A literal `scheme://host/` prefix before any f-string interpolation brace — an f-string
# matching this is judged a dynamic PATH segment on an otherwise-fixed, literal host, not a
# host-position injection (see module docstring's http-client-dynamic-url paragraph).
_LITERAL_SCHEME_HOST_PREFIX = re.compile(r"^[fF]['\"]https?://[^{}/'\"]+/")

# Allowlist / validation markers anywhere in the file that make a dynamic URL safe
# (this guard cannot prove they actually gate the fetch — see "Known bypass" above).
_ALLOWLIST_MARKER = re.compile(
    r"\ballowed_domains\b|\ballowlist\b|\ballow_list\b|\bwhitelist\b|"
    r"\burlparse\b|\bnetloc\b|\bvalidate_url\b|\bis_allowed_domain\b|"
    r"\bALLOWED_HOSTS\b|\ballowed_hosts\b",
    re.IGNORECASE,
)

# An f-string with an interpolation brace is always dynamic, even though the naive
# "strip every quoted literal" pass below would otherwise consume the whole token
# (quotes and interpolated identifier alike) and misread it as a bare literal.
_FSTRING_WITH_BRACE = re.compile(r"[fF]['\"][^'\"]*\{")

# Removes quoted string literals (any of the four quote-char/prefix combinations) so what
# remains can be checked for leftover identifiers/expressions.
_STRING_LITERAL = re.compile(
    r"(?:[uUrRbBfF]{0,2})('''|\"\"\"|'|\")(?:.*?)\1", re.DOTALL
)

# A benign keyword argument — its NAME plus `=` plus an optional scalar literal value
# (bool/None/number). Applied AFTER string literals are blanked, so `encoding="utf-8"`,
# `verify_ssl=False`, and `timeout=5` are all consumed. A kwarg with a DYNAMIC value
# (`web_path=user_url`) leaves the identifier behind, so it is still judged dynamic (#423).
_BENIGN_KWARG = re.compile(r"\b\w+\s*=\s*(?:True|False|None|\d+(?:\.\d+)?)?", re.IGNORECASE)

_PUNCTUATION = re.compile(r"[\[\]\{\}\(\)\s,:]")


def _is_literal_only(arg_text: str) -> bool:
    """True if the URL argument(s) of a WebBaseLoader call are string literals — a bare
    literal URL or a list/tuple of literals — ignoring benign trailing kwargs (verify_ssl,
    encoding, timeout, …) that are not the URL (#423)."""
    text = arg_text.strip()
    if not text:
        return True  # no argument at all — nothing dynamic to flag
    if _FSTRING_WITH_BRACE.search(text):
        return False  # an f-string with an interpolation is dynamic regardless
    remainder = _STRING_LITERAL.sub("", text)  # drop string literals (incl. the literal URL)
    remainder = _BENIGN_KWARG.sub("", remainder)  # drop benign scalar kwargs
    remainder = _PUNCTUATION.sub("", remainder)
    return remainder == ""


def _first_call_arg(arg_text: str) -> str:
    """Isolate just the FIRST positional argument (or an explicit `url=` keyword argument)
    from a call's raw argument text, stopping at the first top-level comma. This keeps
    unrelated kwargs (`json=`, `params=`, `headers=`, `data=`, ...) — common and often
    legitimately dynamic on general-purpose HTTP-client sinks — from making an otherwise-
    literal URL argument look dynamic (#423-style lesson, extended beyond scalar kwargs)."""
    depth = 0
    first = arg_text
    for idx, ch in enumerate(arg_text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            first = arg_text[:idx]
            break
    first = first.strip()
    m = re.match(r"url\s*=\s*(.*)", first, re.DOTALL)
    return m.group(1) if m else first


def _is_literal_url_arg(arg_text: str) -> bool:
    """Like `_is_literal_only`, but additionally tolerates an f-string whose interpolation
    braces occur only AFTER a literal `scheme://host/` prefix — a dynamic path segment
    appended to an otherwise-fixed, developer-controlled host. An interpolation in the host
    position itself, or an f-string with no literal scheme+host prefix at all, is still
    treated as dynamic."""
    text = arg_text.strip()
    if _FSTRING_WITH_BRACE.search(text) and _LITERAL_SCHEME_HOST_PREFIX.match(text):
        return True
    return _is_literal_only(text)


class AgentToolUrlFetchSsrfGuard(Guard):
    id = "agent-tool-url-fetch-ssrf"
    title = "Agent tool wraps WebBaseLoader with an unvalidated, non-literal URL"
    area = "AI agent"

    # Canary plant: the WebBaseLoader violation is EXPECTS-ONLY — it lives in the canary's
    # shared `web_fetch_tool.py` (which `agent-tool-audit-log` also trips), so that file stays
    # in `canary.py`'s base owned by no guard (the `xxe_safe.py` ownership rule). The widened
    # http-client-dynamic-url rule owns its OWN plant file here (#617: every guard declares its
    # own plant) — a bare `@agent.tool` parameter passed straight into `requests.get(...)`,
    # with no allowlist marker anywhere in the file. FIRE-strings: `@agent.tool` (registration)
    # + `requests.get(url)` (bare, non-literal URL arg).
    canary_plant = CanaryPlant(
        files={
            "web_fetch_tool_http_client.py": (
                "import requests\n"
                "from pydantic_ai import Agent\n"
                "\n"
                "agent = Agent('openai:gpt-4o')\n"
                "\n"
                "\n"
                "@agent.tool\n"
                "async def fetch_url(ctx, url: str) -> str:\n"
                "    return requests.get(url).text\n"
            ),
        },
        expects=frozenset({
            "agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url",
            "agent-tool-url-fetch-ssrf/http-client-dynamic-url",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

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
                out.extend(self._scan(root, f, r))
        return out

    def _scan(self, root: Path, f: Path, r: str) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect="python"):
            return []
        if not _TOOL_REGISTRATION.search(text):
            return []
        if _ALLOWLIST_MARKER.search(text):
            return []

        return (
            self._scan_webbaseloader(text, r)
            or self._scan_url_loaders(text, r)
            or self._scan_http_clients(text, r)
        )

    def _scan_webbaseloader(self, text: str, r: str) -> list[Finding]:
        names = {"WebBaseLoader"} | set(_WEBBASELOADER_ALIAS_IMPORT.findall(text))
        call_pat = re.compile(
            r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\s*\("
            r"([^()]*(?:\([^()]*\)[^()]*)*)\)",
            re.DOTALL,
        )

        for m in call_pat.finditer(text):
            arg_text = m.group(1)
            if _is_literal_only(arg_text):
                continue
            lineno = text[: m.start()].count("\n") + 1
            return [Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{r}:{lineno}",
                message=(
                    "`WebBaseLoader` is constructed with a non-literal URL argument in a "
                    "file that registers an agent tool. If this loader is invoked with a "
                    "URL the agent (or a prompt injection) controls, the server issues an "
                    "HTTP fetch on the agent's behalf — reaching internal services, the "
                    "cloud metadata endpoint (169.254.169.254), or exfiltrating data by "
                    "encoding it into an attacker-controlled URL."
                ),
                remediation=(
                    "Validate the URL against an explicit allow-list of permitted hosts/"
                    "domains before constructing `WebBaseLoader`, and block RFC-1918 / "
                    "link-local / metadata IPs (resolve the host, then check). If the tool "
                    "genuinely needs open web access, document why and suppress with "
                    "`# security: allow-tool-url-fetch-ssrf`."
                ),
                rule="agent-tool-url-fetch-ssrf/webbaseloader-dynamic-url",
                standards=list(_STANDARDS),
            )]
        return []

    def _scan_url_loaders(self, text: str, r: str) -> list[Finding]:
        names = set(_URL_LOADER_NAMES) | set(_URL_LOADER_ALIAS_IMPORT.findall(text))
        call_pat = re.compile(
            r"\b(?:" + "|".join(re.escape(n) for n in names) + r")\s*\("
            r"([^()]*(?:\([^()]*\)[^()]*)*)\)",
            re.DOTALL,
        )

        for m in call_pat.finditer(text):
            arg_text = m.group(1)
            if _is_literal_only(arg_text):
                continue
            lineno = text[: m.start()].count("\n") + 1
            sink = m.group(0).split("(", 1)[0].strip()
            return [Finding(
                check_id=self.id,
                severity="high",
                title="Agent tool wraps a URL-fetching loader with an unvalidated, non-literal URL",
                location=f"{r}:{lineno}",
                message=(
                    f"`{sink}` is constructed with a non-literal URL argument in a file that "
                    "registers an agent tool. Like `WebBaseLoader`, this loader issues a "
                    "server-side HTTP fetch — if the agent (or a prompt injection) controls "
                    "the URL, the fetch can reach internal services, the cloud metadata endpoint "
                    "(169.254.169.254), or exfiltrate data by encoding it into an "
                    "attacker-controlled URL."
                ),
                remediation=(
                    "Validate the URL against an explicit allow-list of permitted hosts/"
                    "domains before constructing the loader, and block RFC-1918 / link-local "
                    "/ metadata IPs (resolve the host, then check). If the tool genuinely "
                    "needs open web access, document why and suppress with "
                    "`# security: allow-tool-url-fetch-ssrf`."
                ),
                rule="agent-tool-url-fetch-ssrf/http-client-dynamic-url",
                standards=list(_STANDARDS),
            )]
        return []

    def _scan_http_clients(self, text: str, r: str) -> list[Finding]:
        # Strip trailing `#` line-comments (string-safe) before matching, so a commented-out
        # call (`# requests.get(url)`) is not mistaken for live code — the regex previously ran
        # over the raw text (review M7). Preserves line structure (same line count), so offsets
        # into `scanned` still correspond to `text`'s own line numbers.
        scanned = "\n".join(strip_python_line_comment(ln) for ln in text.splitlines())
        for m in _HTTP_CLIENT_CALL.finditer(scanned):
            url_arg = _first_call_arg(m.group(1))
            if _is_literal_url_arg(url_arg):
                continue
            lineno = scanned[: m.start()].count("\n") + 1
            sink = m.group(0).split("(", 1)[0].strip()
            return [Finding(
                check_id=self.id,
                severity="high",
                title="Agent tool passes an unvalidated, non-literal URL to an HTTP-client sink",
                location=f"{r}:{lineno}",
                message=(
                    f"`{sink}(...)` is called with a non-literal URL argument in a file that "
                    "registers an agent tool. If this call is invoked with a URL the agent "
                    "(or a prompt injection) controls, the server issues an HTTP fetch on the "
                    "agent's behalf — reaching internal services, the cloud metadata endpoint "
                    "(169.254.169.254), or exfiltrating data by encoding it into an "
                    "attacker-controlled URL."
                ),
                remediation=(
                    "Validate the URL against an explicit allow-list of permitted hosts/"
                    "domains before making the request, and block RFC-1918 / link-local / "
                    "metadata IPs (resolve the host, then check). If the tool genuinely needs "
                    "open web access, document why and suppress with "
                    "`# security: allow-tool-url-fetch-ssrf`."
                ),
                rule="agent-tool-url-fetch-ssrf/http-client-dynamic-url",
                standards=list(_STANDARDS),
            )]
        return []
