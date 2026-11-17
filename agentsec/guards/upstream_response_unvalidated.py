"""Guard: external HTTP API response data used without schema validation (OWASP:A03, CWE-20).

Agent and RAG pipelines routinely call external HTTP APIs — tool servers, data sources,
third-party enrichment endpoints — and then act on the response. When the response JSON
is subscripted or returned directly, without validating it against a Pydantic schema,
any of the following hazards are live:

- **Prompt injection via poisoned upstream data.** A compromised or malicious API
  returns a payload containing `"role":"system"` or `"\\n\\nIgnore previous instructions"`.
  Because the agent extracts the value blindly, those instructions land in the model context
  without sanitization.

- **Unexpected structure causes unhandled exceptions.** The API changes a field name or
  drops an optional key. Without validation, the subscript crashes mid-request; with
  Pydantic, the exception is at the boundary and the error is structured.

- **Type confusion / injection in downstream sinks.** A numeric field returns a string
  with SQL metacharacters. Pydantic type coercion (and validation) strips that before it
  reaches any query or command.

Two statically detectable patterns:

  1. **`api-response-used-unvalidated` — chained .json() on same line** (HIGH):
     `requests.<method>(url).json()` or `httpx.<method>(url).json()` on a single line,
     with no `model_validate` / `model_dump` on the same line AND no Pydantic parsing call
     anywhere FORWARD of it within the enclosing function (
     `enclosing_function_span()`). A call with no enclosing function (module-level code)
     falls back to checking only the next non-blank line.

  2. **`api-response-used-unvalidated` — immediate subscript** (HIGH):
     `.json()[` on a single line (response JSON subscripted immediately), with no
     `model_validate` or `model_dump` on the same line.

**Silence conditions:**
- Same line contains `model_validate` or `model_dump` — assumed validated.
- A Pydantic parsing call (`model_validate(`, `.model_validate(`, `TypeAdapter(`, or a
  `SomeModel(**` construction) appears anywhere FORWARD of the chained `.json()` call,
  within its enclosing function — assign-then-validate pattern, safe, even when the
  validation call is several lines later or inside a same-function nested helper
  (`iter_functions` already inlines those). A call with no enclosing function
  (module-level code) falls back to checking only the next non-blank line.
- The file contains `# security: allow-unvalidated-upstream` anywhere.

**False-negative scope:** This guard looks forward from the chained `.json()` call to the
END of its enclosing function (or just the next non-blank line, at module level). A
validation call performed in a genuinely DIFFERENT function this one merely calls (not a
same-function nested closure, which `iter_functions` already inlines into the enclosing
block) is still not detected — a documented, narrow gap, traded for not doing full
cross-function dataflow analysis.

**Checklist item:** `3a-upstream-api-response-validated` (partial — catches direct
chained and subscripted patterns; multi-step dataflow requires a full data-flow analysis).

Additionally (mined from MCPVul's `PromptInjectionAnalyzer` + its
`PROMPT_INJECTION_PATTERNS` catalog, verified against real source), this guard also fires on five
non-JSON raw-external-data-return shapes the chained-`.json()` anchor above never matches at all
(no `.json()` call in any of them), scoped to LLM/agent **tool** functions specifically — a
`@tool`/`@<name>.tool`/`@<name>.tool_plain`-decorated function (the same decorator shape
`agent-tool-audit-log`/`agent-tool-url-fetch-ssrf` already use as "is this an agent tool" signal)
that `return`s one of the following directly, with no sanitization call (`sanitize*`/`escape*`/
`filter*`/`validate*`/`clean*`/`strip*`/`purify*`/`html.escape(`/`bleach.`/`markupsafe.`/
`defusedxml`) anywhere forward in the function:

  1. **`http-text-content-raw-return`** (HIGH): `requests.<verb>(...).text`/`.content`,
     `httpx.<verb>(...).text`/`.content` — the non-`.json()` sibling of this guard's own
     chained-JSON check.
  2. **`urllib-raw-return`** (HIGH): `urllib.request.urlopen(...).read()`.
  3. **`file-raw-return`** (HIGH): `open(...).read()`.
  4. **`subprocess-raw-return`** (HIGH): `subprocess.run/check_output/Popen(...).stdout`/
     `.stderr`/`.output`.
  5. **`db-raw-return`** (MEDIUM): `cursor/conn/connection.fetchall()`/`fetchone()`/`fetchmany()`.

**Why tool-scoped, not "anywhere in the codebase":** an ordinary helper function that returns
raw file/HTTP/subprocess/DB content for conventional backend use is completely normal — the risk
this guard's docstring opens with (poisoned upstream data landing unsanitized in the model's
context) only exists once that raw value becomes an LLM/agent tool's result. Gating on the
decorator keeps this precise instead of flooding every repo with findings on ordinary I/O code.

**False-negative scope:** same single-file, same-function limitation as the chained-JSON check
above — a sanitizer applied in a genuinely different function this one calls is not detected.

**Suppress:** `# security: allow-unvalidated-upstream` in any file silences the check
for that file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-unvalidated-upstream"

_STANDARDS = ["OWASP:A03", "CWE-20"]

# --- tool-function raw-external-return sinks, independent of the chained-.json()
# check above (none of these involve a .json() call at all). ---------------------------------

_HTTP_TEXT_CONTENT_RAW_RETURN = re.compile(
    r"return\s+.*(?:requests|httpx)\.[a-z]+\([^)]*\)\.(?:text|content)\b"
)
_URLLIB_RAW_RETURN = re.compile(r"return\s+.*urllib\.request\.urlopen\([^)]*\)\.read\(\)")
_FILE_RAW_RETURN = re.compile(r"return\s+.*\bopen\([^)]*\)\.read\(\)")
_SUBPROCESS_RAW_RETURN = re.compile(
    r"return\s+.*subprocess\.(?:run|check_output|Popen)\([^)]*\)\.(?:stdout|stderr|output)\b"
)
_DB_RAW_RETURN = re.compile(r"return\s+.*\b(?:cursor|conn|connection)\.(?:fetchall|fetchone|fetchmany)\(\)")

# (rule suffix, severity, matcher, human-readable detail clause).
_TOOL_RAW_RETURN_CATEGORIES: tuple[tuple[str, Severity, re.Pattern[str], str], ...] = (
    ("http-text-content-raw-return", "high", _HTTP_TEXT_CONTENT_RAW_RETURN,
     "an HTTP response's raw `.text`/`.content`"),
    ("urllib-raw-return", "high", _URLLIB_RAW_RETURN, "a raw `urllib` response body"),
    ("file-raw-return", "high", _FILE_RAW_RETURN, "raw file content"),
    ("subprocess-raw-return", "high", _SUBPROCESS_RAW_RETURN, "raw subprocess output"),
    ("db-raw-return", "medium", _DB_RAW_RETURN, "a raw database query result"),
)

# A sanitization call anywhere forward in the enclosing function silences the finding — its
# presence is not proof it's applied to THIS value, the same caveat `_FORWARD_VALIDATED` above
# accepts for Pydantic validation; a whole-function absence check is this guard's established
# precision level. `strip` counts only as a `strip_*` sanitizer (`strip_tags`): a bare `.strip()`
# trims whitespace and leaves the content raw, and with the return line in scope (H4) it would
# otherwise silence `return requests.get(url).text.strip()` (#1053 round-2 M2).
_SANITIZATION_CALL = re.compile(
    r"\b(?:sanitize|escape|filter|validate|clean|purify)\w*\s*\(|\bstrip_\w+\s*\(|"
    r"\bhtml\.escape\s*\(|\bbleach\.|\bmarkupsafe\.|\bdefusedxml\b"
)

# The same "is this function an LLM/agent tool" decorator shape `agent-tool-audit-log`/
# `agent-tool-url-fetch-ssrf` already use: a bare `@tool`, or a receiver-qualified
# `@<name>.tool`/`@<name>.tool_plain` (pydantic-ai/LangChain/MCP conventions).
_TOOL_DECORATOR_LINE = re.compile(r"^[ \t]*@(?:\w+\s*\.\s*)?tool(?:_plain)?\b", re.IGNORECASE | re.MULTILINE)


def _tool_decorated(lines: list[str], scope_start: int, anchor_idx: int) -> bool:
    """True if a tool-registration decorator line appears anywhere between the enclosing
    function's span start (1-based `scope_start`, which includes its decorator stack when
    present) and the anchor line (0-based `anchor_idx`)."""
    window = "\n".join(lines[scope_start - 1 : anchor_idx])
    return bool(_TOOL_DECORATOR_LINE.search(window))

_RULE = "upstream-response-unvalidated/api-response-used-unvalidated"

# Detect an *upstream* HTTP client response: requests/httpx call with .json() chained on
# the same line. Catches: requests.get(...).json()  httpx.post(...).json()  etc.
#
# NOTE: a bare `.json()[` subscript pattern was removed — it matched inbound
# `request.json()["x"]` (FastAPI request bodies, not upstream API responses) and was the
# guard's dominant false-positive source. We only flag responses from a real HTTP client.
_CHAINED_JSON = re.compile(r"(?:requests|httpx)\.[a-z]+\([^)]+\)\.json\(\)")

# Validation markers — if the same line contains these, the data is considered validated.
_INLINE_VALIDATED = re.compile(r"model_validate|model_dump")

# Pydantic parsing patterns to look for anywhere FORWARD of the hit, within its enclosing
# function (`enclosing_function_span()` — not just the literal next line).
# Covers: UserModel.model_validate(raw), TypeAdapter(MyModel), UserModel(**data), SomeModel(**r.json())
_FORWARD_VALIDATED = re.compile(
    r"model_validate\s*\(|TypeAdapter\s*\(|\w+\s*\(\s*\*\*"
)


def _next_nonblank_line(lines: list[str], current_idx: int) -> str:
    """Return the next non-blank line after `current_idx` (0-based), or empty string."""
    for i in range(current_idx + 1, len(lines)):
        stripped = lines[i].strip()
        if stripped:
            return stripped
    return ""


class UpstreamResponseUnvalidatedGuard(Guard):
    id = "upstream-response-unvalidated"
    title = "Upstream API response used without schema validation"
    area = "Reliability"

    # Canary plant: the original rule is EXPECTS-ONLY — the violation is planted in the
    # canary's shared `api_client.py` (which `secret-in-url-query` also trips), so that file
    # stays in `canary.py`'s base owned by no guard (see `xxe_safe.py`'s ownership rule).
    # api_client.py: requests.get(url).json() chained on same line, no model_validate ->
    # api-response-used-unvalidated.
    # The rules are a new, independent violation shape (needs a @tool-decorated
    # function, which api_client.py has no reason to have), so they get their own plant file.
    canary_plant = CanaryPlant(
        files={
            "tool_raw_return.py": (
                "import requests\n"
                "from pydantic_ai import Agent\n"
                "\n"
                "agent = Agent('test')\n"
                "\n"
                "\n"
                "@agent.tool\n"
                "def fetch_page(ctx, url: str) -> str:\n"
                "    return requests.get(url).text\n"
            ),
        },
        expects=frozenset({
            "upstream-response-unvalidated/api-response-used-unvalidated",
            "upstream-response-unvalidated/http-text-content-raw-return",
        }),
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue  # test/example/fixture code is not an upstream call site
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        # Parsed lazily: computed once per file, but only after a real chained-.json() anchor is
        # found. Most scanned files have no such call, and iter_functions() is a full safe_ast_parse
        # + strip_python_strings — pure waste on an anchor-free file (issue #771). Memoized after the
        # first parse so enclosing_function_span() doesn't re-parse per match (~900x slower over a
        # many-function file #685 review).
        funcs: list[tuple[int, str]] | None = None

        for idx, line in enumerate(lines):
            # Skip comment lines early.
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue

            # Skip lines that already contain validation markers (inline-safe pattern).
            if _INLINE_VALIDATED.search(line):
                continue

            fired = False

            # An upstream requests/httpx response with .json() chained, not validated on
            # this line nor parsed anywhere forward of it within the enclosing function.
            if _CHAINED_JSON.search(line):
                if funcs is None:
                    funcs = iter_functions(text, filename=path)
                if not self._validated_forward(text, lines, idx, funcs):
                    fired = True

            if fired:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, path)}:{idx + 1}",
                        message=(
                            "An external HTTP API response is used directly (subscripted or "
                            "returned) without validating it against a Pydantic schema. "
                            "In an agentic pipeline, a compromised upstream endpoint can "
                            "return payloads that inject instructions into the model context "
                            "(prompt injection via poisoned data), cause unhandled exceptions "
                            "on unexpected structure, or introduce type confusion in downstream "
                            "sinks (SQL, shell, file paths). Validation at the trust boundary "
                            "is the primary defense."
                        ),
                        remediation=(
                            "Declare a Pydantic model for the expected response shape and call "
                            "`MyModel.model_validate(response.json())` (or "
                            "`TypeAdapter(MyModel).validate_python(response.json())`) "
                            "immediately after fetching. Never subscript `.json()` directly in "
                            "production code. If this specific call is intentional (e.g. a "
                            "health-check endpoint where the body is discarded), suppress with "
                            "`# security: allow-unvalidated-upstream` in the file."
                        ),
                        rule=_RULE,
                        standards=list(_STANDARDS),
                    )
                )

            # a raw external-data return inside an LLM/agent tool function, with
            # no sanitization call anywhere forward in the function. Independent of the
            # chained-.json() check above (none of these sink shapes involve .json() at all),
            # so both can fire on the same file without conflict.
            for category, severity, matcher, detail in _TOOL_RAW_RETURN_CATEGORIES:
                if not matcher.search(line):
                    continue
                if funcs is None:
                    funcs = iter_functions(text, filename=path)
                span = enclosing_function_span(text, idx + 1, functions=funcs)
                if span is None:
                    continue  # module-level code is not a tool function
                scope_start, scope_end = span
                if not _tool_decorated(lines, scope_start, idx):
                    continue
                # Include the anchor (return) line itself — the sinks above are all
                # single-line `return sanitizer(...)` shapes, so a mitigation applied
                # directly on the return is the common case, not something that only
                # ever appears on a later line (H4, PR #1053 review).
                scope = "\n".join(lines[idx:scope_end])
                if _SANITIZATION_CALL.search(scope):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity=severity,
                        title="LLM/agent tool returns raw external data without sanitization",
                        location=f"{rel(root, path)}:{idx + 1}",
                        message=(
                            f"This LLM/agent tool function returns {detail} directly, with no "
                            "sanitization call anywhere in the function. Unlike the sibling "
                            "`api-response-used-unvalidated` rule above (which looks for "
                            "Pydantic schema validation on a chained `.json()` call), this is a "
                            "non-JSON external-data shape: the raw bytes/text reach the model's "
                            "tool-result context unfiltered, so an attacker-controlled upstream "
                            "source can inject instructions the model then treats as trusted "
                            "content."
                        ),
                        remediation=(
                            "Strip or validate the external content before returning it from "
                            "the tool — at minimum, remove instruction-like markers and cap the "
                            "length. If this specific return is intentional (e.g. deliberately "
                            "exposing raw content as the tool's documented purpose), suppress "
                            "with `# security: allow-unvalidated-upstream` in the file."
                        ),
                        rule=f"upstream-response-unvalidated/{category}",
                        standards=list(_STANDARDS),
                    )
                )
                break  # one raw-return finding per line is enough
        return out

    @staticmethod
    def _validated_forward(
        text: str, lines: list[str], idx: int, funcs: list[tuple[int, str]]
    ) -> bool:
        """True if a Pydantic parsing call appears anywhere FORWARD of the chained `.json()`
        hit at `lines[idx]`, within its enclosing function (`enclosing_function_span()`
        — not a fixed next-line-only check). Look-FORWARD only, never back: validation is
        performed AFTER the response is fetched. Falls back to checking only the next
        non-blank line when there is no enclosing function (module-level code)."""
        span = enclosing_function_span(text, idx + 1, functions=funcs)
        if span is not None:
            _scope_start, scope_end = span
            scope = "\n".join(lines[idx + 1 : scope_end])
            return bool(_FORWARD_VALIDATED.search(scope))
        return bool(_FORWARD_VALIDATED.search(_next_nonblank_line(lines, idx)))
