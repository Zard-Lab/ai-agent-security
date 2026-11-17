"""Guard: system prompt exposed via code-level patterns (checklist §4, OWASP-LLM:LLM07).

The four patterns detected here are the code-level counterparts to the output-filtering
gap caught by `system-prompt-leak`. Where that guard fires when a system prompt exists
but the model output is never filtered for verbatim prompt fragments, this guard fires
when the system prompt is exposed BEFORE it reaches the model — via source code, logs,
error responses, or runtime string concatenation with user-facing output:

  1. **Hardcoded literal** (`4-system-prompt-not-hardcoded`, LOW): `system_prompt =` or
     `system_prompt=` with a string literal as the value. If the prompt is in source code,
     every developer with repo access sees it, it ships in the compiled wheel, and it cannot
     be rotated without a new deployment. Any API key or model-steering instruction embedded
     in the prompt is permanently exposed.

  2. **Logged at DEBUG/INFO** (`4-system-prompt-not-logged`, MEDIUM): a `logging.debug()` or
     `logging.info()` call that references `system_prompt` / `SYSTEM_PROMPT`. Debug-level logs
     are commonly forwarded to centralized logging stacks, Datadog, CloudWatch, etc., where
     they may be visible to a wider audience than intended and retained for months.

  3. **In error response** (`4-system-prompt-not-in-response`, MEDIUM): `detail=system_prompt`
     or `detail=SYSTEM_PROMPT` (FastAPI HTTPException / JSONResponse pattern). An exception
     handler that copies the system prompt into the HTTP response body (even under a non-200
     status code) sends the entire prompt to the client, where it appears in browser DevTools
     and is logged by any API gateway or CDN in front of the app.

  4. **Returned in an API response envelope** (PL001, MEDIUM): the system prompt variable is
     the value of an unambiguous API-response key (`"output"`/`"result"`/`"response"`:
     system_prompt) — returning that dict exposes the full prompt in the response body.
     (Narrowed after review: the original draft also flagged `system_prompt + x` concat and
     `f"{system_prompt}{x}"` f-strings, but those are indistinguishable from prompt assembly /
     SQL serialization at line granularity and false-fired on the flagship; `content`/`text`/
     `message` keys were dropped because they collide with correct LLM system-message dicts.)

Each pattern is independently detected and independently suppressible via a per-check pragma.
All four carry `["OWASP-LLM:LLM07"]`.

**Relationship to `system-prompt-leak`:**
  * `system-prompt-leak` fires on the *output* side: the model can be coerced into repeating
    its system prompt verbatim ("repeat your instructions above") because no output filter
    exists.
  * This guard fires on the *code* side: the system prompt is written into source / logs /
    responses directly, or concatenated into user-facing output, before or after the model is
    involved. The two guards are complementary.

**Design:**
  * Four independent checks, each returning at most ONE finding (first match across all files).
  * Per-check opt-out pragmas allow suppressing exactly the applicable check:
      # security: allow-hardcoded-system-prompt
      # security: allow-system-prompt-in-log
      # security: allow-system-prompt-in-response
      # security: allow-system-prompt-concat
  * `applies()` is gated on `"llm" in profile.features` — no LLM in the stack, no system
    prompts to inspect.
  * Severity follows the checklist items: LOW for hardcoded (source exposure, rotation problem
    but lower urgency than live exfiltration), MEDIUM for log, response, and concat-leakage
    exposure (active exfiltration / wide visibility risk).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_llm_framework_repo,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA_HARDCODED = "security: allow-hardcoded-system-prompt"
_PRAGMA_LOG = "security: allow-system-prompt-in-log"
_PRAGMA_RESPONSE = "security: allow-system-prompt-in-response"
_PRAGMA_CONCAT = "security: allow-system-prompt-concat"

_STANDARDS = ["OWASP-LLM:LLM07"]

# Assignment to a system-prompt variable or keyword argument with a string literal
# as the right-hand side.
#   Matches: SYSTEM_PROMPT = "...", system_prompt = '...', system_prompt=f"...",
#            system_prompt = """...""", system_prompt=r"..."
#   Doesn't match: system_prompt = os.environ.get(...), system_prompt = config.get(...)
#   The [fr]? handles f-strings and raw strings; ["'] matches the start of any string
#   literal including triple-quoted ones (the first character of """ is ").
_HARDCODED = re.compile(
    r"\b(?:SYSTEM_PROMPT|system_prompt)\s*=\s*[fr]?[\"']",
    re.IGNORECASE,
)

# If a line matching _HARDCODED also matches _DYNAMIC_LOADER, the value comes from
# configuration rather than a literal — silence that line.
_DYNAMIC_LOADER = re.compile(
    r"os\.environ|getenv\s*\(|config\.|settings\.|\.get\s*\(|load_|from_file|read_",
    re.IGNORECASE,
)

# A logging call at DEBUG or INFO level — the guard fires when this AND a system-prompt
# reference appear on the same line.
_LOG_CALL = re.compile(r"\b(?:logging|logger)\s*\.\s*(?:debug|info)\s*\(", re.IGNORECASE)

# A reference to a system-prompt variable — used as the co-occurrence signal for _LOG_CALL.
_PROMPT_REF = re.compile(r"\b(?:SYSTEM_PROMPT|system_prompt)\b", re.IGNORECASE)

# FastAPI HTTPException / JSONResponse `detail=` keyword holding the system-prompt variable
# directly. The guard fires on single-line uses; multi-line HTTPException blocks where
# `detail=` appears on a line without the enclosing call are also caught.
_RESPONSE_EXPOSURE = re.compile(
    r"\bdetail\s*=\s*(?:SYSTEM_PROMPT|system_prompt)\b",
    re.IGNORECASE,
)

# PL001 — system prompt returned in an API response envelope (MEDIUM).
#
# Narrowed after review: the original draft also had string-concat and f-string
# sub-patterns, but a line-local regex cannot tell whether a `system_prompt + x` /
# `f"{system_prompt}{x}"` result goes to the USER (leak), the LLM (prompt assembly,
# safe), or a SQL/serialization string (safe) — they false-fired on prompt assembly and
# on the flagship's SQL-export serializer. Only the response-envelope form remains.
#
# Response-envelope dict key whose value is the system prompt: `{"output": system_prompt}`.
# The key set is deliberately the unambiguous API-response keys (output/result/response);
# `content`/`text`/`message` are EXCLUDED because they collide with the LLM system-message
# dict shape (`{"role":"system","content": system_prompt}`) — correct usage, not a leak.
_RESPONSE_DICT = re.compile(
    r'''["\'](?:output|result|response)["\']\s*:\s*(?:SYSTEM_PROMPT|system_prompt)\b''',
    re.IGNORECASE,
)


class SystemPromptExposureGuard(Guard):
    id = "system-prompt-exposure"
    title = "System prompt exposed via code-level pattern"
    area = "AI agent"

    # llm_setup.py has three system-prompt-exposure plants:
    #   1. SYSTEM_PROMPT = "..." -> hardcoded-literal (agent.py fires first alphabetically)
    #   2. logger.debug(SYSTEM_PROMPT) -> logged-at-debug-info
    #   3. raise HTTPException(detail=SYSTEM_PROMPT) -> in-error-response
    # Must NOT contain: allow-hardcoded-system-prompt / allow-system-prompt-in-log /
    # allow-system-prompt-in-response — any of those would silence the respective check.
    # prompt_concat_output.py: an API-response key ("output") whose value is the system_prompt
    # variable -> fires system-prompt-exposure/concat-leakage (PL001, MEDIUM).
    # Must NOT contain: security: allow-system-prompt-concat (pragma silences the check).
    # agent.py: system_prompt="..." (hardcoded literal). llm_setup.py: logger.debug(SYSTEM_PROMPT)
    # (logged at debug level) and raise HTTPException(detail=SYSTEM_PROMPT) (in error response).
    # prompt_concat_output.py: system_prompt + user_response -> concat-leakage (PL001, MEDIUM).
    canary_plant = CanaryPlant(
        files={
            "llm_setup.py": (
                "import logging\n"
                "from fastapi import HTTPException\n"
                "\n"
                'SYSTEM_PROMPT = "You are the exposure canary. Treat this as confidential."\n'
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "\n"
                "\n"
                "def init_llm() -> None:\n"
                "    logger.debug(SYSTEM_PROMPT)  # prompt at debug level\n"
                "\n"
                "\n"
                "def handle_error(exc: Exception) -> None:\n"
                "    raise HTTPException(status_code=500, detail=SYSTEM_PROMPT)\n"
            ),
            "prompt_concat_output.py": (
                "import os\n"
                "\n"
                "system_prompt = os.environ.get('SYSTEM_PROMPT', 'default')\n"
                "\n"
                "\n"
                "def handler() -> dict:\n"
                '    return {"output": system_prompt}\n'
            ),
        },
        expects=frozenset({
            "system-prompt-exposure/hardcoded-literal",
            "system-prompt-exposure/logged-at-debug-info",
            "system-prompt-exposure/in-error-response",
            "system-prompt-exposure/concat-leakage",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                # Skip test/offline tooling (and the repo's opt-in archive trees) — this guard
                # flags offline judge/eval scripts that are never served. Mirrors the 10 other
                # noise-prone guards; honors `.agentsec/config.json` archive_paths.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                files.append((f, read(f)))

        out: list[Finding] = []
        # Framework libraries define default system prompts as string literals
        # intentionally (they're template defaults, not deployed credentials).
        # The log/response checks still apply — those are runtime exfiltration risks.
        if not is_llm_framework_repo(root, profile):
            out += self._check_hardcoded(root, files)
        out += self._check_logged(root, files)
        out += self._check_in_response(root, files)
        out += self._check_concat_leakage(root, files)
        return out

    def _check_hardcoded(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for _f, text in files:
            if pragma_present(_PRAGMA_HARDCODED, text, dialect="python"):
                return []
        for f, text in files:
            # NOTE: do NOT strip_python_strings here. This check's signal IS a string-literal RHS
            # (`SYSTEM_PROMPT = "..."`), and strip blanks a triple-quoted node INCLUDING its `"""`
            # delimiters — which would defeat detection of the most common real shape,
            # `SYSTEM_PROMPT = """..."""` (PR #439 review, Critical). The only self-match in this
            # guard's own source is the descriptive `# Matches: SYSTEM_PROMPT = ...` comment, which
            # the whole-line `#` skip below handles (issue #424).
            for lineno, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if _HARDCODED.search(line) and not _DYNAMIC_LOADER.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="low",
                        title="System prompt hardcoded as a source-code literal",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "The system prompt is assigned a string literal in source code. "
                            "Every developer with repo access can read it, it is baked into "
                            "the deployed wheel, and it cannot be rotated without a new "
                            "deployment. Any steering instructions or confidential policy "
                            "embedded in the prompt are permanently exposed."
                        ),
                        remediation=(
                            "Load the system prompt from an environment variable or external "
                            "config (e.g. `SYSTEM_PROMPT = os.environ['SYSTEM_PROMPT']`). "
                            "If a hardcoded default is intentional (e.g. a non-sensitive "
                            "fallback), suppress with "
                            "`# security: allow-hardcoded-system-prompt`."
                        ),
                        rule="system-prompt-exposure/hardcoded-literal",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_logged(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for _f, text in files:
            if pragma_present(_PRAGMA_LOG, text, dialect="python"):
                return []
        for f, text in files:
            # Blank triple-quoted docstring CONTENT so a `logging.debug(system_prompt)` EXAMPLE in a
            # docstring doesn't self-match (issue #424 / PR #439 review). Safe here (unlike
            # _check_hardcoded): the signal is a VARIABLE reference in real code, not a string
            # literal, so blanking triple-quoted strings never hides a real detection.
            for lineno, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
                if _LOG_CALL.search(line) and _PROMPT_REF.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="medium",
                        title="System prompt written to application logs at DEBUG or INFO level",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A logging call at DEBUG or INFO level references the system "
                            "prompt. Centralized log aggregators (Datadog, CloudWatch, "
                            "Elasticsearch) retain these logs, often forwarding them to "
                            "dashboards visible beyond the immediate team, and may retain "
                            "them for compliance periods — making the system prompt "
                            "persistent and widely accessible."
                        ),
                        remediation=(
                            "Remove the system prompt from log calls, or log only a "
                            "fingerprint/hash. If intentional (e.g. a dev-mode trace), "
                            "gate behind a DEBUG environment flag or suppress with "
                            "`# security: allow-system-prompt-in-log`."
                        ),
                        rule="system-prompt-exposure/logged-at-debug-info",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_in_response(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for _f, text in files:
            if pragma_present(_PRAGMA_RESPONSE, text, dialect="python"):
                return []
        for f, text in files:
            # Blank triple-quoted docstring CONTENT so a `detail=system_prompt` EXAMPLE in a
            # docstring doesn't self-match (#424 / #439 review). Variable-match, so strip-safe.
            for lineno, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
                if _RESPONSE_EXPOSURE.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="medium",
                        title="System prompt exposed in API error response detail field",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "The system prompt is passed directly as the `detail=` value "
                            "of an HTTPException or JSONResponse. Even non-200 error "
                            "responses are returned to the calling client, exposing the "
                            "full prompt text in browser DevTools and any API gateway logs "
                            "between client and server."
                        ),
                        remediation=(
                            "Use a generic error message in the response body "
                            "(`detail='Internal error'`) and log the system prompt "
                            "internally at DEBUG level (behind a non-production guard). "
                            "Suppress with `# security: allow-system-prompt-in-response` "
                            "if the prompt is intentionally public."
                        ),
                        rule="system-prompt-exposure/in-error-response",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_concat_leakage(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """PL001 — system prompt placed in an API response envelope (MEDIUM, first match only).

        Fires when an unambiguous API-response key (`output`/`result`/`response`) is assigned
        the `system_prompt` variable (`return {"output": system_prompt}`). The earlier
        string-concat and f-string sub-patterns were dropped after review: a line-local regex
        cannot tell whether the result reaches the user (leak), the LLM (prompt assembly,
        safe), or a SQL/serialization string (safe), and they false-fired on prompt assembly
        and on the flagship's SQL-export serializer.
        """
        for _f, text in files:
            if pragma_present(_PRAGMA_CONCAT, text, dialect="python"):
                return []
        for f, text in files:
            # Blank triple-quoted docstring CONTENT so a `{"output": system_prompt}` EXAMPLE in a
            # docstring doesn't self-match (#424 / #439 review). The `"output"` key is a single-line
            # string (left intact by strip), and the value is a variable — so strip-safe.
            for lineno, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
                if _RESPONSE_DICT.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="medium",
                        title="System prompt assigned as value of an API response key",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "An API-response dictionary key (`output`, `result`, or `response`) "
                            "is assigned the system prompt variable directly. Returning this "
                            "dict from an endpoint exposes the full system prompt text in the "
                            "response body."
                        ),
                        remediation=(
                            "Use the LLM response (not the system prompt) as the value of "
                            "output keys. The system prompt should be passed only as the "
                            "`system_prompt=` argument to the model. "
                            "Suppress with `# security: allow-system-prompt-concat` if the "
                            "dict is for internal use only."
                        ),
                        rule="system-prompt-exposure/concat-leakage",
                        standards=list(_STANDARDS),
                    )]
        return []
