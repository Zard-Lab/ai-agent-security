"""Guard: environment secret directly interpolated into an LLM prompt (OWASP-LLM:LLM02/A02).

A common developer mistake in LLM applications: reading a secret from the environment
and immediately interpolating it into an f-string on the same line. When that string
becomes part of an LLM prompt, the secret is transmitted to the model provider, stored
in the conversation history, logged by observability tools, and potentially repeated
back to end users in the model's response.

This pattern is distinct from the legitimate use of `os.environ` for authentication:

  # LEGITIMATE — secret read once and stored in a variable for the SDK:
  client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

  # DANGEROUS — secret directly in a string that may become a prompt:
  prompt = f"Your admin key is {os.environ.get('OPENAI_API_KEY')} — keep it safe."

One statically detectable pattern:

  **`secret-in-fstring`** (HIGH): A Python line that is (or contains) an f-string AND
  reads a secret-named env var — via `os.environ.get(...)`/`os.getenv(...)` OR the bare
  subscript form `os.environ["..."]` (no `.get()` — the idiomatic way to read a *required*
  secret, where a missing var should raise `KeyError` rather than silently pass `None`) —
  with a key name that matches common secret patterns (KEY, SECRET, PASSWORD, TOKEN, PASS,
  CRED, PRIVATE, AUTH). The same-line co-occurrence signals the developer formatted the
  secret into the string directly rather than passing it to an SDK authentication parameter.

**Why HIGH?** Secrets embedded in LLM prompts are:
  - Transmitted to the model provider (OpenAI, Anthropic, etc.) as part of the conversation
  - Stored in conversation history, chat logs, and analytics dashboards
  - Visible in observability tools (Logfire, Langfuse, Datadog LLM Observability)
  - Potentially repeated in model output to end users ("here is the key you asked for: ...")
  - Subject to prompt injection: an attacker who can inject into the prompt can elicit
    the secret in the model's response

**False-negative scope:** This guard only catches single-line direct interpolation (call form
`.get()`/`getenv()` OR bracket-subscript form `os.environ[...]`). NOT caught: patterns where
the env var is read into a variable and the variable is used elsewhere (multi-line patterns —
these require dataflow analysis beyond the scope of static line-level detection), string
concatenation/`.format()`/`%`-interpolation instead of an f-string, and secrets read off a
settings/config object attribute (`settings.API_KEY`) rather than `os.environ`/`os.getenv`
directly (statically indistinguishable from any other attribute access without type
resolution).

**Checklist item:** `4-llm-no-env-secrets` (partial — catches direct same-line interpolation
via both the call and bracket access forms; multi-line patterns, string concatenation, and
secrets passed via config objects are not detected).

**Suppress:** `# security: allow-secret-in-prompt` in any file silences this check
repo-wide. Use only when you have confirmed the string in question is NOT sent to an LLM
and its interpolation is intentional (e.g. a developer tool that prints the key for
diagnostic purposes, scoped behind an admin flag).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel
from .env_secret_logged import _SECRET_NAME

_PRAGMA = "security: allow-secret-in-prompt"

_STANDARDS = ["OWASP-LLM:LLM02", "OWASP:A02"]

# Matches os.environ.get("..."), os.getenv("..."), or the bracket/subscript form
# os.environ["..."] (no .get() call — the idiomatic way to read a *required* secret, where
# a missing var should KeyError rather than silently pass None) where the key name's
# secret-sounding word is a whole `_`/`.`-delimited SEGMENT — reuses env_secret_logged's
# `_SECRET_NAME` (PR #397) so a substring like TOKEN inside MAX_TOKENS, PASS inside
# BYPASS_CACHE, or KEY inside MONKEY does NOT false-fire (#423 sibling-divergence). The
# subscript alternative mirrors env_secret_logged.py's `_ENV_SECRET_ACCESS` (same two-branch
# shape). Case-insensitive so DATABASE_PASSWORD and db_password both match.
_SECRET_ENV_ACCESS = re.compile(
    rf"""(?:
        (?:os\.environ\.get|os\.getenv)\s*\(\s*['"]{_SECRET_NAME}['"]
        |
        os\.environ\s*\[\s*['"]{_SECRET_NAME}['"]\s*\]
    )""",
    re.IGNORECASE | re.VERBOSE,
)

# An f-string opening quote — signals the line contains a format string.
_FSTRING_OPEN = re.compile(r"""\bf['"]""")


class EnvSecretInPromptGuard(Guard):
    id = "env-secret-in-prompt"
    title = "Environment secret directly interpolated into a string (potential LLM prompt injection)"
    area = "Secrets"

    # env_setup.py has env-secret-in-prompt plants:
    #   f-string with os.environ.get("API_SECRET_KEY") on same line -> secret-in-fstring
    #   f-string with os.environ["API_SECRET_KEY"] (bracket form)   -> secret-in-fstring
    #     Since #425 the check reports every matching line, so a canary run reaches this line
    #     too (until then it returned on the first hit and never did: review M9, 2026-09-03).
    #     `expects` is a rule set, though, so the canary still cannot tell the two lines
    #     apart: the bracket-subscript branch is proven by
    #     `test_env_secret_in_prompt_flags_bracket_access_in_fstring`, not by this plant.
    # Must NOT contain: allow-secret-in-prompt pragma — it silences the guard repo-wide.
    canary_plant = CanaryPlant(
        files={
            "env_setup.py": (
                "import os\n"
                "\n"
                "# Secret directly interpolated into f-string — what the guard detects.\n"
                'header = f"Authorization: Bearer {os.environ.get(\'API_SECRET_KEY\')}"\n'
                "\n"
                "# Bracket/subscript access form — same-line co-occurrence, no .get() call.\n"
                'bracket_header = f"Bearer {os.environ[\'API_SECRET_KEY\']}"\n'
            ),
        },
        expects=frozenset({
            "env-secret-in-prompt/secret-in-fstring",
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
                files.append((f, read(f)))

        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        return self._check_secret_in_fstring(root, files)

    def _check_secret_in_fstring(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per offending line, every file (#425): returning the first hit capped
        # the rule at one finding repo-wide, so an exception on it hid all the others.
        out: list[Finding] = []
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _FSTRING_OPEN.search(line) and _SECRET_ENV_ACCESS.search(line):
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Environment secret directly interpolated into an f-string",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "An environment variable with a secret-sounding name is read "
                            "via `os.environ.get()`/`os.getenv()`/`os.environ[...]` and "
                            "immediately interpolated into an f-string on the same line. In an LLM "
                            "application, f-strings are typically prompt components — "
                            "the secret will be transmitted to the model provider, stored "
                            "in conversation history, and may appear in the model's output. "
                            "Observability tools (Logfire, Datadog LLM Observability, "
                            "Langfuse) log prompt contents, extending exposure further."
                        ),
                        remediation=(
                            "Remove the secret from the prompt. Pass secrets to the model "
                            "provider via the SDK's authentication parameter (e.g. "
                            "`OpenAI(api_key=os.environ.get('OPENAI_API_KEY'))`), not as "
                            "prompt content. If the string must reference a secret for "
                            "legitimate non-LLM use, store it in a named variable first "
                            "and use the variable — that single-line co-occurrence is what "
                            "triggers this check. Suppress with "
                            "`# security: allow-secret-in-prompt` only after confirming "
                            "the string is not sent to a model."
                        ),
                        rule="env-secret-in-prompt/secret-in-fstring",
                        standards=list(_STANDARDS),
                    ))
        return out
