"""Guard: LLM call with no max_tokens ceiling — economic DoS / run-away cost (checklist §4).

A direct OpenAI/Anthropic API call without `max_tokens` lets an attacker send a 100 k-token
prompt and drain API credits at will. With no ceiling the model will try to produce a maximally
long completion for whatever garbage is sent, multiplying the cost. This is the principal
economic-denial-of-service vector for LLM-backed services.

This guard detects DIRECT API call sites (`chat.completions.create`, `completions.create`,
`responses.create`, `messages.create`) in Python files where:

  **`no-max-tokens`** (HIGH): the call has no `max_tokens` keyword argument anywhere in the
  file — the cost ceiling is absent entirely.

  **`user-controlled-max-tokens`** (MEDIUM): `max_tokens` IS present but its value is taken
  directly from `request.*` or a `user_*` variable — the attacker controls the ceiling itself.

Intentionally excludes high-level agent wrappers (`agent.run_sync`, `.invoke`, etc.) because
those configure token limits through model-level settings, not per-call kwargs.

A call site counts only when its arguments carry the SDK's keyword-only signature (`model=`,
`messages=`, `prompt=`, `extra_body=` or a `**` spread), via the shared `base.LLM_SDK_CREATE` +
`is_llm_sdk_create_call` (#561). The method path alone also matches a Twilio SMS send or a Django
reverse-relation create, which have no token ceiling to set.

Checklist item: `4-llm-input-cap-all-endpoints` (MANUAL → partial).

Comments, docstrings and string literals are blanked before matching, so prose that quotes
a call shape neither fires a finding nor counts as a ceiling (#563). One string survives:
a literal that IS the kwarg name (`**{"max_tokens": 512}`), the dict-key form of a real
ceiling.

Suppress: `# security: allow-unbounded-llm-input` anywhere in a file silences this guard
for that file. Use only when token limits are enforced at the gateway/proxy layer. The
opt-out is read from the raw text, since it is itself a comment.
"""
from __future__ import annotations

import re
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    LLM_SDK_CREATE,
    CanaryPlant,
    Guard,
    is_llm_sdk_create_call,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    router_code_view,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-unbounded-llm-input"

# Only direct SDK `create` calls, NOT high-level wrappers like agent.run_sync() (which configure
# token limits at model level). The call shape is the shared `LLM_SDK_CREATE`, confirmed by
# `is_llm_sdk_create_call`'s argument gate: this guard used to keep its own three-arm copy
# (`\b\w+\.` then the method path), which a Twilio `client` receiver or a Django `survey`
# relation satisfied as readily as an OpenAI client, and which disagreed with
# guardrail-architecture's four-arm one (#561).
# Prose is excluded by `_code_only`, which blanks comments, docstrings and string literals before
# any regex runs (#563). The argument walk reads `router_code_view` instead (see
# `_first_llm_call_line`): `_code_only` pairs quotes line by line, which mangles the row that closes
# a multi-line triple-quoted argument.

# Accept BOTH the legacy `max_tokens` and OpenAI's current `max_completion_tokens`
# (required for o1+; the recommended parameter today). Keying only on `max_tokens`
# raised a HIGH "no token ceiling" on up-to-date codebases that DO cap output (#423).
_MAX_TOKENS_PRESENT = re.compile(r"\bmax(?:_completion)?_tokens\b")
_MAX_TOKENS_USER = re.compile(
    r"max(?:_completion)?_tokens\s*=\s*(?:request\.|user_\w+)",
    re.IGNORECASE,
)

_STANDARDS = ["OWASP-LLM:LLM10", "CWE-400"]

# The one string content a ceiling legitimately lives in: the kwarg NAME as a dict key,
# `**{"max_tokens": 512}` / `extra_body={"max_completion_tokens": 100}`.
_CEILING_KEYS = frozenset({"max_tokens", "max_completion_tokens"})


def _blank_one_line_strings(line: str) -> str:
    # `_SL_STRING` is base's escape-aware one-line literal, the same one `strip_python_line_comment`
    # masks with, so the two passes agree on where a string is. Runs after that comment is gone, so
    # an apostrophe in a comment cannot open one. A same-quote nest inside an f-string (3.12+)
    # mis-pairs, which only over-blanks that line: nothing this guard matches lives in an f-string.
    def keep_key_or_blank(m: re.Match[str]) -> str:
        lit = m.group()
        return lit if lit[1:-1] in _CEILING_KEYS else lit[0] + " " * (len(lit) - 2) + lit[-1]

    return _SL_STRING.sub(keep_key_or_blank, line)


def _first_llm_call_line(code: str, raw: str, f: Path) -> int | None:
    """The 1-based line of the first SDK `create` call in `code` that passes the argument gate.

    `code` is the `_code_only` view, which nominates the candidates. None means the file makes no
    direct SDK call, which is the file gate.

    The gate reads the candidate's arguments from `router_code_view(raw)` at the same row and
    column, not from `code`. Both views keep the source's rows and every column before a comment,
    but `_code_only` pairs quotes line by line. On the row that closes a multi-line triple-quoted
    argument, its leftover delimiter pairs with the next quote and blanks the text between them:
    `''', model='gpt-4o', input=q)` lost its `model=`, and a real `responses.create` was rejected
    (#1050 review). `router_code_view` locates literals with the tokenizer, blanks only their text,
    and keeps the keyword. Where that view does not have the candidate's `(` at the same spot, the
    gate reads `code`, as before.
    """
    view: tuple[str, list[str], list[int]] | None = None  # built for the first candidate only
    for m in LLM_SDK_CREATE.finditer(code):
        open_idx = m.end() - 1
        row = code.count("\n", 0, open_idx)
        col = open_idx - (code.rfind("\n", 0, open_idx) + 1)
        if view is None:
            text = router_code_view(raw, filename=f)
            rows = text.split("\n")
            view = text, rows, [0, *accumulate(len(r) + 1 for r in rows)]
        text, rows, starts = view
        if row < len(rows) and rows[row][col : col + 1] == "(":
            confirmed = is_llm_sdk_create_call(text, starts[row] + col)
        else:
            confirmed = is_llm_sdk_create_call(code, open_idx)
        if confirmed:
            return row + 1
    return None


def _code_only(raw: str, f: Path) -> str:
    """The file with docstrings, string literals and `#` comments blanked, line count kept.

    All three signals are file-wide, so prose left in would both create a call (an FP) and
    create a ceiling that masks a real unbounded call (an FN) (#563). The one-line literals go
    too (`log("no max_tokens set")` masked an unbounded call, #968 review), except a literal that
    is exactly a ceiling kwarg's name: that is the dict-key spelling of a real ceiling.
    """
    return "\n".join(
        "" if line.lstrip().startswith("#") else _blank_one_line_strings(strip_python_line_comment(line))
        for line in strip_python_strings(raw, filename=f).splitlines()
    )


class LLMInputSizeCapGuard(Guard):
    id = "llm-input-size-cap"
    title = "LLM call site has no max_tokens ceiling — economic DoS risk"
    area = "AI agent"

    # llm_sizing.py has one llm-input-size-cap plant:
    #   chat.completions.create with no max_tokens -> no-max-tokens (HIGH).
    # Must NOT contain: allow-unbounded-llm-input pragma (silences the guard).
    # Must NOT contain: max_tokens keyword (would silence the no-ceiling check).
    # Must NOT contain: user_ prefix f-string (would fire prompt-string-interp separately).
    canary_plant = CanaryPlant(
        files={
            "llm_sizing.py": (
                "import openai\n"
                "\n"
                "client = openai.OpenAI()\n"
                "\n"
                "\n"
                "def answer(question: str) -> str:\n"
                "    response = client.chat.completions.create(\n"
                "        model='gpt-4o',\n"
                "        messages=[{'role': 'user', 'content': question}],\n"
                "    )\n"
                "    return response.choices[0].message.content\n"
            ),
        },
        expects=frozenset({
            "llm-input-size-cap/no-max-tokens",
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
                raw = read(f)
                if pragma_present(_PRAGMA, raw, dialect="python"):  # read before stripping: the opt-out IS a comment
                    continue
                code = _code_only(raw, f)
                call_line = _first_llm_call_line(code, raw, f)
                if call_line is None:
                    continue
                out.extend(self._check(root, f, code, call_line))
        return out

    def _check(self, root: Path, f: Path, text: str, call_line: int) -> list[Finding]:
        r = rel(root, f)
        lines = text.splitlines()

        if not _MAX_TOKENS_PRESENT.search(text):
            return [
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="LLM API call has no max_tokens — unbounded cost",
                    location=f"{r}:{call_line}",
                    message=(
                        "This direct LLM API call has no max_tokens argument. Without "
                        "a token ceiling an attacker can send a 100k-token prompt and "
                        "drain API credits proportionally. This is the primary "
                        "economic-denial-of-service vector for LLM-backed services "
                        "(OWASP-LLM:LLM10 — Unbounded Consumption)."
                    ),
                    remediation=(
                        "Add max_tokens=<N> to every chat.completions.create / "
                        "responses.create / messages.create call. Set N to the smallest "
                        "value your use-case allows (e.g. 512 for Q&A, 2048 for "
                        "summarisation). Also enforce input length at the API boundary: "
                        "reject requests where len(user_message) exceeds a hard cap "
                        "(checklist §4). Suppress with "
                        "`# security: allow-unbounded-llm-input` only when the proxy "
                        "layer enforces its own token ceiling."
                    ),
                    rule="llm-input-size-cap/no-max-tokens",
                    standards=list(_STANDARDS),
                )
            ]

        elif _MAX_TOKENS_USER.search(text):
            for lineno, line in enumerate(lines, 1):
                if _MAX_TOKENS_USER.search(line):
                    return [
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="max_tokens value sourced from user-controlled input",
                            location=f"{r}:{lineno}",
                            message=(
                                "The max_tokens ceiling is set from a request field or "
                                "user_* variable, giving the caller direct control over "
                                "their own cost ceiling. An attacker can set max_tokens to "
                                "the provider maximum and run up the bill."
                            ),
                            remediation=(
                                "Clamp max_tokens to a server-side maximum regardless of "
                                "what the caller sends: "
                                "max_tokens=min(int(request.max_tokens or 0), MAX_ALLOWED). "
                                "Define MAX_ALLOWED as a constant, not a config value "
                                "the caller can influence."
                            ),
                            rule="llm-input-size-cap/user-controlled-max-tokens",
                            standards=list(_STANDARDS),
                        )
                    ]

        return []
