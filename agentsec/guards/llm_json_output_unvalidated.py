"""Guard: LLM response text parsed as JSON without schema validation (checklist §4, new item).

Structured-output pipelines ask the model to return JSON, then parse the response text
with `json.loads(...)` and act directly on the resulting dict. Two risks compound:

1. **Untrusted structure.** The model's output is attacker-influenceable (via prompt
   injection or plain non-determinism) — nothing guarantees the parsed dict has the keys,
   types, or ranges the calling code assumes. A field like `{"is_admin": true}` or
   `{"amount": -1}` flows straight into a decision with no gate.
2. **Unhandled malformed output.** If the model doesn't return valid JSON at all, the
   bare `json.loads(...)` call raises with no recovery.

This mirrors `upstream-response-unvalidated`'s pattern for external HTTP API responses,
applied to the LLM's own text output — llm-guard's `JSON` output scanner exists to close
exactly this gap (validate the shape before the app trusts it).

One statically detectable pattern:

  **`llm-json-output-unvalidated`** (HIGH): `json.loads(...)` is called with an argument
  that references a variable previously assigned from an LLM generation call
  (`.invoke`/`.generate`/`.chat`/`.create`/`.complete`), and neither the same line nor the
  next non-blank line contains a Pydantic schema-validation call (`.model_validate(`,
  `.parse_obj(`, `TypeAdapter(`, or a `SomeModel(**parsed)` construction).

**Silence conditions:**
- Same line or next non-blank line contains a schema-validation call
  (`model_validate`/`.parse_obj(`/`TypeAdapter(...).validate_python(`/a `SomeModel(**`
  construction) whose OWN argument correlates with the value `json.loads(...)` just
  produced — the tracked name appears anywhere in the validation call's own argument
  list (a bare reference, a keyword argument like `obj=data`, or wrapped in another call
  like `dict(data)`), or the call's argument is a list-comprehension loop variable whose
  `for x in <tracked name>` clause names the parsed value, or one hop of plain
  reassignment (`cleaned = strip_nulls(data)` immediately before the real validation
  call). A validation call present on those lines but targeting an unrelated variable no
  longer silences the finding (closes the checklist gap: presence-of-validation-call was
  checked, but not that it targeted the parsed value).
- The `json.loads(...)` argument does not reference any tracked LLM-result variable —
  it may be parsing something else entirely (a config file, a webhook body).
- The argument is *terminally* an SDK envelope serializer — `json.loads(resp.json())`,
  `json.loads(resp.model_dump_json())` (#715). The envelope still *contains* the model's
  text, nested inside it; what the SDK's schema guarantees is its **structure**, and
  structure is what this rule is about. Prompt injection cannot add a key, drop `choices`,
  or change a field's type, so the finding's own claim ("nothing guarantees the parsed dict
  has the keys, types, or ranges the calling code assumes") is simply untrue of an envelope,
  and its remediation would re-validate the SDK's own schema for no gain.
  "Terminally" is load-bearing: `json.loads(resp.json()["choices"][0]["message"]["content"])`
  uses the same serializer and then reaches *through* it to the model's text, so it fires.
- The file contains `# security: allow-llm-json-unvalidated` anywhere.

**False-negative scope:** Single-file, name-based dataflow — a variable renamed across
function boundaries, or `json.loads` called on a differently-named alias of the same
value, is not tracked. When `json.loads(...)`'s result isn't captured by a simple
`x = json.loads(...)` assignment (e.g. it's used inline or returned directly), there is
no single name to correlate a validation call against, so the guard falls back to its
older presence-only check for that line pair. Separately, parsing the envelope into a
variable and then `json.loads`-ing a field read out of it on a later line
(`data = json.loads(resp.model_dump_json())` … `json.loads(data["choices"][0]["message"]
["content"])`) is NOT tracked, because that field is a derived name rather than one
captured from the generation-call assignment. That is the pre-existing one-hop derivation
limit and NOT a consequence of the #715 silence condition — measured, the same line is
missed with and without it — and `test_dump_then_extract_then_parse_is_a_known_limit` pins
it so it cannot drift silently.

**Known residual false positive:** `json.loads(json.dumps(resp.model_dump()))` still fires —
the terminal call is `json.dumps(`, not a serializer. A contrived double round-trip, left
documented rather than special-cased.
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
)

_PRAGMA = "security: allow-llm-json-unvalidated"

_STANDARDS = ["OWASP-LLM:LLM05", "OWASP:A03"]

# A variable assigned from an unambiguous LLM-framework generation method (langchain/pydantic-ai
# `.invoke` etc. — not used by stripe/ORM/boto3), so no gate needed.
_LLM_RESULT_VAR = re.compile(
    r"(\w+)\s*=\s*(?:await\s+)?[\w.]+\.(?:invoke|generate|complete|chat|ainvoke)\s*\(",
    re.IGNORECASE,
)

# A variable assigned from `.create(` — OpenAI's method, BUT also stripe/ORM/boto3; counts only
# when the file imports an LLM SDK (see _LLM_SDK_IMPORT). `(?:await\s+)?` covers the standard async
# convention (`response = await client.chat.completions.create(...)`).
_LLM_RESULT_VAR_CREATE = re.compile(r"(\w+)\s*=\s*(?:await\s+)?[\w.]+\.create\s*\(", re.IGNORECASE)

_LLM_SDK_IMPORT = re.compile(
    r"(?:from|import)\s+(?:"
    r"openai|anthropic|langchain\w*|llama_index|llama_cpp|litellm|cohere|mistralai|groq|ollama"
    r"|google\.generativeai|google\.genai|vertexai|together|replicate|transformers|vllm|huggingface_hub"
    r")\b",
    re.IGNORECASE,
)

# json.loads(...) — capture the full argument expression for a word-boundary name check.
# The capture MUST start on a non-whitespace character and MUST stay bounded (#676, the #674
# shape): `\(\s*(.+?)\s*\)` was ambiguous because `.` matches a space too, so an unterminated
# `json.loads(` followed by a long whitespace run was partitioned combinatorially before the
# absent `)` failed (2.3s on a 2,000-char line, non-terminating at 8,000 — and this searches
# every raw source line, with no line-length cap on the path). `[^\s]` makes the capture
# disjoint from the preceding `\s*`, which is the part that removes the blow-up; `.{0,300}`
# caps the residual per-line work. An argument expression longer than 301 chars is no longer
# matched: a deliberate trade, pinned at the boundary by its test.
_JSON_LOADS = re.compile(r"json\.loads\s*\(\s*([^\s].{0,300}?)\s*\)")

# A Pydantic schema-validation signal, presence-only (no argument correlation) — kept as the
# fallback for the rare line shape `_JSON_LOADS_ASSIGN` can't parse (see `_JSON_LOADS_ASSIGN`).
_SCHEMA_VALIDATE = re.compile(
    r"\.model_validate\s*\(|\.parse_obj\s*\(|\bTypeAdapter\s*\(|\b[A-Z]\w*\s*\(\s*\*\*",
)

# The OPEN paren of a schema-validation call — used to extract its own balanced argument span
# (via `_balanced_arg`) rather than requiring the tracked name to sit immediately after `(` with
# only a dotted-attribute prefix. That immediately-after-paren shape missed a keyword argument
# (`obj=data`), a wrapping call (`dict(data)`), and a list-comprehension loop variable
# (`[Model.model_validate(x) for x in data]`) — all correctly-validated code, all reported HIGH
# (review finding H5). `m.end()` for the `SomeModel(**` alternative already lands just past the
# `**`, which is still "one paren deep" for `_balanced_arg`'s depth bookkeeping (the `**` itself
# contains no bracket characters).
_VALIDATION_CALL_OPEN = re.compile(
    r"\.model_validate\s*\(|\.parse_obj\s*\(|\.validate_python\s*\(|\b[A-Z]\w*\s*\(\s*\*\*"
)

# `for <var> in <iterable>` — correlates a validation call's own loop-variable argument back to
# the tracked name one level up, for the `[Model.model_validate(x) for x in data]` shape.
_FOR_LOOP_VAR = re.compile(r"\bfor\s+(\w+)\s+in\s+([\w.]+)")

# The assignment target of `json.loads(...)` itself — the parsed value's own name, so an
# eventual validation call can be checked against the SAME value it produced rather than any
# validation-shaped call that happens to sit nearby while validating something else entirely.
_JSON_LOADS_ASSIGN = re.compile(r"^\s*(\w+)\s*=\s*json\.loads\s*\(")

# A plain reassignment `newname = <expr>` — one hop of alias tracking so a rename between the
# parse and the real validation call (`cleaned = strip_nulls(data)`) doesn't defeat correlation.
_STRAIGHT_REASSIGN = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")

# An SDK *envelope* serializer: the response OBJECT re-serialized by the SDK itself
# (`resp.json()`, `resp.model_dump_json()`), whose STRUCTURE is the SDK's API contract. The
# model's text is still in there, nested; what cannot be attacker-shaped is the set of keys
# and their types. Structural trust is this rule's threat, so deserializing an envelope is
# not it, and it is silenced (#715). The model's text is reached through a different accessor
# (`.content`, `.text`, `.output_text`, `.arguments`) — which keeps firing when that accessor
# is inside the SAME `json.loads(...)` call. Reached via an intervening variable it is not
# tracked at all: see the docstring's false-negative scope.
# `model_dump`/`to_dict`/`dict` return a dict, so `json.loads` of them raises TypeError and
# cannot occur in working code; they are kept as cheap defense against a non-standard
# override that returns a string.
_ENVELOPE_SERIALIZER = re.compile(
    r"\.\s*(?:json|model_dump_json|model_dump|to_json|to_dict|dict)\s*\($"
)

# Cap the balanced scan so a pathological line stays linear (the #676 constraint).
_ARG_SCAN_LIMIT = 400

_DEF = re.compile(r"[ \t]*(?:async[ \t]+)?def[ \t]")


def _balanced_arg(line: str, open_idx: int) -> str | None:
    """The full argument starting at `open_idx` (the index just past a call's open paren, or
    just past a `**` immediately inside one), or None if unterminated within `_ARG_SCAN_LIMIT`.

    A scan, not a wider regex: widening the capture is what reopened the #676 hang.

    NOT quote-aware: brackets are counted positionally, so a paren inside a string literal
    (`resp.content.replace(")", "")`) desyncs the depth count and truncates the argument
    early. The consequence is asymmetric, which is why it is tolerated: a truncated argument
    stops short of any trailing serializer call, so `_is_sdk_envelope` returns False and the
    finding still FIRES; for `_validation_targets`, a truncated argument can only shrink the
    name-search text, so it can only miss a correlation, never fabricate one, which fails
    toward firing there too. Do not make the scan quote-aware without re-checking both callers.
    """
    depth = 1
    out: list[str] = []
    for ch in line[open_idx : open_idx + _ARG_SCAN_LIMIT]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return "".join(out)
        out.append(ch)
    return None


def _is_sdk_envelope(arg: str) -> bool:
    """True when `arg` is *terminally* an SDK envelope-serializer call — the whole expression
    is `<obj>.json()` / `<obj>.model_dump_json()` with nothing indexing into the result.

    Terminal is the load-bearing word. `resp.json()` is the envelope; but
    `resp.json()["choices"][0]["message"]["content"]` uses the same serializer and then reaches
    THROUGH it to the model's text, so it must still fire. Likewise `resp.content.strip()`
    ends in a call, but the trailing call is not a serializer.
    """
    arg = arg.strip()
    if not arg.endswith(")"):
        return False
    depth = 0
    for i in range(len(arg) - 1, -1, -1):
        if arg[i] == ")":
            depth += 1
        elif arg[i] == "(":
            depth -= 1
            if depth == 0:
                return bool(_ENVELOPE_SERIALIZER.search(arg[: i + 1]))
    return False


def _validation_targets(line: str, names: set[str]) -> bool:
    """True if `line` contains a schema-validation-shaped call whose OWN argument correlates
    with one of `names` — i.e. it actually validates one of the tracked values, not just ANY
    validation call that happens to sit on this line while validating something unrelated.

    Extracts each candidate call's real argument span via `_balanced_arg` and searches for a
    tracked name anywhere inside it (a bare reference, `obj=data`, `dict(data)`, ...), rather
    than requiring the name immediately after the open paren with only a dotted prefix — that
    narrower shape missed keyword arguments and wrapping calls (H5). Also handles a
    list-comprehension loop variable (`[Model.model_validate(x) for x in data]`): when the
    call's own argument is a single bare name, checks whether that name is a `for ... in
    <tracked name>` loop variable on the same line.
    """
    if not names:
        return False
    for m in _VALIDATION_CALL_OPEN.finditer(line):
        arg = _balanced_arg(line, m.end())
        if arg is None:
            arg = line[m.end():]
        if any(re.search(r"\b" + re.escape(n) + r"\b", arg) for n in names):
            return True
        loop_var = arg.strip()
        if re.fullmatch(r"\w+", loop_var):
            for lm in _FOR_LOOP_VAR.finditer(line):
                if lm.group(1) == loop_var and any(
                    re.search(r"\b" + re.escape(n) + r"\b", lm.group(2)) for n in names
                ):
                    return True
    return False


def _validated_nearby(lines: list[str], i: int, parsed_var: str | None, names: set[str]) -> bool:
    """True if a schema-validation call correlated with the parsed value appears on the same
    line as `lines[i]`'s `json.loads(...)`, the next non-blank line, or — one hop of alias
    tracking — the line after a plain reassignment of the parsed value that itself carries no
    validation call.

    When `parsed_var` is None (the `json.loads(...)` call wasn't a simple `x = json.loads(...)`
    assignment, so there is no single name to correlate against), falls back to the guard's
    original presence-only check against the wider LLM-result-var set `names` — correlation
    isn't possible for that line shape, so this preserves prior behavior rather than invent a
    new one for an edge case that isn't the gap being closed here.
    """
    line = lines[i]
    if parsed_var is None:
        found_same = bool(_SCHEMA_VALIDATE.search(line))
    else:
        found_same = _validation_targets(line, names)
    if found_same:
        return True

    next_line, next_idx = "", -1
    for idx in range(i + 1, len(lines)):
        if lines[idx].strip():
            next_line, next_idx = lines[idx], idx
            break

    if parsed_var is None:
        return bool(_SCHEMA_VALIDATE.search(next_line))

    if _validation_targets(next_line, names):
        return True

    # One hop of alias tracking: a plain reassignment of the parsed value, itself carrying no
    # validation call, widens the tracked-name set for the line right after it.
    reassign = _STRAIGHT_REASSIGN.match(next_line)
    if reassign and not _SCHEMA_VALIDATE.search(next_line):
        alias, rhs = reassign.group(1), reassign.group(2)
        if re.search(r"\b" + re.escape(parsed_var) + r"\b", rhs):
            after_line = ""
            for idx in range(next_idx + 1, len(lines)):
                if lines[idx].strip():
                    after_line = lines[idx]
                    break
            if _validation_targets(after_line, names | {alias}):
                return True

    return False


def _enclosing_def_span(lines: list[str], i: int) -> tuple[int, int] | None:
    """(start, end) line indices of the function whose body contains line `i`, or None if `i` is at
    module level. Scopes LLM-result-variable tracking to the *function* a `json.loads` sits in — so a
    `response` assigned from an LLM call in one function doesn't taint a same-named `response` in
    another (the file-wide FP the review reproduced). Module-level `json.loads` keeps file scope."""
    if not lines[i].strip():
        return None
    line_indent = len(lines[i]) - len(lines[i].lstrip())
    j = i - 1
    while j >= 0:
        s = lines[j]
        if s.strip():
            ind = len(s) - len(s.lstrip())
            if ind < line_indent:
                if _DEF.match(s):
                    k = j + 1
                    while k < len(lines):
                        ln = lines[k]
                        if ln.strip() and (len(ln) - len(ln.lstrip())) <= ind:
                            break
                        k += 1
                    return j, k
                line_indent = ind  # left a nested block; keep looking for the def below this indent
        j -= 1
    return None


def _llm_result_vars(scope: str, has_sdk: bool) -> set[str]:
    """LLM-result variable names in `scope`: unambiguous methods always, `.create(` only when the
    file imports an LLM SDK."""
    names = {m.group(1) for m in _LLM_RESULT_VAR.finditer(scope)}
    if has_sdk:
        names |= {m.group(1) for m in _LLM_RESULT_VAR_CREATE.finditer(scope)}
    return names


class LlmJsonOutputUnvalidatedGuard(Guard):
    id = "llm-json-output-unvalidated"
    title = "LLM response text parsed as JSON without Pydantic schema validation"
    area = "AI agent"

    # llm_json_unvalidated.py: json.loads(response.content) on an LLM-result variable,
    # no Pydantic schema validation same-line or next-line -> fires
    # llm-json-output-unvalidated/no-schema-validation (HIGH).
    #
    # llm_json_unvalidated_unrelated_validation.py: the correlation-gap regression plant — a
    # schema-validation call IS present on the very next line, but it validates a DIFFERENT
    # variable (`other`) than the one `json.loads(...)` produced (`data`), which is the value
    # actually used in the admin decision. Must still fire, else the guard would silently
    # accept any nearby validation call regardless of what it validates.
    canary_plant = CanaryPlant(
        files={
            "llm_json_unvalidated.py": (
                "def handle(prompt):\n"
                "    response = llm_client.invoke(prompt)\n"
                "    data = json.loads(response.content)\n"
                "    if data['is_admin']:\n"
                "        grant_admin()\n"
            ),
            "llm_json_unvalidated_unrelated_validation.py": (
                "def handle(prompt):\n"
                "    response = llm_client.invoke(prompt)\n"
                "    data = json.loads(response.content)\n"
                "    other = OtherModel(**other_dict)\n"
                "    if data['is_admin']:\n"
                "        grant_admin()\n"
            ),
        },
        expects=frozenset({
            "llm-json-output-unvalidated/no-schema-validation",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue

                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                has_sdk = bool(_LLM_SDK_IMPORT.search(text))

                lines = text.splitlines()
                for i, line in enumerate(lines):
                    m = _JSON_LOADS.search(line)
                    if not m:
                        continue

                    # LLM-result vars scoped to THIS json.loads' enclosing function (not file-wide),
                    # so a same-named var in an unrelated function can't taint it.
                    span = _enclosing_def_span(lines, i)
                    scope = "\n".join(lines[span[0] : span[1]]) if span else text
                    llm_result_vars = _llm_result_vars(scope, has_sdk)
                    if not llm_result_vars:
                        continue

                    arg = m.group(1)
                    if not any(re.search(r"\b" + re.escape(v) + r"\b", arg) for v in llm_result_vars):
                        continue

                    # The tracked variable is the SDK's response OBJECT. Reaching it through an
                    # envelope serializer re-parses the SDK's own contract, not model text (#715).
                    full = _balanced_arg(line, m.start(1))
                    if full is not None and _is_sdk_envelope(full):
                        continue

                    assign_m = _JSON_LOADS_ASSIGN.match(line)
                    parsed_var = assign_m.group(1) if assign_m else None
                    correlate_names = {parsed_var} if parsed_var else set(llm_result_vars)

                    if _validated_nearby(lines, i, parsed_var, correlate_names):
                        continue

                    lineno = i + 1
                    findings.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="LLM response parsed as JSON without schema validation",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "The LLM's response text is parsed with json.loads() and "
                            "used without Pydantic schema validation. The model's output "
                            "is attacker-influenceable (prompt injection) or simply "
                            "non-deterministic — nothing guarantees the parsed dict has "
                            "the keys, types, or ranges the calling code assumes."
                        ),
                        remediation=(
                            "Validate the parsed dict against a Pydantic model before "
                            "using any field: `SomeModel.model_validate(parsed)`. This "
                            "also turns a malformed-JSON crash into a structured error."
                        ),
                        rule="llm-json-output-unvalidated/no-schema-validation",
                        standards=_STANDARDS,
                    ))

        return findings
