"""Guard: LLM application missing independent guardrail or using circular self-validation.

The attack surface is the architectural design of how safety is enforced in an LLM
application. Two structural flaws are detected:

1. **GUARD-POLICY-001 — No external guardrail layer (MEDIUM):** An LLM application
   that makes generation calls (invoke/generate/chat/complete) but imports no external
   guardrail library. Relying solely on the LLM's built-in safety training provides no
   structural defense against prompt injection or jailbreaks — the model that was
   attacked is also the one producing the output without a separate safety layer.

   This is a PROJECT-LEVEL check: if ANY .py file in the project imports a known
   guardrail library (nemo_guardrails, guardrails, llm_guard, presidio, rebuff,
   lakera_guard, protect_ai, pii_safe, detoxify, perspective, moderation, etc.),
   calls a recognized guardrail endpoint (OpenAI moderation), or directly loads/invokes
   Llama Guard (HF transformers `from_pretrained`/`AutoModelForCausalLM`/`AutoTokenizer`,
   or a hosted-inference `model="meta-llama/Llama-Guard-3-8B"` call), the check is
   suppressed entirely.

2. **GUARD-DUAL-001 — Same model used as both generator and validator (HIGH):** When
   the same LLM variable is used to generate output AND to evaluate/check/moderate
   that output in the same function context. This is circular: a successful jailbreak
   of the generator also compromises the validator.

3. **GUARD-HITL-002 — High-stakes action without approval gate (HIGH):** An LLM call
   result used to trigger a payment, credential change, or account-deletion action
   without any human-in-the-loop confirmation in the same function. An SDK `create` result
   counts only when the call's arguments carry the SDK's keyword-only signature, so a Twilio
   SMS or a Django reverse-relation create is not an LLM result (#561).

4. **GUARD-SCAN-IGNORED — Guardrail scan called but its result not enforced (MEDIUM/HIGH):**
   A project can import a real guardrail library (llm-guard, etc.) and still provide no
   protection if the scan's validity result is never checked. llm-guard's `scan_prompt()` /
   `scan_output()` return `(sanitized_text, is_valid_map, risk_scores)` — a developer who
   calls one of these as a bare statement (return value fully discarded) or who captures
   the tuple but never references the validity result again has a scan that runs but
   enforces nothing. Rule 1 only proves a guardrail *import* exists; this rule proves
   whether an individual scan call site actually gates on the outcome.

Rules 1-4 above prove a guardrail LAYER exists and is enforced; they cannot see whether
that layer is itself *configured* soundly. Rules 5-9 read NeMo Guardrails' own `config.yml`
for five documented misconfiguration patterns (source: NVIDIA's own guardrail-catalog docs):

5. **GUARD-NEMO-NOINJ — Injection detection not configured (MEDIUM):** NeMo's YARA-based
   `injection_detection` rail is opt-in and disabled by default — a config with active
   input/output rails but no `injection_detection` block has no defense against the
   injection classes (code/SQL/XSS/template/command) that rail exists to catch.

6. **GUARD-NEMO-SELFCHECK — Self-check-only, no dedicated safety model (MEDIUM):** NeMo's
   own docs state self-check's reliability "is strongly dependent on the capability of the
   LLM to follow the instructions in the prompt" and explicitly recommend "a purpose-built
   input safety model instead" (Llama Guard, Nemotron Content Safety, ShieldGemma) if the
   LLM doesn't reliably comply. A config using only `self check input`/`self check output`
   with no dedicated content-safety model configured relies solely on the (attacker-
   targeted) generator LLM correctly following its own safety instructions.

7. **GUARD-NEMO-IORAILS — Tool rails declared without the IORails engine wired (HIGH):**
   Tool-call/tool-result validation rails only run on NeMo's opt-in `IORails` engine — the
   default `LLMRails` engine silently ignores them. NeMo's own docs warn a misdirected,
   unknown, or duplicated tool flow name "makes the configuration ineligible for IORails,"
   and the facade "silently falls back to `LLMRails`... with only a log warning." A config
   declaring tool rails with no `require_iorails`/`IORails` wiring anywhere in the project
   looks protected but the validation never runs.

8. **GUARD-NEMO-JAILBREAK — Jailbreak heuristics run in-process (MEDIUM):** NeMo's own docs
   mark running `jailbreak detection heuristics` in-process as "TESTING PURPOSES ONLY" and
   "NOT RECOMMENDED FOR PRODUCTION DEPLOYMENTS," recommending a separately deployed server
   instead. A config enabling the heuristics flow with no `server_endpoint` configured is
   running the explicitly-not-production-ready in-process mode.

9. **GUARD-NEMO-PII-PARTIAL — PII masking configured for input only (MEDIUM):** A PII/
   sensitive-data rail (GLiNER, Presidio, Private AI) masking user input but never
   configured for the `output`/`retrieval` flows lets PII the input side would have
   caught leak right back out through the bot's own response or RAG-retrieved chunks.

Suppress a known-safe pattern with the inline pragma:

    response = llm.invoke(...)  # security: allow-guardrail-architecture
"""
from __future__ import annotations

import re
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    LLM_SDK_CREATE,
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_llm_sdk_create_call,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    router_code_view,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-guardrail-architecture"

# --- RULE 1: No external guardrail layer (project-level) ---------------------

# An LLM generation call (used by rules 2/3 for variable tracking).
_LLM_CALL = re.compile(
    r"\.\s*(?:invoke|generate|complete|chat|ainvoke|create)\s*\(",
    re.IGNORECASE,
)

# R1 gate: the project must actually USE an LLM (import a generation SDK). This is what proves
# "LLM application" — NOT a bare `.create(` (which matches stripe.PaymentIntent.create, ORM
# `.objects.create()`, boto3, etc. and made R1 self-fire on agentsec — PR #227 review).
_LLM_SDK_IMPORT = re.compile(
    r"(?:from|import)\s+(?:"
    r"openai|anthropic|langchain\w*|llama_index|llama_cpp|litellm|cohere|mistralai|groq|ollama"
    r"|google\.generativeai|google\.genai|vertexai|together|replicate|transformers|vllm|huggingface_hub"
    r")\b",
    re.IGNORECASE,
)

# Any of these imports anywhere in the project means the project has a guardrail layer.
_GUARDRAIL_IMPORTS = re.compile(
    r"""
    (?:from|import)\s+
    (?:
        nemo_guardrails
        | guardrails
        | llm_guard
        | presidio_analyzer
        | presidio_anonymizer
        | rebuff
        | lakera_guard
        | protect_ai
        | pii_safe
        | detoxify
        | perspective
        | moderation
        | openai\.moderation
        | anthropic.*moderation
        | azure\.ai\.contentsafety
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# A guardrail used via a CALL rather than an import — chiefly the OpenAI moderation endpoint
# (`client.moderations.create(...)`). Recognising it prevents a false "no guardrail" finding
# on a project that moderates without a named guardrail-library import (PR #227 review).
_GUARDRAIL_CALL = re.compile(
    r"\.\s*moderations?\.\s*create\s*\(|\bModerationPipeline\b|\bcontent_safety\b",
    re.IGNORECASE,
)

# Llama Guard used DIRECTLY (not via NeMo config — that's Rule 6's `_NEMO_CONTENT_SAFETY_RAIL`,
# which only fires while scanning a NeMo config.yml and is never consulted here). A project that
# loads/invokes Llama Guard itself (HF transformers `AutoModelForCausalLM.from_pretrained(
# "meta-llama/Llama-Guard-3-8B")`, or a hosted-inference `model="meta-llama/Llama-Guard-3-8B"` call
# on Together/Groq/etc.) has a genuine external guardrail layer, even with no named-library import.
# The checklist item this rule feeds names Llama Guard as one of its two flagship examples of a
# valid guardrail — matching only NeMo's config.yml (Rules 5-9) and missing a directly-invoked
# Llama Guard here was a false "no guardrail" MEDIUM against exactly the tool the item names.
#
# Deliberately requires BOTH the name AND a call shape that actually loads/invokes a model on the
# SAME line — not a bare project-wide substring search. A bare substring match would also fire on
# a comment/docstring mention, or on a dead/commented-out reference
# (`# model = "meta-llama/Llama-Guard-3-8B"  # TODO: wire this in later`) that never actually runs,
# wrongly suppressing Rule 1's project-wide "no guardrail" finding. Scoped to a known, bounded set
# of call shapes: `.from_pretrained(`, `AutoModelForCausalLM`, `AutoTokenizer` (the HF-transformers
# direct-load path), or one of the already-recognized LLM generation call shapes
# (`.chat.completions.create(`, `.messages.create(`, `.invoke(`, `.generate(` — covers a hosted
# `model="meta-llama/Llama-Guard-3-8B"` kwarg on an OpenAI-compatible endpoint).
_LLAMA_GUARD_REFERENCE = re.compile(r"llama[-_]?guard", re.IGNORECASE)
_LLAMA_GUARD_LOADED = re.compile(
    r"\.\s*from_pretrained\s*\(|\bAutoModelForCausalLM\b|\bAutoTokenizer\b"
    r"|\.\s*(?:chat\.completions\.create|messages\.create|invoke|generate)\s*\(",
    re.IGNORECASE,
)

# --- RULE 2: Same model used as generator AND validator ----------------------

# Phase 1: capture the MODEL/CLIENT variable name from an LLM generation call.
# Group 1: the result variable (left of =).
# Group 2: the MODEL variable (object before .invoke).
# Matches: `response = llm.invoke(...)` -> result_var=response, model_var=llm
_LLM_GENERATION_ASSIGN = re.compile(
    r"(\w+)\s*=\s*(\w+)\.(invoke|generate|complete|ainvoke)\s*\(",
    re.IGNORECASE,
)

# Phase 2: in context around a generation call, the same client/model variable is
# invoked again with safety/evaluation keywords nearby.
_SAFETY_EVAL_KEYWORDS = re.compile(
    r"\b(?:judge|eval|check|safe|moderate|review|validate|guard)\b",
    re.IGNORECASE,
)

# --- RULE 3: High-stakes action without approval gate ------------------------

# LLM call result captured in a variable. Group 1 is the variable. Two arms:
#   * a direct method call, `response = llm.invoke(...)` (or generate/complete/ainvoke), on any
#     receiver;
#   * an OpenAI/Anthropic SDK `create`, in two steps. The regex's named group `create` takes a
#     `.create(` on any attribute path, and `_llm_result_assignment` keeps it only when that path is
#     the shared `base.LLM_SDK_CREATE` shape. `_sdk_create_confirmed` then reads the call's
#     arguments (`is_llm_sdk_create_call`).
#     The shape is checked beside this regex, not spliced into it: the ReDoS lint
#     (`scripts/lint_regex_redos.py`) resolves a pattern only from its own module's constants, so
#     an imported pattern built into this one would drop it out of that lint's coverage.
# History, because each step was right for the shapes it tested and the residue stayed invisible:
#   * the bare `.create(` arm was dropped (#423, mirrors PR #227's Rule-1 fix). It matched
#     stripe.PaymentIntent.create / `.objects.create()` / boto3, so a payment intent feeding a
#     `charge(...)` within 30 lines fired a HIGH FP.
#   * #445 restored `responses.create` (the shape OpenAI now recommends) and the legacy
#     `completions.create`, because dropping them silenced Rule 3 on a genuinely unapproved
#     high-stakes action.
#   * those arms still gated on the ATTRIBUTE PATH, not on an LLM: a Django reverse relation (a
#     survey's `responses.create`) or a Twilio SMS (`messages.create` with `body=`, `to=`) feeding
#     `transfer(...)` emitted a HIGH. The argument gate closes that (#561). Sharing the shape also
#     ends the disagreement with `llm_input_size_cap`, whose own copy had three arms and a prefix
#     (`\b\w+\.`) that only looked stricter.
#
# The call shapes in these comments are written WITHOUT their receivers and parentheses. That was a
# workaround for `llm_input_size_cap` reading raw source, fixed in #563. It is kept because other
# guards that still read comments raw (#424) may match the full call shape.
_LLM_RESULT_VAR = re.compile(
    r"(\w+)\s*=\s*(?:"
    r"[\w.]+\.(?:invoke|generate|complete|ainvoke)\s*\("
    r"|(?P<create>[\w.]*\.create\s*\()"
    r")",
    re.IGNORECASE,
)


def _llm_result_assignment(line: str) -> re.Match[str] | None:
    """The leftmost LLM result assignment on `line`, as a `_LLM_RESULT_VAR` match.

    A `create` match counts only when its method path is the SDK shape. A `.create(` on any other
    path (`stripe.PaymentIntent.create`, `Order.objects.create`) is not an LLM result, and the
    search resumes after it, so a later assignment on the same line is still found."""
    pos = 0
    while (m := _LLM_RESULT_VAR.search(line, pos)) is not None:
        if m.group("create") is None or LLM_SDK_CREATE.search(line, m.start("create"), m.end("create")):
            return m
        pos = m.end()
    return None


def _code_rows(text: str, f: Path) -> tuple[str, list[str], list[int]]:
    """`router_code_view(text)` as (the view, its rows, each row's start offset in the view).

    The view blanks comments and literal text and keeps the source's rows and columns, so Rule 3's
    raw `(line, column)` of a candidate addresses the same `(` in it."""
    view = router_code_view(text, filename=f)
    rows = view.splitlines()
    return view, rows, [0, *accumulate(len(row) + 1 for row in rows)]


def _sdk_create_confirmed(code: tuple[str, list[str], list[int]], line: str, i: int, col: int) -> bool:
    """Is the SDK-shaped `.create(` whose `(` sits at `line[col]` (row `i`) a real SDK call (#561)?

    The argument walk reads the code view, from that `(` to wherever the call closes, so a call split
    over several lines is judged on all of its arguments, and a `#` comment inside it cannot throw the
    walk off: a numbered note's `)` (`# 1) ...`) read raw would close the call before its `model=`.
    A `(` the view blanked means the candidate itself sits in a comment or a docstring. Rule 3 has
    always matched those raw (#1040), so it is judged on its own raw line, never waved through. A call
    that continues past that line does not split, and the gate fails open on it, as before."""
    view, rows, starts = code
    if i < len(rows) and rows[i][col : col + 1] == "(":
        return is_llm_sdk_create_call(view, starts[i] + col)
    return is_llm_sdk_create_call(line, col)


# High-stakes actions that should require human approval.
_HIGH_STAKES_ACTIONS = re.compile(
    r"\b(?:transfer|payment|charge|withdraw|debit|credit|delete_account|"
    r"change_password|reset_credentials|grant_access|revoke_access)\s*\(",
    re.IGNORECASE,
)

# Approval/confirmation patterns that indicate HITL is present.
_APPROVAL_PATTERNS = re.compile(
    r"\b(?:confirm|approve|mfa|verify_identity|hitl|require_approval|"
    r"human_review|await_approval|get_confirmation)\b",
    re.IGNORECASE,
)

# FastAPI route or async function decorator.
_ASYNC_OR_ROUTE = re.compile(
    r"(?:@\w+\.(?:post|put|delete|patch|get)\s*\(|async\s+def\s+\w+)",
    re.IGNORECASE,
)

# Window for same-function detection (number of lines to look ahead/back).
_CONTEXT_WINDOW = 30

# --- RULE 4: Guardrail scan result ignored (scan-and-ignore) -----------------

# llm-guard's `scan_prompt`/`scan_output` (or a module-qualified `llm_guard.scan_prompt(`)
# return a 3-tuple: (sanitized_text, is_valid_map, risk_scores). Assigned form: capture the
# tuple-unpack target names before `=`.
_SCAN_CALL_ASSIGN = re.compile(
    r"^\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*){0,3})\s*=\s*(?:[\w.]+\.)?scan_(?:prompt|output)\s*\(",
)

# Bare call: the scan is invoked but nothing at all captures its return value.
_SCAN_CALL_BARE = re.compile(
    r"^\s*(?:[\w.]+\.)?scan_(?:prompt|output)\s*\(",
)

_SCAN_RESULT_WINDOW = 15

# --- RULES 5-9: NeMo Guardrails config.yml misconfiguration patterns ---------
# Regex text-scans, not a real YAML parse (no pyyaml in the guard sandbox, G2) — same
# text-heuristic approach this codebase already uses for other config formats
# (vite_sourcemap_prod.py). All gated on `_NEMO_CONFIG_NAMES` + a genuine top-level
# `rails:` key, so an unrelated config.yml (e.g. a different tool's config) is never mistaken
# for a NeMo Guardrails config.

_NEMO_CONFIG_NAMES = ("config.yml", "config.yaml")

# A real NeMo config: a top-level `rails:` key (column 0) — distinctive enough that an
# unrelated config.yml is very unlikely to coincidentally match.
_NEMO_RAILS_BLOCK = re.compile(r"^rails:\s*$", re.MULTILINE)
# Proves the rails are actually wired to something (not an empty/stub `rails:` block) —
# an `input:`/`output:`/`dialog:` sub-key followed eventually by a `flows:` list.
_NEMO_ACTIVE_FLOWS = re.compile(r"^\s+flows:\s*$", re.MULTILINE)

# Rule 5: injection_detection rail.
_NEMO_INJECTION_DETECTION = re.compile(r"\binjection_detection\b")

# Rule 6: self-check flows vs. a dedicated content-safety-class model. Deliberately does
# NOT include gliner/presidio/privateai — those are PII detectors, a different concern
# from jailbreak/harmful-content self-check (would otherwise let a PII-only config falsely
# satisfy "has a dedicated safety model").
_NEMO_SELF_CHECK_FLOW = re.compile(r"-\s*self check (?:input|output)\b")
_NEMO_CONTENT_SAFETY_RAIL = re.compile(
    r"\bcontent[_-]?safety\b|\btopic[_-]?safety\b|llama[_-]?guard|\bshieldgemma\b"
    r"|\bnemotron\b|\bactivefence\b|\bpolicyai\b|\balignscore\b",
    re.IGNORECASE,
)

# Rule 7: tool-call/tool-result validation rails vs. the IORails engine wiring (checked
# across the whole project's .py files, not just the config file itself).
_NEMO_TOOL_RAIL_FLOW = re.compile(r"\btool (?:call|result) validation\b")
_IORAILS_WIRING = re.compile(r"\brequire_iorails\b|\bIORails\b")

# Rule 8: jailbreak heuristics vs. an external server endpoint.
_NEMO_JAILBREAK_HEURISTICS = re.compile(r"-\s*jailbreak detection heuristics\b")
_NEMO_SERVER_ENDPOINT = re.compile(r"\bserver_endpoint\s*:")

# Rule 9: PII/sensitive-data masking on input only.
_NEMO_PII_BLOCK = re.compile(r"\bgliner\s*:|\bpresidio\b|\bprivateai\s*:|\bsensitive_data_detection\s*:")
_NEMO_PII_INPUT_FLOW = re.compile(r"(?:mask|detect)\s+(?:sensitive data|pii)\s+on\s+input", re.IGNORECASE)
_NEMO_PII_OUTPUT_FLOW = re.compile(r"(?:mask|detect)\s+(?:sensitive data|pii)\s+on\s+output", re.IGNORECASE)


def _has_llama_guard_reference(text: str) -> bool:
    """True when a line both names Llama Guard and shows a call shape that loads/invokes a
    model — see the comment above `_LLAMA_GUARD_REFERENCE`/`_LLAMA_GUARD_LOADED` for why this
    is a per-line co-occurrence check, not a whole-text substring search.

    Comment-stripped (#692 review, H2): the docstring's own claim — that requiring both the
    name and a call shape on the same line stops a bare comment mention from wrongly
    suppressing Rule 1 — was not actually true, because a `#`-comment naming Llama Guard AND
    describing a `from_pretrained(...)` call in prose satisfies both patterns without a single
    line of real code. A triple-quoted-string mention (docstring form) is a known residual
    gap not covered by this fix — `strip_python_line_comment` only handles `#`."""
    for raw_line in text.splitlines():
        line = strip_python_line_comment(raw_line)
        if _LLAMA_GUARD_REFERENCE.search(line) and _LLAMA_GUARD_LOADED.search(line):
            return True
    return False


class GuardrailArchitectureGuard(Guard):
    id = "guardrail-architecture"
    title = "LLM application missing independent guardrail or using circular self-validation"
    area = "AI agent"

    # config/config.yml: a genuine NeMo Guardrails config (top-level `rails:` + active
    # input/output flows) that simultaneously triggers all 5 NeMo misconfiguration rules:
    # self-check flows with no content-safety model (rule 6), tool rails with no IORails
    # wiring anywhere in the canary repo (rule 7), jailbreak heuristics with no
    # server_endpoint (rule 8), PII masking on input only, no output flow (rule 9), and
    # no injection_detection block at all (rule 5). No other canary file references
    # require_iorails/IORails/server_endpoint, so rules 7/8 fire as designed. Named
    # `config.yml` (not e.g. `nemo_config.yml`) to match the guard's file-name filter
    # (`_NEMO_CONFIG_NAMES`) — NeMo's own convention is `config/config.yml`.
    # guardrail_scan.py: scan_prompt(...) called, sanitized text used, but the validity
    # result (results_valid) is never referenced again -> fires
    # guardrail-architecture/scan-result-ignored (MEDIUM). Deliberately has NO
    # guardrail-library import (so it doesn't also feed rule 1's suppression check —
    # the function name alone proves the scan call, no import needed for this rule).
    # guardrail_validator.py: same llm variable used to generate then validate (with a safety
    # keyword in context) -> fires guardrail-architecture/same-model-self-validation (HIGH).
    # Must NOT contain: security: allow-guardrail-architecture (pragma silences the guard).
    # Must NOT contain: nemo_guardrails, guardrails, llm_guard, presidio, rebuff, lakera_guard,
    # protect_ai, pii_safe, detoxify, perspective, moderation (any guardrail import silences
    # the no-external-guardrail rule across the whole project — kept out to let that rule fire
    # only on this plant; the canary has no other guardrail import in any file).
    # guardrail_validator.py: same `llm` variable used to generate then check safety ->
    # same-model-self-validation (HIGH). The canary has no guardrail library import in any
    # file, so no-external-guardrail (MEDIUM) also fires from this plant; both rules are
    # expected. guardrail_scan.py: scan_prompt(...) called, validity result never
    # referenced again -> scan-result-ignored (MEDIUM). All three are declared in
    # EXPECTED_RULES (the canary liveness test checks that at least the expected rules
    # fire — additional rules, e.g. high-stakes-no-approval if it ever co-fires, are OK).
    canary_plant = CanaryPlant(
        files={
            "config/config.yml": (
                "rails:\n"
                "  input:\n"
                "    flows:\n"
                "      - self check input\n"
                "      - jailbreak detection heuristics\n"
                "      - tool result validation\n"
                "      - gliner detect pii on input\n"
                "  output:\n"
                "    flows:\n"
                "      - self check output\n"
                "      - tool call validation\n"
                "  config:\n"
                "    gliner:\n"
                "      threshold: 0.5\n"
                "      input:\n"
                "        entities:\n"
                "          - email\n"
            ),
            "guardrail_scan.py": (
                "def handle_chat(prompt: str) -> str:\n"
                "    scanners = build_scanners()\n"
                "    sanitized_prompt, results_valid, results_score = scan_prompt(scanners, prompt)\n"
                "    return llm_client.invoke(sanitized_prompt)\n"
            ),
            "guardrail_validator.py": (
                "from langchain_openai import ChatOpenAI\n"
                "\n"
                "llm = ChatOpenAI(model='gpt-4o')\n"
                "\n"
                "\n"
                "def safe_answer(user_prompt: str) -> str:\n"
                "    response = llm.invoke(user_prompt)\n"
                "    # check if the response is safe using the same model\n"
                "    safety_check = llm.invoke(f'Is this safe? {response}')\n"
                "    return response if safety_check else ''\n"
            ),
        },
        expects=frozenset({
            "guardrail-architecture/same-model-self-validation",
            "guardrail-architecture/no-external-guardrail",
            "guardrail-architecture/scan-result-ignored",
            "guardrail-architecture/nemo-injection-detection-absent",
            "guardrail-architecture/nemo-self-check-only",
            "guardrail-architecture/nemo-tool-rails-without-iorails",
            "guardrail-architecture/nemo-jailbreak-in-process",
            "guardrail-architecture/nemo-pii-masking-input-only",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        all_files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                all_files.append((f, read(f)))

        nemo_configs: list[tuple[Path, str]] = []
        for f in iter_files_named(root, *_NEMO_CONFIG_NAMES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if _NEMO_RAILS_BLOCK.search(text) and _NEMO_ACTIVE_FLOWS.search(text):
                nemo_configs.append((f, text))

        out: list[Finding] = []
        out += self._check_no_external_guardrail(root, all_files)
        out += self._check_same_model_self_validation(root, all_files)
        out += self._check_high_stakes_no_approval(root, all_files)
        out += self._check_guardrail_scan_result_ignored(root, all_files)
        out += self._check_nemo_injection_detection_absent(root, nemo_configs)
        out += self._check_nemo_self_check_only(root, nemo_configs)
        out += self._check_nemo_tool_rails_without_iorails(root, nemo_configs, all_files)
        out += self._check_nemo_jailbreak_heuristics_in_process(root, nemo_configs)
        out += self._check_nemo_pii_masking_input_only(root, nemo_configs)

        # Collapse exact duplicates by (rule, location): two LLM-result vars feeding ONE high-stakes
        # call (Rule 3), or two generation sites converging on one validate line (Rule 2), can each
        # qualify and fire at the same line (#351 review). Same rule + same location == same finding.
        seen_keys: set[tuple[str, str]] = set()
        deduped: list[Finding] = []
        for finding in out:
            key = (finding.rule, finding.location)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped.append(finding)
        return deduped

    def _check_no_external_guardrail(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 1 (GUARD-POLICY-001): project imports an LLM generation SDK but no guardrail layer.

        Gated on a real LLM-SDK import (not a bare `.create(`) and cites that import — so the rule
        no longer self-fires on a `stripe.PaymentIntent.create(` / ORM `.create()` (PR #227 review)."""
        # A guardrail import, a moderation-endpoint call, or a directly loaded/invoked Llama
        # Guard model anywhere → the project has a layer; skip.
        for _f, text in files:
            if (
                _GUARDRAIL_IMPORTS.search(text)
                or _GUARDRAIL_CALL.search(text)
                or _has_llama_guard_reference(text)
            ):
                return []

        # Files that import an LLM generation SDK — what makes this an "LLM app".
        sdk_files = [(f, text) for f, text in files if _LLM_SDK_IMPORT.search(text)]
        # Pragma opt-out: scoped to a file that actually uses an LLM SDK (not a mention anywhere).
        if any(pragma_present(_PRAGMA, text, dialect="python") for _f, text in sdk_files):
            return []
        for f, text in sdk_files:
            for i, line in enumerate(text.splitlines(), start=1):
                if _LLM_SDK_IMPORT.search(line):
                    return [Finding(
                            check_id=self.id,
                            severity="medium",
                            title="LLM application has no external guardrail layer",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "This LLM application has no external guardrail layer. "
                                "Relying solely on the LLM's built-in safety training provides "
                                "no structural defense against prompt injection or jailbreaks — "
                                "the model that was attacked is also the one validating its own output."
                            ),
                            remediation=(
                                "Add an independent guardrail: NeMo Guardrails, Guardrails AI, "
                                "LLM Guard, or Presidio for PII. The guardrail must be a separate "
                                "system from the generation model."
                            ),
                            rule="guardrail-architecture/no-external-guardrail",
                            standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"],
                        )]

        return []

    def _check_same_model_self_validation(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 2 (GUARD-DUAL-001): same LLM model variable used to generate and then validate."""
        findings: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue

            lines = text.splitlines()
            for i, line in enumerate(lines):
                m = _LLM_GENERATION_ASSIGN.search(line)
                if not m:
                    continue

                # group 1 = the generation RESULT var; group 2 = the model/client var.
                result_var = m.group(1)
                model_var = m.group(2)

                # Look in a window of the next _CONTEXT_WINDOW lines for:
                # the SAME model variable being called again as a method target,
                # the FIRST CALL'S RESULT fed into that second call (so it's validating THIS output,
                # not just an unrelated sequential generation), AND a safety/eval keyword nearby.
                window_end = min(i + _CONTEXT_WINDOW + 1, len(lines))
                window = lines[i + 1 : window_end]

                for j, ctx_line in enumerate(window):
                    # Check if the same MODEL variable is re-invoked (as the callee, not just mentioned).
                    # Pattern: `model_var.invoke(` or `model_var.generate(` etc.
                    if not re.search(
                        r"\b" + re.escape(model_var) + r"\s*\.(invoke|generate|complete|ainvoke)\s*\(",
                        ctx_line,
                        re.IGNORECASE,
                    ):
                        continue

                    # The generation result must flow INTO this second call — otherwise it's just a
                    # benign multi-step pipeline reusing one client (PR #227 review FP fix).
                    if not re.search(r"\b" + re.escape(result_var) + r"\b", ctx_line):
                        continue

                    # Also require a safety/eval keyword somewhere in that line's context.
                    ctx_start = max(0, j - 2)
                    ctx_end = min(len(window), j + 3)
                    local_ctx = "\n".join(window[ctx_start:ctx_end])

                    if not _SAFETY_EVAL_KEYWORDS.search(local_ctx):
                        continue

                    lineno = i + 1 + j + 1  # 1-based
                    findings.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Same LLM instance used to generate and validate its own output",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "The same LLM instance is used to both generate output and validate "
                            "its own safety. This is circular: a successful jailbreak of the "
                            "generator also compromises the validator. The validation provides "
                            "false security assurance."
                        ),
                        remediation=(
                            "Use an independent model for safety validation — a different model "
                            "class, a fine-tuned safety model, or a rules-based guardrail. The "
                            "validator must be architecturally separate from the generator."
                        ),
                        rule="guardrail-architecture/same-model-self-validation",
                        standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"],
                    ))
                    break  # one finding per generation site; scan the remaining sites/files

        return findings

    def _check_high_stakes_no_approval(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 3 (GUARD-HITL-002): high-stakes action triggered by LLM result without approval gate."""
        findings: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue

            lines = text.splitlines()
            code: tuple[str, list[str], list[int]] | None = None  # built for the first SDK-shaped candidate

            # Find each LLM result assignment.
            for i, line in enumerate(lines):
                m = _llm_result_assignment(line)
                if not m:
                    continue
                if m.group("create") is not None:
                    code = code or _code_rows(text, f)
                    if not _sdk_create_confirmed(code, line, i, m.end("create") - 1):
                        continue

                result_var = m.group(1)

                # Look in the next _CONTEXT_WINDOW lines for a high-stakes action.
                window_end = min(i + _CONTEXT_WINDOW + 1, len(lines))
                window_lines = lines[i + 1 : window_end]
                window_text = "\n".join(window_lines)

                # Check if there's a high-stakes action that uses the result variable.
                hs_match = _HIGH_STAKES_ACTIONS.search(window_text)
                if not hs_match:
                    continue

                # Confirm the result variable is actually passed to the high-stakes action.
                # Only match at the character level: the result variable must appear
                # on the SAME line as the high-stakes function call (single-line argument
                # check). This avoids matching subsequent return/log statements that happen
                # to reference the same variable.
                hs_line_idx = window_text[: hs_match.start()].count("\n")
                hs_line = window_lines[hs_line_idx] if hs_line_idx < len(window_lines) else ""

                if result_var not in hs_line:
                    continue

                # Check if an approval pattern appears anywhere in the same window.
                if _APPROVAL_PATTERNS.search(window_text):
                    continue

                # Also check a few lines BEFORE the LLM call for approval patterns.
                pre_start = max(0, i - 10)
                pre_text = "\n".join(lines[pre_start:i])
                if _APPROVAL_PATTERNS.search(pre_text):
                    continue

                lineno = i + 1 + hs_line_idx + 1
                findings.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="High-stakes action triggered by LLM output without human approval gate",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "An LLM-generated result is used to trigger a high-stakes action "
                        "(payment, transfer, credential change, or account deletion) without "
                        "any human-in-the-loop confirmation. If the LLM output is influenced "
                        "by a prompt injection attack, the attacker can trigger these actions "
                        "autonomously without user awareness or consent."
                    ),
                    remediation=(
                        "Add an explicit approval gate before any high-stakes action driven by "
                        "LLM output: MFA re-verification, an explicit user confirmation step, "
                        "or a human-review queue (HITL). Never let LLM output directly authorize "
                        "financial or privileged operations without independent verification."
                    ),
                    rule="guardrail-architecture/high-stakes-no-approval",
                    standards=["OWASP-LLM:LLM06", "OWASP:A05"],  # Excessive Agency
                ))

        return findings

    def _check_guardrail_scan_result_ignored(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 4 (GUARD-SCAN-IGNORED): a guardrail scan is called but its validity result
        is discarded or never referenced again — the scan runs, nothing enforces it."""
        findings: list[Finding] = []
        for f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue

            lines = text.splitlines()
            for i, line in enumerate(lines):
                assign_m = _SCAN_CALL_ASSIGN.match(line)
                if assign_m:
                    names = [n.strip() for n in assign_m.group(1).split(",")]
                    # The validity dict is conventionally the 2nd unpacked name; if the
                    # developer used a different arity, check every captured name instead.
                    # `_` placeholders are throwaways, never a real downstream reference — strip
                    # them so `_ = scan(...)` or `sanitized, _ = scan(...)` still fires (the scan's
                    # result is discarded, not enforced) instead of matching a stray `_` in the window.
                    candidates = [n for n in (names[1:] if len(names) > 1 else names) if n != "_"]
                    window_end = min(i + 1 + _SCAN_RESULT_WINDOW, len(lines))
                    window = "\n".join(lines[i + 1 : window_end])
                    if any(re.search(r"\b" + re.escape(n) + r"\b", window) for n in candidates):
                        continue  # the validity result IS referenced again downstream

                    lineno = i + 1
                    findings.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Guardrail scan result captured but never checked",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A guardrail scan (scan_prompt/scan_output) is called and its "
                            "validity result is captured in a variable, but that variable "
                            "is never referenced again — the scan runs, but nothing gates "
                            "on its outcome. A flagged prompt or response still proceeds."
                        ),
                        remediation=(
                            "Check the returned validity result before proceeding, e.g. "
                            "`if not all(results_valid.values()): reject()`. Scanning "
                            "without enforcing the result provides no real protection."
                        ),
                        rule="guardrail-architecture/scan-result-ignored",
                        standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "NIST:MANAGE"],
                    ))
                    continue

                if _SCAN_CALL_BARE.match(line):
                    lineno = i + 1
                    findings.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Guardrail scan called but its result is fully discarded",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A guardrail scan (scan_prompt/scan_output) is invoked as a "
                            "bare statement — its sanitized text AND validity result are "
                            "both discarded. The original, unscanned prompt or output is "
                            "what actually continues through the application."
                        ),
                        remediation=(
                            "Capture and use the scan's return value: `sanitized_prompt, "
                            "results_valid, scores = scan_prompt(scanners, prompt)`, then "
                            "send `sanitized_prompt` onward and gate on `results_valid`."
                        ),
                        rule="guardrail-architecture/scan-result-discarded",
                        standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "NIST:MANAGE"],
                    ))

        return findings

    def _check_nemo_injection_detection_absent(
        self, root: Path, nemo_configs: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 5 (GUARD-NEMO-NOINJ): NeMo config has active rails but no injection_detection."""
        out: list[Finding] = []
        for f, text in nemo_configs:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if _NEMO_INJECTION_DETECTION.search(text):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="NeMo Guardrails config has no injection_detection rail configured",
                location=rel(root, f),
                message=(
                    "This NeMo Guardrails config has active input/output rails but no "
                    "`injection_detection` block. NeMo's YARA-based injection detection is "
                    "opt-in and disabled by default — without it, code/SQL/XSS/template/command "
                    "injection payloads pass through unchecked by this rail."
                ),
                remediation=(
                    "Add an `injection_detection` block under `rails.config` naming the "
                    "relevant rule types for your deployment context (code injection for "
                    "interpreters, SQL for databases, XSS for HTML rendering), and an "
                    "`injection detection` output flow to activate it."
                ),
                rule="guardrail-architecture/nemo-injection-detection-absent",
                standards=["OWASP-LLM:LLM01", "OWASP:A05"],
            ))
        return out

    def _check_nemo_self_check_only(
        self, root: Path, nemo_configs: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 6 (GUARD-NEMO-SELFCHECK): self-check flows with no dedicated safety model."""
        out: list[Finding] = []
        for f, text in nemo_configs:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _NEMO_SELF_CHECK_FLOW.search(text):
                continue
            if _NEMO_CONTENT_SAFETY_RAIL.search(text):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="NeMo Guardrails relies solely on self-check, no dedicated safety model",
                location=rel(root, f),
                message=(
                    "This config enables `self check input`/`self check output` with no "
                    "dedicated content-safety model (Llama Guard, Nemotron Content Safety, "
                    "ShieldGemma, etc.) also configured. NeMo's own docs state self-check's "
                    "reliability depends entirely on the generator LLM correctly following its "
                    "own safety instructions — the same LLM an attacker's jailbreak targets."
                ),
                remediation=(
                    "Add a dedicated content-safety model rail alongside self-check, per "
                    "NVIDIA's own recommendation: \"If your LLM does not reliably follow this "
                    "prompt, consider a purpose-built input safety model instead.\""
                ),
                rule="guardrail-architecture/nemo-self-check-only",
                standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"],
            ))
        return out

    def _check_nemo_tool_rails_without_iorails(
        self,
        root: Path,
        nemo_configs: list[tuple[Path, str]],
        all_files: list[tuple[Path, str]],
    ) -> list[Finding]:
        """RULE 7 (GUARD-NEMO-IORAILS): tool rails declared but IORails engine never wired."""
        out: list[Finding] = []
        iorails_wired = any(_IORAILS_WIRING.search(text) for _f, text in all_files)
        if iorails_wired:
            return out
        for f, text in nemo_configs:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _NEMO_TOOL_RAIL_FLOW.search(text):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title="NeMo tool-call rails declared without the IORails engine wired",
                location=rel(root, f),
                message=(
                    "This config declares `tool call validation`/`tool result validation` "
                    "rails, but no file in the project references `require_iorails`/`IORails`. "
                    "Tool rails only run on NeMo's opt-in IORails engine — the default LLMRails "
                    "engine silently ignores them. NeMo's own docs warn that a misdirected, "
                    "unknown, or duplicated tool flow name makes the whole config ineligible "
                    "for IORails, and the facade falls back to LLMRails with only a log "
                    "warning — tool calls then execute with no validation at all."
                ),
                remediation=(
                    "Confirm the app explicitly constructs the IORails engine "
                    "(`require_iorails=True` or the equivalent constructor) and that every "
                    "declared tool flow name matches exactly — a single typo silently disables "
                    "all tool-call validation."
                ),
                rule="guardrail-architecture/nemo-tool-rails-without-iorails",
                standards=["OWASP-LLM:LLM06", "OWASP:A05"],
            ))
        return out

    def _check_nemo_jailbreak_heuristics_in_process(
        self, root: Path, nemo_configs: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 8 (GUARD-NEMO-JAILBREAK): jailbreak heuristics run in-process, no server_endpoint."""
        out: list[Finding] = []
        for f, text in nemo_configs:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _NEMO_JAILBREAK_HEURISTICS.search(text):
                continue
            if _NEMO_SERVER_ENDPOINT.search(text):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="NeMo jailbreak detection heuristics run in-process",
                location=rel(root, f),
                message=(
                    "This config enables `jailbreak detection heuristics` with no "
                    "`server_endpoint` configured, meaning the heuristics run in-process. "
                    "NeMo's own docs mark in-process heuristics \"TESTING PURPOSES ONLY\" and "
                    "\"NOT RECOMMENDED FOR PRODUCTION DEPLOYMENTS,\" recommending a separately "
                    "deployed detection server instead."
                ),
                remediation=(
                    "Deploy the jailbreak detection heuristics server separately and point "
                    "the config at it via `server_endpoint`, per NVIDIA's own production "
                    "guidance — or accept the reduced detection rate the in-process heuristics "
                    "document (documented false-positive/false-negative trade-offs) as a "
                    "deliberate choice."
                ),
                rule="guardrail-architecture/nemo-jailbreak-in-process",
                standards=["OWASP-LLM:LLM01", "OWASP:A05"],
            ))
        return out

    def _check_nemo_pii_masking_input_only(
        self, root: Path, nemo_configs: list[tuple[Path, str]]
    ) -> list[Finding]:
        """RULE 9 (GUARD-NEMO-PII-PARTIAL): PII masking configured for input only."""
        out: list[Finding] = []
        for f, text in nemo_configs:
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            if not _NEMO_PII_BLOCK.search(text):
                continue
            if not _NEMO_PII_INPUT_FLOW.search(text):
                continue
            if _NEMO_PII_OUTPUT_FLOW.search(text):
                continue
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title="NeMo PII masking configured for input only",
                location=rel(root, f),
                message=(
                    "This config masks PII on the input flow but has no matching `output` "
                    "flow for the same PII/sensitive-data rail. PII the input side would have "
                    "caught can still leak back out through the bot's own response or "
                    "RAG-retrieved chunks — masking only one direction of a two-way "
                    "conversation protects half of it."
                ),
                remediation=(
                    "Add the matching `output` (and `retrieval`, for RAG stacks) flow for the "
                    "same PII rail — e.g. `gliner mask pii on output` alongside "
                    "`gliner mask pii on input` — so both directions are covered."
                ),
                rule="guardrail-architecture/nemo-pii-masking-input-only",
                standards=["OWASP-LLM:LLM02", "OWASP:A05"],
            ))
        return out
