"""Guard: PII sent into an LLM prompt and the model's result returned to the client
with no redaction layer anywhere in between (checklist §4, new item).

A common LLM-app mistake: user PII (email, SSN, credit card, phone, date of birth,
passport, bank account) is interpolated directly into a prompt so the model can act on
it, and the model's response is then returned straight to the client. Two related risks
compound:

1. The PII is transmitted to the model provider, stored in conversation history, and
   visible in observability tooling — the same transmission-surface risk documented for
   `env-secret-in-prompt`, but for personal data rather than credentials.
2. Because the model saw the PII, it can echo it back — verbatim or reformatted — in its
   response. If nothing redacts the response before it reaches the client, a bug, a
   misrouted request, or a prompt-injection-influenced answer can leak that PII to the
   wrong party.

This is exactly the gap llm-guard's `Anonymize` (input) / `Deanonymize` (output) scanner
pair is designed to close — scrub before send, unmask only for the authorized caller.
Agentsec cannot verify semantic correctness of a redaction step, but it CAN verify one is
present anywhere in the round-trip.

One statically detectable pattern:

  **`pii-roundtrip-no-redaction`** (MEDIUM): within the same function, a PII-shaped
  variable name (`email`, `ssn`, `credit_card`, `card_number`, `phone_number`,
  `date_of_birth`, `passport_number`, `bank_account`, `routing_number`, …) appears in an
  f-string/concatenation that flows into an LLM generation call
  (`.invoke`/`.generate`/`.chat`/`.create`/`.complete`), and that call's result flows into
  a `return`/`Response(`/`JSONResponse(` — with no `anonymize`/`redact`/`scrub`/`mask`/
  `presidio`/`pseudonymize` call anywhere between the two.

**False-negative scope:** Single-file, windowed detection — PII interpolated in one
function and returned from a different one (or a different file) is not caught. Variable
names outside the recognized PII list (e.g. a custom `client_ssn_value`) are missed
unless they contain one of the listed substrings.

Suppress an audited pattern with the inline pragma:

    prompt = f"Patient SSN: {ssn}"  # security: allow-pii-llm-roundtrip
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

_PRAGMA = "security: allow-pii-llm-roundtrip"

_STANDARDS = ["OWASP-LLM:LLM02", "OWASP:A01"]

# A PII-shaped name. The token must start a sub-word (preceded by start-of-word or `_`), so
# `email`/`user_email`/`email_address` match but `voicemail_transcript` does NOT — the review's FP
# was `email` matching inside `voic-email`. The `(?<![A-Za-z0-9])` lookbehind enforces that.
_PII_NAME = re.compile(
    r"(?<![A-Za-z0-9])(?:email|ssn|social_security|credit_card|card_number|cvv|phone_number|"
    r"date_of_birth|passport_number|drivers_license|bank_account|routing_number)",
    re.IGNORECASE,
)

# An f-string or concatenation — signals a prompt-building line rather than a bare
# variable reference or a comment mentioning the same word.
_FSTRING_OR_CONCAT = re.compile(r"""\bf['"]|['"]\s*\+|\+\s*['"]|\.format\s*\(""")

# An LLM-SDK import — used ONLY to disambiguate the overloaded `.create(` below (see _LLM_CREATE).
_LLM_SDK_IMPORT = re.compile(
    r"(?:from|import)\s+(?:"
    r"openai|anthropic|langchain\w*|llama_index|llama_cpp|litellm|cohere|mistralai|groq|ollama"
    r"|google\.generativeai|google\.genai|vertexai|together|replicate|transformers|vllm|huggingface_hub"
    r")\b",
    re.IGNORECASE,
)

# Unambiguous LLM-framework generation methods — these always count as an LLM call (langchain/
# pydantic-ai/etc. `.invoke`, not used by stripe/ORM/boto3, so no gate needed).
_LLM_CALL = re.compile(
    r"\.\s*(?:invoke|generate|complete|chat|ainvoke)\s*\(",
    re.IGNORECASE,
)

# `.create(` is OpenAI's generation method BUT also stripe.PaymentIntent.create / ORM
# `.objects.create()` / boto3 — so it counts as an LLM call only when the file imports an LLM SDK.
_LLM_CREATE = re.compile(r"\.\s*create\s*\(", re.IGNORECASE)

_RETURN_TO_CLIENT = re.compile(
    r"\breturn\b|\bResponse\s*\(|\bJSONResponse\s*\(|\bStreamingResponse\s*\(",
    re.IGNORECASE,
)

_REDACT_CALL = re.compile(
    r"\b(?:anonymiz\w*|redact\w*|scrub\w*|mask\w*|presidio\w*|pseudonymiz\w*)\b",
    re.IGNORECASE,
)

# How far past the PII line to look for the LLM call, and past the LLM call to look
# for the return-to-client. Kept modest — this is a same-function heuristic.
_LLM_CALL_WINDOW = 15
_RETURN_WINDOW = 20


class PiiLlmRoundtripGuard(Guard):
    id = "pii-llm-roundtrip"
    title = "PII sent to an LLM and the response returned to the client with no redaction layer"
    area = "AI agent"

    # pii_roundtrip.py: SSN interpolated into a prompt, sent to an LLM, response returned
    # to the client with no redaction call anywhere -> fires
    # pii-llm-roundtrip/no-redaction (MEDIUM). No logging call on `ssn` (would be a
    # different guard's concern) and no guardrail-library import (keeps this isolated
    # to its own rule).
    canary_plant = CanaryPlant(
        files={
            "pii_roundtrip.py": (
                "def handle_support_request(request) -> dict:\n"
                "    ssn = request.ssn\n"
                "    prompt = f'Verify this customer SSN: {ssn}'\n"
                "    response = llm_client.invoke(prompt)\n"
                "    return {'answer': response}\n"
            ),
        },
        expects=frozenset({"pii-llm-roundtrip/no-redaction"}),
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
                # `.create(` counts as an LLM call only when the file imports an LLM SDK.
                has_sdk = bool(_LLM_SDK_IMPORT.search(text))

                lines = text.splitlines()
                # One finding per return site — multiple PII lines feeding the same
                # round-trip shouldn't emit duplicate findings at the same location.
                reported_returns: set[int] = set()
                for i, line in enumerate(lines):
                    if not (_PII_NAME.search(line) and _FSTRING_OR_CONCAT.search(line)):
                        continue

                    # Both windows include their anchor line: the PII line may itself be the
                    # LLM call, and the LLM-call line may itself be the return
                    # (`return llm.invoke(prompt)`). The end bounds are unchanged.
                    llm_search_end = min(i + 1 + _LLM_CALL_WINDOW, len(lines))
                    llm_window = lines[i : llm_search_end]
                    llm_idx = next(
                        (
                            j for j, wl in enumerate(llm_window)
                            if _LLM_CALL.search(wl) or (has_sdk and _LLM_CREATE.search(wl))
                        ),
                        None,
                    )
                    if llm_idx is None:
                        continue
                    llm_line_idx = i + llm_idx  # actual index in `lines` of the LLM call

                    ret_search_end = min(llm_line_idx + 1 + _RETURN_WINDOW, len(lines))
                    ret_window = lines[llm_line_idx : ret_search_end]
                    ret_idx = next(
                        (k for k, wl in enumerate(ret_window) if _RETURN_TO_CLIENT.search(wl)),
                        None,
                    )
                    if ret_idx is None:
                        continue
                    ret_line_idx = llm_line_idx + ret_idx

                    # No redaction call anywhere between the PII line and the return line.
                    full_span = "\n".join(lines[i : ret_line_idx + 1])
                    if _REDACT_CALL.search(full_span):
                        continue

                    if ret_line_idx in reported_returns:
                        continue
                    reported_returns.add(ret_line_idx)

                    lineno = ret_line_idx + 1
                    findings.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title="PII sent to an LLM and the response returned to the client "
                              "with no redaction layer",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A PII-shaped value flows into an LLM prompt, and that call's "
                            "result is returned to the client — with no anonymization or "
                            "redaction call anywhere in between. The PII is transmitted to "
                            "the model provider, and nothing prevents the model from "
                            "echoing it back in a response that reaches the wrong caller."
                        ),
                        remediation=(
                            "Anonymize PII before it enters the prompt (e.g. llm-guard's "
                            "Anonymize scanner or Presidio) and only unmask it for the "
                            "authorized caller after the response is validated."
                        ),
                        rule="pii-llm-roundtrip/no-redaction",
                        standards=_STANDARDS,
                    ))

        return findings
