---
type: Guard
title: "pii-llm-roundtrip"
description: "PII sent to an LLM and the response returned to the client with no redaction layer."
timestamp: "2026-07-01T17:32:52+08:00"
guard_id: "pii-llm-roundtrip"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02", "OWASP:A01"]
---

# PII sent to an LLM and the response returned to the client with no redaction layer

_Author — 2026-07-01_

---

## The threat

An attacker doesn't need to compromise anything to exploit this — it's a structural gap.
An LLM application takes a PII field straight from the caller (SSN, email, credit card,
phone, date of birth, passport/bank/routing number), interpolates it into a prompt so the
model can act on it, and returns the model's response straight to the client. Two risks
compound: (1) the PII is transmitted to the model provider and stored in conversation
history, chat logs, and LLM-observability dashboards — the same surface risk as
`env-secret-in-prompt`, but for personal data rather than credentials; (2) because the
model saw the PII, nothing stops it from echoing that PII back — verbatim, reformatted,
or attached to the wrong response — if a bug, a misrouted session, or a prompt-injection-
influenced answer causes the response to reach an unintended party. OWASP-LLM:LLM02
(Sensitive Information Disclosure), OWASP:A01 (Broken Access Control — PII crossing a
trust boundary with no gate).

## Why it's often introduced

Developers wire PII into a prompt to let the model do something useful with it (verify an
identity, summarize a support ticket, draft a response) and then return the model's
answer directly — the redaction step nobody adds because "the model already has this
data legitimately, so what's exposed?":

```python
def handle(request):
    ssn = request.ssn
    prompt = f"Verify this customer's identity: SSN {ssn}, name {request.name}"
    response = llm.invoke(prompt)
    return response          # nothing scrubs the model's reply before this
```

This is exactly the gap llm-guard's `Anonymize` (input) / `Deanonymize` (output) scanner
pair — and Presidio underneath it — exist to close: scrub PII before it enters the
prompt, only unmask it for the authorized caller after the response comes back.

## Detection design

1. **applies() gate:** `"llm" in profile.features` — only runs for detected LLM stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`no-redaction`, MEDIUM), same-file windowed check:**
   - Anchor: a line matching `_PII_NAME` (a PII token at a sub-word boundary — `email`,
     `ssn`, `social_security`, `credit_card`, `card_number`, `cvv`, `phone_number`,
     `date_of_birth`, `passport_number`, `drivers_license`, `bank_account`,
     `routing_number`; the `(?<![A-Za-z0-9])` lookbehind means `user_email` matches but
     `voicemail_transcript` does NOT) AND `_FSTRING_OR_CONCAT` (an f-string open quote, string
     concatenation, or `.format(`) on the same line — this is what proves the PII is
     being built into a prompt string, not just referenced or logged.
   - Forward window (15 lines): an LLM generation call. Unambiguous framework methods
     (`.invoke`/`.generate`/`.chat`/`.complete`/`.ainvoke`) always count; the overloaded
     `.create(` counts only when the file imports an LLM SDK (`_LLM_SDK_IMPORT`) — otherwise
     it matches `stripe.PaymentIntent.create()` / ORM / boto3 (the review's reproduced FP).
   - Forward window from the LLM call (20 lines): a return-to-client signal
     (`return`/`Response(`/`JSONResponse(`/`StreamingResponse(`).
   - If both windows resolve, the whole span from the PII line to the return line is
     checked for `_REDACT_CALL` (`anonymiz*`/`redact*`/`scrub*`/`mask*`/`presidio*`/
     `pseudonymiz*`). If absent anywhere in that span → fire.

4. **Inline opt-out pragma:** `# security: allow-pii-llm-roundtrip`

5. **Severity and rule:** `"medium"`, rule `"pii-llm-roundtrip/no-redaction"`, standards
   `["OWASP-LLM:LLM02", "OWASP:A01"]`. Medium (surfacing): PII-detection-by-variable-name is a
   heuristic guess, so it surfaces for review rather than hard-blocking CI at `--fail-on high`.

## When NOT to flag

- Any redaction/anonymization call anywhere between the PII interpolation and the return
  — the guard trusts the call is real and effective, same trust model as
  `guardrail-architecture`'s approval-pattern check.
- PII referenced in a log line or an internal-only path (no LLM call in the forward
  window, or the LLM result never reaches a `return`/`Response(`) — the guard requires
  the full round-trip shape, not just PII's presence.
- A custom PII field name outside the recognized list (e.g. `client_tax_id`) — false
  negative, not a false positive; suppress with the pragma if a different in-house
  redaction pattern is already used and the name list needs extending instead.

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_llm_feature_present` | Guard activates on `llm` feature |
| `test_not_applies_without_llm_feature` | Guard skips non-LLM stacks |
| `test_fires_on_pii_roundtrip_no_redaction` | Fires: SSN f-string → LLM call → `return`, no redaction |
| `test_fires_on_concat_form` | Fires: `+` string concatenation form (not just f-strings) |
| `test_fp_bait_when_redacted_before_return` | Silent: `redact_pii(response)` call present before return |
| `test_fp_bait_no_llm_call` | Silent: PII present but never sent to an LLM |
| `test_fp_bait_result_not_returned_to_client` | Silent: LLM result stored internally, not returned |
| `test_fp_bait_when_pragma_present` | Silent: file-level pragma |

## Known bypasses

- A PII-shaped variable assigned to a plain (non-f-string, non-concatenated) variable
  and passed to a prompt-builder function (`prompt = build_prompt(ssn)`) is not detected
  — the guard requires the PII name and prompt construction on the SAME line.
- PII interpolated in one function and the LLM call/return happening in a different
  function (or file) is not detected — same-file, forward-window-only heuristic.
- A variable name outside the recognized PII list evades detection entirely.
- Any reference to a redaction-shaped word anywhere in the span — including a comment or
  an unrelated variable named `redact_flag` — silences the rule without verifying an
  actual redaction call ran.
- The pragma `# security: allow-pii-llm-roundtrip` silences the rule for the entire file.

## What this guard does NOT prove

- That the redaction/anonymization call actually removes the PII in question (could be a
  no-op stub, or scrub the wrong field).
- That the unmasking step (if using llm-guard's Deanonymize/Vault pattern) only restores
  PII for the authorized original caller.
- That PII doesn't reach the LLM through a different path entirely (a RAG-retrieved
  document, an uploaded file) — this guard only covers direct prompt interpolation.

# Citations

[1] agentsec checklist item `4-pii-redacted-before-llm` (§4)
[2] OWASP-LLM:LLM02
[3] OWASP:A01
