---
type: Guard
title: "guardrail-architecture"
description: "LLM application missing independent guardrail or using circular self-validation."
timestamp: "2026-10-07T12:00:00+08:00"
guard_id: "guardrail-architecture"
checklist_section: ["14", "3c", "4"]
standards: ["NIST:MANAGE", "OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP-LLM:LLM06", "OWASP-LLM:LLM09", "OWASP:A01", "OWASP:A05"]
---

# LLM application missing independent guardrail or using circular self-validation

_Author — 2026-06-28_

---

## The threat

An LLM application without an external guardrail layer, or one that uses the same
model to both generate and validate output, has a structural safety flaw: any
successful jailbreak of the generator also bypasses the "validator." This is not a
configuration mistake but an architectural one — the same system cannot be both the
attacker's target and the defense.

Three concrete attack paths:

1. **GUARD-POLICY-001 (OWASP-LLM:LLM01, LLM02):** An attacker injects a prompt that
   causes the LLM to produce harmful output. With no independent guardrail layer (no
   NeMo Guardrails, LLM Guard, Presidio, etc.), the only safety mechanism is the model's
   own alignment training — which the attacker has already compromised. A secondary
   model call by the same session is equally compromised.

2. **GUARD-DUAL-001 (OWASP-LLM:LLM01):** A developer adds a "safety check" by asking
   the same LLM to evaluate its own output: `is_safe = llm.invoke(f"Is this safe?
   {response}")`. If the attacker has jailbroken `llm`, then `llm.invoke(...)` for the
   safety check is equally jailbroken — the check passes vacuously. The architecture
   creates the illusion of validation while providing none.

3. **GUARD-HITL-002 (OWASP-LLM:LLM06, OWASP:A05):** An LLM output is used to drive a
   payment, fund transfer, account deletion, or credential change without human
   confirmation. A prompt injection attack can embed instructions that cause the LLM to
   output parameters for an unauthorized transaction, which the application then executes
   autonomously.

4. **GUARD-SCAN-IGNORED (OWASP-LLM:LLM01, LLM02):** A real guardrail library (llm-guard,
   etc.) is imported and its scan function is called — but the validity result is
   discarded or never checked before the (possibly still-unsafe) text is used. Rule 1
   only proves a guardrail import exists somewhere in the project; it cannot see whether
   any individual scan call actually enforces its own outcome. `scan_prompt()` /
   `scan_output()` return `(sanitized_text, is_valid_map, risk_scores)` — a bare call
   discards all three; an assigned-but-unchecked call keeps the sanitized text but never
   gates on `is_valid_map`, so a flagged prompt still reaches the model unmodified.

Rules 1-4 prove a guardrail layer exists and is enforced; they cannot see whether that
layer is itself *configured* soundly. Rules 5-9 (added by NeMo Guardrails research, #295)
read NeMo's own `config.yml` for five documented misconfiguration patterns — every claim
below is sourced from NVIDIA's own guardrail-catalog docs, not inferred:

5. **GUARD-NEMO-NOINJ (OWASP-LLM:LLM01, OWASP:A05):** NeMo's YARA-based `injection_detection`
   rail is opt-in and disabled by default. A config with active input/output rails but no
   `injection_detection` block has no defense against the injection classes (code/SQL/XSS/
   template/command) that rail exists to catch.

6. **GUARD-NEMO-SELFCHECK (OWASP-LLM:LLM01/LLM02, OWASP:A05):** NeMo's own docs state
   self-check's reliability "is strongly dependent on the capability of the LLM to follow
   the instructions in the prompt" and explicitly recommend "a purpose-built input safety
   model instead" if the LLM doesn't reliably comply. A config relying only on
   `self check input`/`self check output` — with no dedicated content-safety model
   (Llama Guard, Nemotron Content Safety, ShieldGemma) also configured — depends entirely
   on the same LLM an attacker's jailbreak targets to police its own output.

7. **GUARD-NEMO-IORAILS (OWASP-LLM:LLM06, OWASP:A05):** Tool-call/tool-result validation
   rails only run on NeMo's opt-in `IORails` engine — the default `LLMRails` engine
   silently ignores them. NeMo's docs warn that a misdirected, unknown, or duplicated tool
   flow name "makes the configuration ineligible for IORails," and the facade "silently
   falls back to `LLMRails`... with only a log warning." A config declaring tool rails
   with no `require_iorails`/`IORails` wiring anywhere in the project looks protected but
   the validation never runs — a single typo disables it silently.

8. **GUARD-NEMO-JAILBREAK (OWASP-LLM:LLM01, OWASP:A05):** NeMo's docs mark running
   `jailbreak detection heuristics` in-process as "TESTING PURPOSES ONLY" and "NOT
   RECOMMENDED FOR PRODUCTION DEPLOYMENTS," recommending a separately deployed server
   instead. A config enabling the heuristics flow with no `server_endpoint` configured is
   running the explicitly-not-production-ready in-process mode.

9. **GUARD-NEMO-PII-PARTIAL (OWASP-LLM:LLM02, OWASP:A05):** A PII/sensitive-data rail
   (GLiNER, Presidio, Private AI) masking user input but never configured for the
   `output`/`retrieval` flows lets PII the input side would have caught leak right back
   out through the bot's own response or RAG-retrieved chunks.

---

## Why it's often introduced

In a FastAPI + LLM stack, developers add LLM calls for generation quickly, then add a
"validator" call for safety — but use the same client object. The pattern feels safe
because there are two calls:

```python
response = llm.invoke(user_prompt)
is_safe = llm.invoke(f"Is this response safe? {response}")  # same llm — circular!
```

For high-stakes automation, the pattern is common in agentic systems where an LLM
parses a task description and the application acts on the parsed result:

```python
decision = llm.invoke(task_request)
payment_service.transfer(amount=decision["amount"])  # LLM output drives financial action
```

---

## Detection design

1. **applies() gate:** `"llm" in profile.features` — only runs for detected LLM stacks.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from `python_scan_dirs`.
   Non-product paths (tests, fixtures) are skipped via `is_nonproduct_path`.

3. **Patterns and logic:**

   **Rule 1 (no-external-guardrail):** Project-level check. Scans all `.py` files for
   `_GUARDRAIL_IMPORTS` — a regex matching any `from`/`import` of `nemo_guardrails`,
   `guardrails`, `llm_guard`, `presidio_analyzer`, `presidio_anonymizer`, `rebuff`,
   `lakera_guard`, `protect_ai`, `pii_safe`, `detoxify`, `perspective`, `moderation`,
   `openai.moderation`, `anthropic.*moderation`, or `azure.ai.contentsafety`. If any
   file has such an import — OR a moderation-endpoint call (`_GUARDRAIL_CALL`:
   `.moderations.create(`) — OR a directly loaded/invoked Llama Guard model
   (`_has_llama_guard_reference`, see below) — the rule is suppressed. **Gated on a
   real LLM-SDK import** (`_LLM_SDK_IMPORT`: openai/anthropic/langchain*/litellm/cohere/
   google.generativeai/…), NOT a bare `.create(` — the old `.create(` gate self-fired on
   `stripe.PaymentIntent.create(` / ORM `.objects.create()` (PR #227 review). One finding
   per project, citing the first LLM-SDK import; the pragma opt-out is scoped to a file
   that actually imports an LLM SDK.

   **Rule 1, Llama Guard signal (`_has_llama_guard_reference`):** The checklist item this
   guard feeds (`14-guardrail-layer-present`) names Llama Guard by name, alongside NeMo
   Guardrails, as a valid guardrail layer — but before this addition, nothing outside the
   NeMo-config-only Rule 6 recognized it, so a project running Llama Guard directly (HF
   transformers, or a hosted-inference call) got a false "no guardrail" MEDIUM. Fires when
   a single line both names Llama Guard (`_LLAMA_GUARD_REFERENCE`: `llama[-_]?guard`,
   case-insensitive) AND shows a call shape that actually loads or invokes a model
   (`_LLAMA_GUARD_LOADED`: `.from_pretrained(`, `AutoModelForCausalLM`, `AutoTokenizer`, or
   one of the already-recognized LLM generation call shapes — `.chat.completions.create(`,
   `.messages.create(`, `.invoke(`, `.generate(`). Deliberately a **same-line co-occurrence
   check, not a project-wide substring search** — a bare `llama[-_]?guard` match anywhere
   would also fire on a comment, docstring, or dead/commented-out reference that never
   actually runs, wrongly suppressing Rule 1 (see "Known bypasses").

   **Rule 2 (same-model-self-validation):** Per-file, per-function. Finds a variable
   assigned from an LLM call (`_LLM_GENERATION_ASSIGN`), then within `_CONTEXT_WINDOW`
   (30) lines looks for the same model variable called again **with the first call's RESULT
   fed into it** (so it's validating *that* output, not just a benign sequential generation —
   PR #227 review) AND a safety/evaluation keyword
   (`judge|eval|check|safe|moderate|review|validate|guard`) in the surrounding context.

   **Rule 3 (high-stakes-no-approval):** Per-file. Finds an LLM result variable, then
   within 30 lines looks for a high-stakes action call that includes the result variable.
   Checks if any approval pattern (`confirm|approve|mfa|verify_identity|hitl|
   require_approval|human_review`) appears in the same window or in the 10 lines
   preceding the LLM call. Reports every qualifying site (#280); `run()` collapses exact
   `(rule, location)` duplicates, so two LLM results feeding one call report once.

   An LLM result is assigned from either a direct method call (`llm.invoke(...)`, or
   `generate`/`complete`/`ainvoke`, on any receiver) or an OpenAI/Anthropic SDK `create`. The
   `create` shape is the shared `base.LLM_SDK_CREATE` (a `.chat.completions` / `.completions` /
   `.responses` / `.messages` path, then `.create(`), and it counts only when
   `base.is_llm_sdk_create_call` confirms a top-level argument is `model=`, `messages=`,
   `prompt=`, `extra_body=` or a `**` spread (#561). The method path is shared by non-LLM APIs:
   `survey.responses.create(answer=q)` (a Django reverse relation) and a Twilio
   `client.messages.create(body=q, from_=a, to=n)` both fired a HIGH when fed to `transfer(...)`.
   Every OpenAI and Anthropic SDK `create` is keyword-only, so a real call spells its arguments
   the SDK's way. A receiver-name allowlist cannot do this: `client` is the dominant receiver for
   both OpenAI and Twilio.

   The argument walk reads `router_code_view` (comments and literal text blanked, rows and
   columns kept) from the candidate's `(` to wherever the call closes, so a call split over
   several lines is judged on all its arguments, and a `)` in a comment inside it cannot end the
   walk early. A candidate that itself sits in a comment or docstring is judged on its raw line.
   The gate fails open: an argument list it cannot split counts as a call, which is what Rule 3
   did before the gate.

   **Rule 4 (scan-result-discarded / scan-result-ignored):** Per-file. Matches a call to
   `scan_prompt(`/`scan_output(` (optionally module-qualified, e.g. `llm_guard.evaluate.
   scan_prompt(`). Two shapes:
   - **Bare call** (`_SCAN_CALL_BARE`, no assignment at all) → HIGH
     `scan-result-discarded`: the return value — sanitized text AND validity — is fully
     thrown away.
   - **Assigned call** (`_SCAN_CALL_ASSIGN`, tuple-unpack target names captured) → checks
     whether the conventional 2nd unpacked name (the validity dict) is referenced again
     within the next 15 lines. If never referenced → MEDIUM `scan-result-ignored`: the
     sanitized text is kept and used, but nothing gates on whether the scan actually
     flagged anything.

   **Rule 5 (nemo-injection-detection-absent):** Reads every genuine NeMo `config.yml`/
   `config.yaml` (see "NeMo config files scanned" below). Fires when `injection_detection`
   does not appear anywhere in the file.

   **Rule 6 (nemo-self-check-only):** Fires when `self check input`/`self check output`
   appears in the config AND none of the content-safety-class rail names
   (`content_safety`, `topic_safety`, `llama_guard`, `shieldgemma`, `nemotron`,
   `activefence`, `policyai`, `alignscore`) appear anywhere in the file. Deliberately
   excludes GLiNER/Presidio/Private AI from the "dedicated safety model" set — those are
   PII detectors, a different concern from jailbreak/harmful-content self-check; a
   PII-only config must not falsely satisfy this rule.

   **Rule 7 (nemo-tool-rails-without-iorails):** Cross-file. Fires when the config
   declares `tool call validation`/`tool result validation` AND no `.py` file anywhere in
   the project references `require_iorails`/`IORails`.

   **Rule 8 (nemo-jailbreak-in-process):** Fires when `jailbreak detection heuristics`
   appears in the config AND no `server_endpoint:` key appears anywhere in the file.

   **Rule 9 (nemo-pii-masking-input-only):** Fires when a PII/sensitive-data config block
   (`gliner:`, `presidio`, `privateai:`, `sensitive_data_detection:`) is present, an
   "on input" mask/detect flow is configured, and no matching "on output" flow is present.

   **NeMo config files scanned:** `iter_files_named(root, "config.yml", "config.yaml")`,
   filtered to files with a genuine top-level `rails:` key (`_NEMO_RAILS_BLOCK`, column 0 —
   distinctive enough that an unrelated tool's `config.yml` won't coincidentally match)
   AND at least one active `flows:` sub-list (`_NEMO_ACTIVE_FLOWS` — excludes an empty/stub
   `rails:` block from being treated as a real config). Rules 5-9 are regex text-scans, not
   a real YAML parse — the guard sandbox (G2) forbids `pyyaml`, so this matches the same
   text-heuristic approach `vite_sourcemap_prod.py` already uses for its own config format.

4. **Inline opt-out pragma:** `# security: allow-guardrail-architecture` (checked per-file
   for Rules 5-9, same as Rules 1-4).

5. **Severities and rules:**
   - `"medium"`, rule `"guardrail-architecture/no-external-guardrail"`,
     standards `["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"]`
   - `"high"`, rule `"guardrail-architecture/same-model-self-validation"`,
     standards `["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"]`
   - `"high"`, rule `"guardrail-architecture/high-stakes-no-approval"`,
     standards `["OWASP-LLM:LLM06", "OWASP:A05"]` (Excessive Agency — corrected from LLM01/02
     in PR #227 review to match the repo's agency-axis convention)
   - `"high"`, rule `"guardrail-architecture/scan-result-discarded"`,
     standards `["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "NIST:MANAGE"]`
   - `"medium"`, rule `"guardrail-architecture/scan-result-ignored"`,
     standards `["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "NIST:MANAGE"]`
   - `"medium"`, rule `"guardrail-architecture/nemo-injection-detection-absent"`,
     standards `["OWASP-LLM:LLM01", "OWASP:A05"]`
   - `"medium"`, rule `"guardrail-architecture/nemo-self-check-only"`,
     standards `["OWASP-LLM:LLM01", "OWASP-LLM:LLM02", "OWASP:A05"]`
   - `"high"`, rule `"guardrail-architecture/nemo-tool-rails-without-iorails"`,
     standards `["OWASP-LLM:LLM06", "OWASP:A05"]`
   - `"medium"`, rule `"guardrail-architecture/nemo-jailbreak-in-process"`,
     standards `["OWASP-LLM:LLM01", "OWASP:A05"]`
   - `"medium"`, rule `"guardrail-architecture/nemo-pii-masking-input-only"`,
     standards `["OWASP-LLM:LLM02", "OWASP:A05"]`

---

## When NOT to flag

**Rule 1:** Any project that imports a recognized guardrail library in any `.py` file —
even a separate utility module — is treated as having a guardrail layer. Suppress with
`# security: allow-guardrail-architecture` if using a custom or proprietary guardrail
system not in the library list.

**Rule 1, Llama Guard signal:** Any line naming Llama Guard alongside a model-loading/
invocation call shape (`.from_pretrained(`, `AutoModelForCausalLM`, `AutoTokenizer`, or an
LLM generation call carrying the name in a `model=` kwarg) — even in a separate utility
module, same as the import check above.

**Rule 2:** When the generator and validator use different variable names (even if both
are `ChatOpenAI` — the guard checks the variable name, not the class). Architecturally
separate models accessed through different variables are safe by design.

**Rule 3:** When any approval/confirmation/MFA pattern appears in the function — even
a simple `if not confirmed: raise`. The guard trusts that the developer has added a
human gate and does not fire.

**Rule 4:** When the tuple-unpacked validity name (or any of the captured names, for a
non-standard arity) is referenced again within 15 lines — the guard trusts that any
subsequent reference means the developer is gating on it, without checking that the
reference is actually a conditional (a stray `print(results_valid)` would also silence it).

**Rules 5-9:** Any file not matching `config.yml`/`config.yaml` with a genuine top-level
`rails:` key and at least one active `flows:` list — a config.yml for an unrelated tool,
or a NeMo config that's just a stub with no rails actually wired, is never scanned.

**Rule 6 specifically:** A PII-only config (GLiNER/Presidio/Private AI, no content-safety
model) does NOT silence this rule — those are a different concern from self-check's
jailbreak/harmful-content scope (see `test_nemo_self_check_fp_bait_gliner_alone_is_not_a_safety_model`).

**Rule 7 specifically:** `require_iorails`/`IORails` wiring anywhere in the project silences
it, even in a file unrelated to the actual rails setup — the guard proves the string is
somewhere in the codebase, not that it's correctly wired to the same config.

---

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_llm_feature_present` | Guard activates on `llm` feature |
| `test_not_applies_without_llm_feature` | Guard skips non-LLM stacks |
| `test_no_guardrail_fires_when_llm_calls_present` | Rule 1 fires: LLM calls, no guardrail imports |
| `test_no_guardrail_fires_with_langchain_invoke` | Rule 1 fires: langchain `.invoke()` pattern |
| `test_no_guardrail_silent_when_guardrail_import_present` | Rule 1 silent: `from guardrails import Guard` present |
| `test_no_guardrail_silent_when_nemo_guardrails_present` | Rule 1 silent: `nemo_guardrails` in a separate file |
| `test_no_guardrail_silent_when_pragma_present` | Rule 1 silent: file-level pragma |
| `test_no_guardrail_silent_when_llama_guard_loaded_via_transformers` | Rule 1 silent: Llama Guard loaded via HF `AutoModelForCausalLM`/`AutoTokenizer.from_pretrained(...)` |
| `test_no_guardrail_silent_when_llama_guard_used_via_hosted_inference` | Rule 1 silent: `model='meta-llama/Llama-Guard-3-8B'` on a hosted-inference `.chat.completions.create(` call |
| `test_no_guardrail_fp_bait_llama_guard_mentioned_but_not_loaded` | Rule 1 still fires: "Llama Guard" only in a comment/dead assignment, never actually loaded or invoked |
| `test_no_guardrail_fp_bait_llama_guard_call_shape_inside_one_comment_line` | Rule 1 still fires: name + `from_pretrained(...)` call shape both inside a single `#` comment line, no real code (2026-08-23 fix, #692 review H2) |
| `test_no_guardrail_silent_when_no_llm_calls` | Rule 1 silent: no LLM generation calls |
| `test_same_model_self_validation_fires` | Rule 2 fires: same `llm` variable used to generate + validate |
| `test_same_model_validation_fp_bait_different_model_vars` | Rule 2 silent: separate generator/guard_model vars |
| `test_high_stakes_no_approval_fires_for_transfer` | Rule 3 fires: `transfer()` after LLM invoke, no approval |
| `test_high_stakes_fp_bait_with_mfa_confirmation` | Rule 3 silent: `verify_identity` present before transfer |
| `test_high_stakes_no_approval_fires_for_delete_account` | Rule 3 fires: `delete_account()` driven by LLM output |
| `test_high_stakes_fp_bait_no_llm_result_passed` | Rule 3 silent: LLM result not passed to high-stakes action |
| `test_guardrail_high_stakes_ignores_sdk_shaped_non_llm_create` | Rule 3 silent: a Django reverse relation, a bare `completions` path and a Twilio SMS on SDK-shaped method paths (#561) |
| `test_guardrail_high_stakes_non_llm_create_reaches_the_gate` | Mutation proof: the same sites all fire once the argument gate is waved through |
| `test_guardrail_high_stakes_still_fires_for_every_sdk_argument_form` | Rule 3 fires: `**` spread, `extra_body=`, `prompt=`, `messages=`-only, multi-line, comment inside the call |
| `test_guardrail_high_stakes_gate_reads_the_code_view` | Mutation proof: walking raw text, a numbered note's `)` would hide `model=` |
| `test_guardrail_high_stakes_commented_candidate_is_judged_on_its_raw_line` | A commented-out SMS stays silent; a commented-out SDK call still fires (#1040, pinned) |
| `test_scan_result_discarded_fires_on_bare_call` | Rule 4 fires: `scan_prompt(...)` called with no assignment |
| `test_scan_result_ignored_fires_when_validity_never_checked` | Rule 4 fires: validity captured but never referenced |
| `test_scan_result_fp_bait_when_validity_checked` | Rule 4 silent: validity result gated with `if not all(...)` |
| `test_scan_result_discarded_fires_on_module_qualified_call` | Rule 4 fires: `llm_guard.evaluate.scan_prompt(...)` |
| `test_scan_result_fp_bait_when_pragma_present` | Rule 4 silent: file-level pragma |
| `test_nemo_injection_detection_absent_fires` | Rule 5 fires: active rails, no `injection_detection` |
| `test_nemo_injection_detection_fp_bait_when_configured` | Rule 5 silent: `injection_detection` block present |
| `test_nemo_self_check_only_fires` | Rule 6 fires: self-check flows, no content-safety rail |
| `test_nemo_self_check_fp_bait_when_content_safety_model_present` | Rule 6 silent: `llama_guard` also configured |
| `test_nemo_self_check_fp_bait_gliner_alone_is_not_a_safety_model` | Rule 6 fires even with GLiNER present (PII ≠ content-safety) |
| `test_nemo_tool_rails_without_iorails_fires` | Rule 7 fires: tool rails, no IORails wiring anywhere |
| `test_nemo_tool_rails_fp_bait_when_iorails_wired_in_different_file` | Rule 7 silent: `require_iorails=True` in app.py (cross-file) |
| `test_nemo_jailbreak_in_process_fires` | Rule 8 fires: heuristics flow, no `server_endpoint` |
| `test_nemo_jailbreak_fp_bait_when_server_endpoint_configured` | Rule 8 silent: external server configured |
| `test_nemo_pii_masking_input_only_fires` | Rule 9 fires: input flow, no output flow |
| `test_nemo_pii_masking_fp_bait_when_output_flow_present` | Rule 9 silent: both input and output flows present |
| `test_nemo_rules_silent_without_active_rails_block` | Rules 5-9 silent: `rails:` present but no active flows (stub file) |
| `test_nemo_rules_silent_when_pragma_present` | Rules 5-9 silent: file-level pragma |

---

## Known bypasses

- **Rule 1:** A guardrail system not in `_GUARDRAIL_IMPORTS` (e.g. a custom in-house
  content filter, or a new library not yet in the list) will not be detected — the rule
  fires even when a real but unknown guardrail is present.
- **Rule 1:** A guardrail imported under a local alias that does not match the pattern
  (`import nemo_guardrails as ng` matches; a vendored copy does not).
- **Rule 1, Llama Guard signal:** Requires the model name and the load/invoke call shape on
  the SAME line — a legitimate direct-load or hosted-inference call split across multiple
  lines (e.g. `AutoModelForCausalLM.from_pretrained(\n    MODEL_NAME\n)` with `MODEL_NAME`
  defined on a prior line, or a multi-line `.chat.completions.create(\n    model="meta-llama/
  Llama-Guard-3-8B",\n    ...\n)` kwarg wrap) is not recognized and the project would still
  be flagged as having no guardrail layer if it has no other signal. This is a deliberate
  false-negative trade-off: broadening to a multi-line window to catch this case would also
  re-open the FP the same-line requirement exists to close (a nearby but unrelated/dead
  Llama Guard mention silently suppressing Rule 1 — see the module comment above
  `_LLAMA_GUARD_REFERENCE`).
- **Rule 1, Llama Guard signal — fixed 2026-08-23 (#692 review, H2):** the same-line
  requirement above does **not**, by itself, defend against a same-line `#` **comment** that
  names Llama Guard and describes a call shape in prose (e.g. `# TODO integrate llama-guard:
  guard = AutoModelForCausalLM.from_pretrained(...)`) — as originally shipped, that single
  comment line satisfied both patterns with no real code and wrongly suppressed Rule 1
  project-wide. Fixed by comment-stripping each line (`strip_python_line_comment`) before the
  co-occurrence check runs. **A triple-quoted-string (docstring) mention of the same shape is
  a known, disclosed residual gap, not covered by this fix** — `strip_python_line_comment`
  only handles `#` comments, not string literals.
- **Rule 1, Llama Guard signal:** Only recognizes Llama Guard by name — a different
  purpose-built safety model used the same way (ShieldGemma, Nemotron Content Safety) is not
  recognized as a guardrail signal outside the NeMo-config path (Rule 6). Out of scope for
  this addition; NeMo's `config.yml` path (Rule 6) already recognizes those names.
- **Rule 2:** If the developer assigns the LLM client to different variables in different
  call sites pointing to the same object, the guard will not detect the circular usage.
- **Rule 2:** Multi-file circular validation (file A generates, file B validates with the
  same model object) is not detected; the guard only looks within the same file's context
  window.
- **Rule 3:** Any string containing an approval keyword in the 30-line window silences
  the rule — a comment like `# no approval needed` containing `approval` would suppress it.
- **Rule 3, SDK `create` argument gate (#561):** a real SDK call whose arguments carry none of
  `model=`, `messages=`, `prompt=`, `extra_body=` or a `**` spread is not an LLM result. The one
  measured model-less form, an Azure AI Foundry agent reference, is covered by `extra_body=`. A
  wrapper forwarding only a positional `*args` is not covered, but a keyword-only SDK `create`
  would reject it at runtime. The OpenAI Assistants API's `beta.threads.messages.create(...)`
  (a thread message, no generation) no longer counts either.
- **Rule 3, the same gate, over-alerting direction:** a `**` spread inside a dict-literal argument
  (`survey.responses.create(answers={"q": a, **rest})`) or a lambda default
  (`key=lambda a, model=None: a`) reads as an SDK argument, so that non-LLM create still fires.
- **Rule 3:** an `await`ed call (`x = await client.responses.create(...)`) is not matched, so
  Rule 3 does not see async LLM calls at all. Found during #561 and not part of it, because
  admitting `await` is a widening that needs its own FP-bait.
- **Rule 3:** the receiver-agnostic `invoke` arm also matches a non-LLM `.invoke(`, such as boto3's
  `lambda_client.invoke(FunctionName=...)`.
- **Rule 4:** A guardrail library imported and called under a local alias
  (`from llm_guard.evaluate import scan_prompt as sp`) is not recognized — the regex
  matches the literal names `scan_prompt`/`scan_output` only.
- **Rule 4:** Any reference to the validity variable — including a log statement or an
  unrelated re-assignment — silences the rule, even if the code never actually branches
  on it.
- **All rules:** The pragma `# security: allow-guardrail-architecture` silences all rules
  for the entire file/project (Rules 5-9 check it per config-file, same as Rules 1-4 per
  Python file).
- **Rule 5:** Doesn't verify the configured injection rule *types* actually match the
  app's real attack surface (e.g. only `xss` rules configured on an app with a SQL sink) —
  only that the block exists at all.
- **Rule 6:** A content-safety-class rail name appearing ANYWHERE in the file silences the
  rule, even if it's commented out or configured for an unrelated rail.
- **Rule 7:** `require_iorails`/`IORails` appearing anywhere in the project silences it,
  even in a file unconnected to the actual config being scanned — proves the string exists
  in the codebase, not that it's correctly wired to this specific config.
- **Rule 8:** A `server_endpoint:` key anywhere in the file silences the rule, even if it
  belongs to a different rail (e.g. GLiNER's PII server) and not the jailbreak detector's
  own endpoint — a known, accepted imprecision given no real YAML parse is available.
- **Rule 9:** Only recognizes the flow-name vocabulary from NVIDIA's own docs (`mask`/
  `detect` × `sensitive data`/`pii` × `on input`/`on output`) — a custom flow name for the
  same rail would not be recognized either way (fails safe, not silent).

---

## What this guard does NOT prove

- That the external guardrail is correctly configured or effective against novel attacks.
- That separate model variables are actually different systems (could be two instances
  of the same model).
- That a HITL gate is actually blocking the operation vs. just logging.
- That the LLM is not used in high-stakes contexts beyond the patterns listed.
- Rule 1's Llama Guard signal proves the model is loaded/invoked somewhere in the project —
  not that its verdict actually gates the request (the same "scan called but result
  ignored" gap Rule 4 proves for llm-guard applies here too, and is not separately checked
  for a directly-invoked Llama Guard call).
- Rule 2 does not cross file boundaries — a generation in `api.py` validated by a same-
  model call in `safety.py` is not detected.
- Rule 4 does not prove the validity result is checked *correctly* (e.g. inverted logic,
  `if results_valid: proceed()` instead of `if not all(...): reject()`) — only that it's
  referenced again at all.
- Rules 5-9 prove NeMo config *presence/absence* patterns documented as risky by NVIDIA
  itself — they do not prove the configured rails actually block a real attack in this
  specific deployment (that requires the "LLM Vulnerability Scanning" evaluation NeMo's
  own docs separately describe, out of scope for static analysis).

# Citations

[1] agentsec checklist item `14-guardrail-layer-present` (§14)
[2] agentsec checklist item `3c-llm-as-judge-output` (§3c)
[3] agentsec checklist item `4-human-in-the-loop` (§4)
[4] NIST:MANAGE
[5] OWASP-LLM:LLM01
[6] OWASP-LLM:LLM02
[7] OWASP-LLM:LLM06
[8] OWASP-LLM:LLM09
[9] OWASP:A01
[10] OWASP:A05
