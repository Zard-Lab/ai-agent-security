---
type: Guard
title: "sfn-observability"
description: "Step Functions state machine missing execution logging or X-Ray tracing."
timestamp: "2026-08-24T00:00:00Z"
guard_id: "sfn-observability"
checklist_section: ["7"]
standards: ["OWASP:A09", "CWE-778"]
---

# Step Functions state machine missing execution logging or X-Ray tracing

_Author — Marconi, 2026-08-24_

---

## The threat

An `aws_sfn_state_machine` Terraform resource with no `logging_configuration` block (or
one whose `level` is `"OFF"`) sends no execution history to CloudWatch Logs. When a
workflow execution fails, there is no record of which state it was in, what input it
received, or what output (or error) it produced — an incident responder investigating a
compromised or misbehaving agentic/orchestration pipeline has nothing to look at.
Separately, an `aws_sfn_state_machine` with no `tracing_configuration` block (or one with
`enabled = false`) means AWS X-Ray never traces the workflow's calls into Lambda,
DynamoDB, or other downstream services, so a slow, hung, or failing multi-step execution
cannot be traced across service boundaries either. Both gaps are execution-visibility
holes rather than confidentiality/integrity holes, but they are exactly the data an
incident responder or on-call engineer needs first. CWE-778 (Insufficient Logging),
OWASP:A09 (Security Logging and Monitoring Failures).

## Why it's often introduced

Step Functions is frequently used to orchestrate multi-step agentic/LLM pipelines (a
Lambda that calls an LLM, a DynamoDB write, a follow-up Lambda) — exactly the kind of
workflow this tool's stack (FastAPI + LLM/RAG) tends to add once it grows past a single
request/response call. The state machine's `definition` (the actual step graph) is the
part everyone iterates on; `logging_configuration`/`tracing_configuration` are optional
blocks that don't affect whether `terraform apply` succeeds or whether the workflow
"works", so they're easy to never add:

```hcl
resource "aws_sfn_state_machine" "workflow" {
  name     = "order-workflow"
  role_arn = aws_iam_role.sfn.arn
  definition = jsonencode({ ... })
  # no logging_configuration block, no tracing_configuration block ->
  # zero execution visibility into this workflow
}
```

The Terraform AWS provider's defaults make this worse, not better: an absent
`logging_configuration` block means no logging destination is configured at all (nothing
to opt out of — there's no on-by-default log group), and an absent
`tracing_configuration` block (or one that omits `enabled`) defaults X-Ray tracing to
`false`. There is no warning, no plan-time diff to notice — the workflow simply runs with
zero observability.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. Scans every `.tf` file under the repo root via `iter_files(root, (".tf",))`, skipping
   non-product paths (`is_nonproduct_path`).
3. Uses the shared `iter_terraform_resources()` helper (`agentsec/guards/base.py`) to
   isolate each `aws_sfn_state_machine "<name>" { ... }` block (brace/string/heredoc-aware,
   so the resource's own `definition = jsonencode({...})` — which contains many braces of
   its own — cannot desync the block boundary).
4. Within each block, comments are blanked (not dropped, so line numbers are preserved)
   into a `code_body` view before either pattern is evaluated, so a commented-out
   `# tracing_configuration { enabled = true }` cannot silence a genuinely unconfigured
   workflow.
   - `_LOGGING_LEVEL_OK` searches `code_body` for `level = "ALL"` / `"ERROR"` / `"FATAL"`
     (case-insensitive). If absent, the guard checks whether a `logging_configuration {`
     block opened at all (`_LOGGING_BLOCK_OPEN`) to pick the right message (block present
     but wrong/missing `level`, vs. no block at all) — either way it fires.
   - `_TRACING_ENABLED_TRUE` searches `code_body` for `enabled = true`. If absent, the
     guard checks whether a `tracing_configuration {` block opened at all
     (`_TRACING_BLOCK_OPEN`) for the same message-selection purpose, and fires.
5. Inline opt-outs (two independent pragmas, since the two rules are independently
   triggerable): `# security: allow-sfn-logging` for the logging rule,
   `# security: allow-sfn-tracing` for the tracing rule — either anywhere in the resource
   block (checked against the comment-only view of the body text, #424, since the pragma itself is
   a comment).
6. Severity: `medium` for both rules. Rule ids: `sfn-observability/logging-disabled` and
   `sfn-observability/tracing-disabled`. Standards: `["OWASP:A09", "CWE-778"]`.

Both findings are anchored on the resource's own opening line — neither rule
distinguishes "explicit bad value" from "attribute omitted" in the finding location
(mirrors `kms-key-rotation-not-enabled`'s single-message treatment of "missing OR
explicitly false").

## When NOT to flag

- `logging_configuration { level = "ALL" }` (or `"ERROR"`/`"FATAL"`) present anywhere in
  the block — logging rule silent.
- `tracing_configuration { enabled = true }` present anywhere in the block — tracing rule
  silent.
- An audited case (e.g. a low-value internal workflow where the extra CloudWatch Logs
  cost isn't justified), suppressed with `# security: allow-sfn-logging` and/or
  `# security: allow-sfn-tracing` anywhere in the resource block.

## Tests

| Test | What it checks |
|---|---|
| `test_sfn_observability_flags_missing_logging_and_tracing` | Positive: both blocks entirely absent fires both rules, anchored on the resource's opening line (**verified_by**). |
| `test_sfn_observability_flags_logging_level_off` | Positive: `logging_configuration { level = "OFF" }` fires only the logging rule. |
| `test_sfn_observability_flags_tracing_disabled` | Positive: `tracing_configuration { enabled = false }` fires only the tracing rule. |
| `test_sfn_observability_silent_when_fully_configured` | FP-bait: `level = "ERROR"` + `enabled = true` → silent. |
| `test_sfn_observability_silent_other_resource` | A non-`aws_sfn_state_machine` resource → silent. |
| `test_sfn_observability_logging_pragma_silences` | Logging pragma suppresses the logging finding (tracing still configured, so nothing else fires). |
| `test_sfn_observability_tracing_pragma_silences` | Tracing pragma suppresses the tracing finding (logging still configured, so nothing else fires). |
| `test_sfn_observability_comment_does_not_suppress_finding` | A commented `# tracing_configuration { enabled = true }` does NOT suppress a genuine finding. |
| `test_sfn_observability_applies_gate` / `test_sfn_observability_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `enabled = var.tracing_on` where the variable defaults to
  `true` elsewhere, or a `level` built from a local/expression rather than a literal
  string — only literal values are matched; resolving `variables.tf`/`locals.tf` is out
  of scope for a regex-based guard.
- **A resource nested inside a `module` block** passing either sub-block through at the
  call site — the helper only sees the resource's own literal body.
- **`level`/`enabled` values that are technically well-formed but semantically wrong at
  apply time** (e.g. AWS API rejects the combination) are out of scope — this is a
  presence/value check on the Terraform source, not a live-plan validator.

## What this guard does NOT prove

A silent guard does not mean the workflow is actually emitting logs or traces in AWS —
it only means a literal `level = "ALL"/"ERROR"/"FATAL"` and `enabled = true` were found
in the Terraform source at audit time. It does not confirm the applied infrastructure
matches the source (drift), that the CloudWatch log group referenced by
`log_destination` actually exists or has a sane retention policy, that the IAM role
attached to the state machine actually has permission to write logs/traces, or that a
state machine provisioned outside Terraform (console, CloudFormation, another IaC tool)
has observability configured. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-sfn-observability` (§7)
[2] CWE-778
[3] OWASP:A09
