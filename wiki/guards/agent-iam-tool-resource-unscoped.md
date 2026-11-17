---
type: Guard
title: "agent-iam-tool-resource-unscoped"
description: "Flags an AI agent's IAM policy granting a tool-execution/data-access action with no resource-level scoping (Resource: \"*\")."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "agent-iam-tool-resource-unscoped"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# Agent IAM policy grants a tool-execution/data-access action with no resource scoping

_Author: 2026-10-08; S3 and Resource parsing narrowed in the PR #1051 review (2026-10-18)_

---

## The threat

A policy that passes `iam-wildcard`'s bare-`*` check can still hand an agent far more than it
needs at the SERVICE level. `lambda:InvokeFunction` against `Resource: "*"` lets the agent invoke
ANY Lambda in the account, including admin utilities, data pipelines, or credential-rotation
functions, not just its intended tools. `s3:PutObject`/`DeleteObject` against `*` or an
every-bucket ARN (`arn:aws:s3:::*/*`) lets it overwrite or delete objects in every bucket of the
account. `bedrock:InvokeModel` with no foundation/provisioned/custom-model ARN scoping lets it call
any model in the account, including expensive ones. `dynamodb:Scan`/`Query` (or the RDS Data API
equivalent) with no row/attribute-level condition and `Resource: "*"` lets it read entire tables
rather than its own tenant's rows.

## Why this guard fits the stack

A FastAPI + LLM/RAG agent's tool layer is exactly where "Resource: *" gets left in place during
development and never tightened. Each tool call is a real AWS API call under the agent's own
execution role, and the blast radius of an unscoped grant is "every resource of that type in the
account", not just the one the tool was built for.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.tf` and `.json` files via `iter_files`, `is_nonproduct_path()`-filtered. A `.json`
   file is pre-filtered on a `"Statement"` key before the statement walk.
3. `iter_policy_statement_blocks` isolates each statement; within an `Effect: Allow` statement,
   the quoted `Action` and `Resource` values are extracted (`NotAction`/`NotResource` are never
   read as `Action`/`Resource`). A statement with no quoted `Resource` literal (a `NotResource`
   statement, or HCL `Resource = aws_s3_bucket.x.arn`) is not judged: "not provably scoped" is
   not "unscoped" (PR #1051 review, M2; it used to report every non-literal Bedrock resource as
   unscoped). Four independent rules, each ported from a distinct aws-agent-identity-guard check:
   - **`tool-execution-unscoped`**: a tool-execution action (Lambda invoke, SSM send-command,
     Step Functions start, ECS run-task, Bedrock/SageMaker invoke, API Gateway invoke) with
     `Resource: "*"`.
   - **`s3-write-unscoped`**: `s3:PutObject`/`DeleteObject`/`PutObjectAcl` where a resource
     reaches every bucket in the account: a bare `"*"`, `arn:aws:s3:::*`, or `arn:aws:s3:::*/...`.
     One bucket's objects (`arn:aws:s3:::bucket/*`) is the ordinary scoped write and stays silent;
     the source's key-prefix rule flagged it and was narrowed in the PR #1051 review (M2).
   - **`bedrock-model-unscoped`**: `bedrock:InvokeModel`/`InvokeModelWithResponseStream` where
     no resource contains a `foundation-model/`, `provisioned-model/` or `custom-model/` ARN
     segment, or an `inference-profile/`/`application-inference-profile/` segment followed by a
     CONCRETE profile id (inference profiles added after the PR #1051 re-review, because newer
     Claude models are invocable only through one; a `*` or `?` in the profile id, as in
     `inference-profile/*`, still fires, round-2 re-review). Each resource is judged on its own
     (round-3 re-review): the rule fires when ANY resource is `*` or an unscoped model/profile ARN
     (so a concrete profile no longer vouches for an `inference-profile/*` sibling, matching the S3
     rule), or when no resource is a scoped model resource at all. `agent/` and `knowledge-base/`
     ARNs are not model resources and neither scope nor unscope the statement. Round-4 re-review:
     `imported-model/`, `default-prompt-router/` and `prompt-router/` ARNs are judged like
     profiles (concrete id scoped, `*`/`?` in the id unscoped), and a resource that is one whole
     `${...}` interpolation counts as scoped (not statically evaluable, like a bare HCL
     reference). `marketplace/model-endpoint/...` ARNs are not recognised (treated as non-model).
   - **`database-unscoped`**: `dynamodb:Scan`/`Query`/`rds-data:ExecuteStatement` with
     `Resource: "*"` and no `dynamodb:LeadingKeys`/`Attributes`/`aws:PrincipalTag` condition (or
     any other Condition at all).
4. Suppression: `# security: allow-agent-iam-tool-resource-unscoped` in a `.tf` file; the literal
   string anywhere in a `.json` file.
5. Fires HIGH for all four rules, `standards = ["OWASP:A01", "CWE-269"]`.

**Deliberately not ported:** the source's Lambda-specific resource-naming check (AIG016). Read
against the source itself, it fires on the identical `lambda:InvokeFunction` + `Resource: "*"`
condition `tool-execution-unscoped` already catches. A second finding for the same condition
would be a self-duplicate in the source, not an independent signal, so it was dropped rather than
ported blindly.

## When NOT to flag

A resource scoped to a specific ARN (a named Lambda function, one S3 bucket or prefix, a specific
foundation-model ARN, a specific DynamoDB table) stays silent for each respective rule. A
`dynamodb:Scan` with a `dynamodb:LeadingKeys` condition (or any other Condition at all, the same
conservative posture `iam-escalation-action-no-condition`'s general rule uses) stays silent. A
`Deny` statement stays silent, and so does a statement whose resource is not a quoted literal.

## Tests

| Test | What it checks |
|---|---|
| `test_tool_execution_unscoped_fires` | `lambda:InvokeFunction` + `Resource: "*"` fires. |
| `test_tool_execution_scoped_stays_silent` | FP-bait: a scoped function ARN stays silent. |
| `test_s3_write_any_bucket_fires` | Still-fires: `s3:PutObject` on `*`, `arn:aws:s3:::*`, `arn:aws:s3:::*/*`, or a list containing `*`. |
| `test_s3_write_single_bucket_stays_silent` | FP-bait (review M2): one bucket's objects, plus the bucket ARN, stays silent. |
| `test_s3_write_scoped_to_prefix_stays_silent` | FP-bait: a key-prefix-scoped resource stays silent. |
| `test_not_resource_value_is_not_read_as_resource` | FP-bait: `NotResource: "*"` is not read as `Resource: "*"`. |
| `test_unresolvable_hcl_resource_is_not_reported_unscoped` | FP-bait: HCL `Resource = data.x.arn` is not judged. |
| `test_bedrock_invoke_unscoped_fires` | `bedrock:InvokeModel` + `Resource: "*"` fires. |
| `test_bedrock_invoke_scoped_to_model_stays_silent` | FP-bait: a foundation-model ARN stays silent. |
| `test_bedrock_invoke_scoped_to_inference_profile_stays_silent` | FP-bait: an inference-profile or application-inference-profile ARN stays silent. |
| `test_bedrock_invoke_on_non_model_arn_still_fires` | Still-fires: a Bedrock ARN naming no model is not model scoping. |
| `test_bedrock_invoke_on_wildcard_inference_profile_fires` | Still-fires: `inference-profile/*`, `application-inference-profile/*` and `inference-profile/us.anthropic.*` are not model scoping. |
| `test_known_gap_foundation_model_wildcard_is_accepted_as_scoped` | Pins the KNOWN GAP below: `foundation-model/*` is currently accepted as scoped. |
| `test_known_gap_foundation_model_wildcard_in_a_list_is_accepted_as_scoped` | Pins the same KNOWN GAP when `foundation-model/*` sits next to a concrete model. |
| `test_bedrock_invoke_on_concrete_imported_model_or_router_stays_silent` | FP-bait: concrete imported-model, default-prompt-router and prompt-router ARNs stay silent. |
| `test_bedrock_invoke_on_wildcard_imported_model_or_router_fires` | Still-fires: their `*`/`?` forms fire. |
| `test_bedrock_invoke_on_whole_interpolation_resource_stays_silent` | FP-bait: a resource that is one whole `${...}` stays silent. |
| `test_bedrock_invoke_on_whole_interpolation_plus_star_fires` | Still-fires: a whole `${...}` next to `*` fires. |
| `test_bedrock_invoke_any_unscoped_resource_fires` | Still-fires: a concrete ARN next to `inference-profile/*`, `*`, or an every-type Bedrock ARN fires. |
| `test_bedrock_invoke_all_resources_scoped_stays_silent` | FP-bait: concrete model + profile, and a concrete model next to `agent/`/`knowledge-base/` ARNs, stay silent. |
| `test_database_scan_unscoped_fires` | `dynamodb:Scan` + `Resource: "*"` + no condition fires. |
| `test_database_scan_with_leading_keys_condition_stays_silent` | FP-bait: a `LeadingKeys` condition stays silent. |
| `test_database_scan_scoped_to_table_stays_silent` | FP-bait: a specific table ARN stays silent. |
| `test_deny_statement_stays_silent` | FP-bait: a `Deny` statement stays silent. |
| `test_terraform_file_flags_same_shape` | The S3 rule fires in a `.tf` `jsonencode()` body (`arn:aws:s3:::*/*`). |
| `test_pragma_suppresses` | The raw-string pragma suppresses in `.json`. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |

## Known bypasses

The action sets (tool-execution, S3-write, Bedrock-invoke, DB-scan) are fixed lists, so an action
outside them that has the identical unscoped-resource risk shape is invisible to this guard. The
S3 check is textual ARN parsing: a multi-bucket wildcard such as `arn:aws:s3:::app-*/*` is not
flagged, and a resource built via Terraform string interpolation/locals is not evaluated. An
`Allow` + `NotResource` statement (everything except the listed resources) is not judged. **Known
gap:** the model-ARN check is a substring test, so `arn:aws:bedrock:*::foundation-model/*` (every
foundation model) is accepted as model scoping, alone or next to a concrete model; this predates
PR #1051 and is pinned by `test_known_gap_foundation_model_wildcard_is_accepted_as_scoped` and
`..._in_a_list_...` rather than changed here (the same wildcard in an inference-profile id does
fire). The
database-scan rule's condition check is presence-only (any Condition suppresses it, matching the
conservative posture used elsewhere), so a Condition present but not actually scoping rows still
stays silent.

A native HCL `data "aws_iam_policy_document"` source is not read at all: its `statement { ... }`
blocks carry lowercase `actions = [...]` / `resources = [...]` lists (and often no `effect`), which
the shared statement walker does not recognise as `Action`/`Resource` keys. This is a pre-existing
blind spot of the whole IAM-policy guard family, not specific to this guard (PR #1051 re-review,
L3; measured: a document granting `iam:PassRole`, `sts:AssumeRole`, `bedrock:CreateAgent` and
`lambda:InvokeFunction` on `*` produced no finding from any of the seven guards).

A `{`/`}` inside a quoted string within a `${...}` interpolation (`"${replace(var.arn, "{",
"")}"`), or an unterminated `${` (`"x${"`, HCL `"x$${"`), makes the brace-depth interpolation scan
run on past the string, so `Action`/`Resource`/`Principal` values LATER in the same statement go
unread. Scope: the rest of that enclosing statement object only; other statements are unaffected.
Known gap from the PR #1051 final review (F1), deferred; pinned by
`tests/test_iam_policy_guard_prechecks.py::test_known_gap_brace_in_interpolation_string_hides_later_values`.

## What this guard does NOT prove

A clean result proves each matched action's resource isn't one of the specific unscoped shapes
this guard checks for. It does not prove the scoping is actually correct (a bucket the agent should
not write to at all, a foundation-model ARN that still covers every model from one provider) or
that the action itself should be granted at all (that is `iam-escalation-action-no-condition`'s
and `agent-iam-control-plane-exposure`'s territory).

# Citations

[1] agentsec checklist item `6c-agent-iam-tool-resource-unscoped` (§6c)
[2] OWASP:A01, Broken Access Control
[3] CWE-269, Improper Privilege Management
[4] poojakira/aws-agent-identity-guard, https://github.com/poojakira/aws-agent-identity-guard,
    `src/aws_agent_identity_guard/scanner.py` at commit `8e6fa80e` (2026-10-07), MIT licence at
    that version, Copyright (c) 2026 Pooja Kiran (full notice, and the upstream's 2026-10-13 move
    to a proprietary licence for new material, in `wiki/research/aws-agent-identity-guard-patterns.md`):
    the source of this guard's action sets and the original S3 prefix-parsing logic
    (`TOOL_EXECUTION_PATTERNS`, AIG006/014/015/018).
