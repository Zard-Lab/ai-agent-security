---
type: Guard
title: "agent-iam-control-plane-exposure"
description: "Flags an AI agent's IAM policy granting a Bedrock/SageMaker control-plane action instead of only the data-plane action its runtime actually needs."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "agent-iam-control-plane-exposure"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# Agent IAM policy grants a Bedrock/SageMaker control-plane action instead of data-plane only

_Author: 2026-10-08; severity and finding granularity revised in the PR #1051 review (2026-10-18)_

---

## The threat

An agent that only needs to RUN inference (`bedrock:InvokeModel`, `sagemaker-runtime:
InvokeEndpoint`) has no legitimate runtime reason to also hold the actions that CREATE or MODIFY
the thing it runs on. `bedrock:CreateAgent`/`UpdateAgent`/`CreateGuardrail`/`DeleteGuardrail` let an
agent reconfigure its own capabilities or disable its own safety guardrails. `sagemaker:
CreateEndpoint`/`CreateTrainingJob`/`CreateModel` let an agent that can deploy an endpoint or start
a training job substitute a poisoned model or exfiltrate training data. These are the only AWS APIs
that change what a Bedrock agent or SageMaker model actually IS, as opposed to merely calling it.

## Why this guard fits the stack

A FastAPI + LLM/RAG app running a Bedrock agent or a SageMaker-hosted model needs an execution-role
policy, and the control-plane/data-plane distinction is exactly the kind of thing that gets
blurred when a role is copy-pasted from deployment tooling into the agent's own runtime role. None
of agentsec's existing 10+ IAM guards check action identity against an AI-service-specific
allowlist; they check structural shape (wildcard, escalation list, NotAction) that applies to any
AWS workload.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.tf` and `.json` files via `iter_files`, `is_nonproduct_path()`-filtered. A `.json` file
   is pre-filtered on a `"Statement"` key (on the comment/heredoc-blanked view) before paying for
   the statement walk.
3. `iter_policy_statement_blocks` (the shared, format-agnostic walker `iam-wildcard` also uses)
   isolates each statement. Within an `Effect: Allow` statement, every `Action` value is extracted
   and checked (case-insensitive) against two fixed sets ported from aws-agent-identity-guard:
   `BEDROCK_CONTROL_PLANE` and `SAGEMAKER_CONTROL_PLANE`.
4. Suppression: `# security: allow-agent-iam-control-plane-exposure` in a `.tf` file (a real
   comment); the literal string anywhere in a `.json` file (no comment syntax).
5. Fires ONE finding per statement and service, HIGH, naming every control-plane action of that
   service: `agent-iam-control-plane-exposure/bedrock-control-plane` and/or
   `.../sagemaker-control-plane`. A statement mixing both services yields one finding for each, so
   a rule-id exception for one service never hides the other (PR #1051 re-review, L2). Each
   finding is anchored at its service's first matched action.
6. The guard declares `surfacing = True`. It never identifies whether the policy belongs to an
   agent RUNTIME role or a deployment/CI role, and a CI role that creates agents and guardrails
   legitimately needs these actions. Until the PR #1051 review (M1) it fired CRITICAL once per
   action, so one CI deploy statement with three Bedrock actions produced three CRITICAL
   findings. Scoping to roles whose trust principal is a runtime service is a possible later
   refinement; it needs the cross-resource role/policy attachment this text scan does not do.

## When NOT to flag

The data-plane action an agent actually needs (`bedrock:InvokeModel`, `sagemaker-runtime:
InvokeEndpoint`) stays silent: only the control-plane action NAME is checked, not the service
prefix generally. A `Deny` statement stays silent (a lockdown, not a grant). An unrelated action
whose RESOURCE happens to contain a substring like "bedrock" (e.g. an S3 bucket named
`bedrock-data-bucket`) stays silent: only the `Action` value is checked, never the `Resource`.

## Tests

| Test | What it checks |
|---|---|
| `test_bedrock_control_plane_fires_high` | A Bedrock control-plane action fires HIGH. |
| `test_one_finding_per_statement_not_per_action` | A CI deploy statement with three Bedrock actions is one finding naming all three. |
| `test_mixed_service_statement_gives_one_finding_per_service` | A statement mixing SageMaker and Bedrock actions gives one finding per service, each naming only its own actions. |
| `test_two_statements_give_two_findings` | Still-fires: each statement keeps its own finding. |
| `test_guard_is_a_surfacing_review_signal` | The guard declares `surfacing = True`. |
| `test_sagemaker_control_plane_fires_high` | A SageMaker control-plane action fires HIGH. |
| `test_flags_in_terraform_file` | The same shape fires in a `.tf` `jsonencode()` body. |
| `test_data_plane_action_stays_silent` | FP-bait: `bedrock:InvokeModel` stays silent. |
| `test_sagemaker_data_plane_action_stays_silent` | FP-bait: `sagemaker-runtime:InvokeEndpoint` stays silent. |
| `test_deny_statement_stays_silent` | FP-bait: a `Deny` statement stays silent. |
| `test_pragma_suppresses` | The raw-string pragma suppresses in `.json`. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_unrelated_json_stays_silent` | FP-bait: an ordinary `package.json` stays silent. |

## Known bypasses

The dangerous-action sets are fixed lists ported from one source: a control-plane action AWS adds
later, or one this list simply missed, is invisible until the list is updated. A wildcard pattern
(`bedrock:Create*`) is not expanded against the lists. A value built via string interpolation/locals
in Terraform is not evaluated.

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

A clean result proves no action from these two fixed lists was granted. It does not prove the
granted data-plane actions are themselves correctly scoped (that's `iam-escalation-action-no-
condition`'s/`iam-wildcard`'s territory), nor that a managed policy attached elsewhere doesn't
grant the same control-plane action by a different path.

# Citations

[1] agentsec checklist item `6c-agent-iam-control-plane-exposure` (§6c)
[2] OWASP:A01, Broken Access Control
[3] CWE-269, Improper Privilege Management
[4] poojakira/aws-agent-identity-guard, https://github.com/poojakira/aws-agent-identity-guard,
    `src/aws_agent_identity_guard/scanner.py` at commit `8e6fa80e` (2026-10-07), MIT licence at
    that version, Copyright (c) 2026 Pooja Kiran (full notice, and the upstream's 2026-10-13 move
    to a proprietary licence for new material, in `wiki/research/aws-agent-identity-guard-patterns.md`):
    the source of this guard's `BEDROCK_CONTROL_PLANE`/`SAGEMAKER_CONTROL_PLANE`
    action lists.
