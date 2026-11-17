---
type: Guard
title: "agent-iam-killchain-combination"
description: "Flags an AI agent IAM policy that combines credential-access, lateral-movement, and identity-discovery action categories across the statements of one policy document, a multi-step breach-chain shape no single statement reveals."
timestamp: "2026-10-08T00:00:00Z"
guard_id: "agent-iam-killchain-combination"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# Agent IAM policy combines action categories that chain into a multi-step breach

_Author: 2026-10-08; detection narrowed in the PR #1051 review (2026-10-18)_

---

## The threat

Every other IAM guard in this family looks at one statement in isolation. A breach chain crosses
statements: an agent that can READ a credential (`secretsmanager:GetSecretValue`,
`ssm:GetParameter*`, `sts:GetSessionToken`, `iam:CreateAccessKey`, ...) AND separately PIVOT
identity (`sts:AssumeRole`, `iam:PassRole`, `ssm:SendCommand`, `ssm:StartSession`, ...) can use the
first capability to obtain a credential and the second to move laterally with it. Each statement
looks like an ordinary least-privilege grant in a per-statement review, but together they describe
the two steps of a credential-theft-then-pivot chain. Credential-read combined with
instance-metadata/identity-discovery actions (`ec2:DescribeInstances`,
`iam:GetInstanceProfile`/`ListInstanceProfiles`, ...) is the shape of a
harvest-then-reconnaissance chain. All three categories together describe a role that is
over-scoped for any single agent, independent of any one statement's own Condition/Resource
scoping.

**These are heuristic combinations of Allow statements across one policy document, not proof of
effective permissions, exploitability, or that any incident can be reproduced.** A legitimate
infra-automation role can genuinely need all three categories. The guard therefore declares
`surfacing = True` (a review signal, ranked below a proven finding of the same severity) and no
rule is above HIGH.

## Why this guard fits the stack

Every other guard in this batch (`iam-escalation-action-no-condition`,
`agent-iam-tool-resource-unscoped`, `agent-iam-control-plane-exposure`) is architecturally a
per-statement check. An agent's execution-role policy routinely accumulates capability across many
statements as tools get added over a project's lifetime, which is exactly the shape where no single
statement would trip a per-statement guard but the combination is the actual risk.

## Detection design

1. `applies()` gates on `"llm" in profile.features`.
2. Scans `.tf` and `.json` files via `iter_files`, `is_nonproduct_path()`-filtered. A `.json`
   file is pre-filtered on a `"Statement"` key before the walk.
3. **The unit of analysis is ONE POLICY DOCUMENT**: the innermost `{...}` object that declares a
   `Statement` key (a JSON policy file's root, or the `jsonencode({...})` / heredoc body of one
   Terraform `policy` attribute). Every `Effect: Allow` statement inside that document contributes
   its granted `Action` values. Two policy resources in one `main.tf` are judged separately. Until
   the PR #1051 review the whole FILE was pooled, which made two unrelated roles in one file look
   like one over-scoped identity.
4. A statement that carries `Principal` or `NotPrincipal` is skipped: it is a trust policy or a
   resource policy, not a grant to the identity under review. Without this, the `sts:AssumeRole`
   in every role's own trust statement counted as "lateral movement", so a plain Lambda role plus
   one scoped secret read was CRITICAL (review H3).
5. A bare `*` action is skipped (`iam-wildcard/action-star` owns it); a service wildcard such as
   `secretsmanager:*` still counts.
6. Three fixed action-category tuples (ported from aws-agent-identity-guard's
   `_CREDENTIAL_HARVEST_ACTIONS`/`_LATERAL_MOVEMENT_ACTIONS`/`_METADATA_REACH_ACTIONS`) are each
   checked against the document's actions via `fnmatchcase`, so a granted wildcard like
   `secretsmanager:*` covers the literal `secretsmanager:GetSecretValue` category entry.
7. Three independent rules, all HIGH, all checked (a full-chain document fires all three):
   - **`harvest-plus-lateral`**: a credential-harvest action AND a lateral-movement action.
   - **`harvest-plus-metadata`**: a credential-harvest action AND a metadata-reach action.
   - **`full-chain`**: all three categories present.
8. Suppression: `# security: allow-agent-iam-killchain-combination` in a `.tf` file; the literal
   string anywhere in a `.json` file.
9. `location` is the line that opens the policy document.
10. Cost is linear in the file: the `Statement` keys are located in one pass and each statement is
    assigned to its innermost document in one ordered sweep (PR #1051 re-review, L1; the first
    per-document version scanned every document root per statement, 7 to 21 s on a 3000-document
    JSON).

**Deliberately not ported:** the source's `NotAction`-complement modeling (treating an
`Allow`+`NotAction` statement's complement, "everything except the excluded list", as potentially
contributing to each category). A disclosed scope narrowing, not a silent one.

## When NOT to flag

Only ONE category present in a document stays silent: a credential-harvest action alone, or a
lateral-movement action alone, is each individually a normal, often-necessary grant; it is the
COMBINATION that is the signal. Actions in a `Deny` statement, in a statement with a `Principal`,
in a different policy document, or in a different file are never combined.

## Tests

| Test | What it checks |
|---|---|
| `test_harvest_plus_lateral_fires_high` | Credential-harvest + lateral-movement in one statement fires HIGH, anchored at the document line. |
| `test_harvest_plus_metadata_fires_high` | Credential-harvest + metadata-reach fires HIGH. |
| `test_full_chain_fires_all_three_rules` | All three categories present fires all three rules, all HIGH. |
| `test_combination_crosses_separate_statements` | The two categories in DIFFERENT statements of one document still combine. |
| `test_single_terraform_policy_with_chain_still_fires_next_to_a_role` | Still-fires: one Terraform policy resource with the chain fires, even beside a trust-bearing role. |
| `test_terraform_role_trust_plus_scoped_secret_read_stays_silent` | FP-bait (review H3): a role's trust `sts:AssumeRole` plus one scoped secret read is silent. |
| `test_json_trust_statement_is_not_counted_as_a_grant` | FP-bait: a `Principal`-bearing statement is not a grant. |
| `test_separate_policy_resources_in_one_file_are_not_pooled` | FP-bait: two policy resources in one `main.tf` are judged separately. |
| `test_bare_star_action_is_left_to_iam_wildcard` | FP-bait: a bare `*` action is not counted. |
| `test_harvest_only_stays_silent` / `test_lateral_only_stays_silent` | FP-bait: only one category present stays silent. |
| `test_deny_statement_actions_not_counted` | FP-bait: a `Deny` statement's action is never counted. |
| `test_wildcard_action_in_category_matches` | A granted `secretsmanager:*` wildcard covers the category. |
| `test_terraform_file_flags_same_shape` | The same shape fires in a `.tf` `jsonencode()` body. |
| `test_guard_is_a_surfacing_review_signal` | The guard declares `surfacing = True`. |
| `test_document_grouping_is_linear_in_the_number_of_documents` | `assert_growth`: document grouping stays linear (1000 to 8000 documents). |
| `test_pragma_suppresses` | The raw-string pragma suppresses in `.json`. |
| `test_nonproduct_path_skipped` | A fixture under `tests/fixtures/` is skipped. |
| `test_does_not_apply_without_llm_feature` | `applies()` is False with no `llm` feature. |
| `test_unrelated_json_stays_silent` | FP-bait: an ordinary `package.json` stays silent. |

## Known bypasses

The three action-category lists are fixed, so an action with the identical risk shape but outside
these lists is invisible. The combination analysis is per DOCUMENT: a credential-harvest action in
one policy and a lateral-movement action in a separate policy attached to the SAME role are not
combined, even though AWS evaluates both as the role's effective permissions (resolving
attachments across resources and files is out of scope for a static text scan). A bare `*` action
is not counted here. The `NotAction`-complement modeling from the source is not ported (see above).

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

A clean result proves no two of the three fixed categories were found together in one policy
document. It does not prove the agent's EFFECTIVE permissions (across every policy attached to the
role, inline and managed, across every file) are free of this combination, nor that a flagged
combination is actually exploitable (resource scoping, conditions, and permission boundaries
elsewhere can all narrow what the combination can actually do).

# Examples

Fires (`harvest-plus-lateral`, HIGH, a review signal):

```json
{"Statement": [
  {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
  {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*"}
]}
```

Silent: a role's own trust statement (`Principal` + `sts:AssumeRole`) next to a policy that reads
one scoped secret, or two different policy resources in one `.tf` file that each hold one category.

# Citations

[1] agentsec checklist item `6c-agent-iam-killchain-combination` (§6c)
[2] OWASP:A01, Broken Access Control
[3] CWE-269, Improper Privilege Management
[4] poojakira/aws-agent-identity-guard, https://github.com/poojakira/aws-agent-identity-guard,
    `src/aws_agent_identity_guard/scanner.py` at commit `8e6fa80e` (2026-10-07), MIT licence at
    that version, Copyright (c) 2026 Pooja Kiran (full notice, and the upstream's 2026-10-13 move
    to a proprietary licence for new material, in `wiki/research/aws-agent-identity-guard-patterns.md`):
    the source of this guard's three action-category lists and the cross-statement
    correlation design (`_scan_killchain_combinations`, AIG019/020/021).
