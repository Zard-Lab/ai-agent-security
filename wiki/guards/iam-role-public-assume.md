---
type: Guard
title: "iam-role-public-assume"
description: "IAM role trust policy allows any AWS account to assume it."
timestamp: "2026-07-14T14:41:42+08:00"
guard_id: "iam-role-public-assume"
checklist_section: ["6c"]
standards: ["CWE-284", "OWASP:A01", "SOC2:CC6.3"]
---

# IAM role trust policy allows any AWS account to assume it

## What it detects

A Terraform `aws_iam_role` resource's `assume_role_policy`, OR a bare trust-policy `.json`
document (2026-10-08, aws-agent-identity-guard research-cycle, the same format-widening
rationale as `iam-wildcard`/`iam-notaction-with-allow`/`iam-escalation-action-no-condition`):

1. **`wildcard-principal`**: an `"Effect": "Allow"` statement with `"Principal": {"AWS": "*"}`
   (or the bare `"Principal": "*"`). Any AWS account in existence can call `sts:AssumeRole` and
   take on the role's permissions.
2. **`service-principal-no-source-scope`** (2026-10-08, narrowed in the PR #1051 review): a
   service principal from the short list of services that assume a role ON BEHALF OF another
   resource (`sns`, `s3`, `events`, `scheduler`, `cloudtrail`, `config`, `logs` incl. the regional
   `logs.<region>` form, `delivery.logs`), with no `aws:SourceArn`/`SourceAccount`/`SourceOrgID`/
   `SourceOrgPaths` condition. Without one, a resource of that service type in any account can
   make the service assume this role: the cross-service confused deputy [5]. MEDIUM and a review
   signal (`surfacing_rule_prefixes`), not HIGH: AWS recommends rather than requires the
   condition, and its own canonical EventBridge (`events.amazonaws.com`) and Config
   (`config.amazonaws.com`) service-role trust policies omit it, so a HIGH rule failed the default
   `--fail-on high` gate on ordinary IaC (PR #1051 re-review, M1).

Deliberately NOT flagged (PR #1051 review, H1):

- A compute/runtime service assuming its own execution role (`lambda`, `ecs-tasks`, `ec2`,
  `bedrock`, and every other service not on the list). That is the ordinary service-role shape;
  the first version of this rule fired HIGH on every one of them. Several of these services do
  publish their own optional source-scoping guidance, so a later revision could add them as a
  review signal; they are kept out of the rule for now.
- An explicit `arn:aws:iam::...` principal with no `sts:ExternalId`. AWS documents ExternalId for
  third-party delegation [5], and a static scan cannot tell a third party's account from the
  role's own, so the rule fired HIGH on the same-account `:root` trust. It was dropped rather
  than downgraded because the pre-existing benign-neighbour tests pin an `arn:aws:iam::111:root`
  trust with no ExternalId as silent.
- A RESOURCE policy (S3 bucket, SNS topic, SQS queue, KMS key) in a `.json` file. It carries a
  `Principal`, but only a statement whose `Action` names `sts:AssumeRole`,
  `sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML` is read as a trust statement.

## Why it matters

This is a different attribute and JSON shape from `iam-wildcard` (which flags
`Action`/`Resource` wildcards on a policy's own *permissions*, not who may *assume*
the role carrying them) and from `s3-bucket-policy-wildcard-principal` (a different
resource type — an S3 bucket policy, not an IAM role trust policy). Checkov's own
`CKV_AWS_60` check exists for the same reason. CWE-284 (Improper Access Control). The
confused-deputy rule is CWE-441. It is not specific to AI agents, but an agent framework's own
infrastructure is where a copy-pasted delivery-role trust without the mitigation tends to land.

## Detection scope

- Languages/formats: Terraform (`.tf`) and bare IAM trust-policy JSON (`.json`)
- Applies when: universal (`return True`, 2026-10-08): a trust policy can live in any repo with
  no stack feature detected at all. Previously gated on `"terraform" in profile.features`.
- Scanned files: every `.tf` and `.json` file under the repo root
- **`.tf` path**: uses `iter_terraform_resources()` to isolate `aws_iam_role` blocks; only
  proceeds if the block contains `assume_role_policy` at all
- **`.json` path**: a bare trust-policy document has no `resource "aws_iam_role"` wrapper, so
  the shared `iter_policy_statement_blocks` walker (the same one `iam-wildcard` uses) isolates
  each statement directly. The file must carry a `"Principal"` key, and each statement must be
  an `Allow` whose `Action` names `sts:AssumeRole`, `...WithWebIdentity` or `...WithSAML`, or a
  pattern covering one of them (`sts:*`, `sts:Assume*`); a bare `*` does not count. Every other
  statement (identity policies and S3/SNS/SQS/KMS resource policies) is skipped.
- For each `"Effect": "Allow"` (or `Effect = "Allow"`) occurrence in the block, the guard
  isolates the **brace-bounded statement object** — the `{...}` that directly encloses that
  `Effect` key — and searches only within that object's own span for a wildcard principal:
  - `"Principal": "*"` (bare string form, no `AWS` key),
  - `"AWS": "*"` (string), or
  - `"AWS": [ ..., "*", ... ]` (the wildcard **anywhere** in the array, not just the first
    element).
  Because the search is bounded to one statement object, a **sibling** `Deny` statement's own
  wildcard principal elsewhere in the same `Statement` array cannot be misattributed to the
  `Allow` — and `Effect` and `Principal` may appear in **either order and any distance** apart
  within the statement. The brace bounding runs on a **string/comment-aware skeleton**
  (`_skeletonize`): string CONTENTS and `#`/`//` comment bodies are blanked before braces are
  matched, so a `{`/`}`/`//`/`#` inside a `Condition` string value (e.g. an `https://` URL or an
  OIDC `aud`) cannot corrupt the object span; the principal search runs on a parallel copy that
  keeps string literals intact but blanks comments. This replaced an earlier fixed 8-line
  forward-window scan that assumed Effect-before-Principal ordering and a first-element array
  wildcard; that shape had three documented false-negatives (Principal-before-Effect, wildcard
  non-first in the array, Principal beyond
  the window) plus a missed bare-string principal — all closed by the brace-bounded scan.
- A `Deny` statement, a principal scoped to a specific account ID/ARN, or a `Service`
  principal outside the source-scoping list does not fire
- A wildcard principal whose statement restricts principals TO one organization does not fire
  `wildcard-principal`: the documented org-wide trust shape, not "any AWS account" (PR #1051
  re-review L4; this narrowed the pre-existing `.tf` path too). See "Org-scoping design rule"
  below for exactly what counts.

### Org-scoping design rule

Settled in the PR #1051 round-3/round-4 re-reviews after the check oscillated between
presence-only (missed negations) and literal-only (fired on Terraform references):

**Fire only on what is provably unscoped. A Condition is evaluated only where it is a readable
literal; anything that cannot be evaluated statically counts as scoped.** Applied at three levels
of the statement's `Condition`:

1. The `Condition` value itself. A reference or function call (`Condition = var.cond`,
   `local.org_condition`, `merge(local.a, {...})`) counts as scoped.
2. A positive operator's value. `StringEquals`, `StringLike`, `ArnEquals` or `ArnLike`
   (optionally `ForAnyValue:`) whose value is not a `{...}` literal (`StringEquals =
   var.org_cond`) counts as scoped.
3. The `aws:PrincipalOrgID`/`aws:PrincipalOrgPaths` value under such an operator. A reference
   (`var.org_id`, `data.aws_organizations_organization.current.id`), a `${...}` interpolation
   (also multi-line or with nested braces, and `"${var.prefix}*"`), a list holding only such
   values, or a specific literal (`"o-abc123def4"`, `"o-x/r-y/ou-*"`) counts as scoped.

Provably unscoped, so `wildcard-principal` still fires:

- a `*` or `?` in the org id (`*`, `o-*`, `o-a*`, `o-abc123def?`; for `PrincipalOrgPaths`, in the
  first path segment);
- a list with any such element (a list is an OR), however it is padded or laid out;
- the self-referential policy variable `${aws:PrincipalOrgID}` (also HCL's escaped
  `$${aws:PrincipalOrgID}`), which any principal in any organization satisfies;
- an operator that never scopes, readable or not: `StringNotEquals` (everyone OUTSIDE the org),
  `Null`, `Bool`, and the `...IfExists` suffix or `ForAllValues:` prefix, both of which evaluate
  true when the key is absent, i.e. for an account in no organization;
- the org key only in a `Sid`, a readable Condition with no org key, or no Condition at all.

**No length caps.** Every list and string value (the `AWS`, `Action` and `Service` lists, the org
value, the operator map) is read by a linear, uncapped scan (`base.iter_policy_key_values`, one
`str.find` per value; `base.neutralize_interpolations`, one brace-depth pass). Round 3 bounded the
value regexes with 1024/4096-char caps to stop quadratic matching; round 4 showed a cap is a
silent bypass (4200 spaces before the `"*"` of an AWS list hid it), so they were removed and the
linearity is pinned by `assert_growth` tests instead.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `iam-role-public-assume/wildcard-principal` | HIGH | `Effect: Allow` statement object contains a wildcard principal: `Principal = "*"`, `AWS = "*"`, or `"*"` anywhere in the `AWS` array, and no positive `aws:PrincipalOrgID`/`aws:PrincipalOrgPaths` condition whose value is not a provable wildcard |
| `iam-role-public-assume/service-principal-no-source-scope` | MEDIUM (review signal) | `Effect: Allow` trust statement grants a source-scoping-list service principal (`sns`, `s3`, `events`, `scheduler`, `cloudtrail`, `config`, `logs`, `delivery.logs`) with no `aws:SourceArn`/`SourceAccount`/`SourceOrgID`/`SourceOrgPaths` condition anywhere in the statement. Skipped if `wildcard-principal` already fired on the same statement (already maximally open). |

## Opt-out

`# security: allow-iam-role-public-assume` in a `.tf` resource block (a real comment); the literal
string anywhere in a `.json` file (JSON has no comment syntax; the same fallback the other
widened IAM guards use, #424).

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| `assume_role_policy = data.aws_iam_policy_document.xyz.json` (external data source, not inline JSON) | No inline `Effect`/`Principal` text exists in the resource body to scan — same class of limitation as `iam_wildcard`'s reliance on visible `"Statement"` content |
| Native HCL `principals { type = "AWS" identifiers = ["*"] }` block form (inside a separate `aws_iam_policy_document` data source, not the inline JSON/`jsonencode()` form) | Out of scope — matches checkov's own `CKV_AWS_60`, which also only handles the JSON-Statement form via `extract_policy_dict` |
| `Principal.AWS` scoped correctly but a *different* attacker-controlled condition narrows nothing | Condition-key semantics are not evaluated (same conservative-vs-precise tradeoff `s3-bucket-policy-wildcard-principal` documents) |
| `aws:SourceArn` present but set to something weak (e.g. a wildcard ARN) | Presence, not strength, is checked: the confused-deputy rule answers "is the documented mitigation key there at all", not "does its value pin one resource" |
| A third-party cross-account trust with no `sts:ExternalId` | Not detected: statically indistinguishable from a same-account or same-org trust (see "Deliberately NOT flagged") |
| A runtime service (`lambda`, `ecs-tasks`, `bedrock`, ...) trusted with no source scoping where that service's docs recommend it | Out of the rule by design; the list is limited to services that act on behalf of another resource |
| A Condition that is not statically readable but in fact does NOT restrict to an organization (`Condition = var.cond` holding nothing org-related) | By the design rule it counts as scoped: only a provably unscoped Condition fires |
| A wildcard trust narrowed by an org key whose NAME is computed (`(local.k) = "o-..."`, `"${var.k}" = ...`) or by an unrelated readable key that does restrict principals (`aws:PrincipalAccount`, `aws:PrincipalArn`) | The org key is not recognised, so the statement fires (a false POSITIVE, the conservative direction); only the two org keys are evaluated |
| A `{`/`}` inside a quoted string within `${...}`, or an unterminated `${` (`"x${"`, HCL `"x$${"`), before the `Principal`/`Action`/`Condition` of the same statement | The brace-depth interpolation scan runs on past the string, so later values in that statement object go unread (only that statement). PR #1051 final review F1, deferred; pinned by `test_known_gap_brace_in_interpolation_string_hides_later_values` |
| A `${...}` interpolation whose own quotes confuse the `.tf` statement-object bounding (`_skeletonize` is string-aware but not interpolation-aware) | Rare layout edge; the org and list scans themselves are interpolation-safe |

## False positive scenarios

None identified in adversarial self-testing — the brace-bounded statement-object scan
matches a wildcard principal only within the same object as an `Effect: Allow`, so a `Deny`
statement's wildcard principal in the same trust policy is not misattributed. The brace
bounding is string/comment-aware, so a `//`/`#`/`{`/`}` inside a `Condition` string value does
not corrupt the object span (covered by `test_iam_role_public_assume_silent_deny_sibling_statement`,
`..._silent_scoped_allow_url_condition_with_deny_sibling`, and
`..._silent_scoped_allow_brace_in_string_with_deny_sibling`).

## Checklist mapping

`6c-iam-role-public-assume` (new item, HIGH)

## Standards

- OWASP:A01 (Broken Access Control)
- CWE-284 (Improper Access Control): `wildcard-principal`
- CWE-441 (Unintended Proxy or Intermediary, the confused-deputy weakness class):
  `service-principal-no-source-scope`

## Related guards

- `iam-wildcard`: flags a policy's own `Action`/`Resource` wildcards, not who may
  assume the role.
- `s3-bucket-policy-wildcard-principal`: the same "wildcard Principal" shape, but for
  S3 bucket policies rather than IAM role trust policies — different resource type,
  same underlying access-control concern.

# Citations

[1] agentsec checklist item `6c-iam-role-public-assume` (§6c)
[2] CWE-284
[3] OWASP:A01
[4] SOC2:CC6.3
[5] AWS IAM User Guide, "The confused deputy problem" (cross-account ExternalId; cross-service
    `aws:SourceArn`/`SourceAccount`/`SourceOrgID`/`SourceOrgPaths`, with the CloudTrail-to-S3
    example): https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html (fetched
    2026-10-18). The per-service list is from the services' own "cross-service confused deputy
    prevention" pages as known to the reviewer; only the IAM guide page and the existence of the
    EventBridge Scheduler page were re-checked on 2026-10-18.
