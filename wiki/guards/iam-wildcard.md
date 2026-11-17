---
type: Guard
title: "iam-wildcard"
description: "No wildcard-everything (*) IAM policy grants."
timestamp: "2026-06-17T11:40:50+08:00"
guard_id: "iam-wildcard"
checklist_section: ["6c"]
standards: ["OWASP:A01", "SOC2:CC6.3"]
---

# No wildcard-everything (*) IAM policy grants

Flags an IAM policy statement granting `"Action": "*"` or `"Resource": "*"` under `"Effect": "Allow"`,
plus (2026-10-08, aws-agent-identity-guard research-cycle) a PARTIAL wildcard action pattern
(`iam:*Role*`, `iam:Put*`) that EXPANDS, via the same glob matching AWS's own policy evaluation uses,
to cover a privilege-escalation or defence-evasion action. Closes checklist item `6c-iam-no-wildcard`. Scans `.json`/`.tf`
files that look like an IAM policy.

## The threat
A full wildcard grant hands whatever assumes the role the entire account: a stolen token or a
prompt-injected agent can then delete every bucket, read every secret, and escalate. Least privilege
(CWE-269) is the control. OWASP A01. A partial wildcard is the same threat in a less obvious shape:
`iam:*Role*` doesn't look like a wildcard-everything grant, but `fnmatch.fnmatchcase` (the same
shell-glob semantics IAM itself uses to decide whether an action pattern matches a given action)
shows it covers `iam:PassRole`, the single highest-value privilege-escalation action on AWS.

## Exploitability rationale
HIGH. The blast radius is the whole account (bare wildcard) or a specific dangerous capability
(partial wildcard); reachable by anything that can assume the role.

## When NOT to flag (and the pragma)
- **Scoped wildcards** (`s3:*`, an ARN with a trailing `*`) are common and not flagged — only the
  all-actions (`"*"` / `"*:*"`) and all-resources (`"Resource": "*"`) cases fire via `action-star`/
  `resource-star`. The new `partial-wildcard-dangerous` rule deliberately excludes these same two
  forms too (a bare `"*"` or an exact `"svc:*"` suffix never reaches it): only a pattern that
  wildcards WITHIN an action name (not the whole service) is checked against the dangerous-action
  set.
- The dangerous-action set holds privilege-escalation and defence-evasion actions only: the IAM
  policy/role/user writes (`iam:PassRole`, `iam:PutRolePolicy`, `iam:AttachRolePolicy`,
  `iam:CreatePolicyVersion`, ...), `sts:AssumeRole`, `cloudtrail:StopLogging`/`DeleteTrail` and
  `guardduty:DeleteDetector`. Data reads and invokes are NOT in it (PR #1051 review, H2): `s3:Get*`,
  `ssm:Get*`, `kms:Decrypt*`, `secretsmanager:Get*`, `lambda:Invoke*` and `bedrock:Invoke*` stay
  silent under this rule, because a read scoped to one bucket or parameter path is the
  least-privilege grant, and the guard never flagged the strictly wider `s3:*`. `ec2:Describe*`
  stays silent for the same reason.
- A pattern under `NotAction` is an exclusion, not an expansion, so this rule reads `Action` only;
  `iam-notaction-with-allow` owns the `Allow` + `NotAction` statement.
- A file that is not an IAM policy (no `"Statement"` + `"Effect"`) is skipped (so a `tsconfig.json`
  with `"*"` is silent).
- An audited statement → `# security: allow-iam-wildcard` in the file.

## Known bypasses (honest limits)
- (partial-wildcard rule) A `{`/`}` inside a quoted string within a `${...}` interpolation (`"${replace(var.arn, "{",
  "")}"`), or an unterminated `${` (`"x${"`, HCL `"x$${"`), makes the brace-depth interpolation scan
  run on past the string, so `Action`/`Resource`/`Principal` values LATER in the same statement go
  unread. Scope: the rest of that enclosing statement object only; other statements are unaffected.
  Known gap from the PR #1051 final review (F1), deferred; pinned by
  `tests/test_iam_policy_guard_prechecks.py::test_known_gap_brace_in_interpolation_string_hides_later_values`.
- Policies built at runtime (CDK/Pulumi code, `jsonencode` with variables) are not evaluated.
- A wildcard split across constructs the regex cannot see is missed.
- The dangerous-action set the partial-wildcard check matches against is a fixed list (adapted
  from aws-agent-identity-guard): a pattern that expands to a dangerous action NOT on that list is
  invisible to this rule, even though the mechanism (fnmatch expansion) would catch it if the list
  were complete. A partial wildcard over a sensitive DATA read (`secretsmanager:Get*` on
  `Resource: "*"`) is out of this rule by design; `resource-star` still fires on the `*` resource.

## What this guard does NOT prove
It flags literal `*` grants in policy documents; it does not evaluate effective permissions, attached
managed policies, or runtime-constructed policies. Absence of a finding ≠ least privilege.

# Citations

[1] agentsec checklist item `6c-iam-no-wildcard` (§6c)
[2] OWASP:A01
[3] SOC2:CC6.3
