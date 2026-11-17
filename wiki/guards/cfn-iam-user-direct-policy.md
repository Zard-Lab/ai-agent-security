---
type: Guard
title: "cfn-iam-user-direct-policy"
description: "No IAM policy (inline or managed) attached directly to a CloudFormation IAM user instead of via a group."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-iam-user-direct-policy"
checklist_section: ["6c"]
standards: ["OWASP:A01", "CWE-269"]
---

# IAM policy attached directly to a user instead of via a group (CloudFormation)

Flags CloudFormation IAM resources that attach a policy straight to an individual `AWS::IAM::User`
instead of through a group. Closes a NEW checklist item, `6c-cfn-iam-user-direct-policy` — this is
not a CFN counterpart to the existing Terraform-only `iam-policy-attached-to-user-directly` guard;
it combines two distinct cfn_nag rules into one guard, a shape the Terraform sibling doesn't share,
so it gets its own checklist item rather than extending the Terraform one.

## The threat

Attaching policies directly to individual IAM users (instead of to a group the user is a member
of) means every permission change has to be made per-user. Permissions drift silently as people
join, change roles, and leave, and there is no single place to audit "what can this user's team
do." CWE-269 (Improper Privilege Management).

## Exploitability rationale

MEDIUM. A hygiene/scalability anti-pattern, not itself a direct privilege-escalation vector — one
notch below the escalation-action/wildcard-principal items. It compounds risk over time (drift,
orphaned grants) rather than granting excess privilege in the moment.

## What counts as a hit (and what doesn't)

Two distinct sub-patterns, fired as two distinct rules:

- **`cfn-iam-user-direct-policy/inline-policy-on-user`** — an `AWS::IAM::User` resource whose
  block contains a `Policies:`/`"Policies":` key (an inline policy attached straight to the user).
- **`cfn-iam-user-direct-policy/managed-policy-on-user`** — an `AWS::IAM::ManagedPolicy` or the
  older `AWS::IAM::Policy` resource whose block contains a `Users:`/`"Users":` key (a managed
  policy attached directly to one or more users instead of via that resource's `Groups` property).

Stays silent on:

- An `AWS::IAM::Group` resource with a `Policies` property — the correct pattern, not a hit.
- A `ManagedPolicy`/`Policy` resource that sets `Groups` instead of `Users`.
- An `AWS::IAM::User` resource with no `Policies` property at all.
- Any unrelated resource type.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

Suppress an audited case (e.g. a break-glass user managed outside the normal group model) with a
comment containing `security: allow-iam-user-direct-policy` anywhere in the resource's block (YAML
templates only — JSON has no comment syntax, so a JSON-authored template cannot carry this pragma
at all, a known limitation shared by every CFN guard in this batch):

```yaml
Resources:
  BreakGlassUser:
    Type: AWS::IAM::User
    Properties:
      UserName: break-glass
      Policies:  # security: allow-iam-user-direct-policy
        - PolicyName: emergency-access
          PolicyDocument: {}
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** Fires on the property's presence directly; it does
  not resolve whether a `Users` list actually contains real logical references vs. empty/removed
  entries.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **Textual/regex-only** — a `Policies`/`Users` key anywhere in the resource's block text is
  treated as the property (not a nested unrelated structure that happens to reuse the same key
  name), the same convention every `cfn-*` guard in this batch uses.
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::IAM::User`/`ManagedPolicy`/`Policy` resource in the scanned templates
attaches a policy directly to a user via these two shapes — it says nothing about a user or policy
created outside CloudFormation entirely (the AWS Console, a different IaC tool, a nested stack
this scan didn't independently discover), nor about a `Users` list driven by a CloudFormation
parameter or condition this guard's textual scan can't resolve.

## Canary plant

`cfn_iam_user_direct_policy.yaml` — `AWS::IAM::User` with an inline `Policies` property and no
suppression pragma. Expected rule: `cfn-iam-user-direct-policy/inline-policy-on-user`.

# Citations

[1] agentsec checklist item `6c-cfn-iam-user-direct-policy` (§6c)
[2] OWASP:A01 (Broken Access Control)
[3] CWE-269 (Improper Privilege Management)
[4] cfn_nag (`Stelligent/cfn_nag`) — `UserHasInlinePolicyRule.rb` (rule F10) and
    `ManagedPolicyOnUserRule.rb` (rule F12) (provenance only; detection logic here is original)
