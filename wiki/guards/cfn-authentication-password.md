---
type: Guard
title: "cfn-authentication-password"
description: "AWS::CloudFormation::Authentication resource carrying a literal (non-referenced) password value."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "cfn-authentication-password"
checklist_section: ["8"]
standards: ["OWASP:A02", "CWE-798"]
---

# AWS::CloudFormation::Authentication resource carries a literal password

Flags `AWS::CloudFormation::Authentication` resources whose `password` property is a hardcoded
literal rather than a reference. Closes checklist item `8-cfn-authentication-password` — a
brand-new item, since this resource type is unique to CloudFormation (there is no Terraform
equivalent to extend).

## The threat

`AWS::CloudFormation::Authentication` is a deprecated resource type that supplies credentials
`AWS::CloudFormation::Init` (`cfn-init`) needs to fetch private content during instance
bootstrap — an S3 object behind role-based/IAM auth, or a basic-auth-protected URI. Its
properties are a map of named authentication blocks (the block name and exact nesting are
author-chosen — e.g. an `S3`-typed or `basic`-typed sub-block), each of which can carry a
`password` key at some depth under `Properties`.

Unlike almost every other CFN credential-shaped property, this resource's properties are **not**
accepted as `NoEcho` — AWS's own documentation notes it predates that protection. That means a
hardcoded password here is stored, and displayed, in **plaintext** in the CloudFormation console
(the Resources tab, and the template body itself) to anyone with console read access to the
stack — a materially larger exposure surface than "whoever can read the repo": every IAM
principal with `cloudformation:GetTemplate` or console read on the stack, not just repo
contributors. CWE-798 (Use of Hard-coded Credentials).

## Exploitability rationale

HIGH. This is a real plaintext-credential-exposure risk, but it is gated behind console/API read
access to the stack rather than being a directly network-reachable exploit primitive — the same
reasoning that keeps it below CRITICAL (contrast `hardcoded-private-key-in-source`, which fires
CRITICAL because a committed PEM key is reachable by anyone who can read the repo, a wider and
more passive audience than "has IAM access to this specific stack").

## What counts as a hit (and what doesn't)

- Resource `Type: AWS::CloudFormation::Authentication` with a `Password`/`password` key
  (case-insensitive, any nesting depth inside the resource's own block — the nesting varies by
  auth-block type, so this guard does not assume one specific schema path) whose value is a bare
  or quoted literal string (`password: hunter2`, `"Password": "hunter2"`) → **fires**.
- `password: !Ref DBPassword` (or any other YAML short-form intrinsic tag — `!Sub`, `!GetAtt`,
  `!If`, `!FindInMap`, `!ImportValue`, ...) → **silent**. A leading unquoted `!` is reserved for a
  YAML tag, so it is never a literal value.
- `password: {"Ref": "DBPassword"}` / `password: {Fn::Sub: "..."}` (JSON object syntax, or YAML
  flow-mapping syntax) → **silent**. Any flow-mapping/object-shaped value is treated
  conservatively as non-literal — this guard only fires on an unambiguous bare/quoted scalar.
- `password: '{{resolve:secretsmanager:MySecret:SecretString:password}}'` (a Secrets Manager or
  SSM **dynamic reference**) → **silent**. This looks like a plain string to the parser, but
  CloudFormation resolves it from the named secret at deploy time — no credential material is
  actually present in the template.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).
- An unrelated resource type carrying an incidental `password` key → **silent** (the resource
  `Type` gate is exact-match).

## When NOT to flag (and the pragma)

- Any reference form above (`!Ref`, `Fn::*`, a dynamic reference) → silent, by design.
- A deliberately planted decoy/fixture value → suppress explicitly (YAML templates only — JSON
  has no comment syntax, so a JSON-authored template cannot carry this pragma at all, a known
  limitation shared by every CFN guard in this batch):

```yaml
Resources:
  DecoyAuth:
    Type: AWS::CloudFormation::Authentication
    Properties:
      testBasicAuth:
        type: basic
        password: not-a-real-secret  # security: allow-cfn-authentication-password
```

## Known bypasses (honest limits)

- **No dataflow, no cross-resource reasoning.** The guard reads the literal text of the
  `password` value directly; it does not trace where a referenced parameter's default or a
  `Fn::Sub`'d value ultimately comes from.
- **Textual/regex-only.** The `Password`/`password` key match is a case-insensitive substring
  match anchored by word boundaries (so `PasswordHash` is correctly excluded, since there's no
  word boundary between `d` and `H`), not a structural property-path resolution. Any key literally
  named `password`/`Password` anywhere in the resource's block is treated as the target,
  regardless of the true schema depth.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **An unrecognized object-shaped value is always treated as non-literal**, even if some future,
  unusual object shape were to somehow embed a real literal password inside it — a deliberate
  false-negative bias to keep the guard from misreading a reference form it doesn't recognize as
  a literal (and firing a false positive).
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no `AWS::CloudFormation::Authentication` resource in the scanned templates
carries an unambiguous literal password — it says nothing about a resource created outside
CloudFormation entirely, a nested stack this scan didn't independently discover (see
`agentsec.cfn`'s module docstring on nested-stack scope), or a referenced parameter whose actual
runtime value is itself hardcoded somewhere else (a default value on the parameter, a value
passed at `aws cloudformation deploy` time) — this guard only reasons about the template body.

## Canary plant

`cfn_authentication.yaml` — `AWS::CloudFormation::Authentication` with a `testBasicAuth` block
carrying a literal `password: canary-literal-secret`. Expected rule:
`cfn-authentication-password/literal-password`.

# Citations

[1] agentsec checklist item `8-cfn-authentication-password` (§8)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-798 (Use of Hard-coded Credentials)
[4] cfripper (`Skyscanner/cfripper`) — `cloudformation_authentication.py` (provenance only;
    detection logic here is original)
