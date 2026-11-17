---
type: Guard
title: "cfn-rds-hardcoded-password-no-echo"
description: "No literal or unmasked MasterUserPassword on a CloudFormation RDS instance or cluster."
timestamp: "2026-09-13T00:00:00Z"
guard_id: "cfn-rds-hardcoded-password-no-echo"
checklist_section: ["7"]
standards: ["OWASP:A02", "CWE-798"]
---

# RDS instance/cluster MasterUserPassword is not a literal value / lacks NoEcho on its parameter

Flags `AWS::RDS::DBInstance` and `AWS::RDS::DBCluster` resources whose `MasterUserPassword`
property is either a literal value baked directly into the template, or sourced from a Parameter
that does not declare `NoEcho: true`. This is a **new** checklist item (`7-cfn-rds-hardcoded-
password`) — no existing agentsec item, for any IaC format, covered this pattern before.

## The threat

A database master password is the one credential that unlocks everything the database holds.
Two related CloudFormation authoring mistakes both defeat the point of parameterizing it:

- **A literal value** (`MasterUserPassword: 'hunter2'`) puts the plaintext password directly in
  source control. Every commit, every fork, every CI log that prints the template body has it
  forever — rotating the real database password does not un-leak the copy sitting in git history.
- **A parameter without `NoEcho: true`.** `MasterUserPassword: !Ref DBPassword` looks safer, but
  if `DBPassword`'s own Parameter declaration omits `NoEcho: true`, CloudFormation does not mask
  the value in the console, the CLI/API `describe-stacks`/`describe-stack-events` responses, or
  CloudTrail — the password is still disclosed, one indirection later, to anyone who can read
  stack events/parameters instead of the template file itself.

CWE-798 (Use of Hard-coded Credentials).

## Exploitability rationale

- **Literal value → CRITICAL.** A plaintext database password committed to source is about as
  severe as a hardcoded credential gets: broad blast radius (git history, forks, CI logs, anyone
  with repo read access) and no expiry.
- **Missing `NoEcho` → HIGH.** Real disclosure, but one indirection removed and scoped to whoever
  can read stack events/parameters (typically already AWS-account-privileged) rather than the
  repository's full read-access population — the guard reports it at `high`, one notch below the
  literal case, though the checklist item itself is `critical` overall (the worse of the two
  outcomes the item covers).

## What counts as a hit (and what doesn't)

- `AWS::RDS::DBInstance`/`AWS::RDS::DBCluster` with a literal (non-`Ref`) `MasterUserPassword` —
  bare or quoted, YAML or JSON — fires `cfn-rds-hardcoded-password-no-echo/literal-password`.
- `MasterUserPassword: !Ref X` (YAML) or `{"Ref": "X"}` (JSON) where Parameter `X`'s own
  declaration in the **same file**'s `Parameters:` section does not have `NoEcho: true` fires
  `cfn-rds-hardcoded-password-no-echo/param-missing-noecho`.
- `MasterUserPassword: !Ref X` where `X` **does** declare `NoEcho: true` → silent (the fix).
- A CFN intrinsic other than a bare `Ref` (`!Sub`, `!GetAtt`, `!ImportValue`, `!Join`, `!Select`,
  `!FindInMap`, `!If`, any `Fn::*` form) → silent. This guard does no dataflow tracing beyond the
  one `Ref → Parameter` hop it performs explicitly; an unresolvable intrinsic is treated as
  "unknown" rather than guessed at, to avoid a false positive on a pattern it cannot evaluate.
- A Secrets Manager / SSM Parameter Store dynamic reference embedded in the value
  (`'{{resolve:secretsmanager:...}}'` or `{{resolve:ssm-secure:...}}`) → silent. This is the
  AWS-recommended safe pattern — the opposite of a hardcoded password — and is recognized
  explicitly rather than mistaken for a literal string.
- An unrelated resource type (e.g. `AWS::S3::Bucket`) → silent.
- Both YAML and JSON template formats are scanned identically (see `agentsec/cfn.py`'s module
  docstring for how the two formats converge on one `block` text every CFN guard scans the same
  way).

## When NOT to flag (and the pragma)

Suppress an audited exception (e.g. a canary/demo template intentionally seeded with a throwaway
value) with a comment anywhere in the resource's block (YAML templates only — JSON has no
comment syntax, so a JSON-authored template cannot carry this pragma at all, the same known
limitation shared by every CFN guard in this batch):

```yaml
Resources:
  ThrowawayDemoDb:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: demo-only-value  # security: allow-rds-hardcoded-password
```

## Known bypasses (honest limits)

- **No dataflow beyond one `Ref` hop.** `MasterUserPassword: !Ref X` is traced to `X`'s
  declaration in the same file only; a Parameter defined in a nested/parent stack, or referenced
  indirectly through a `Fn::Sub` string interpolation, is not resolved — silently not flagged.
- **File-level location, not line-level** — like every CFN guard in this batch, the finding
  reports the template file, not a specific line (see `agentsec/cfn.py`'s module docstring for
  why: a JSON block is a `json.dumps` reconstruction with no original line mapping to report).
- **JSON templates cannot carry the suppression pragma** — JSON has no comment syntax.
- **The cluster/instance relationship is not cross-checked.** cfripper's real implementation
  (`hardcoded_RDS_password.py`) suppresses flagging a `DBInstance` for a password already covered
  by its `DBCluster` (via `DBClusterIdentifier`), to avoid a double-flag on a cluster-managed
  instance. This guard makes a deliberate, simpler v1 scope choice instead: it evaluates every
  `AWS::RDS::DBInstance`/`AWS::RDS::DBCluster` resource independently, on whatever
  `MasterUserPassword` value is actually present in *that* resource's own block. In practice a
  `DBInstance` that is part of a cluster normally has no `MasterUserPassword` property at all (the
  cluster owns it), so this guard's independent-evaluation approach produces no finding for it
  either — the same net effect as cfripper's cross-check, reached by a narrower mechanism. The
  case that genuinely differs: if an instance belonging to a cluster is *also* given its own
  literal/unmasked `MasterUserPassword` (unusual, and arguably a separate authoring mistake in its
  own right), this guard flags both resources rather than suppressing the instance — treated here
  as a defensible, honest trade rather than an oversight, since both resources really do carry an
  exposed password value in that scenario.
- **Case (b) was implemented, not deferred** (`NoEcho`-parameter tracing). A first read suggested
  deferring it as "the harder cross-section case", but the same-file `Parameters:` block lookup is
  the same indentation-scoped section splitting `Resources:` already needs (YAML) plus a plain dict
  lookup (JSON) — no new parsing strategy, so it was in scope. It now shares `agentsec.cfn`'s one
  `iter_yaml_section_blocks` walker with `_yaml_resources` rather than carrying its own copy: the
  copy silently missed #856's header-comment (`Parameters:  # ...`) tolerance fix and became a
  false negative (#857), which is exactly the drift a shared walker prevents. What's still deferred
  is the cross-*file*/nested-stack case above, which is a materially different (and materially
  harder) problem.
- **YAML block-scalar values inside a resource are captured as ordinary block text** — a
  documented, not-yet-observed-in-practice residual shared by the whole `agentsec.cfn` parser.

## What this guard does NOT prove

A clean scan means no scanned `AWS::RDS::DBInstance`/`AWS::RDS::DBCluster` resource has a literal
`MasterUserPassword` or an unmasked parameterized one traceable within the same file. It says
nothing about a database provisioned outside CloudFormation entirely (the AWS Console, a different
IaC tool, a nested stack this scan didn't independently discover), a password rotated later via
Secrets Manager rotation (a separate, orthogonal control this guard doesn't evaluate), or a
Parameter referenced across files/stacks that this guard's same-file lookup cannot resolve.

## Canary plant

`cfn_rds_password.yaml` — `AWS::RDS::DBInstance` with a literal `MasterUserPassword`. Expected
rule: `cfn-rds-hardcoded-password-no-echo/literal-password`.

# Examples

Vulnerable (literal):

```yaml
Resources:
  MyDb:
    Type: AWS::RDS::DBInstance
    Properties:
      Engine: postgres
      MasterUsername: admin
      MasterUserPassword: hunter2
```

Vulnerable (parameterized, but the parameter isn't masked):

```yaml
Parameters:
  DBPassword:
    Type: String
Resources:
  MyDb:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: !Ref DBPassword
```

Fixed:

```yaml
Parameters:
  DBPassword:
    Type: String
    NoEcho: true
Resources:
  MyDb:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUserPassword: !Ref DBPassword
```

# Citations

[1] agentsec checklist item `7-cfn-rds-hardcoded-password` (§7)
[2] OWASP:A02 (Cryptographic Failures)
[3] CWE-798 (Use of Hard-coded Credentials)
[4] cfripper (`Skyscanner/cfripper`) — `hardcoded_RDS_password.py` (provenance only; detection
    logic here is original, including this guard's own take on the cluster/instance relationship)
