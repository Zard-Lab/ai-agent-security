---
type: Guard
title: "terraform-hardcoded-secret-literal"
description: "Hardcoded credential literal in a Terraform resource attribute."
timestamp: "2026-07-15T08:42:55+08:00"
guard_id: "terraform-hardcoded-secret-literal"
checklist_section: ["6c"]
standards: ["CWE-259", "OWASP:A04"]
---

# Hardcoded credential literal in a Terraform resource attribute

_Author — 2026-07-15_

---

## The threat

A Terraform resource or provider block that assigns a credential-shaped attribute
(`password`, `secret`, `access_key`, `secret_key`, and close variants) a literal quoted
string commits that credential to version control the moment the file is committed.
Anyone with read access to the repository — including its full git history, any fork, or a
CI log that echoes the plan/apply output — has the live value. This is CWE-259 (Use of
Hard-coded Password) and OWASP:A04 (Cryptographic Failures): a static secret baked into
source is not rotatable without a code change, is trivially exfiltrated by anyone who ever
had repo access (even after the line is later removed — git history retains it), and is the
exact failure mode `git-secrets`/`gitleaks`/`trufflehog` exist to catch retroactively. This
guard catches it proactively, at the source, before the commit ever needs a history scan.

## Why this guard fits the stack

Terraform is the delivery mechanism for the flagship stack's cloud infrastructure (RDS,
S3, IAM, VPC). A database `password`, a provider's static AWS `access_key`/`secret_key`, or
an application's `api_key`/`client_secret` config value is routinely typed as a literal
during a first draft or a quick local test — `terraform apply` doesn't care whether the
value came from a variable or a literal, so nothing forces the safer form:

```hcl
resource "aws_db_instance" "app" {
  engine   = "postgres"
  password = "hunter2CHANGE"     # <- committed straight into version control
}

provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
```

The correct form routes the value through a variable (`sensitive = true`) sourced from
`TF_VAR_*` or a secrets manager, never a literal in the `.tf` file itself.

## Detection design

1. **`applies()` gate** — `"terraform" in profile.features` (same gate as
   `rds-publicly-accessible` and `iam-wildcard`'s `.tf` half).
2. **Scanned files** — every `.tf` file under the repo root (`iter_files(root, (".tf",))`),
   skipping non-product paths (tests/fixtures/examples) via `is_nonproduct_path`.
3. **Block scoping** — two block shapes are walked, both scanned for the same attribute
   pattern:
   - `resource "type" "name" { ... }` via the shared `iter_terraform_resources()` helper
     (`agentsec/guards/base.py`), which isolates each block by string/comment/heredoc-aware
     brace-depth tracking from the resource's own opening line.
   - `provider "type" { ... }` via the shared `iter_terraform_provider_blocks()` helper
     (`agentsec/guards/base.py`) — `iter_terraform_resources()` only recognizes the two-label
     `resource "type" "name"` opener, not a provider block's single-label form, and a
     provider block (a static-credentials AWS/GCP/etc. provider) is a common real-world home
     for exactly this mistake, so it needed its own opener rather than being silently out of
     scope. It uses the SAME string/comment/heredoc-aware brace counting as the resource walker
     (both share `base.py::_tf_line_scan`), so a stray `}` inside a `<<EOF` heredoc body no
     longer closes a provider block early (an earlier hand-rolled local walker did have that
     gap; it was replaced with the shared helper).
   - Deliberately **not** restricted to specific resource/provider types (unlike
     `rds-publicly-accessible`'s `aws_db_instance`/`aws_rds_cluster_instance` filter, or
     `iam-managed-admin-policy-attached`'s IAM-type filter) — a hardcoded credential is the
     same mistake regardless of which resource or provider carries it.
4. **The pattern** — within a block's own body lines, a line matching (case-insensitive):
   `^\s*(password|secret|secret_key|secret_access_key|access_key|access_key_id|api_key|api_token|auth_token|client_secret|private_key)\s*=\s*"[^"]{8,}"`
   anchored so the attribute name must open the (trimmed) line — `password_hash_algorithm = "bcrypt"`
   does not match, because after `password` the regex requires `\s*=`, not `_hash_algorithm...`.
   A comment line (`#`/`//` prefix) is skipped before the pattern is even tried.
5. **The opt-out pragma** — `# security: allow-tf-hardcoded-secret` on the attribute line.
6. **Severity / rule / standards** — HIGH,
   `terraform-hardcoded-secret-literal/attribute-literal`, `["OWASP:A04", "CWE-259"]`.

### Source and adaptation from drogonsec

Ported from drogonsec's (`filipi86/drogonsec`) `TF-001` Terraform rule:

```go
Pattern: mustCompile(`(?i)(password|secret|access_key|secret_key)\s*=\s*"[^"]{4,}"`),
```

Two deliberate changes from the source pattern:

- **Block-scoped, not file-wide.** drogonsec's regex runs unscoped over the whole file text.
  This guard instead walks resource/provider block bodies (see above) so every finding is
  attributed to the specific block it lives in (`resource_type.resource_name` or
  `provider.type` in the message) — consistent with every other Terraform guard in this
  codebase, and it means a credential-shaped word appearing in a non-block context (a
  top-level `locals`/`output`/`variable` block, or free text outside any block) does not fire,
  since those are not resource configuration.
- **Minimum literal length raised from 4 to 8.** A 4-7 character literal
  (`"xxx"`, `"TODO"`, `"test"`, `"none"`) is overwhelmingly a placeholder, not a real secret,
  and was the dominant noise source when prototyping this guard against realistic Terraform
  fixtures. Real credential-shaped values (generated passwords, API keys, access-key IDs) are
  near-universally 8+ characters, so this cuts the placeholder-noise class without losing a
  real positive in practice.

## When NOT to flag

- **A variable reference**: `password = var.db_password`. The right-hand side is not a
  quoted string literal, so the regex's `=\s*"` never matches — this is the correct,
  recommended pattern and must stay silent.
- **A data-source reference**: `secret_key = data.aws_secretsmanager_secret_version.x.secret_string`.
  Same reasoning — no literal quote immediately follows `=`.
- **A short/placeholder value**: `password = "xxx"` (under 8 chars) — treated as noise, not a
  credential, per the length-threshold rationale above.
- **A commented-out line**: `# password = "example12345"` — skipped before the pattern is
  even tried, matching every other guard's comment-handling convention.
- **An audited, intentionally-fake value** (e.g. a documented placeholder in an example/demo
  module): suppress with `# security: allow-tf-hardcoded-secret` on the attribute line.

## Tests

| Test | What it checks |
|---|---|
| `test_terraform_hardcoded_secret_literal_flags_resource_password` | `aws_db_instance.password = "hunter2CHANGE"` fires one finding, HIGH, correct rule id |
| `test_terraform_hardcoded_secret_literal_flags_provider_secret_key` | `provider "aws" { access_key = "...", secret_key = "..." }` fires two findings — proves the provider-block walker works |
| `test_terraform_hardcoded_secret_literal_fires_after_provider_heredoc` | a `secret_key` after a heredoc with a stray `}` in a provider block still fires — proves the shared heredoc-aware walker does not close the block early |
| `test_terraform_hardcoded_secret_literal_silent_on_variable_reference` | `password = var.db_password` stays silent |
| `test_terraform_hardcoded_secret_literal_silent_on_data_source_reference` | `secret_key = data.aws_secretsmanager_secret_version.x.secret_string` stays silent |
| `test_terraform_hardcoded_secret_literal_silent_on_comment` | `# password = "example12345"` stays silent |
| `test_terraform_hardcoded_secret_literal_silent_below_length_threshold` | `password = "abcd"` (4 chars) stays silent |
| `test_terraform_hardcoded_secret_literal_silent_on_unrelated_attribute_name` | `password_hash_algorithm = "bcrypt12"` stays silent (name-anchoring proof) |
| `test_terraform_hardcoded_secret_literal_pragma_silences` | `# security: allow-tf-hardcoded-secret` suppresses an otherwise-firing line |
| `test_terraform_hardcoded_secret_literal_applies_gate` | `applies()` is `False` without `"terraform"` in features |
| `test_terraform_hardcoded_secret_literal_applies_with_terraform` | `applies()` is `True` with `"terraform"` in features |

## Known bypasses

- **Any indirection at all** — a value built from `local.` interpolation, a
  `templatefile()` call, string concatenation (`"${var.prefix}-secret"`), or a value read
  from a `.tfvars` file (which this guard does not scan) all evade the literal-string match.
  Only a bare, directly-typed literal on the attribute's own line is caught.
- **A credential-shaped word the guard's name list doesn't include** — e.g. a
  project-specific `db_pass`/`token` attribute name that isn't one of the listed spellings.
  The name list is deliberately conservative (common AWS/Terraform-provider spellings) to
  avoid false positives on unrelated `*_secret`-suffixed config knobs.
- **A value split across multiple lines or built via `jsonencode`/a nested object** — the
  pattern expects the literal on the same physical line as the attribute name.

## What this guard does NOT prove

- It does not prove the flagged value is actually a *live, currently-valid* credential — a
  finding fires on any literal ≥ 8 chars on a credential-shaped attribute, including an
  already-rotated/dead value left in place, or a well-known public example key
  (`AKIAIOSFODNN7EXAMPLE`, AWS's own documentation placeholder — still worth flagging, since
  its presence signals the pattern even when the specific value is safe).
- It does not scan `.tfvars`/`.tfvars.json` files, environment files, or Terraform Cloud
  workspace variable configuration — a credential could be hardcoded there instead, entirely
  outside this guard's `.tf`-only scope.
- It does not detect a credential leaked via Terraform *state* (`.tfstate`, which stores
  resolved attribute values including ones sourced from a variable) — a separate, larger
  problem (state files routinely need their own encryption-at-rest / access-control review)
  this guard makes no claim about.
- Passing this guard does not mean the repo's Terraform is otherwise secure — it is one
  narrow literal-credential check, not a substitute for `tfsec`/`checkov`-class full IaC
  scanning.

## Checklist mapping

Section 7 (data/infra security) — no prior checklist item exists for a Terraform
credential literal specifically (the closest existing item, `1-gitleaks-secret-scan`, is a
retroactive git-history secret scan via an external scanner, not a proactive static check on
`.tf` source itself). Proposed new item id: `7-terraform-no-hardcoded-secret-literal`
(left for the integration pass — this guard's own change set does not touch
`checklist.json`).

## Standards

- OWASP:A04 (Cryptographic Failures)
- CWE-259 (Use of Hard-coded Password)

## Related guards

- **`iam-wildcard`**: scans `.json`/`.tf` files that look like an AWS IAM *policy statement*
  (the file must contain both `"Statement"` and `"Effect"`), flagging `"Action": "*"` /
  `"Resource": "*"` wildcards. Completely different attribute shape and completely different
  file scope — an IAM policy document has no bare `password = "literal"` attribute at all,
  and this guard never looks inside a `"Statement"` array. Verified via
  `grep -rn "applies_when\|\.tf\b" agentsec/guards/iam_wildcard.py` and reading its scan
  logic: it only ever regex-searches lines for `"Action"`/`"Resource"` wildcard JSON shapes,
  never a generic resource/provider attribute. Cross-checked against `iam-wildcard`'s own
  canary fixture (`infra/policy.json`, an `Action: "*"` policy with no bare credential
  attribute) — this guard does not fire on it (and would not even inspect it, since it only
  scans `.tf` files).
- **`iam-managed-admin-policy-attached`**: flags an AWS-managed admin policy *ARN reference*
  attached to an IAM role/user (e.g. `arn:aws:iam::aws:policy/AdministratorAccess`) — an
  over-privileged access-control finding, not a credential-value finding. An ARN string is
  not a credential literal in the sense this guard cares about, so there is no overlap: this
  guard's pattern only matches a credential-shaped attribute *name* (`password`, `secret_key`,
  etc.) assigned a literal, never a `policy_arn`/`managed_policy_arns` attribute.
- **`rds-publicly-accessible`**: same `iter_terraform_resources()` helper and file scope
  (`.tf`), but a completely different attribute (`publicly_accessible = true`, a boolean
  network-exposure flag) and resource-type-restricted (`aws_db_instance`/
  `aws_rds_cluster_instance` only). Verified this guard's own canary fixture (`rds.tf`, which
  sets `publicly_accessible = true` but has no bare `password`/`secret`/`access_key` literal)
  does not cross-fire on `terraform-hardcoded-secret-literal`.

# Citations

[1] agentsec checklist item `6c-terraform-hardcoded-secret-literal` (§6c)
[2] CWE-259
[3] OWASP:A04
