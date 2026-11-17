---
type: Research
title: Checkov IaC Policies — Agentic Security Patterns
description: Statically-detectable Terraform and Dockerfile security patterns distilled from Checkov's built-in policy catalog, covering exposed and unencrypted RDS databases, S3 bucket public-access controls, S3 bucket policy wildcard principals, IAM hygiene (managed-admin-policy attachment, direct-to-user policies, public role-assumption trust policies), CloudTrail audit-logging gaps, resource-level encryption-at-rest/KMS hygiene (DynamoDB, Secrets Manager, EBS, SQS, SNS, ECR, CloudWatch Logs), and Docker layer-caching package hygiene.
tags: [research, terraform, iac, docker, aws, s3, rds, iam, cloudtrail, kms, encryption]
timestamp: "2026-08-16T00:00:00Z"
---

# Checkov IaC Policies — Agentic Security Patterns

## What this covers

Checkov is a static code analysis tool for infrastructure as code (IaC) with over 1,000
built-in policies covering Terraform, CloudFormation, Kubernetes, Dockerfile, and several
other IaC formats. Its Python check source (unlike some scanners whose rule engines are
written in a compiled language) is directly readable, making its detection logic easy to
verify and adapt. This document distills patterns targeted specifically at the thinnest
areas of existing static coverage: Terraform database and storage exposure, IAM hygiene,
CloudTrail audit logging, and Dockerfile package-management hygiene.

## Terraform — RDS database exposure

| Pattern | What it catches | Detection approach |
|---|---|---|
| `aws_db_instance`/`aws_rds_cluster_instance` with `publicly_accessible = true` | The database is assigned a public IP reachable from the internet — combined with any permissive security-group rule, one of the most common real-world causes of an exposed production database | Resource-block scan (brace-depth tracking from the resource's own opening line) for the attribute set to `true`; an omitted attribute is safe (defaults to `false`) |
| `aws_db_instance` without `storage_encrypted = true` anywhere in its body | RDS storage encryption is opt-in and defaults to `false` if never set — a database with disk-level encryption disabled lets anyone with access to the underlying storage layer (a snapshot, a volume backup) read the raw data directly | Absence check across the whole resource body, not a per-line presence check — "attribute missing entirely" and "explicit false" are treated identically, since the missing case is the more common real-world mistake |

## Terraform — S3 bucket exposure

| Pattern | What it catches | Detection approach |
|---|---|---|
| `aws_s3_bucket_public_access_block` with any of its four controls (`block_public_acls`, `block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`) set to `false` | AWS's Block Public Access feature exists so a later accidental public ACL or bucket policy can't actually make a bucket public — disabling one control re-opens that specific path | Per-attribute regex within the resource block; an omitted attribute is safe (all four default to `true`) |
| An S3 bucket policy statement granting an action to `Principal: "*"` with no `Condition` anywhere in the resource | Grants the action to every AWS account in existence, and to anyone on the internet if the bucket isn't otherwise locked down | Whole-resource-body scan (not per-line — the nested `{"AWS": "*"}` form commonly spans multiple physical lines) for a wildcard principal, JSON-string or `jsonencode()` HCL-map form; any `Condition` present anywhere in the resource is conservatively treated as a plausible narrowing |

The `Condition`-presence check is a deliberate simplification: a real policy-analysis engine
would need to determine whether a given `Condition` actually narrows the grant (some
condition keys do, some don't) — this pattern instead treats any `Condition` at all as
sufficient reason to stay silent, trading a known false-negative class (an ineffective
`Condition`) for a much lower false-positive rate than attempting to fully replicate that
condition-key-aware logic with pattern matching.

## Terraform — IAM hygiene

| Pattern | What it catches | Detection approach |
|---|---|---|
| `aws_iam_role`/attachment resources referencing the AWS-managed `AdministratorAccess` policy ARN via `policy_arn`/`managed_policy_arn(s)` | The managed policy grants unrestricted `Action: "*"` / `Resource: "*"` on every AWS service — the single-ARN equivalent of an inline wildcard statement, but invisible to a guard that only looks for inline JSON `Statement` content | Resource-block scan for a line carrying both a `policy_arn`/`managed_policy_arn(s)` attribute name and the literal AdministratorAccess ARN |
| `aws_iam_user_policy`/`aws_iam_user_policy_attachment` resources, or an `aws_iam_policy_attachment` with a non-empty `users` list | Policies attached directly to individual users (instead of a group or role) drift silently as people join, change roles, and leave, with no single group/role to audit | Resource-type declaration itself is the signal for the two user-specific resource types (no legitimate non-user use exists); a text check for non-empty `users = [...]` on the mixed-target attachment resource |
| `aws_iam_role`'s `assume_role_policy` (trust policy) with `Effect: Allow` and `Principal: {"AWS": "*"}` | Any AWS account in existence can call `sts:AssumeRole` and take on the role's permissions — no membership in the same account required | Per-statement bounded scan: same line first (for a compact/minified statement), else forward to the next `Effect` line as a boundary, so a sibling `Deny` statement's own wildcard principal in the same trust policy can't be misattributed to a preceding scoped `Allow` statement |

## Terraform — CloudTrail audit logging

| Pattern | What it catches | Detection approach |
|---|---|---|
| `aws_cloudtrail` with `enable_logging = false` | The trail exists but records no API activity at all, leaving zero audit history to investigate a compromise | Resource-block scan for the literal `false` |
| `aws_cloudtrail` with `is_multi_region_trail = false` | The trail silently misses every API call made outside its home region — a common blind spot for an attacker pivoting through a compromised credential | Resource-block scan for the literal `false` |

## Dockerfile — package-management layer hygiene

| Pattern | What it catches | Detection approach |
|---|---|---|
| `RUN apt-get update` (or `apt`/`yum`/`dnf`/`apk` equivalents) with no matching install command in the same `RUN` instruction | Docker caches each `RUN` instruction as an independent layer — an update in one layer and an install in a separate later layer risks a rebuild reusing a stale cached update layer while rebuilding the install layer, installing packages missing security patches released since | Per-`RUN`-instruction scan (backslash line continuations joined into one logical line first) for an update keyword without an install-family keyword in the same instruction |

This pattern is checked at the single-instruction level rather than as a whole-file
occurrence count — an update and a matching install in two *separate* `RUN` instructions
still carries the layer-caching risk this pattern targets, even though a looser whole-file
balance check would treat that shape as fine.

## Terraform — resource encryption-at-rest / KMS

Seven AWS resource types, none with any prior static coverage. Two distinct risk shapes
appear across them, worth distinguishing rather than treating uniformly:

- **Opt-in encryption, genuinely off by default** (EBS, SNS): the resource ships
  unencrypted unless a specific attribute is set. Missing the attribute means plaintext
  at rest, no caveat.
- **Encrypted by default with an AWS-owned/managed key, missing only the upgrade to a
  customer-managed key** (SQS, DynamoDB, Secrets Manager, ECR, CloudWatch Logs): data is
  never actually in the clear, but the account has no independent key-policy control or audit
  trail separate from the resource's own IAM permissions. SQS gained SSE-SQS (an AWS-owned
  key) as the default for every new queue in October 2022, so a queue with neither
  `sqs_managed_sse_enabled = true` nor a `kms_master_key_id` is encrypted with that AWS-owned
  key, not plaintext — the guard fires `medium` for the missing customer-managed upgrade.

| Pattern | What it catches | Detection approach |
|---|---|---|
| `aws_ebs_volume` without `encrypted = true` | EBS encryption is opt-in per volume, defaulting to `false` — anyone with access to the underlying storage (snapshot, detached volume) reads raw data directly | Whole-block absence check, same shape as `RDSEncryption` |
| `aws_sqs_queue` with neither `sqs_managed_sse_enabled = true` nor a non-empty `kms_master_key_id` | SSE-SQS (an AWS-owned key) is on by default since Oct 2022, so message bodies (often carrying async job payloads with PII or internal context) are encrypted — but with a key the account cannot independently audit or narrow, missing the customer-managed upgrade | Either-of-two-attributes absence check across the whole resource body |
| `aws_sns_topic` without a non-empty `kms_master_key_id` | SNS server-side encryption is opt-in — fan-out message bodies stored in plaintext | Single-attribute absence check (ANY_VALUE semantics — any literal value, including an AWS-managed alias, satisfies it) |
| `aws_dynamodb_table` without a `server_side_encryption { enabled = true; kms_key_arn = ... }` block, both fields present | Encrypted by default with an AWS-owned key; without a CMK, the account has no independent key-policy control | Nested single-level block extraction, then both-attributes-present check inside it |
| `aws_secretsmanager_secret` without a `kms_key_id` not containing the `aws/` default-alias substring | Encrypted by default with the account's `aws/secretsmanager` AWS-managed key; the key policy is AWS-controlled, not narrowable | Literal-value extraction + default-alias substring match |
| `aws_ecr_repository` without `encryption_configuration { encryption_type = "KMS" }` | Encrypted by default (AES256, AWS-owned key); container images (which can embed secrets, private source, or model weights) have no independently auditable key | Nested single-level block extraction, then literal-value match inside it |
| `aws_cloudwatch_log_group` without a non-empty `kms_key_id` | Encrypted by default with CloudWatch Logs' own AWS-managed key; log data (which routinely captures request bodies or accidental secrets) has no independent key-policy control | Single-attribute absence check (ANY_VALUE semantics) |

All seven honor a per-resource `# security: allow-<guard-id>` suppress pragma and treat a
commented-out attribute as absent (comment-blanked before pattern matching, so a
`# encrypted = true` left as a TODO can't silently suppress a genuine finding).

## Coverage summary

| Category | Detection technique | Coverage |
|---|---|---|
| RDS public accessibility | Single-attribute resource-block scan | `aws_db_instance`/`aws_rds_cluster_instance` literal `true` covered; variable-indirected values and module-passthrough are not |
| RDS storage encryption | Whole-block absence check | `aws_db_instance` covered; Aurora cluster resources (`aws_rds_cluster`) use a different attribute shape and are out of scope |
| S3 public-access-block | Per-attribute resource-block scan | All four Block Public Access attributes covered when the resource exists; a bucket with no public-access-block resource at all requires cross-resource correlation this pattern doesn't attempt |
| S3 bucket policy wildcard principal | Whole-resource-body scan, condition-presence heuristic | Direct and nested wildcard-principal forms covered; condition-key semantic analysis (whether a `Condition` actually narrows the grant) is deliberately not attempted |
| Dockerfile update/install layer separation | Per-instruction scan with line-continuation joining | Any single `RUN` instruction's own command text covered; a called external script's internal update/install behavior is not visible |
| IAM managed-admin-policy attachment | Attribute-line literal-ARN match | `policy_arn`/`managed_policy_arn(s)` attribute on the same line as the attribute name covered; a list where the ARN is on its own separate line is not |
| IAM direct-to-user policy attachment | Resource-type declaration + attribute check | `aws_iam_user_policy`/`aws_iam_user_policy_attachment` fully covered (the resource type alone is the signal); `aws_iam_policy_attachment` covered only when `users` is a visible non-empty literal list |
| IAM role trust-policy wildcard principal | Bounded per-statement scan | Inline JSON/`jsonencode()` `Effect`+`Principal` forms covered, including compact single-line statements; a trust policy sourced from a separate `data.aws_iam_policy_document` (native HCL `principals {}` block) is out of scope |
| CloudTrail logging/multi-region | Resource-block literal-boolean scan | Explicit `false` on either attribute covered; an omitted attribute is treated as safe (provider defaults) |
| EBS/SNS opt-in encryption (genuinely off by default) | Whole-block / single-attribute absence check | Literal-value presence covered; account/region-level "encryption by default" settings (EBS only) are invisible to a source-only check |
| SQS encryption declaration (missing customer-managed upgrade) | Either-of-two-attributes absence check | A block with neither `sqs_managed_sse_enabled = true` nor a non-empty `kms_master_key_id` covered; the SSE-SQS AWS-owned-key default (on since Oct 2022) is invisible to a source-only check, so the finding is the absent explicit encryption / customer-managed upgrade |
| DynamoDB/ECR customer-managed-KMS upgrade | Nested single-level block extraction | Both-attributes-present (DynamoDB) / literal-enum-match (ECR) covered; a resource nested inside a `module` block is out of scope |
| Secrets Manager/CloudWatch Logs customer-managed-KMS upgrade | Default-alias / ANY_VALUE absence check | Literal and reference presence covered; a variable- or resource-indirected `kms_key_id` is treated as "set" and stays silent for all of them (matching checkov's own permissive `is not None` semantics), except Secrets Manager still fires on the bare keyword `null` and on an `aws/` default-alias literal |

## Examples

```hcl
# FLAGGED: database directly reachable from the internet
resource "aws_db_instance" "app" {
  engine              = "postgres"
  publicly_accessible = true
}

# FLAGGED: storage encryption never set, defaults to false
resource "aws_db_instance" "app" {
  engine = "postgres"
}

# FLAGGED: one of the four Block Public Access controls explicitly disabled
resource "aws_s3_bucket_public_access_block" "app" {
  block_public_acls = false
}

# FLAGGED: wildcard principal, no Condition to narrow it
resource "aws_s3_bucket_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
    }]
  })
}

# SAFE: wildcard principal narrowed by a Condition
resource "aws_s3_bucket_policy" "app" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Condition = {
        StringEquals = { "aws:SourceVpce" = "vpce-123" }
      }
    }]
  })
}
```

```dockerfile
# FLAGGED: update and install in separate layers
RUN apt-get update
RUN apt-get install -y curl

# SAFE: combined into one layer, both invalidate together
RUN apt-get update && apt-get install -y curl
```

```hcl
# FLAGGED: AWS-managed AdministratorAccess attached directly
resource "aws_iam_role" "app" {
  managed_policy_arns = ["arn:aws:iam::aws:policy/AdministratorAccess"]
}

# FLAGGED: policy attached directly to a user, not a group/role
resource "aws_iam_user_policy" "app" {
  user   = aws_iam_user.app.name
  policy = jsonencode({})
}

# FLAGGED: any AWS account can assume this role
resource "aws_iam_role" "app" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# SAFE: sibling Deny statement's wildcard principal doesn't taint the scoped Allow
resource "aws_iam_role" "app" {
  assume_role_policy = jsonencode({
    Statement = [
      { Effect = "Allow", Principal = { AWS = "123456789012" }, Action = "sts:AssumeRole" },
      { Effect = "Deny", Principal = { AWS = "*" }, Action = "sts:AssumeRole",
        Condition = { StringNotEquals = { "aws:PrincipalOrgID" = "o-xxxx" } } }
    ]
  })
}

# FLAGGED: no audit trail at all
resource "aws_cloudtrail" "main" {
  enable_logging        = false
  is_multi_region_trail = false
}
```

```hcl
# FLAGGED: EBS encryption never set, defaults to false
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
}

# FLAGGED: neither SSE-SQS nor SSE-KMS set
resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}

# FLAGGED: SNS server-side encryption never set
resource "aws_sns_topic" "alerts" {
  name = "alerts"
}

# FLAGGED: encrypted with the AWS-owned key, no CMK
resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"
}

# SAFE: customer-managed CMK referenced
resource "aws_dynamodb_table" "sessions" {
  name = "sessions"
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.app.arn
  }
}

# FLAGGED: encrypted with the default aws/secretsmanager alias
resource "aws_secretsmanager_secret" "db_password" {
  name = "db_password"
}

# FLAGGED: AES256 (AWS-owned key), not a customer-managed KMS key
resource "aws_ecr_repository" "app" {
  name = "app"
  encryption_configuration {
    encryption_type = "AES256"
  }
}

# FLAGGED: no customer-managed key for log data
resource "aws_cloudwatch_log_group" "app" {
  name = "/app/prod"
}
```

## Citations
[1] [Checkov: RDSPubliclyAccessible (CKV_AWS_17)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/RDSPubliclyAccessible.py)
[2] [Checkov: RDSEncryption (CKV_AWS_16)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/RDSEncryption.py)
[3] [Checkov: S3BlockPublicACLs (CKV_AWS_53)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/S3BlockPublicACLs.py)
[4] [Checkov: S3AllowsAnyPrincipal (CKV_AWS_70)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/S3AllowsAnyPrincipal.py)
[5] [Checkov: UpdateNotAlone (CKV_DOCKER_5)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/dockerfile/checks/UpdateNotAlone.py)
[6] [Checkov: IAMManagedAdminPolicy (CKV_AWS_274)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/IAMManagedAdminPolicy.py)
[7] [Checkov: IAMPolicyAttachedToGroupOrRoles (CKV_AWS_40)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/IAMPolicyAttachedToGroupOrRoles.py)
[8] [Checkov: IAMRoleAllowsPublicAssume (CKV_AWS_60)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/IAMRoleAllowsPublicAssume.py)
[9] [Checkov: CloudtrailEnableLogging (CKV_AWS_251)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/CloudtrailEnableLogging.py)
[10] [Checkov: CloudtrailMultiRegion (CKV_AWS_67)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/CloudtrailMultiRegion.py)
[11] [Checkov: EBSEncryption (CKV_AWS_3)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/EBSEncryption.py)
[12] [Checkov: SQSQueueEncryption (CKV_AWS_27)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/SQSQueueEncryption.py)
[13] [Checkov: SNSTopicEncryption (CKV_AWS_26)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/SNSTopicEncryption.py)
[14] [Checkov: DynamoDBTablesEncrypted (CKV_AWS_119)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/DynamoDBTablesEncrypted.py)
[15] [Checkov: SecretManagerSecretEncrypted (CKV_AWS_149)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/SecretManagerSecretEncrypted.py)
[16] [Checkov: ECRRepositoryEncrypted (CKV_AWS_136)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/ECRRepositoryEncrypted.py)
[17] [Checkov: CloudWatchLogGroupKMSKey (CKV_AWS_158)](https://raw.githubusercontent.com/bridgecrewio/checkov/main/checkov/terraform/checks/resource/aws/CloudWatchLogGroupKMSKey.py)
