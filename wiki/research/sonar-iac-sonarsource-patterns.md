---
type: Research
title: sonar-iac (SonarSource) — Terraform AWS Patterns
description: Statically-detectable Terraform AWS misconfiguration patterns distilled from SonarSource's commercial IaC check catalog, covering S3 hardening, managed-service encryption in transit and at rest, and TLS policy strength.
tags: [research, terraform, aws, encryption, tls]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-25T00:00:00Z }
stale_after: 2027-01-23
---

# sonar-iac (SonarSource) — Terraform AWS Patterns

## What this covers

SonarSource's SonarQube IaC plugin ships an extensive, commercial-grade Terraform check catalog
(dozens of rule classes, `S6xxx`-numbered). This page distills the patterns relevant to a
FastAPI/React/Postgres/LLM app's AWS infrastructure layer that agentsec did not yet cover, each
verified against the real source before being built — not taken on a README's word.

## S3 bucket hardening

| Pattern | What it catches | Detection |
|---|---|---|
| Versioning without MFA-delete | `aws_s3_bucket`/`aws_s3_bucket_versioning` has versioning on but `mfa_delete` missing or disabled | Both the legacy inline `versioning` block and the provider v4+ split-resource form |
| Policy allows insecure transport | An explicit `aws_s3_bucket_policy` has no `Deny` statement conditioned on `aws:SecureTransport` | Policy-statement walk (`Effect`/`Condition` keys), scoped to buckets that already have a policy |
| Public canned ACL | `acl` attribute (inline or the split `aws_s3_bucket_acl` resource) set to `public-read`/`public-read-write`/`authenticated-read` | Literal enum match, the Terraform-side sibling of a CloudFormation-only check |

## AWS managed-service encryption

The richest category: several AWS managed services default to **unencrypted** or **plaintext**
unless a specific nested attribute is set, and that attribute is easy to omit entirely (the
Terraform AWS provider does not warn on omission the way the AWS Console's own defaults would).

| Service | Resource | Gap when omitted |
|---|---|---|
| MSK | `aws_msk_cluster` | `encryption_info.encryption_in_transit.client_broker` defaults to allowing plaintext; `in_cluster` can be explicitly disabled |
| OpenSearch/Elasticsearch | `aws_opensearch_domain` / `aws_elasticsearch_domain` | Three independent controls: `domain_endpoint_options.enforce_https`, `node_to_node_encryption.enabled`, `encrypt_at_rest.enabled` |
| ElastiCache | `aws_elasticache_replication_group` | `transit_encryption_enabled` |
| EFS | `aws_efs_file_system` | `encrypted` (at rest) |
| EFS-via-ECS | `aws_ecs_task_definition` volume's `efs_volume_configuration.transit_encryption` | Per-mount transit encryption, distinct from the file system's own at-rest flag |
| Kinesis | `aws_kinesis_stream` | `encryption_type` (`"NONE"` or omitted) |
| SageMaker | `aws_sagemaker_notebook_instance` | `kms_key_id` (no boolean toggle — a missing key id is the only signal) |
| ALB/NLB | `aws_lb_listener` | Plaintext `protocol = "HTTP"` |

## TLS policy strength

Several AWS resources accept a *named* TLS policy string rather than a raw protocol version, and
an outdated or absent policy name silently permits old TLS versions:

| Resource | Attribute | Weak when |
|---|---|---|
| `aws_api_gateway_domain_name` / `aws_apigatewayv2_domain_name` | `security_policy` | Absent, or not a `TLS_1_2`/`TLS12`/`TLS13`-naming policy |
| `aws_opensearch_domain` / `aws_elasticsearch_domain` | `domain_endpoint_options.tls_security_policy` | Absent, or the named `Policy-Min-TLS-1-0-2019-07` policy |
| `aws_lb_listener` / `aws_alb_listener` | `ssl_policy` (only relevant when `protocol` is HTTPS/TLS) | Absent, or names a `-1-0-`/`-1-1-` policy or the deprecated `ELBSecurityPolicy-2016-08` |

## Backup retention

`aws_db_instance` (excluding Aurora engines and read replicas, whose real retention control lives
on the owning cluster) and `aws_rds_cluster`: `backup_retention_period` absent or below a 7-day
floor — a straightforward availability/recovery gap, distinct from the encryption-focused patterns
above.

## A deliberate non-finding: tag exactness depth varies by image

Not a Terraform pattern, but worth recording: extending a *different* part of agentsec (the
`dependency-version-floor` guard's Docker base-image ecosystem) to `postgres` in the same research
window surfaced that its exact-tag match assumes every image uses 3-component versioning
(`major.minor.patch`). The official `postgres` image's own tags are 2-component
(`16.15`, not `16.1.5`) — checked against Docker Hub's real tag list before writing any floor
data, not assumed from the pattern that holds for `php`/`python`/`node`. Recorded here as a
pattern worth knowing if you're auditing another image-based checker: "does this tool's exactness
rule actually match this image's real versioning scheme" is worth checking before trusting
coverage claims, including agentsec's own.
