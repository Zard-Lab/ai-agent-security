---
type: Guard
title: "ecr-repository-hygiene"
description: "ECR repository missing vulnerability scanning, immutable tags, or a lifecycle policy."
timestamp: "2026-08-24T00:00:00Z"
guard_id: "ecr-repository-hygiene"
checklist_section: ["7"]
standards: ["OWASP:A05", "OWASP:A06", "OWASP:A08", "CWE-345", "CWE-770"]
---

# ECR repository missing vulnerability scanning, immutable tags, or a lifecycle policy

_Author — Marconi, 2026-08-24_

---

## The threat

Three independent `aws_ecr_repository` Terraform hygiene gaps, none of which are the
repository's KMS encryption (that is the separate, already-covered
`ecr-repository-not-kms-encrypted` concern):

1. **No vulnerability scanning on push** — a repository with no
   `image_scanning_configuration { scan_on_push = true }` lets an image with known CVEs
   reach the registry, and from there a deployment, with no automated check. OWASP:A06
   (Vulnerable and Outdated Components).
2. **Mutable image tags** — `image_tag_mutability` defaults to `"MUTABLE"` when omitted,
   so the same tag (`:prod`, `:v1.2.3`) can be silently re-pushed to point at a different
   image after it was reviewed, scanned, or approved. An attacker (or a compromised CI
   pipeline) can swap a pinned image without changing the reference anything downstream
   uses to pull it — a supply-chain integrity failure. CWE-345 (Insufficient Verification
   of Data Authenticity), OWASP:A08 (Software and Data Integrity Failures).
3. **No lifecycle policy attached** — with no `aws_ecr_lifecycle_policy` resource
   referencing the repository, images accumulate without bound: old, superseded, and
   already-known-vulnerable images are never pruned, growing both cost and the surface
   area of "which image did we actually deploy". CWE-770 (Allocation of Resources Without
   Limits or Throttling), OWASP:A05 (Security Misconfiguration).

## Why it's often introduced

`aws_ecr_repository` is usually created once per service, early, with just a `name`:

```hcl
resource "aws_ecr_repository" "app" {
  name = "app-image"
  # no image_scanning_configuration -> images pushed with no vulnerability scan
  # no image_tag_mutability = "IMMUTABLE" -> a tag can be silently overwritten
}
# no aws_ecr_lifecycle_policy resource references aws_ecr_repository.app ->
# images accumulate forever, including old/vulnerable ones
```

None of the three attributes are required for `terraform apply` to succeed, none of them
affect whether `docker push` works, and the AWS provider's defaults are all on the
insecure side (`scan_on_push` defaults `false`, `image_tag_mutability` defaults
`"MUTABLE"`, and a lifecycle policy is an entirely separate resource nobody is prompted
to add). The gap is silent at every stage until an incident (a swapped tag, an
unscanned CVE, a registry that never gets cleaned up) makes it visible.

## Detection design

1. `applies()` gate — `"terraform" in profile.features`.
2. `run()` first walks every `.tf` file under the repo root (skipping non-product paths)
   to collect every `aws_ecr_lifecycle_policy` resource's raw `repository = ...`
   expression into a repo-wide set (`_collect_lifecycle_refs`) — **cross-file**, since a
   lifecycle policy is commonly declared in a different `.tf` file from the repository it
   targets (the same cross-file reasoning `auth-dependency-not-applied` uses for router
   wiring split across files).
3. It then re-walks the same files, using `iter_terraform_resources()`
   (`agentsec/guards/base.py`) to isolate each `aws_ecr_repository "<name>" { ... }`
   block, and evaluates all three rules against it:
   - Comments are blanked (not dropped, so line numbers are preserved) into a `code_body`
     view before either literal pattern is evaluated, so a commented-out
     `# scan_on_push = true` cannot silence a genuinely unconfigured repository.
   - `_SCAN_ON_PUSH_TRUE` searches `code_body` for `scan_on_push = true` anywhere in the
     block (whether nested inside `image_scanning_configuration` or not — the attribute
     name is distinctive enough that a flat search is sufficient, the same simplicity
     `kms-key-rotation-not-enabled` uses for its own single-attribute check). Absent →
     fires `scan-on-push-disabled`.
   - `_TAG_IMMUTABLE` searches `code_body` for `image_tag_mutability = "IMMUTABLE"`
     (case-insensitive). Absent (whether omitted or set to `"MUTABLE"`/anything else) →
     fires `mutable-tags`.
   - The resource's own name is checked against the repo-wide lifecycle-ref set from
     step 2: if no collected `repository = ...` expression contains the literal
     `aws_ecr_repository.<name>` substring, fires `no-lifecycle-policy`.
4. Inline opt-outs (three independent pragmas, one per rule):
   `# security: allow-ecr-scan-on-push`, `# security: allow-ecr-tag-mutability`,
   `# security: allow-ecr-lifecycle-policy` — any of them anywhere in the
   `aws_ecr_repository` resource block (checked against the raw, comment-INCLUDING body
   text).
5. Severity: `medium` for all three rules. Rule ids:
   `ecr-repository-hygiene/scan-on-push-disabled`,
   `ecr-repository-hygiene/mutable-tags`, `ecr-repository-hygiene/no-lifecycle-policy`.
   Standards: `["OWASP:A06", "CIS:AWS"]` / `["OWASP:A08", "CWE-345"]` /
   `["OWASP:A05", "CWE-770"]` respectively.

All three findings are anchored on the repository resource's own opening line.

## When NOT to flag

- `scan_on_push = true` present anywhere in the block — scan-on-push rule silent.
- `image_tag_mutability = "IMMUTABLE"` present anywhere in the block — mutable-tags rule
  silent.
- Some `aws_ecr_lifecycle_policy` resource anywhere in the scanned repo has
  `repository = aws_ecr_repository.<this repo's name>....` — lifecycle-policy rule
  silent.
- An audited case (e.g. a scratch/dev repository that's deliberately unmanaged),
  suppressed with the matching `# security: allow-ecr-*` pragma anywhere in the resource
  block.

## Tests

| Test | What it checks |
|---|---|
| `test_ecr_repository_hygiene_flags_all_three_gaps` | Positive: a bare repository (name only) fires all three rules, anchored on the resource's opening line (**verified_by**). |
| `test_ecr_repository_hygiene_flags_scan_on_push_explicit_false` | Positive: `scan_on_push = false` fires only the scan-on-push rule (mutability + lifecycle policy addressed). |
| `test_ecr_repository_hygiene_flags_mutable_tags` | Positive: `image_tag_mutability = "MUTABLE"` fires only the mutable-tags rule. |
| `test_ecr_repository_hygiene_flags_no_lifecycle_policy` | Positive: no `aws_ecr_lifecycle_policy` anywhere fires only the lifecycle-policy rule. |
| `test_ecr_repository_hygiene_lifecycle_policy_found_in_other_file` | Cross-file: a lifecycle policy declared in a *different* `.tf` file still silences the lifecycle-policy rule. |
| `test_ecr_repository_hygiene_lifecycle_policy_for_different_repo_still_fires` | A lifecycle policy referencing a *different* repository does not silence this one's finding. |
| `test_ecr_repository_hygiene_silent_when_fully_configured` | FP-bait: scan-on-push + immutable tags + a matching lifecycle policy → silent. |
| `test_ecr_repository_hygiene_silent_other_resource` | A non-`aws_ecr_repository` resource → silent. |
| `test_ecr_repository_hygiene_pragmas_silence_each_rule` | All three pragmas together suppress all three rules. |
| `test_ecr_repository_hygiene_comment_does_not_suppress_finding` | A commented `# scan_on_push = true` / `# image_tag_mutability = "IMMUTABLE"` does NOT suppress a genuine finding. |
| `test_ecr_repository_hygiene_applies_gate` / `test_ecr_repository_hygiene_applies_with_terraform` | `applies()` gate. |

## Known bypasses

- **Variable indirection**: `scan_on_push = var.scan` or `repository = var.repo_ref`
  where the variable resolves favorably elsewhere — only literal values/expressions are
  matched; resolving `variables.tf`/`locals.tf` is out of scope for a regex-based guard.
- **Literal-string lifecycle references**: `repository = "app-image"` (a hardcoded
  string matching the repository's `name` rather than a Terraform
  `aws_ecr_repository.app...` reference) is NOT recognized as a match — the guard only
  resolves the idiomatic Terraform-reference form. A lifecycle policy written this way
  is a documented false negative on rule 3.
- **A resource nested inside a `module` block** passing any of the three attributes
  through at the call site — the helper only sees each resource's own literal body.
- **A repository provisioned outside this Terraform root** (a separate state file, a
  different IaC tool, ClickOps) that a lifecycle policy in the scanned root references —
  out of scope; this guard only reasons about resources visible in the scanned files.

## What this guard does NOT prove

A silent guard does not mean the repository is actually enforcing any of the three
controls in AWS — it only means the literal attributes/resources were found in the
Terraform source at audit time. It does not confirm the applied infrastructure matches
the source (drift), that the referenced lifecycle policy's *rules* actually expire
anything meaningful (an `aws_ecr_lifecycle_policy` with an empty or no-op policy body
still silences rule 3), that scan findings from `scan_on_push` are ever triaged or acted
on, or that a repository provisioned outside Terraform (console, CloudFormation, another
IaC tool) has any of these controls. This is a presence-based, source-only check.

# Citations

[1] agentsec checklist item `7-ecr-repository-hygiene` (§7)
[2] CWE-345
[3] CWE-770
[4] OWASP:A05
[5] OWASP:A06
[6] OWASP:A08
