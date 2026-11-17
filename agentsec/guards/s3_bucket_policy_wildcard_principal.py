"""Guard: Terraform resource policy grants an action to any AWS principal (checklist §6a).

    resource "aws_s3_bucket_policy" "app" {
      bucket = aws_s3_bucket.app.id
      policy = jsonencode({
        Statement = [{
          Effect    = "Allow"
          Principal = "*"          # any AWS account, or anyone if the bucket is also public
          Action    = "s3:GetObject"
          Resource  = "${aws_s3_bucket.app.arn}/*"
        }]
      })
    }

    resource "aws_kms_key" "app" {
      policy = jsonencode({
        Statement = [{
          Effect    = "Allow"
          Principal = "*"          # any AWS account can Decrypt/Encrypt/GenerateDataKey/...
          Action    = "kms:Decrypt"
        }]
      })
    }

A resource policy statement with `"Effect": "Allow"` and `"Principal": "*"` (or
`"Principal": {"AWS": "*"}`) grants the action to every AWS account in existence — and if
the resource isn't otherwise locked down (Block Public Access, a restrictive ACL, key-policy
defaults), to anyone on the internet with no AWS account at all. A `Condition` block can
legitimately narrow a wildcard principal (e.g. `aws:SourceVpce`, `aws:PrincipalOrgID`) —
checkov's own checks spend ~80 lines walking every recognized condition-key shape to decide
whether a specific `Condition` actually narrows the grant. This guard uses a simpler, more
conservative heuristic: any `Condition` present anywhere in the same policy resource is
treated as a plausible narrowing and the statement is not flagged, trading some false
negatives (a `Condition` that doesn't actually narrow anything) for a much lower false
positive rate than trying to re-implement checkov's condition-key allowlist in regex.
CWE-284 (Improper Access Control), OWASP:A01.

Originally scoped to S3 bucket policies (checkov `CKV_AWS_70`); extended to also cover an
`aws_kms_key`'s own `policy` attribute (checkov `CKV_AWS_33`, `KMSKeyWildcardPrincipal.py`)
because it is the exact same `Effect`/`Principal`/`Condition` JSON-policy shape applied to a
different AWS resource type, not a new detection technique — see
`wiki/guards/s3-bucket-policy-wildcard-principal.md` for the KMS-specific
notes (e.g. `Deny` statements are out of scope for both resource types).

Fires HIGH when an `aws_s3_bucket_policy` (or `aws_s3_bucket`), or an `aws_kms_key`,
resource's policy body contains a wildcard `Principal` — either the JSON-string form
(`"Principal": "*"`) or the `jsonencode()` HCL-map form (`Principal = "*"`), including the
nested `{"AWS": "*"}` / `{ AWS = "*" }` shape — AND the resource body contains no
`Condition`/`condition` key at all.

Suppress an audited case (e.g. a deliberately public read bucket, or a `Condition` shape
this heuristic doesn't recognize) with `# security: allow-s3-wildcard-principal` anywhere
in the resource block.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_policy_statement_blocks,
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
)

_WILDCARD_PRINCIPAL_RESOURCE_TYPES = frozenset(
    {"aws_s3_bucket_policy", "aws_s3_bucket", "aws_kms_key"}
)

# Resource types whose `policy` describes a KMS key policy rather than an S3 bucket policy —
# used only to pick the right wording ("KMS key policy" vs "S3 bucket policy") in the finding
# message below; the detection logic itself is identical for both.
_KMS_RESOURCE_TYPES = frozenset({"aws_kms_key"})

# "Principal": "*"  or  Principal = "*"  (JSON-string or jsonencode HCL-map form).
# The `(?<!Not)` guard stops the substring "Principal" inside `NotPrincipal` (the opposite
# semantics — it EXCLUDES that principal) from matching (#423).
_PRINCIPAL_WILDCARD = re.compile(r'(?<!Not)"?Principal"?\s*[:=]\s*"\*"')
# "Principal": {"AWS": "*"}  or  Principal = { AWS = "*" }, plus the LIST form
# "Principal": {"AWS": ["*"]} / Principal = { AWS = ["*", "arn:..."] } — IAM accepts a list
# wherever it accepts a scalar principal, and a `"*"` element grants to every AWS account just
# the same. The scalar-only pattern missed it entirely (#422).
#
# `\[[^\]]*` lets the `"*"` sit at any position in the list (a wildcard mixed in with real ARNs
# is still a wildcard grant) while `[^\]]` keeps the search inside the brackets. The element is
# matched as the WHOLE quoted token `"*"`, so a scoped ARN that merely ends in a star —
# `"arn:aws:iam::123456789012:role/*"` — does not match: the character before the `*` there is
# `/`, not the opening quote.
_PRINCIPAL_AWS_WILDCARD = re.compile(
    r'(?<!Not)"?Principal"?\s*[:=]\s*\{[^{}]*"?AWS"?\s*[:=]\s*(?:\[[^\]]*)?"\*"', re.DOTALL
)
_CONDITION_PRESENT = re.compile(r'"?Condition"?\s*[:=]', re.IGNORECASE)
# Used to skip a wildcard Principal inside an explicit-DENY statement (a deny-to-everyone is a
# lockdown, not a grant) (#423).
_EFFECT_DENY = re.compile(r'"?Effect"?\s*[:=]\s*"Deny"', re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-s3-wildcard-principal")


def _deny_statement_spans(text: str) -> list[tuple[int, int]]:
    """(start, end) offsets of each policy statement block whose Effect is `Deny`, via the
    shared string/comment/heredoc-aware policy walker (PR #446 re-review)."""
    return [
        (start, end)
        for start, end, block in iter_policy_statement_blocks(text)
        if _EFFECT_DENY.search(block)
    ]

_STANDARDS = ["OWASP:A01", "CWE-284"]


class S3BucketPolicyWildcardPrincipalGuard(Guard):
    # Guard id kept stable for check_id/checklist continuity even though the guard now also
    # covers KMS key policies — see wiki/guards/s3-bucket-policy-wildcard-
    # principal.md for why the id wasn't renamed.
    id = "s3-bucket-policy-wildcard-principal"
    title = "Resource policy grants an action to any AWS principal (S3 bucket / KMS key)"
    area = "Cloud & IaC"

    # s3_policy.tf: aws_s3_bucket_policy with Principal = "*" and no Condition ->
    # fires s3-bucket-policy-wildcard-principal. Must NOT contain: allow-s3-wildcard-principal pragma.
    canary_plant = CanaryPlant(
        files={
            "s3_policy.tf": (
                'resource "aws_s3_bucket_policy" "canary" {\n'
                "  bucket = aws_s3_bucket.canary.id\n"
                "  policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      Principal = "*"\n'
                '      Action    = "s3:GetObject"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({"s3-bucket-policy-wildcard-principal/unconditional-wildcard"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type not in _WILDCARD_PRINCIPAL_RESOURCE_TYPES:
                continue
            raw_body = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, raw_body, dialect="hcl"):
                continue
            # Search a comment-blanked view (pragma handled on the comment-only view above, #424) so a
            # commented `# Condition ...` can't suppress a real wildcard finding, and a
            # commented-out `Principal = "*"` can't spuriously fire. Blank, don't drop, so
            # the match-offset -> line-number mapping below stays valid.
            body_text = "\n".join(
                "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
            )
            if _CONDITION_PRESENT.search(body_text):
                continue
            # Resource-type-aware wording only — the detection logic above is identical for
            # an S3 bucket policy and a KMS key policy (same Effect/Principal/Condition JSON
            # shape, see checkov's CKV_AWS_70 vs CKV_AWS_33).
            # The S3 wording is held BYTE-IDENTICAL to what this rule shipped before KMS support
            # was added. `Finding.fingerprint()` hashes `message[:120]`, so rewording an
            # already-released finding silently invalidates every downstream baseline and pinned
            # exception keyed to it: the waived HIGH resurfaces on upgrade and breaks an adopter's
            # CI with no change on their end. Only the NEW KMS branch may word itself freely.
            if resource_type in _KMS_RESOURCE_TYPES:
                policy_message = (
                    f"`{resource_type}.{resource_name}`'s KMS key policy grants an action to "
                    '`Principal: "*"` — every AWS account in existence, and to '
                    "anyone with the right IAM permissions elsewhere in the account if the "
                    "key isn't otherwise locked down. No `Condition` was "
                    "found anywhere in this policy to narrow the grant."
                )
            else:
                policy_message = (
                    f"`{resource_type}.{resource_name}`'s policy grants an action to "
                    '`Principal: "*"` — every AWS account in existence, and to '
                    "anyone on the internet if the bucket isn't otherwise locked down "
                    "(Block Public Access, a restrictive ACL). No `Condition` was "
                    "found anywhere in this policy to narrow the grant."
                )
            # Search the whole block as one blob — the nested `Principal = { AWS = "*" }`
            # form commonly spans multiple physical lines, so a per-line search would miss it.
            matches = list(_PRINCIPAL_WILDCARD.finditer(body_text)) + list(
                _PRINCIPAL_AWS_WILDCARD.finditer(body_text)
            )
            deny_spans = _deny_statement_spans(body_text)
            seen_lines: set[int] = set()
            for m in matches:
                if any(s <= m.start() < e for s, e in deny_spans):
                    continue  # wildcard Principal inside an explicit Deny — a lockdown, not a grant
                body_index = body_text.count("\n", 0, m.start())
                lineno, line_text = body[body_index]
                if lineno in seen_lines or line_text.lstrip().startswith("#"):
                    continue
                seen_lines.add(lineno)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=policy_message,
                        remediation=(
                            "Scope `Principal` to specific account IDs, IAM roles, or a "
                            "service principal, or add a `Condition` that genuinely narrows "
                            "the grant (e.g. `aws:SourceVpce`, `aws:PrincipalOrgID`, "
                            "`aws:PrincipalArn`). Suppress an audited exception with "
                            "`# security: allow-s3-wildcard-principal` anywhere in the block."
                        ),
                        rule="s3-bucket-policy-wildcard-principal/unconditional-wildcard",
                        standards=list(_STANDARDS),
                    )
                )
        return out
