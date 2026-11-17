"""Guard: AWS Terraform resources missing observability or durability hygiene controls (§7).

Bundles three independent missing-config checks against common AWS Terraform resources. None
overlaps `cloudtrail_logging_disabled.py` — that guard validates an EXISTING `aws_cloudtrail`
trail's `enable_logging`/`is_multi_region_trail` settings; this guard never touches CloudTrail.

1. **CloudWatch log group with no `retention_in_days`.**

       resource "aws_cloudwatch_log_group" "app" {
         name = "/app/logs"
         # no retention_in_days -> CloudWatch treats this as "never expire"
       }

   The Terraform AWS provider leaves a log group's retention unset by default, and CloudWatch
   interprets that as "never expire." Logs then accumulate indefinitely — an unbounded storage
   cost (CloudWatch Logs is billed per GB-month with no automatic cap) and a compliance gap for
   any framework that requires a documented, bounded retention window rather than a forever one.
   CWE-778 (Insufficient Logging), OWASP:A09.

2. **S3 bucket with no versioning enabled.**

       resource "aws_s3_bucket" "data" {
         bucket = "app-data"
         # no versioning block, and no aws_s3_bucket_versioning resource anywhere
       }

   Without `versioning { enabled = true }` (the legacy inline block, Terraform AWS provider v3
   and earlier) or a same-purpose `aws_s3_bucket_versioning` resource with `versioning_configuration
   { status = "Enabled" }` (the split-resource form the provider REQUIRES from v4+), an accidental
   delete, an accidental overwrite, or a ransomware-style mass-encrypt of the bucket's objects has
   no rollback path — the previous object version is simply gone. CWE-693 (Protection Mechanism
   Failure), OWASP:A05.

3. **S3 bucket with no access logging.**

       resource "aws_s3_bucket" "data" {
         bucket = "app-data"
         # no logging block, and no aws_s3_bucket_logging resource anywhere
       }

   Without `logging { target_bucket = ... }` (inline) or a same-purpose `aws_s3_bucket_logging`
   resource, there is no server-access-log audit trail for who read/wrote/deleted objects in the
   bucket — exactly the record an incident response needs after a suspected breach. CWE-778
   (Insufficient Logging), OWASP:A09.

Fires MEDIUM for each. Because the AWS provider v4+ split-resource form is routinely declared in a
separate file from the bucket itself (`s3.tf` / `versioning.tf` / `logging.tf`), resources are
gathered across EVERY `.tf` file in the repo before matching bucket <-> versioning/logging resource,
rather than scoping the cross-reference to one file. The link between a bucket and its split-form
versioning/logging resource is a plain `bucket = aws_s3_bucket.<name>.` reference on the
`versioning`/`logging` resource's own `bucket` attribute (not `target_bucket`, which on
`aws_s3_bucket_logging` names the (possibly different) destination bucket for the log records, not
the bucket being logged) — no expression evaluation, so a bucket referenced only through a variable
or a `for_each`-derived resource name is not resolved (accepted false-negative, consistent with the
rest of this codebase's regex/text-scoped Terraform guards, e.g. `cloudtrail_logging_disabled.py`).

Suppress an audited case with the per-check pragma anywhere in the `aws_cloudwatch_log_group` /
`aws_s3_bucket` resource's own block: `# security: allow-cloudwatch-log-retention`,
`# security: allow-s3-versioning`, `# security: allow-s3-logging`.

**2026-10-25 (this session's extension):** added a fourth, independent CloudWatch rule, LOW
severity (deliberately lower than the MEDIUM missing-entirely rule above — a short-but-deliberate
retention window is a much weaker signal than no retention policy at all): fires when
`retention_in_days` IS present with a numeric value from `1` to `2` (CloudWatch's only valid value
in that range is `1`). `retention_in_days = 0` is NOT short: CloudWatch reads `0` as "never
expire", an explicit retention choice, so it stays silent (PR #1162 round-1 M5). Both CloudWatch
rules read the resource through `terraform_code_view`, so a commented-out
`# retention_in_days = 1` is neither a short window nor a retention policy. That low, conservative
threshold is deliberate — log-retention length is a legitimate policy choice many teams make for
cost reasons, and this guard should only flag the clearly-pathological short end (1 or 2 days),
never second-guess a deliberate 7-or-14-day choice. The two CloudWatch rules are mutually
exclusive by construction (missing vs. present-but-short can never both be true for the same
resource) and share the existing `# security: allow-cloudwatch-log-retention` pragma.
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
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
    terraform_code_view,
)

_RETENTION_ATTR = re.compile(r"\bretention_in_days\s*=")
_RETENTION_LITERAL = re.compile(r"\bretention_in_days\s*=\s*(\d+)\b")
_SHORT_RETENTION_DAYS = 3
_INLINE_VERSIONING = re.compile(r"\bversioning\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_INLINE_LOGGING = re.compile(r"\blogging\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_ENABLED_TRUE = re.compile(r"\benabled\s*=\s*true\b", re.IGNORECASE)
_STATUS_ENABLED = re.compile(r'status\s*=\s*"Enabled"', re.IGNORECASE)

_PRAGMA_CW = re.compile(r"#\s*security:\s*allow-cloudwatch-log-retention")
_PRAGMA_VERSIONING = re.compile(r"#\s*security:\s*allow-s3-versioning")
_PRAGMA_LOGGING = re.compile(r"#\s*security:\s*allow-s3-logging")

_CW_STANDARDS = ["OWASP:A09", "CWE-778"]
_VERSIONING_STANDARDS = ["OWASP:A05", "CWE-693"]
_LOGGING_STANDARDS = ["OWASP:A09", "CWE-778"]

_TfBody = list[tuple[int, str]]
_TfResource = tuple[Path, str, int, _TfBody]


def _body_text(body: _TfBody) -> str:
    return "\n".join(line for _, line in body)


def _bucket_ref_pattern(bucket_name: str) -> re.Pattern[str]:
    # Anchored to the `bucket` attribute specifically (not `target_bucket`, which on
    # aws_s3_bucket_logging names the log-destination bucket, a different resource).
    return re.compile(rf"(?m)^\s*bucket\s*=\s*aws_s3_bucket\.{re.escape(bucket_name)}\.")


def _split_form_addressed(
    bucket_name: str, resources: list[tuple[Path, _TfBody]], positive: re.Pattern[str] | None,
) -> bool:
    ref = _bucket_ref_pattern(bucket_name)
    for _f, body in resources:
        text = _body_text(body)
        if not ref.search(text):
            continue
        if positive is None or positive.search(text):
            return True
    return False


class AwsObservabilityHygieneGuard(Guard):
    id = "aws-observability-hygiene"
    title = "AWS resource missing an observability or durability hygiene control"
    area = "Cloud & IaC"

    # observability_hygiene.tf: aws_cloudwatch_log_group with no retention_in_days, and an
    # aws_s3_bucket with no inline versioning/logging block and no split-resource form anywhere
    # -> fires all three rules. Must NOT contain any of the three allow- pragmas.
    # observability_hygiene_short_retention.tf: a SEPARATE aws_cloudwatch_log_group with
    # retention_in_days = 1 -> fires cloudwatch-log-retention-too-short (mutually exclusive with
    # the missing-entirely rule above, so it needs its own resource to prove it's alive).
    canary_plant = CanaryPlant(
        files={
            "observability_hygiene.tf": (
                'resource "aws_cloudwatch_log_group" "canary" {\n'
                '  name = "/canary/app-logs"\n'
                "}\n"
                "\n"
                'resource "aws_s3_bucket" "canary" {\n'
                '  bucket = "canary-observability-bucket"\n'
                "}\n"
            ),
            "observability_hygiene_short_retention.tf": (
                'resource "aws_cloudwatch_log_group" "canary_short" {\n'
                '  name              = "/canary/short-logs"\n'
                "  retention_in_days = 1\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "aws-observability-hygiene/cloudwatch-log-retention-missing",
            "aws-observability-hygiene/cloudwatch-log-retention-too-short",
            "aws-observability-hygiene/s3-versioning-missing",
            "aws-observability-hygiene/s3-logging-missing",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = [
            f for f in iter_files(root, (".tf",))
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]

        log_groups: list[_TfResource] = []
        buckets: list[_TfResource] = []
        versioning_resources: list[tuple[Path, _TfBody]] = []
        logging_resources: list[tuple[Path, _TfBody]] = []

        for f in files:
            text = read(f)
            for resource_type, resource_name, start, body in iter_terraform_resources(text):
                if resource_type == "aws_cloudwatch_log_group":
                    log_groups.append((f, resource_name, start, body))
                elif resource_type == "aws_s3_bucket":
                    buckets.append((f, resource_name, start, body))
                elif resource_type == "aws_s3_bucket_versioning":
                    versioning_resources.append((f, body))
                elif resource_type == "aws_s3_bucket_logging":
                    logging_resources.append((f, body))

        out: list[Finding] = []
        for f, name, start, body in log_groups:
            out.extend(self._check_log_retention(root, f, name, start, body))
        for f, name, start, body in buckets:
            out.extend(self._check_versioning(root, f, name, start, body, versioning_resources))
            out.extend(self._check_logging(root, f, name, start, body, logging_resources))
        return out

    def _check_log_retention(
        self, root: Path, f: Path, name: str, start: int, body: _TfBody,
    ) -> list[Finding]:
        text = _body_text(body)
        if pragma_present(_PRAGMA_CW, text, dialect="hcl"):
            return []
        # Detection reads the comment-blanked view; the pragma above reads the raw body.
        code = terraform_code_view(text)
        m = _RETENTION_LITERAL.search(code)
        if m is None:
            if _RETENTION_ATTR.search(code):
                # Present but not a literal integer (e.g. `retention_in_days = var.retention`) —
                # no expression evaluation, left unresolved rather than guessed at.
                return []
            return [Finding(
                check_id=self.id,
                severity="medium",
                title="CloudWatch log group has no retention period",
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`aws_cloudwatch_log_group.{name}` does not set `retention_in_days` — the "
                    "Terraform AWS provider leaves this unset by default, which CloudWatch treats "
                    "as \"never expire.\" Logs then accumulate indefinitely: an unbounded storage "
                    "cost and a compliance gap for any framework that requires a documented, "
                    "bounded retention window."
                ),
                remediation=(
                    "Set `retention_in_days` to a value matching your retention policy (e.g. "
                    "`90`, `365`). Suppress an audited exception (e.g. a deliberately permanent "
                    "compliance-archive log group) with `# security: allow-cloudwatch-log-"
                    "retention` anywhere in the resource block."
                ),
                rule="aws-observability-hygiene/cloudwatch-log-retention-missing",
                standards=list(_CW_STANDARDS),
            )]
        # `0` is CloudWatch's "never expire": an explicit choice, not a short window.
        if 0 < int(m.group(1)) < _SHORT_RETENTION_DAYS:
            return [Finding(
                check_id=self.id,
                severity="low",
                title="CloudWatch log group retention period is very short",
                location=f"{rel(root, f)}:{start}",
                message=(
                    f"`aws_cloudwatch_log_group.{name}` sets `retention_in_days` to a value "
                    f"below {_SHORT_RETENTION_DAYS} days. A retention policy exists, but a "
                    "window this short leaves little time to notice an issue or pull logs for "
                    "an investigation before they expire."
                ),
                remediation=(
                    "Confirm this short window is a deliberate, documented policy choice (e.g. "
                    "a genuinely high-volume/low-value debug log). If not, raise "
                    "`retention_in_days` to match your team's actual retention policy. Suppress "
                    "an audited exception with `# security: allow-cloudwatch-log-retention` "
                    "anywhere in the resource block."
                ),
                rule="aws-observability-hygiene/cloudwatch-log-retention-too-short",
                standards=list(_CW_STANDARDS),
            )]
        return []

    def _check_versioning(
        self, root: Path, f: Path, name: str, start: int, body: _TfBody,
        versioning_resources: list[tuple[Path, _TfBody]],
    ) -> list[Finding]:
        text = _body_text(body)
        if pragma_present(_PRAGMA_VERSIONING, text, dialect="hcl"):
            return []
        inline = _INLINE_VERSIONING.search(text)
        if inline and _ENABLED_TRUE.search(inline.group("inner")):
            return []
        if _split_form_addressed(name, versioning_resources, _STATUS_ENABLED):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="S3 bucket has no versioning enabled",
            location=f"{rel(root, f)}:{start}",
            message=(
                f"`aws_s3_bucket.{name}` has no versioning enabled — neither an inline "
                "`versioning { enabled = true }` block nor a matching `aws_s3_bucket_versioning` "
                "resource with `versioning_configuration { status = \"Enabled\" }`. An accidental "
                "delete, an accidental overwrite, or a ransomware-style mass-encrypt of this "
                "bucket's objects has no rollback path."
            ),
            remediation=(
                "Add versioning: an inline `versioning { enabled = true }` block (provider v3 and "
                "earlier), or, for the provider v4+ split-resource form, a separate "
                '`aws_s3_bucket_versioning` resource referencing this bucket with '
                '`versioning_configuration { status = "Enabled" }`. Suppress an audited exception '
                "with `# security: allow-s3-versioning` anywhere in this bucket's resource block."
            ),
            rule="aws-observability-hygiene/s3-versioning-missing",
            standards=list(_VERSIONING_STANDARDS),
        )]

    def _check_logging(
        self, root: Path, f: Path, name: str, start: int, body: _TfBody,
        logging_resources: list[tuple[Path, _TfBody]],
    ) -> list[Finding]:
        text = _body_text(body)
        if pragma_present(_PRAGMA_LOGGING, text, dialect="hcl"):
            return []
        if _INLINE_LOGGING.search(text):
            return []
        if _split_form_addressed(name, logging_resources, None):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="S3 bucket has no access logging",
            location=f"{rel(root, f)}:{start}",
            message=(
                f"`aws_s3_bucket.{name}` has no server access logging configured — neither an "
                "inline `logging { ... }` block nor a matching `aws_s3_bucket_logging` resource. "
                "There is no audit trail of who read, wrote, or deleted objects in this bucket, "
                "closing off a record an incident response would depend on after a suspected "
                "breach."
            ),
            remediation=(
                "Add access logging: an inline `logging { target_bucket = ... target_prefix = "
                '... }` block, or, for the provider v4+ split-resource form, a separate '
                "`aws_s3_bucket_logging` resource referencing this bucket. Suppress an audited "
                "exception (e.g. a genuinely low-value scratch bucket) with "
                "`# security: allow-s3-logging` anywhere in this bucket's resource block."
            ),
            rule="aws-observability-hygiene/s3-logging-missing",
            standards=list(_LOGGING_STANDARDS),
        )]
