"""Guard: Terraform S3 bucket versioning without MFA Delete required (checklist §7).

    resource "aws_s3_bucket_versioning" "data" {
      bucket = aws_s3_bucket.data.id
      versioning_configuration {
        status = "Enabled"
        # no mfa_delete -> deletions/version-suppressions need no MFA at all
      }
    }

S3 versioning protects against an accidental or malicious object delete by keeping the prior
version around — but without MFA Delete, a single compromised set of IAM credentials can still
permanently remove that protection: it can suspend versioning, or permanently delete a specific
object version (as opposed to merely creating a delete marker), with no second factor required.
MFA Delete forces a one-time MFA code on exactly those two destructive calls. CWE-306 (Missing
Authentication for Critical Function), OWASP:A05.

Covers Terraform's two generations of the same setting, the same old/new split as
`aws_observability_hygiene.py`'s versioning check:

1. **Legacy inline form** (provider v3 and earlier) — a `versioning { ... }` block nested
   directly inside `aws_s3_bucket`, where `mfa_delete` is a **bool**:

       resource "aws_s3_bucket" "data" {
         bucket = "app-data"
         versioning {
           enabled     = true
           mfa_delete  = false   # or simply absent
         }
       }

2. **Split-resource form** (provider v4+) — a separate `aws_s3_bucket_versioning` resource,
   where `mfa_delete` is a **string enum**, `"Enabled"` / `"Disabled"`, not a bool:

       resource "aws_s3_bucket_versioning" "data" {
         bucket = aws_s3_bucket.data.id
         versioning_configuration {
           status      = "Enabled"
           mfa_delete  = "Disabled"   # or simply absent
         }
       }

Only buckets that already have versioning turned on are in scope. A bucket with no inline
`versioning` block AND no linked split-resource form at all is left to
`aws-observability-hygiene/s3-versioning-missing` — that guard already owns "no versioning
configured"; this guard's job is strictly narrower: versioning is on, but MFA Delete isn't.
"On" means provably on: the inline block's `enabled` is literally `true` (it defaults to `false`
when omitted), or the split resource's `status` is literally `"Enabled"`. A suspended or disabled
configuration (`enabled = false`, `status = "Suspended"` / `"Disabled"`), or one set through a
variable, is out of scope and stays silent (PR #1162 round-1 M6).

Every attribute is read from `terraform_code_view`, so a commented-out `# mfa_delete = true` or
`# status = "Enabled"` neither satisfies nor triggers the check. The suppress pragma is still read
from the raw block.
Resources are gathered across every `.tf` file in the repo before matching bucket <-> split
resource (the v4+ form is routinely declared in a separate file,
e.g. `versioning.tf`), the same cross-file approach `aws_observability_hygiene.py` uses, via the
same `bucket = aws_s3_bucket.<name>.` reference pattern on the split resource's own `bucket`
attribute. If a bucket has a linked split-resource form, that form's result decides this
guard's call for the bucket (the legacy inline block, if any, is not separately re-evaluated).

A bucket links only to split resources in its OWN directory: Terraform scopes a resource
reference to its module, so `aws_s3_bucket_versioning.logs` in another directory is a different
bucket's, however common the label (PR #1162 round-2 Low: a same-labelled split resource
elsewhere used to decide an inline-versioning bucket's verdict). Every DISTINCT linked split
resource is still judged on its own, once (review H7), so two split resources in one directory
that both reference the bucket are never collapsed into one verdict.

No expression evaluation: a bucket referenced only through a variable or a `for_each`-derived
resource name is not resolved (accepted false-negative, consistent with every other
regex/text-scoped Terraform guard in this codebase).

Fires MEDIUM. Rule ids: `s3-mfa-delete-disabled/inline-versioning-block` (legacy form),
`s3-mfa-delete-disabled/versioning-configuration-resource` (split-resource form).

Suppress an audited case (e.g. a bucket where MFA Delete is deliberately not required) with
`# security: allow-s3-mfa-delete` anywhere in the resource block carrying the finding — the
`aws_s3_bucket` block for the inline form, the `aws_s3_bucket_versioning` block for the split
form.
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
    literal_bool_state,
    pragma_present,
    read,
    rel,
    terraform_code_view,
)

_INLINE_VERSIONING = re.compile(r"\bversioning\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_MFA_DELETE_BOOL_TRUE = re.compile(r"\bmfa_delete\s*=\s*true\b")

_VERSIONING_CONFIGURATION = re.compile(r"\bversioning_configuration\s*\{(?P<inner>[^{}]*)\}", re.DOTALL)
_MFA_DELETE_STRING_ENABLED = re.compile(r'\bmfa_delete\s*=\s*"Enabled"', re.IGNORECASE)
_STATUS_ENABLED = re.compile(r'\bstatus\s*=\s*"Enabled"')

_PRAGMA = re.compile(r"#\s*security:\s*allow-s3-mfa-delete")

_STANDARDS = ["OWASP:A05", "CWE-306"]

_TfBody = list[tuple[int, str]]
_TfResource = tuple[Path, str, int, _TfBody]


def _body_text(body: _TfBody) -> str:
    return "\n".join(line for _, line in body)


def _bucket_ref_pattern(bucket_name: str) -> re.Pattern[str]:
    return re.compile(rf"(?m)^\s*bucket\s*=\s*aws_s3_bucket\.{re.escape(bucket_name)}\.")


def _linked_versioning_resources(
    bucket_dir: Path, bucket_name: str, resources: list[tuple[Path, int, _TfBody]],
) -> list[tuple[Path, int, _TfBody]]:
    """The split resources that can be this bucket's: same module directory (Terraform scopes a
    resource reference to its own module, so a same-labelled split resource elsewhere is a
    different bucket's -- PR #1162 round-2 Low, H7's inline form) and a `bucket` reference to
    it."""
    ref = _bucket_ref_pattern(bucket_name)
    return [
        (f, start, body) for f, start, body in resources
        if f.parent == bucket_dir and ref.search(_body_text(body))
    ]


class S3MfaDeleteDisabledGuard(Guard):
    id = "s3-mfa-delete-disabled"
    title = "S3 bucket versioning does not require MFA for object deletion"
    area = "Cloud & IaC"

    # s3_mfa_delete.tf: a bucket whose aws_s3_bucket_versioning split resource enables versioning
    # but omits mfa_delete entirely -> fires s3-mfa-delete-disabled/versioning-configuration-resource.
    canary_plant = CanaryPlant(
        files={
            "s3_mfa_delete.tf": (
                # Resource label deliberately NOT "canary": aws_observability_hygiene's own
                # canary also declares an aws_s3_bucket named "canary", and its cross-file
                # versioning check matches ANY aws_s3_bucket_versioning resource across the
                # whole merged canary repo whose `bucket` attribute references
                # `aws_s3_bucket.canary.` — a second guard reusing that same label here made
                # aws_observability_hygiene's s3-versioning-missing canary go DEAD (this
                # guard's own "Enabled" split resource satisfied that unrelated guard's
                # check). A unique label avoids the cross-guard synthetic-repo collision.
                'resource "aws_s3_bucket" "mfa_delete_canary" {\n'
                '  bucket = "canary-mfa-delete-bucket"\n'
                "}\n"
                "\n"
                'resource "aws_s3_bucket_versioning" "mfa_delete_canary" {\n'
                "  bucket = aws_s3_bucket.mfa_delete_canary.id\n"
                "  versioning_configuration {\n"
                '    status = "Enabled"\n'
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({"s3-mfa-delete-disabled/versioning-configuration-resource"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = [
            f for f in iter_files(root, (".tf",))
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]

        buckets: list[_TfResource] = []
        versioning_resources: list[tuple[Path, int, _TfBody]] = []

        for f in files:
            text = read(f)
            for resource_type, resource_name, start, body in iter_terraform_resources(text):
                if resource_type == "aws_s3_bucket":
                    buckets.append((f, resource_name, start, body))
                elif resource_type == "aws_s3_bucket_versioning":
                    versioning_resources.append((f, start, body))

        out: list[Finding] = []
        seen_split: set[tuple[Path, int]] = set()
        for f, name, start, body in buckets:
            linked = _linked_versioning_resources(f.parent, name, versioning_resources)
            if linked:
                # Split-resource form present -> it decides this bucket's verdict; the legacy
                # inline block (if any) is not separately re-evaluated. The bare-label match has
                # no module scoping, so judge every DISTINCT linked resource once (review H7) --
                # never just the first one found, which would silently decide for every
                # same-named bucket based on whichever file happened to be read first.
                for vf, vstart, vbody in linked:
                    key = (vf, vstart)
                    if key in seen_split:
                        continue
                    seen_split.add(key)
                    out.extend(self._check_split_form(root, vf, name, vstart, vbody))
            else:
                out.extend(self._check_inline_form(root, f, name, start, body))
        return out

    def _check_inline_form(
        self, root: Path, f: Path, name: str, start: int, body: _TfBody,
    ) -> list[Finding]:
        text = _body_text(body)
        inline = _INLINE_VERSIONING.search(terraform_code_view(text))
        if inline is None:
            # No versioning configured at all here, and no linked split resource either —
            # that gap belongs to aws-observability-hygiene/s3-versioning-missing, not this guard.
            return []
        if literal_bool_state("enabled", inline.group("inner")) != "true":
            # Versioning not provably on (off, defaulted off, or a variable): out of scope.
            return []
        if pragma_present(_PRAGMA, text, dialect="hcl"):
            return []
        if _MFA_DELETE_BOOL_TRUE.search(inline.group("inner")):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start}",
            message=(
                f"`aws_s3_bucket.{name}`'s inline `versioning` block does not set "
                "`mfa_delete = true`. Without MFA Delete, a single compromised set of IAM "
                "credentials can permanently delete a specific object version, or suspend "
                "versioning altogether, with no second factor required."
            ),
            remediation=(
                'Add `mfa_delete = true` to the `versioning` block (this also requires the '
                "bucket owner's root account credentials and an MFA device to apply via the "
                "AWS CLI/API — Terraform cannot enable it through a normal IAM role). Suppress "
                "an audited exception with `# security: allow-s3-mfa-delete` anywhere in the "
                "resource block."
            ),
            rule="s3-mfa-delete-disabled/inline-versioning-block",
            standards=list(_STANDARDS),
        )]

    def _check_split_form(
        self, root: Path, f: Path, name: str, start: int, body: _TfBody,
    ) -> list[Finding]:
        text = _body_text(body)
        if pragma_present(_PRAGMA, text, dialect="hcl"):
            return []
        config = _VERSIONING_CONFIGURATION.search(terraform_code_view(text))
        inner = config.group("inner") if config else ""
        if not _STATUS_ENABLED.search(inner):
            # Suspended, Disabled, or set through a variable: versioning is not provably on.
            return []
        if _MFA_DELETE_STRING_ENABLED.search(inner):
            return []
        return [Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start}",
            message=(
                f"`aws_s3_bucket_versioning.{name}`'s `versioning_configuration` block does not "
                'set `mfa_delete = "Enabled"`. Without MFA Delete, a single compromised set of '
                "IAM credentials can permanently delete a specific object version, or suspend "
                "versioning altogether, with no second factor required."
            ),
            remediation=(
                'Add `mfa_delete = "Enabled"` to the `versioning_configuration` block (this also '
                "requires the bucket owner's root account credentials and an MFA device to apply "
                "via the AWS CLI/API — Terraform cannot enable it through a normal IAM role). "
                "Suppress an audited exception with `# security: allow-s3-mfa-delete` anywhere "
                "in the resource block."
            ),
            rule="s3-mfa-delete-disabled/versioning-configuration-resource",
            standards=list(_STANDARDS),
        )]
