"""Guard: Terraform ECR repository missing scan-on-push, immutable tags, or a lifecycle
policy (checklist §7).

    resource "aws_ecr_repository" "app" {
      name = "app-image"
      # no image_scanning_configuration -> images pushed with no vulnerability scan
      # no image_tag_mutability = "IMMUTABLE" -> a tag can be silently overwritten
    }
    # no aws_ecr_lifecycle_policy resource references aws_ecr_repository.app ->
    # images accumulate forever, including old/vulnerable ones

Three independent `aws_ecr_repository` hygiene gaps, none of which are about the
repository's KMS encryption (that is `ecr-repository-not-kms-encrypted`, a separate,
already-covered concern):

1. **No vulnerability scanning on push** — an `aws_ecr_repository` with no
   `image_scanning_configuration { scan_on_push = true }` block lets an image with known
   CVEs reach the registry (and from there, a deployment) with no automated check.
   CWE-1104-adjacent supply-chain gap, OWASP:A06 (Vulnerable and Outdated Components).

2. **Mutable image tags** — `image_tag_mutability` defaults to `"MUTABLE"` when omitted,
   which means the same tag (e.g. `:prod`, `:v1.2.3`) can be silently re-pushed to point
   at a different image after it was reviewed/scanned/approved — an attacker (or a
   compromised CI pipeline) can swap a pinned image without changing the reference
   anything downstream uses to pull it. CWE-345 (Insufficient Verification of Data
   Authenticity), OWASP:A08 (Software and Data Integrity Failures).

3. **No lifecycle policy attached** — with no `aws_ecr_lifecycle_policy` resource
   referencing the repository, images accumulate without bound: old, superseded, and
   already-known-vulnerable images are never pruned, growing both cost and the attack
   surface of "which image did we actually deploy". CWE-770 (Allocation of Resources
   Without Limits or Throttling), OWASP:A05 (Security Misconfiguration).

Fires MEDIUM (`scan-on-push-disabled`) when the resource body does not contain
`scan_on_push = true` anywhere (whether `image_scanning_configuration` is absent, or
present without `scan_on_push = true`).

Fires MEDIUM (`mutable-tags`) when the resource body does not contain
`image_tag_mutability = "IMMUTABLE"` (whether the attribute is absent — the provider
default is `"MUTABLE"` — or explicitly set to `"MUTABLE"` or any other value).

Fires MEDIUM (`no-lifecycle-policy`) when no `aws_ecr_lifecycle_policy` resource
**anywhere in the scanned repo** has a `repository` attribute referencing
`aws_ecr_repository.<this resource's name>` (the idiomatic
`repository = aws_ecr_repository.app.name`/`.arn`/`.id` form). A lifecycle policy that
targets the repository by a literal string (not a Terraform reference) is a known,
documented false-negative — see "Known bypasses" in the design doc.

Suppress an audited case with `# security: allow-ecr-scan-on-push`,
`# security: allow-ecr-tag-mutability`, or `# security: allow-ecr-lifecycle-policy`
(matching the gap being suppressed) anywhere in the `aws_ecr_repository` resource block.
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
)

_ECR_REPO_RESOURCE_TYPES = frozenset({"aws_ecr_repository"})
_ECR_LIFECYCLE_RESOURCE_TYPES = frozenset({"aws_ecr_lifecycle_policy"})

_SCAN_ON_PUSH_TRUE = re.compile(r"\bscan_on_push\s*=\s*true\b")
_TAG_IMMUTABLE = re.compile(r'\bimage_tag_mutability\s*=\s*"IMMUTABLE"', re.IGNORECASE)
_LIFECYCLE_REPO_ATTR = re.compile(r"\brepository\s*=\s*([^\n#]+)")

_PRAGMA_SCAN = re.compile(r"#\s*security:\s*allow-ecr-scan-on-push")
_PRAGMA_MUTABILITY = re.compile(r"#\s*security:\s*allow-ecr-tag-mutability")
_PRAGMA_LIFECYCLE = re.compile(r"#\s*security:\s*allow-ecr-lifecycle-policy")

_SCAN_STANDARDS = ["OWASP:A06", "CIS:AWS"]
_MUTABILITY_STANDARDS = ["OWASP:A08", "CWE-345"]
_LIFECYCLE_STANDARDS = ["OWASP:A05", "CWE-770"]


class EcrRepositoryHygieneGuard(Guard):
    id = "ecr-repository-hygiene"
    title = "ECR repository missing vulnerability scanning, immutable tags, or a lifecycle policy"
    area = "Cloud & IaC"

    # ecr.tf: aws_ecr_repository with no image_scanning_configuration, no
    # image_tag_mutability = "IMMUTABLE", and no aws_ecr_lifecycle_policy anywhere ->
    # fires all three rules. Must NOT contain: allow-ecr-* pragmas.
    canary_plant = CanaryPlant(
        files={
            "ecr.tf": (
                'resource "aws_ecr_repository" "canary" {\n'
                '  name = "canary-image"\n'
                "}\n"
            ),
        },
        expects=frozenset({
            "ecr-repository-hygiene/scan-on-push-disabled",
            "ecr-repository-hygiene/mutable-tags",
            "ecr-repository-hygiene/no-lifecycle-policy",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = [
            f for f in iter_files(root, (".tf",))
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]
        lifecycle_refs = self._collect_lifecycle_refs(files)
        out: list[Finding] = []
        for f in files:
            out.extend(self._scan(root, f, lifecycle_refs))
        return out

    def _collect_lifecycle_refs(self, files: list[Path]) -> frozenset[str]:
        """Every raw `repository = ...` expression from an `aws_ecr_lifecycle_policy`
        resource, across all scanned files — cross-file, since the policy is commonly
        declared alongside other lifecycle resources, not next to its repository."""
        refs: set[str] = set()
        for f in files:
            text = read(f)
            for resource_type, _name, _start, body in iter_terraform_resources(text):
                if resource_type not in _ECR_LIFECYCLE_RESOURCE_TYPES:
                    continue
                for _lineno, line in body:
                    if line.lstrip().startswith(("#", "//")):
                        continue
                    m = _LIFECYCLE_REPO_ATTR.search(line)
                    if m:
                        refs.add(m.group(1).strip())
        return frozenset(refs)

    def _scan(self, root: Path, f: Path, lifecycle_refs: frozenset[str]) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource_type, resource_name, start_line, body in iter_terraform_resources(text):
            if resource_type not in _ECR_REPO_RESOURCE_TYPES:
                continue
            out.extend(self._scan_block(root, f, resource_name, start_line, body, lifecycle_refs))
        return out

    def _scan_block(
        self, root: Path, f: Path, resource_name: str, start_line: int,
        body: list[tuple[int, str]], lifecycle_refs: frozenset[str],
    ) -> list[Finding]:
        out: list[Finding] = []
        raw_body = "\n".join(line for _, line in body)
        # Comment-blanked view so a commented-out `scan_on_push = true` / literal
        # `image_tag_mutability = "IMMUTABLE"` can't silence a genuinely unconfigured
        # repository (mirrors kms_key_rotation_not_enabled).
        code_body = "\n".join(
            "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
        )

        if not _SCAN_ON_PUSH_TRUE.search(code_body) and not pragma_present(_PRAGMA_SCAN, raw_body, dialect="hcl"):
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{start_line}",
                message=(
                    f"`aws_ecr_repository.{resource_name}` does not set "
                    "`image_scanning_configuration { scan_on_push = true }` — an image "
                    "with known CVEs can reach the registry, and from there a "
                    "deployment, with no automated vulnerability check."
                ),
                remediation=(
                    "Add `image_scanning_configuration { scan_on_push = true }` to the "
                    "resource. Suppress an audited exception with "
                    "`# security: allow-ecr-scan-on-push` anywhere in the resource block."
                ),
                rule="ecr-repository-hygiene/scan-on-push-disabled",
                standards=list(_SCAN_STANDARDS),
            ))

        if not _TAG_IMMUTABLE.search(code_body) and not pragma_present(_PRAGMA_MUTABILITY, raw_body, dialect="hcl"):
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{start_line}",
                message=(
                    f'`aws_ecr_repository.{resource_name}` does not set '
                    '`image_tag_mutability = "IMMUTABLE"` (the Terraform AWS provider '
                    'defaults this to `"MUTABLE"`) — the same tag (e.g. `:prod`) can be '
                    "silently re-pushed to point at a different image after it was "
                    "reviewed, scanned, or approved."
                ),
                remediation=(
                    'Set `image_tag_mutability = "IMMUTABLE"` on the resource. Suppress '
                    "an audited exception with `# security: allow-ecr-tag-mutability` "
                    "anywhere in the resource block."
                ),
                rule="ecr-repository-hygiene/mutable-tags",
                standards=list(_MUTABILITY_STANDARDS),
            ))

        ref_key = f"aws_ecr_repository.{resource_name}"
        referenced = any(ref_key in ref for ref in lifecycle_refs)
        if not referenced and not pragma_present(_PRAGMA_LIFECYCLE, raw_body, dialect="hcl"):
            out.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{start_line}",
                message=(
                    f"`aws_ecr_repository.{resource_name}` has no `aws_ecr_lifecycle_policy` "
                    "resource referencing it anywhere in the scanned repo — images "
                    "accumulate without bound, so old, superseded, and "
                    "already-known-vulnerable images are never pruned."
                ),
                remediation=(
                    "Add an `aws_ecr_lifecycle_policy` resource with "
                    f"`repository = {ref_key}.name` and a rule expiring untagged/stale "
                    "images. Suppress an audited exception with "
                    "`# security: allow-ecr-lifecycle-policy` anywhere in the resource "
                    "block."
                ),
                rule="ecr-repository-hygiene/no-lifecycle-policy",
                standards=list(_LIFECYCLE_STANDARDS),
            ))
        return out
