"""Guard: Terraform CloudTrail trail with logging disabled or single-region (checklist §10).

    resource "aws_cloudtrail" "main" {
      name           = "org-trail"
      enable_logging = false          # no API activity is recorded at all
    }

CloudTrail is the account's audit log of every API call — the record an incident
response depends on to answer "what happened." `enable_logging = false` turns the
trail off entirely (the resource exists but records nothing); a trail left
single-region (`is_multi_region_trail` unset or `false`) silently misses every API
call made outside its home region, which is exactly where an attacker pivoting
through a compromised credential would operate to stay off the radar.
CWE-778 (Insufficient Logging), OWASP:A09.

Fires HIGH when an `aws_cloudtrail` resource block sets `enable_logging = false`, and
MEDIUM when the trail is single-region — either an explicit `is_multi_region_trail =
false` OR the attribute **absent entirely**. The Terraform AWS provider defaults
`is_multi_region_trail` to `false` (the insecure, single-region state), so a plain
`resource "aws_cloudtrail" "main" { name = "org-trail" }` is single-region by default —
the majority real-world shape of this bug, and exactly what Checkov's `CKV_AWS_67`
evaluates the effective default for. Only an explicit `is_multi_region_trail = true`
silences the MEDIUM. (For `enable_logging` the default is `true`, the SAFE state, so an
absent `enable_logging` is not flagged — silence is correct there.)

Suppress an audited case with `# security: allow-cloudtrail-logging` on the
attribute line.
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

_CLOUDTRAIL_RESOURCE_TYPES = frozenset({"aws_cloudtrail"})
_LOGGING_DISABLED = re.compile(r"\benable_logging\s*=\s*false\b")
_MULTI_REGION_ATTR = re.compile(r"\bis_multi_region_trail\s*=")
_MULTI_REGION_TRUE = re.compile(r"\bis_multi_region_trail\s*=\s*true\b")
_SINGLE_REGION = re.compile(r"\bis_multi_region_trail\s*=\s*false\b")
_PRAGMA = re.compile(r"#\s*security:\s*allow-cloudtrail-logging")

_STANDARDS = ["OWASP:A09", "CWE-778"]


class CloudtrailLoggingDisabledGuard(Guard):
    id = "cloudtrail-logging-disabled"
    title = "CloudTrail logging disabled or restricted to a single region"
    area = "Cloud & IaC"

    # cloudtrail.tf: aws_cloudtrail with enable_logging = false and is_multi_region_trail = false
    # -> fires both logging-disabled and single-region-trail. Must NOT contain:
    # allow-cloudtrail-logging pragma.
    canary_plant = CanaryPlant(
        files={
            "cloudtrail.tf": (
                'resource "aws_cloudtrail" "canary" {\n'
                '  name                   = "canary-trail"\n'
                "  enable_logging         = false\n"
                "  is_multi_region_trail  = false\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "cloudtrail-logging-disabled/logging-disabled",
            "cloudtrail-logging-disabled/single-region-trail",
        }),
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
        for resource_type, resource_name, start, body in iter_terraform_resources(text):
            if resource_type not in _CLOUDTRAIL_RESOURCE_TYPES:
                continue
            out.extend(self._scan_block(root, f, resource_type, resource_name, start, body))
        return out

    def _scan_block(
        self, root: Path, f: Path, resource_type: str, resource_name: str,
        start: int, body: list[tuple[int, str]],
    ) -> list[Finding]:
        out: list[Finding] = []
        multi_region_true = False        # explicit is_multi_region_trail = true (the safe state)
        multi_region_present = False     # the attribute appears at all (true/false/pragma'd)
        single_region_false_line: int | None = None  # explicit = false, not pragma-suppressed
        start_line_pragma = False        # pragma on the resource opening line -> suppress the absent case
        for lineno, line in body:
            has_pragma = pragma_present(_PRAGMA, line, dialect="hcl")  # a comment on it, never a string (#424)
            if lineno == start and has_pragma:
                start_line_pragma = True
            if line.lstrip().startswith("#"):
                continue
            if _MULTI_REGION_ATTR.search(line):
                multi_region_present = True
                if _MULTI_REGION_TRUE.search(line):
                    multi_region_true = True
                elif _SINGLE_REGION.search(line) and not has_pragma:
                    single_region_false_line = lineno
            if has_pragma:
                continue
            if _LOGGING_DISABLED.search(line):
                out.append(self._finding(root, f, resource_type, resource_name, lineno, kind="disabled"))
        # Single-region MEDIUM: fire unless the trail is explicitly multi-region. An explicit
        # `= false` anchors on its line; an ABSENT attribute (provider-default false) anchors on
        # the resource opening line and is suppressed by a pragma there.
        if not multi_region_true:
            if single_region_false_line is not None:
                out.append(self._finding(
                    root, f, resource_type, resource_name, single_region_false_line, kind="single_region"))
            elif not multi_region_present and not start_line_pragma:
                out.append(self._finding(
                    root, f, resource_type, resource_name, start, kind="single_region_absent"))
        return out

    def _finding(
        self, root: Path, f: Path, resource_type: str, resource_name: str, lineno: int, *, kind: str
    ) -> Finding:
        if kind == "disabled":
            return Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    f"`{resource_type}.{resource_name}` sets `enable_logging = false` — this "
                    "trail records no API activity at all, leaving the account with no audit "
                    "log to investigate a compromise."
                ),
                remediation=(
                    "Remove `enable_logging = false` (or set it to `true`). Suppress an "
                    "audited exception with `# security: allow-cloudtrail-logging` on the "
                    "attribute line."
                ),
                rule="cloudtrail-logging-disabled/logging-disabled",
                standards=list(_STANDARDS),
            )
        if kind == "single_region_absent":
            message = (
                f"`{resource_type}.{resource_name}` does not set `is_multi_region_trail`, which "
                "the AWS provider defaults to `false` — this trail records only its home region, "
                "so API calls made in any other region are silently missed (a common blind spot "
                "for an attacker pivoting through a compromised credential)."
            )
            remediation = (
                "Set `is_multi_region_trail = true` so the trail covers every region. Suppress an "
                "audited single-region exception with `# security: allow-cloudtrail-logging` on "
                "the resource's opening line."
            )
        else:  # "single_region": explicit is_multi_region_trail = false
            message = (
                f"`{resource_type}.{resource_name}` sets `is_multi_region_trail = false` — "
                "API calls made in any other region are not recorded, a common blind spot "
                "for an attacker pivoting through a compromised credential."
            )
            remediation = (
                "Remove `is_multi_region_trail = false` (or set it to `true`) so the trail "
                "covers every region. Suppress an audited exception with "
                "`# security: allow-cloudtrail-logging` on the attribute line."
            )
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule="cloudtrail-logging-disabled/single-region-trail",
            standards=list(_STANDARDS),
        )
