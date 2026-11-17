"""Guard: Terraform Step Functions state machine with no execution logging or tracing (checklist §7).

    resource "aws_sfn_state_machine" "workflow" {
      name     = "order-workflow"
      role_arn = aws_iam_role.sfn.arn
      definition = jsonencode({ ... })
      # no logging_configuration block, no tracing_configuration block ->
      # zero execution visibility into this workflow
    }

An `aws_sfn_state_machine` with no `logging_configuration` (or one whose `level` is
`"OFF"`) sends no execution history to CloudWatch Logs — a failed execution leaves no
record of which state it was in or what input/output it saw, so debugging it after the
fact is impossible. Separately, no `tracing_configuration` (or one with `enabled = false`)
means AWS X-Ray never traces the workflow's calls into Lambda/DynamoDB/other downstream
services, so a slow or failing multi-step workflow can't be traced across service
boundaries either. Both are execution-visibility gaps, not confidentiality/integrity
holes, but an incident responder investigating a compromised or misbehaving workflow
depends on exactly this data. CWE-778 (Insufficient Logging), OWASP:A09.

The Terraform AWS provider's insecure defaults make both gaps easy to introduce silently:
- `logging_configuration` — when the block is entirely absent, the state machine logs
  nothing (the AWS default is no logging destination configured). When the block IS
  present, `level` defaults to `"OFF"` if not set to `"ALL"`/`"ERROR"`/`"FATAL"`.
- `tracing_configuration` — when the block is entirely absent OR `enabled` is omitted
  within it, X-Ray tracing defaults to `false` (disabled).

Fires MEDIUM (`logging-disabled`) when the resource has no `logging_configuration` block,
or the block is present but does not set `level` to `"ALL"`, `"ERROR"`, or `"FATAL"`
(i.e. it is omitted or explicitly `"OFF"`).

Fires MEDIUM (`tracing-disabled`) when the resource has no `tracing_configuration` block,
or the block is present but does not set `enabled = true` (i.e. it is omitted or
explicitly `false`).

Suppress an audited case with `# security: allow-sfn-logging` (logging-disabled) or
`# security: allow-sfn-tracing` (tracing-disabled) anywhere in the resource block.
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

_SFN_RESOURCE_TYPES = frozenset({"aws_sfn_state_machine"})

_LOGGING_BLOCK_OPEN = re.compile(r"\blogging_configuration\s*\{")
_LOGGING_LEVEL_OK = re.compile(r'\blevel\s*=\s*"(?:ALL|ERROR|FATAL)"', re.IGNORECASE)

_TRACING_BLOCK_OPEN = re.compile(r"\btracing_configuration\s*\{")
_TRACING_ENABLED_TRUE = re.compile(r"\benabled\s*=\s*true\b")

_PRAGMA_LOGGING = re.compile(r"#\s*security:\s*allow-sfn-logging")
_PRAGMA_TRACING = re.compile(r"#\s*security:\s*allow-sfn-tracing")

_STANDARDS = ["OWASP:A09", "CWE-778"]


class SfnObservabilityGuard(Guard):
    id = "sfn-observability"
    title = "Step Functions state machine missing execution logging or X-Ray tracing"
    area = "Cloud & IaC"

    # sfn.tf: aws_sfn_state_machine with no logging_configuration and no
    # tracing_configuration block -> fires both logging-disabled and tracing-disabled.
    # Must NOT contain: allow-sfn-logging / allow-sfn-tracing pragmas.
    canary_plant = CanaryPlant(
        files={
            "sfn.tf": (
                'resource "aws_sfn_state_machine" "canary" {\n'
                '  name     = "canary-workflow"\n'
                '  role_arn = "arn:aws:iam::123456789012:role/canary-sfn-role"\n'
                "  definition = jsonencode({\n"
                '    Comment = "canary"\n'
                '    StartAt = "Pass"\n'
                "    States = {\n"
                '      Pass = {\n'
                '        Type = "Pass"\n'
                "        End  = true\n"
                "      }\n"
                "    }\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "sfn-observability/logging-disabled",
            "sfn-observability/tracing-disabled",
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
        for resource_type, resource_name, start_line, body in iter_terraform_resources(text):
            if resource_type not in _SFN_RESOURCE_TYPES:
                continue
            out.extend(self._scan_block(root, f, resource_name, start_line, body))
        return out

    def _scan_block(
        self, root: Path, f: Path, resource_name: str, start_line: int, body: list[tuple[int, str]],
    ) -> list[Finding]:
        out: list[Finding] = []
        raw_body = "\n".join(line for _, line in body)
        # Comment-blanked view so a commented-out `level = "ALL"` / `enabled = true` can't
        # silence a genuinely unconfigured block (mirrors kms_key_rotation_not_enabled).
        code_body = "\n".join(
            "" if line.lstrip().startswith(("#", "//")) else line for _, line in body
        )

        if not _LOGGING_LEVEL_OK.search(code_body) and not pragma_present(_PRAGMA_LOGGING, raw_body, dialect="hcl"):
            has_block = bool(_LOGGING_BLOCK_OPEN.search(code_body))
            out.append(self._finding(
                root, f, resource_name, start_line, kind="logging", has_block=has_block,
            ))

        if not _TRACING_ENABLED_TRUE.search(code_body) and not pragma_present(_PRAGMA_TRACING, raw_body, dialect="hcl"):
            has_block = bool(_TRACING_BLOCK_OPEN.search(code_body))
            out.append(self._finding(
                root, f, resource_name, start_line, kind="tracing", has_block=has_block,
            ))
        return out

    def _finding(
        self, root: Path, f: Path, resource_name: str, start_line: int, *, kind: str, has_block: bool,
    ) -> Finding:
        if kind == "logging":
            reason = (
                "sets `logging_configuration { level = ... }` to something other than "
                "`\"ALL\"`/`\"ERROR\"`/`\"FATAL\"` (or omits `level`, which defaults to `\"OFF\"`)"
                if has_block
                else "has no `logging_configuration` block at all"
            )
            message = (
                f"`aws_sfn_state_machine.{resource_name}` {reason} — this state machine "
                "sends no execution history to CloudWatch Logs, so a failed execution "
                "leaves no record of which state it was in or what input/output it saw."
            )
            remediation = (
                'Add a `logging_configuration` block with `level = "ALL"` (or `"ERROR"`) '
                "and a `log_destination` pointing at a CloudWatch log group. Suppress an "
                "audited exception with `# security: allow-sfn-logging` anywhere in the "
                "resource block."
            )
            rule = "sfn-observability/logging-disabled"
        else:
            reason = (
                "has a `tracing_configuration` block that does not set `enabled = true`"
                if has_block
                else "has no `tracing_configuration` block at all"
            )
            message = (
                f"`aws_sfn_state_machine.{resource_name}` {reason} — AWS X-Ray never "
                "traces this workflow's calls into Lambda/DynamoDB/other downstream "
                "services, so a slow or failing multi-step execution can't be traced "
                "across service boundaries."
            )
            remediation = (
                "Add `tracing_configuration { enabled = true }` to the resource. "
                "Suppress an audited exception with `# security: allow-sfn-tracing` "
                "anywhere in the resource block."
            )
            rule = "sfn-observability/tracing-disabled"
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{start_line}",
            message=message,
            remediation=remediation,
            rule=rule,
            standards=list(_STANDARDS),
        )
