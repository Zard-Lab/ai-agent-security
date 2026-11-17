"""Guard: an AWS IAM policy statement combines `Effect: Allow` with `NotAction` (checklist §6c).

    resource "aws_iam_role_policy" "app" {
      name = "app-policy"
      role = aws_iam_role.app.id
      policy = jsonencode({
        Statement = [{
          Effect      = "Allow"
          NotAction   = ["iam:*", "organizations:*"]   # "allow everything EXCEPT these"
          Resource    = "*"
        }]
      })
    }

`Allow` + `NotAction` is an "allow every action AWS has, except the ones listed" grant. It is a
fundamentally different (and much riskier) shape than `Deny` + `NotAction` ("deny everything except
these" — a common, legitimate guardrail pattern this guard deliberately does NOT flag): AWS adds new
actions and even new services continuously, and every one of them is silently INCLUDED in this
statement's grant the moment it exists — the policy's author never has to touch the file again for
the blast radius to grow. This is the same "over-grants as AWS's own API surface grows" failure
mode as the IAM Access Analyzer and AWS's own IAM best-practices guide both call out explicitly for
`NotAction` used with `Allow`. CWE-269 (Improper Privilege Management), OWASP:A01. Modeled on
Pike's `AWS005` audit rule (github.com/JamesWoolfenden/pike, `src/audit_aws.go`).

Scans Terraform `.tf` files AND bare IAM policy `.json` documents (2026-10-08, aws-agent-identity-
guard research-cycle: an AI agent's execution-role policy is routinely shipped as a standalone JSON
file (e.g. the body passed to `boto3.create_policy()`, or committed for review alongside a Bedrock/
SageMaker agent definition), never wrapped in Terraform/CloudFormation at all, so the `.tf`-only
scope silently missed that whole class of repo) via the shared `iter_policy_statement_blocks`
walker (string/comment/heredoc-aware, tolerant of both the JSON-literal and idiomatic HCL
`jsonencode()` key forms; the same walker already used for both formats by `iam-wildcard`). A
cheap `"Statement"` pre-filter on the comment/heredoc-blanked view (mirroring `iam-wildcard`'s own
gating) keeps this from walking every unrelated `.json` file in a repo. Fires HIGH once per
statement that carries both `Effect: Allow` and a `NotAction` key, regardless of what either is
scoped to (a `Condition` narrows WHICH principal/request the grant applies to, not the fact that
the grant itself is open-ended over the AWS action surface, so a `Condition` does not suppress this
finding the way it does for `iam-escalation-action-no-condition`). Suppress an audited statement
with a `# security: allow-iam-notaction-with-allow` comment in a `.tf` file, or the literal string
anywhere in a `.json` file (JSON has no comment syntax; same fallback `iam-wildcard` already uses,
#424).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_policy_noise,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_policy_statement_blocks,
    pragma_present,
    read,
    rel,
)

_EXTENSIONS = (".tf", ".json")
_IS_POLICY = re.compile(r'"Statement"', re.IGNORECASE)
_EFFECT_WORD = re.compile(r"Effect", re.IGNORECASE)
_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"', re.IGNORECASE)
_NOT_ACTION = re.compile(r'"?NotAction"?\s*[:=]', re.IGNORECASE)
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-iam-notaction-with-allow")

_STANDARDS = ["OWASP:A01", "CWE-269"]


class IamNotactionWithAllowGuard(Guard):
    id = "iam-notaction-with-allow"
    title = 'IAM policy statement combines Effect: "Allow" with NotAction'
    area = "Cloud & IaC"

    # iam_notaction_with_allow.tf: Effect Allow + NotAction -> fires iam-notaction-with-allow.
    # agent_policy.json: the same shape in a bare IAM policy document (no Terraform at all) ->
    # also fires iam-notaction-with-allow, proving the 2026-10-08 format-widening actually works.
    canary_plant = CanaryPlant(
        files={
            "iam_notaction_with_allow.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                '  name = "canary-policy"\n'
                "  role = aws_iam_role.canary.id\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      NotAction = ["iam:*", "organizations:*"]\n'
                '      Resource  = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
            "agent_policy.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "NotAction": ["iam:*", "organizations:*"],\n'
                '    "Resource": "*"\n'
                "  }]\n"
                "}\n"
            ),
        },
        expects=frozenset({"iam-notaction-with-allow/allow-notaction"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # an IAM policy (bare JSON or Terraform) can live in any repo

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        # Cheap raw precheck before the blanking pass (#1051 review M4). Blanking only turns
        # characters into spaces, so a file whose RAW text has no `"Statement"` (JSON) or no
        # `Effect` key word (HCL) cannot hold a policy statement once blanked either.
        if not (_IS_POLICY if f.suffix == ".json" else _EFFECT_WORD).search(text):
            return out
        # Pre-filter on the comment/heredoc-blanked view (mirrors iam-wildcard): skip a
        # `.json` file that was never an IAM policy at all before paying for the statement walk.
        if f.suffix == ".json" and not _IS_POLICY.search(blank_policy_noise(text)):
            return out
        for start, _end, block in iter_policy_statement_blocks(text):
            if not _EFFECT_ALLOW.search(block):
                continue
            m = _NOT_ACTION.search(block)
            if m is None:
                continue
            abs_offset = start + m.start()
            line = text.count("\n", 0, abs_offset) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{line}",
                    message=(
                        'This statement combines `Effect: "Allow"` with `NotAction` -- it '
                        "grants every AWS action EXCEPT the ones listed, including every action "
                        "AWS adds to any service in the future. The grant silently widens over "
                        "time with no change to this file."
                    ),
                    remediation=(
                        "Replace `NotAction` with an explicit `Action` allow-list naming only "
                        "the actions actually needed (least privilege). Suppress an audited "
                        "exception with `# security: allow-iam-notaction-with-allow` in the "
                        "file."
                    ),
                    rule="iam-notaction-with-allow/allow-notaction",
                    standards=list(_STANDARDS),
                )
            )
        return out
