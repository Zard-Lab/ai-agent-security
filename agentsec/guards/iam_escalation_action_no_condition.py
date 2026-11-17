"""Guard: an AWS IAM policy statement grants a privilege-escalation-class action under
`Effect: Allow` with no scoping Condition (checklist §6c).

    resource "aws_iam_role_policy" "app" {
      name = "app-policy"
      role = aws_iam_role.app.id
      policy = jsonencode({
        Statement = [{
          Effect   = "Allow"
          Action   = "iam:PassRole"    # can hand ANY role this identity can reach to a service
          Resource = "*"               # ...with no aws:PassedToService / ResourceTag condition
        }]
      })
    }

These 15 actions are the classic AWS IAM privilege-escalation primitives (Spencer Gietzen's
2018 "AWS IAM Privilege Escalation" research, and the basis for cloud-security tools' own
escalation checks — Pike's `escalation.go::escalationAWS` map, cfripper's `privilege_escalation.py`
CFN-format check already in this repo's corpus-scan history): each one lets an identity that
already has SOME access expand it further — attach a new policy to itself/another principal
(`PutRolePolicy`, `AttachRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`, `PutUserPolicy`,
`PutGroupPolicy`), create a new policy version that IS the attack payload
(`CreatePolicyVersion`, `SetDefaultPolicyVersion`), rewrite what a role trusts
(`UpdateAssumeRolePolicy`), hand its own or another role's permissions to something it controls
(`PassRole`, `sts:AssumeRole`), mint new long-lived credentials (`CreateAccessKey`,
`CreateLoginProfile`, `UpdateLoginProfile`), or join a more-privileged group
(`AddUserToGroup`). CWE-269 (Improper Privilege Management), OWASP:A01. Modeled on Pike's `AWS004`
audit rule (github.com/JamesWoolfenden/pike, `src/audit_aws.go` + `escalation.go`).

A scoping `Condition` (e.g. `iam:PassedToService`, `aws:ResourceTag/...`, `aws:PrincipalOrgID`) can
genuinely narrow one of these grants to a specific, intended use — this guard uses the SAME
conservative heuristic `s3-bucket-policy-wildcard-principal` uses for its own Condition check: ANY
`Condition` block present anywhere in the statement is treated as a plausible narrowing, trading
some false negatives (a `Condition` that doesn't actually narrow anything) for a much lower false
positive rate than re-implementing AWS's own condition-key semantics in regex.

Scans Terraform `.tf` files AND bare IAM policy `.json` documents (2026-10-08, aws-agent-identity-
guard research-cycle; same format-widening rationale as `iam-notaction-with-allow`: an AI agent's
execution-role policy routinely ships as a standalone JSON file, never wrapped in Terraform) via
the shared `iter_policy_statement_blocks` walker (string/comment/heredoc-aware, tolerant of both
the JSON-literal and idiomatic HCL `jsonencode()` key forms). Fires HIGH once per matched
escalation action found inside an `Effect: Allow` statement that has NO `Condition` key anywhere in
the statement. A statement that names a `Principal`/`NotPrincipal` is skipped (PR #1051 review, M3):
it is a role trust policy or a resource policy, so its `sts:AssumeRole` says who may assume THIS
role and grants nothing. Before that, every `aws_iam_role` `assume_role_policy` and every bare
trust-policy `.json` fired `unconditional-grant`.

`iam:PassRole` gets one additional, more precise check (2026-10-08): AWS's own documented mitigation
for PassRole is specifically the `iam:PassedToService` condition key, which scopes the grant to "this
role may only be passed to THIS service". A `Condition` block present but missing that exact key
(e.g. one that only narrows on `aws:RequestedRegion`) still lets the role be passed to ANY service
that will accept it, so it is NOT the general "any Condition is a plausible narrowing" heuristic's
blind spot being closed, it is a second, independent rule that fires ON TOP of a `Condition` already
being present: `iam-escalation-action-no-condition/passrole-missing-passed-to-service`. Suppress an
audited statement with a `# security: allow-iam-escalation-no-condition` comment in a `.tf` file, or
the literal string anywhere in a `.json` file (JSON has no comment syntax; the same fallback
`iam-wildcard`/`iam-notaction-with-allow` already use, #424).
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
    iter_policy_key_values,
    iter_policy_statement_blocks,
    pragma_present,
    read,
    rel,
)

_EXTENSIONS = (".tf", ".json")
_IS_POLICY = re.compile(r'"Statement"', re.IGNORECASE)
_EFFECT_WORD = re.compile(r"Effect", re.IGNORECASE)
_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"', re.IGNORECASE)
# The Action key head; its list/string value is read by base.iter_policy_key_values, uncapped
# and linear (a `\[[^\]]*\]` value regex is quadratic on a run of unterminated `[`, #1051 round 4).
_ACTION_HEAD = re.compile(r'(?<!Not)"?Action"?\s*[:=]\s*', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')
_CONDITION_PRESENT = re.compile(r'"?Condition"?\s*[:=]', re.IGNORECASE)
_PASSED_TO_SERVICE = re.compile(r'"?iam:PassedToService"?', re.IGNORECASE)
# A statement naming a Principal is a trust or resource policy: it says who may act on THIS
# resource and grants nothing to an identity, so it is never an escalation grant (#1051 M3).
_PRINCIPAL_KEY = re.compile(r'"?(?:Not)?Principal"?\s*[:=]', re.IGNORECASE)
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-iam-escalation-no-condition")

_PASSROLE = "iam:passrole"

# The exact 15-action escalation list — case preserved to match real-world policy authoring, but
# compared case-insensitively below (AWS action names are conventionally PascalCase, but the JSON
# and HCL forms are both just quoted strings, and a policy author's casing is not load-bearing to
# AWS's own API).
_ESCALATION_ACTIONS = frozenset({
    a.lower() for a in (
        "iam:PutRolePolicy",
        "iam:AttachRolePolicy",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
        "iam:PassRole",
        "iam:CreateAccessKey",
        "sts:AssumeRole",
        "iam:AttachUserPolicy",
        "iam:AttachGroupPolicy",
        "iam:PutUserPolicy",
        "iam:PutGroupPolicy",
        "iam:AddUserToGroup",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
    )
})

_STANDARDS = ["OWASP:A01", "CWE-269"]


class IamEscalationActionNoConditionGuard(Guard):
    id = "iam-escalation-action-no-condition"
    title = "Privilege-escalation IAM action granted with no scoping Condition"
    area = "Cloud & IaC"

    # iam_escalation_action_no_condition.tf: Effect Allow, Action "iam:PassRole", no Condition ->
    # fires iam-escalation-action-no-condition/unconditional-grant.
    # agent_execution_policy.json: the same shape in a bare IAM policy document -> also fires
    # unconditional-grant, proving the 2026-10-08 format-widening works.
    # iam_passrole_wrong_condition.tf: PassRole WITH a Condition that is not PassedToService ->
    # fires the new, more precise passrole-missing-passed-to-service rule.
    canary_plant = CanaryPlant(
        files={
            "iam_escalation_action_no_condition.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                '  name = "canary-policy"\n'
                "  role = aws_iam_role.canary.id\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "iam:PassRole"\n'
                '      Resource = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
            "agent_execution_policy.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "Action": "iam:PassRole",\n'
                '    "Resource": "*"\n'
                "  }]\n"
                "}\n"
            ),
            "iam_passrole_wrong_condition.tf": (
                'resource "aws_iam_role_policy" "canary2" {\n'
                '  name = "canary-policy-2"\n'
                "  role = aws_iam_role.canary2.id\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      Action    = "iam:PassRole"\n'
                '      Resource  = "*"\n'
                "      Condition = {\n"
                '        StringEquals = { "aws:RequestedRegion" = "us-east-1" }\n'
                "      }\n"
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "iam-escalation-action-no-condition/unconditional-grant",
            "iam-escalation-action-no-condition/passrole-missing-passed-to-service",
        }),
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
        if f.suffix == ".json" and not _IS_POLICY.search(blank_policy_noise(text)):
            return out
        for start, _end, block in iter_policy_statement_blocks(text):
            if not _EFFECT_ALLOW.search(block) or _PRINCIPAL_KEY.search(block):
                continue
            condition_present = _CONDITION_PRESENT.search(block) is not None
            has_passed_to_service = condition_present and _PASSED_TO_SERVICE.search(block) is not None
            seen: set[str] = set()
            for m, val in iter_policy_key_values(block, _ACTION_HEAD):
                val_start = m.end()
                for qm in _QUOTED.finditer(val or ""):
                    action = qm.group(1)
                    if action.lower() not in _ESCALATION_ACTIONS:
                        continue
                    key = action.lower()
                    if key in seen:
                        continue
                    seen.add(key)
                    abs_offset = start + val_start + qm.start()
                    line = text.count("\n", 0, abs_offset) + 1
                    location = f"{rel(root, f)}:{line}"

                    if not condition_present:
                        # The general case: ANY Condition anywhere is treated as a plausible
                        # narrowing (conservative, trades some FN for a low FP rate) -- this rule
                        # only fires when there is NO Condition at all in the statement.
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=location,
                                message=(
                                    f'This Allow statement grants `{action}` — a privilege-'
                                    "escalation-class action — with no `Condition` anywhere in "
                                    "the statement to scope it. An identity holding this "
                                    "permission can use it to expand its own (or another "
                                    "principal's) access."
                                ),
                                remediation=(
                                    "Add a scoping Condition (e.g. `iam:PassedToService`, "
                                    "`aws:ResourceTag/...`, `aws:PrincipalOrgID`) that genuinely "
                                    "narrows this grant to its intended use, or remove the "
                                    "action if it isn't needed. Suppress an audited exception "
                                    "with `# security: allow-iam-escalation-no-condition` in the "
                                    "file."
                                ),
                                rule="iam-escalation-action-no-condition/unconditional-grant",
                                standards=list(_STANDARDS),
                            )
                        )
                    elif key == _PASSROLE and not has_passed_to_service:
                        # A Condition IS present (so the general rule above stays silent) but it
                        # is not the one AWS's own docs name as PassRole's actual mitigation: the
                        # role can still be passed to ANY service that will accept it.
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=location,
                                message=(
                                    "This Allow statement grants `iam:PassRole` with a `Condition` "
                                    "that does not include `iam:PassedToService`. A Condition on "
                                    "something else (region, tag, ...) does not stop the role "
                                    "from being passed to ANY service that will accept it."
                                ),
                                remediation=(
                                    "Add `iam:PassedToService` to the Condition, scoped to the "
                                    "exact service that should receive this role (e.g. "
                                    "`bedrock.amazonaws.com`). Suppress an audited exception "
                                    "with `# security: allow-iam-escalation-no-condition` in the "
                                    "file."
                                ),
                                rule="iam-escalation-action-no-condition/passrole-missing-passed-to-service",
                                standards=list(_STANDARDS),
                            )
                        )
        return out
