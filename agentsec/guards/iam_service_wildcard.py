"""Guard: Terraform AWS IAM policy statement grants a full SERVICE-wide wildcard action
(checklist §6c).

    resource "aws_iam_role_policy" "app" {
      name = "app-policy"
      role = aws_iam_role.app.id
      policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect   = "Allow"
          Action   = "iam:*"          # every IAM action: CreateUser, PutRolePolicy, ...
          Resource = "*"
        }]
      })
    }

`iam-wildcard` (this repo's own guard) deliberately does NOT flag this shape — its own docstring
states "Scoped service wildcards (`s3:*`) are common and not flagged; the all-actions/all-resources
grant is the egregious case this catches." That's a defensible line for baseline hygiene, but a bare
SERVICE wildcard is still a real privilege-escalation surface on its own: `iam:*` alone grants every
action on the 15-action escalation list `iam-escalation-action-no-condition` (this same batch)
enumerates (`PutRolePolicy`, `AttachRolePolicy`, `PassRole`, ...), and `s3:*` grants
`PutBucketPolicy`/`DeleteBucket` on every bucket in the account. This guard complements
`iam-wildcard` rather than duplicating it: it fires ONLY on a genuine `<service>:*` action — exactly
one colon, ending in a bare trailing `*` — inside an `Effect: Allow` statement, and never on
`iam-wildcard`'s own territory: the all-actions `"*"` grant, the `"*:*"` shape, a scoped single
action (`s3:GetObject`), or a Resource ARN that merely ends in `*`
(`arn:aws:s3:::bucket/*` — no colon precedes that star, so it can never match `_SERVICE_WILDCARD`).
CWE-269 (Improper Privilege Management), OWASP:A01. Modeled on Pike's `AWS002` audit rule
(github.com/JamesWoolfenden/pike, `src/audit_aws.go`).

Scans Terraform `.tf` files via the shared `iter_policy_statement_blocks` walker (the same one
`iam-wildcard` and `s3-bucket-policy-wildcard-principal` use) — string/comment/heredoc-aware, and
tolerant of both the JSON-literal (`"Effect": "Allow"`) and idiomatic HCL `jsonencode()`
(`Effect = "Allow"`) key forms. Fires HIGH per offending `Action` string found inside an
`Effect: Allow` statement (never `NotAction` — that shape is `iam-notaction-with-allow`'s territory
— and never inside a `Deny` statement). Suppress an audited statement with a
`# security: allow-iam-service-wildcard` line in the file.
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
    pragma_present,
    read,
    rel,
)

# `Effect: Allow` / `Effect = "Allow"` — both the JSON-literal and idiomatic HCL forms.
_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"', re.IGNORECASE)
# The `Action` key's assigned value — a scalar quoted string or a `[...]` array of them. The
# `(?<!Not)` guard keeps this off `NotAction` (opposite semantics), the same technique
# `s3-bucket-policy-wildcard-principal` uses to keep its own Principal match off `NotPrincipal`.
_ACTION_ASSIGN = re.compile(
    r'(?<!Not)"?Action"?\s*[:=]\s*(?P<val>\[[^\]]*\]|"[^"]*")', re.IGNORECASE
)
# A single quoted action string inside that value.
_QUOTED = re.compile(r'"([^"]*)"')
# A genuine SERVICE-wide wildcard: `<service>:*` — one colon, ending in a bare `*`. Deliberately
# excludes the bare `"*"` grant (iam-wildcard's own territory) and a `"*:*"` shape (no service name
# can appear before the colon and still match `[A-Za-z0-9]+`).
_SERVICE_WILDCARD = re.compile(r"^[A-Za-z0-9]+:\*$")
_PRAGMA = re.compile(r"#\s*security:\s*allow-iam-service-wildcard")

_STANDARDS = ["OWASP:A01", "CWE-269"]


class IamServiceWildcardGuard(Guard):
    id = "iam-service-wildcard"
    title = "IAM policy statement grants a full service-wide wildcard action"
    area = "Cloud & IaC"

    # iam_service_wildcard.tf: Effect Allow, Action "iam:*" -> fires iam-service-wildcard.
    canary_plant = CanaryPlant(
        files={
            "iam_service_wildcard.tf": (
                'resource "aws_iam_role_policy" "canary" {\n'
                '  name = "canary-policy"\n'
                "  role = aws_iam_role.canary.id\n"
                "  policy = jsonencode({\n"
                '    Version = "2012-10-17"\n'
                "    Statement = [{\n"
                '      Effect   = "Allow"\n'
                '      Action   = "iam:*"\n'
                '      Resource = "*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({"iam-service-wildcard/service-action"}),
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
        if pragma_present(_PRAGMA, text, dialect="hcl"):
            return out
        for start, _end, block in iter_policy_statement_blocks(text):
            if not _EFFECT_ALLOW.search(block):
                continue
            for m in _ACTION_ASSIGN.finditer(block):
                val = m.group("val")
                val_start = m.start("val")
                for qm in _QUOTED.finditer(val):
                    action = qm.group(1)
                    if not _SERVICE_WILDCARD.match(action):
                        continue
                    abs_offset = start + val_start + qm.start()
                    line = text.count("\n", 0, abs_offset) + 1
                    service = action.split(":", 1)[0]
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=self.title,
                            location=f"{rel(root, f)}:{line}",
                            message=(
                                f'This Allow statement grants `Action: "{action}"` — every '
                                f"action in the `{service}` service, on whatever Resource the "
                                "statement scopes to. A service-wide wildcard still hands out "
                                "any escalation/destructive action that service exposes, even "
                                "though the statement isn't the all-actions `*` grant."
                            ),
                            remediation=(
                                "List only the specific actions this role/user actually needs "
                                "instead of the whole service (least privilege). Suppress an "
                                "audited exception with `# security: allow-iam-service-wildcard` "
                                "in the file."
                            ),
                            rule="iam-service-wildcard/service-action",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
