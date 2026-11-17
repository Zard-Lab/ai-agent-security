"""Guard: Terraform IAM policy attached directly to a user (checklist §6c).

    resource "aws_iam_user_policy" "app" {
      name   = "app-policy"
      user   = aws_iam_user.app.name
      policy = jsonencode({ ... })
    }

Attaching policies directly to individual IAM users (instead of to a group or role
the user is a member of) means every permission change has to be made per-user —
permissions drift silently as people join, change roles, and leave, and there is no
single place to audit "what can this team do." `aws_iam_user_policy` and
`aws_iam_user_policy_attachment` exist specifically for user-direct attachment (there
is no other legitimate use of either resource type); `aws_iam_policy_attachment` can
target users, roles, or groups via separate arguments, so it only fires when its
`users` argument is actually populated. CWE-269 (Improper Privilege Management),
OWASP:A01.

Fires MEDIUM on every `aws_iam_user_policy` / `aws_iam_user_policy_attachment`
resource declaration, and on an `aws_iam_policy_attachment` resource whose `users`
list is non-empty.

Suppress an audited case with `# security: allow-iam-user-policy` anywhere in the
resource block.
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

_DIRECT_USER_RESOURCE_TYPES = frozenset({"aws_iam_user_policy", "aws_iam_user_policy_attachment"})
_MIXED_ATTACHMENT_TYPE = "aws_iam_policy_attachment"
_USERS_OPEN = re.compile(r"\busers\s*=\s*\[")
_PRAGMA = re.compile(r"#\s*security:\s*allow-iam-user-policy")


def _strip_line_comment(s: str) -> str:
    return re.split(r"#|//", s, maxsplit=1)[0]


def _users_nonempty_line(body: list[tuple[int, str]]) -> int | None:
    """Return the line number of a non-empty `users = [ ... ]` list, or None. Joins the list
    across physical lines up to the matching `]` (so a `terraform fmt`-split multi-line list is
    seen), and treats a list holding only whitespace/comments as empty. Comments are stripped
    from each line BEFORE the `]`-termination test, so a stray `]` inside a comment cannot end
    the join early and drop a real user element below it."""
    for idx, (lineno, line) in enumerate(body):
        if line.lstrip().startswith("#"):
            continue
        m = _USERS_OPEN.search(line)
        if not m:
            continue
        parts = [_strip_line_comment(line[m.end():])]
        j = idx
        while "]" not in parts[-1] and j + 1 < len(body):
            j += 1
            parts.append(_strip_line_comment(body[j][1]))
        content = "\n".join(parts).split("]", 1)[0]
        if content.strip():
            return lineno
    return None

_STANDARDS = ["OWASP:A01", "CWE-269"]


class IamPolicyAttachedToUserDirectlyGuard(Guard):
    id = "iam-policy-attached-to-user-directly"
    title = "IAM policy attached directly to a user instead of a group/role"
    area = "Cloud & IaC"

    # iam_user_policy.tf: aws_iam_user_policy resource declaration alone -> fires
    # direct-user-attachment. Must NOT contain: allow-iam-user-policy pragma.
    canary_plant = CanaryPlant(
        files={
            "iam_user_policy.tf": (
                'resource "aws_iam_user_policy" "canary" {\n'
                '  name = "canary-policy"\n'
                "  user = aws_iam_user.canary.name\n"
                "  policy = jsonencode({})\n"
                "}\n"
            ),
        },
        expects=frozenset({"iam-policy-attached-to-user-directly/direct-user-attachment"}),
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
            raw_body = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, raw_body, dialect="hcl"):
                continue
            if resource_type in _DIRECT_USER_RESOURCE_TYPES:
                out.append(self._finding(root, f, resource_type, resource_name, start))
            elif resource_type == _MIXED_ATTACHMENT_TYPE:
                hit = _users_nonempty_line(body)
                if hit is not None:
                    out.append(self._finding(root, f, resource_type, resource_name, hit))
        return out

    def _finding(self, root: Path, f: Path, resource_type: str, resource_name: str, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"`{resource_type}.{resource_name}` attaches an IAM policy directly to a "
                "user. Permissions attached this way drift silently as people join, change "
                "roles, and leave, with no single group/role to audit."
            ),
            remediation=(
                "Attach the policy to an `aws_iam_group` (or a role the user assumes) and "
                "add the user as a group member instead. Suppress an audited exception with "
                "`# security: allow-iam-user-policy` anywhere in the resource block."
            ),
            rule="iam-policy-attached-to-user-directly/direct-user-attachment",
            standards=list(_STANDARDS),
        )
