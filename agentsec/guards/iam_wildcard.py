"""Guard: no wildcard-everything IAM policies (checklist §6c/§7).

An IAM policy statement that grants `"Action": "*"` (every action) or
`"Resource": "*"` under `"Effect": "Allow"` gives whatever assumes the role the
keys to the whole account — one prompt injection or a stolen token then deletes
every bucket, reads every secret, escalates at will (CWE-269, least-privilege).
Scoped service wildcards (`s3:*`) are common and not flagged; the all-actions /
all-resources grant is the egregious case this catches.

A PARTIAL wildcard is a second, often-overlooked shape (2026-10-08, aws-agent-
identity-guard research-cycle): `iam:*Role*` isn't the bare `*`/`svc:*` case above, but it still
expands, via AWS's own glob-style action matching, to cover `iam:PassRole` and every other action
whose name contains "Role". `fnmatch.fnmatchcase` is the same shell-glob semantics AWS policy
evaluation itself uses for `*`/`?` in an action name, so this check asks the identical question IAM
itself answers when it decides whether a pattern covers a given action. Only privilege-escalation
and defence-evasion targets count (IAM writes, `sts:AssumeRole`, CloudTrail/GuardDuty tamper), and
only under `Action`: a data read like `s3:Get*` is not flagged, and a `NotAction` pattern is an
exclusion, not an expansion (PR #1051 review).

Scans `.json` files that look like an AWS IAM policy (carry `"Statement"` +
`"Effect"`) and Terraform `.tf` policy bodies. Fires HIGH. Suppress an audited
statement with a `# security: allow-iam-wildcard` line in the file.
"""
from __future__ import annotations

import re
from fnmatch import fnmatchcase
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_policy_noise,
    comment_dialect_for,
    iter_files,
    iter_policy_key_values,
    iter_policy_statement_blocks,
    pragma_present,
    read,
    rel,
)

_SUFFIXES = (".json", ".tf")
_IS_POLICY = re.compile(r'"Statement"', re.IGNORECASE)
_ALLOW = re.compile(r'"Effect"\s*:\s*"Allow"', re.IGNORECASE)
# "Action": "*"  /  "Action": ["*"]  /  a service-wide "*:*"
_ACTION_STAR = re.compile(r'"(?:Action|NotAction)"\s*:\s*(?:"\*"|\[\s*"\*"|".*\*:\*")', re.IGNORECASE)
_RESOURCE_STAR = re.compile(r'"Resource"\s*:\s*(?:"\*"|\[\s*"\*")', re.IGNORECASE)
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-iam-wildcard")  # .tf uses #, JSONC uses //

# Adapted from aws-agent-identity-guard's `_DANGEROUS_ACTIONS_FOR_WILDCARD_CHECK`: the actions a
# PARTIAL wildcard pattern (contains `*`/`?` but is not the bare `*`/`svc:*` case `_ACTION_STAR`
# already catches) is judged against. Narrowed in the PR #1051 review to privilege-escalation and
# defence-evasion actions only (IAM policy/role/user writes, sts:AssumeRole, CloudTrail/GuardDuty
# tamper). The source list's data-plane reads and invokes (s3:GetObject, ssm:GetParameter(s),
# kms:Decrypt, secretsmanager:GetSecretValue, lambda:InvokeFunction, bedrock invoke) are left out:
# `s3:Get*` scoped to one bucket is the textbook least-privilege read grant, and the guard has
# never flagged a service wildcard like `s3:*`, which is strictly wider.
_DANGEROUS_ACTIONS_FOR_WILDCARD_CHECK = frozenset({
    a.lower() for a in (
        "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreatePolicy",
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:PassRole",
        "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:UpdateAssumeRolePolicy",
        "iam:PutUserPolicy", "iam:AttachUserPolicy", "iam:AddUserToGroup", "sts:AssumeRole",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "guardduty:DeleteDetector",
    )
})
# `"Action"` only: the leading quote keeps `"NotAction"` out, where a pattern is an EXCLUSION
# (iam-notaction-with-allow owns that statement).
# The quoted Action key head (the leading quote keeps "NotAction" out); its value is read by
# base.iter_policy_key_values, uncapped and linear (#1051 round 4).
_ACTION_HEAD = re.compile(r'"Action"\s*:\s*', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')


def _action_pattern_covers_dangerous(action_pattern: str) -> str | None:
    """The first known-dangerous action a partial wildcard pattern expands to, or None.

    Only meaningful when the pattern itself contains `*`/`?` -- a literal action name matches
    nothing here (it either IS the dangerous action, caught elsewhere, or it isn't).

    Iterates `sorted(...)`, not the raw frozenset -- a frozenset's iteration order is randomized
    per-process (PYTHONHASHSEED), so "first match" silently differed between worker processes
    when a pattern (e.g. `iam:*Role*`) covers more than one dangerous action, breaking the
    guard's determinism guarantee (caught by test_guard_budget.py's parallel-vs-single-lane
    identity check, not by any single-process test run)."""
    if "*" not in action_pattern and "?" not in action_pattern:
        return None
    pattern_lower = action_pattern.lower()
    for dangerous in sorted(_DANGEROUS_ACTIONS_FOR_WILDCARD_CHECK):
        if fnmatchcase(dangerous, pattern_lower):
            return dangerous
    return None


class IamWildcardGuard(Guard):
    id = "iam-wildcard"
    title = "No wildcard-everything (*) IAM policy grants"
    area = "Cloud & IaC"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # IAM policy granting Action:* under Allow -> fires iam-wildcard/action-star.
    # infra/partial_wildcard_policy.json: Action "iam:*Role*" expands to iam:PassRole via
    # wildcard matching -> fires iam-wildcard/partial-wildcard-dangerous.
    canary_plant = CanaryPlant(
        files={
            "infra/policy.json": (
                '{\n  "Version": "2012-10-17",\n  "Statement": [\n'
                '    {"Effect": "Allow", "Action": "*", "Resource": "*"}\n  ]\n}\n'
            ),
            "infra/partial_wildcard_policy.json": (
                '{\n  "Version": "2012-10-17",\n  "Statement": [\n'
                '    {"Effect": "Allow", "Action": "iam:*Role*", "Resource": "*"}\n  ]\n}\n'
            ),
        },
        expects=frozenset({"iam-wildcard/action-star", "iam-wildcard/partial-wildcard-dangerous"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # IAM policies can live in any repo (deploy/infra config)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            text = read(f)
            # The pragma IS a comment, so it is read off the comment-only view of the file: a `.tf`
            # string attribute quoting it is content, not an opt-out. `.json` has no comment
            # dialect here, so a JSONC `//` pragma stays the raw match it always was (#424).
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            # Gate on the comment/heredoc-blanked view, not the raw text: a commented-out
            # policy EXAMPLE ("# {"Statement":[{"Effect":"Allow","Action":"*"}]}" in a doc
            # header) is prose, not a grant, and must not open the door to the fallback
            # scan below (#446 re-review FP). Blanking is length/newline-preserving, so
            # every offset and line number derived from `src` still maps to `text`.
            # Cheap raw precheck before the blanking pass (#1051 review M4): blanking only turns
            # characters into spaces, so no raw `"Statement"` means none after blanking either.
            if not _IS_POLICY.search(text):
                continue
            src = blank_policy_noise(text)
            if not _IS_POLICY.search(src) or not _ALLOW.search(src):
                continue
            # Scan each ALLOW statement in isolation, so a wildcard inside a Deny statement
            # (a hardening pattern) no longer inherits the file-level Allow gate (#423). The
            # shared walker is string/comment/heredoc-aware (PR #446 re-review).
            blocks = iter_policy_statement_blocks(text)
            if blocks:
                for start, _end, block in blocks:
                    if not _ALLOW.search(block):
                        continue
                    base = text.count("\n", 0, start)
                    for j, line in enumerate(block.splitlines()):
                        if _ACTION_STAR.search(line):
                            out.append(self._finding(root, f, base + j + 1, "action"))
                        elif _RESOURCE_STAR.search(line):
                            out.append(self._finding(root, f, base + j + 1, "resource"))
                    # Partial wildcard that EXPANDS to a dangerous action (2026-10-08) --
                    # deliberately excludes the bare "*" and exact "svc:*" forms: those are
                    # either already caught above (bare "*") or a deliberate design choice this
                    # guard has always made not to flag (a scoped service wildcard like "s3:*"
                    # is common and not inherently dangerous on its own).
                    for m, val in iter_policy_key_values(block, _ACTION_HEAD):
                        val_start = m.end()
                        for qm in _QUOTED.finditer(val or ""):
                            pattern = qm.group(1)
                            if pattern == "*" or pattern.endswith(":*"):
                                continue
                            matched = _action_pattern_covers_dangerous(pattern)
                            if matched:
                                abs_offset = start + val_start + qm.start()
                                finding_line = text.count("\n", 0, abs_offset) + 1
                                out.append(
                                    self._partial_wildcard_finding(root, f, finding_line, pattern, matched)
                                )
                                break  # one finding per statement is sufficient
                continue
            # No statement block was recovered, yet the file ALREADY passed both gates above
            # (a real, uncommented `"Statement"` and `"Effect": "Allow"` are present). That
            # combination means the walker could not parse this shape — a truncated or
            # brace-unbalanced document — not that the policy is clean, so fall back to the
            # pre-#423 file-level line scan rather than emitting nothing (#446 review).
            #
            # The original fail-open this backstops (an `admin_doc = <<EOT` heredoc holding a
            # wildcard policy) is now fixed at the root in `blank_policy_noise`, which keeps a
            # heredoc body by its CONTENT instead of the attribute name — that file parses and
            # never reaches here. The fallback stays as depth, and it scans the BLANKED `src`
            # so it inherits the same comment-blindness the block walk has.
            for j, line in enumerate(src.splitlines()):
                if _ACTION_STAR.search(line):
                    out.append(self._finding(root, f, j + 1, "action"))
                elif _RESOURCE_STAR.search(line):
                    out.append(self._finding(root, f, j + 1, "resource"))
        return out

    def _finding(self, root: Path, f: Path, line: int, kind: str) -> Finding:
        what = (
            "grants every action (`Action: *`)" if kind == "action"
            else "grants access to every resource (`Resource: *`)"
        )
        return Finding(
            check_id=self.id,
            severity="high",
            title=f"IAM policy {what}",
            location=f"{rel(root, f)}:{line}",
            message=(
                "This Allow statement uses a full wildcard, so anything that assumes the role can "
                "act on the entire account — a stolen token or a prompt-injected agent then has "
                "near-total access."
            ),
            remediation=(
                "Scope the policy to the specific actions and resource ARNs it needs (least "
                "privilege). Suppress an audited case with `# security: allow-iam-wildcard`."
            ),
            rule=f"iam-wildcard/{kind}-star",
            standards=["OWASP:A01"],
        )

    def _partial_wildcard_finding(
        self, root: Path, f: Path, line: int, pattern: str, matched: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="IAM policy action pattern expands to a dangerous action via wildcard",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"Action pattern `{pattern}` expands to the dangerous action `{matched}` via "
                "wildcard matching. Partial wildcards are often overlooked but can grant "
                "significant privilege (e.g. `iam:*Role*` includes `iam:PassRole`)."
            ),
            remediation=(
                f"Replace `{pattern}` with an explicit list of only the specific actions "
                "needed. Suppress an audited case with `# security: allow-iam-wildcard`."
            ),
            rule="iam-wildcard/partial-wildcard-dangerous",
            standards=["OWASP:A01", "CWE-269"],
        )
