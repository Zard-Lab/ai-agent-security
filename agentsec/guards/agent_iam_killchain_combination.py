"""Guard: a single AI agent IAM policy combines action categories that chain into a multi-step
breach, even when no individual statement looks dangerous on its own (checklist §6c, new item).

Per-statement checks (`iam-escalation-action-no-condition`, `agent-iam-tool-resource-unscoped`,
...) each look at one statement in isolation. A breach chain crosses statements: an agent that can
READ a credential (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, `sts:GetSessionToken`,
...) AND separately PIVOT identity (`sts:AssumeRole`, `iam:PassRole`, `ssm:SendCommand`, ...) can
use the first capability to obtain a credential and the second to move laterally with it -- two
statements that each look like ordinary least-privilege grants in a review, but together describe
exactly the two steps of a credential-theft-then-pivot chain. Likewise, credential-read combined
with instance-metadata/identity-discovery actions (`ec2:DescribeInstances`,
`iam:GetInstanceProfile`, ...) is the shape of a credential-harvest-then-reconnaissance chain, and
all three categories together describe a role that is "over-scoped for any single agent" by
definition, independent of any one statement's own Condition/Resource scoping.

These are **heuristic combinations of Allow statements across one policy document, not proof of
effective permissions, exploitability, or that any incident can be reproduced**, so the guard is a
surfacing (review) signal and every rule is HIGH at most. A legitimate
infra-automation role can genuinely need all three categories; this is a review signal to
investigate (separate the capabilities into distinct roles, or justify why one agent needs both),
not a proven bug. Ported (with the three action-category lists carried over near-verbatim) from
poojakira/aws-agent-identity-guard's `_scan_killchain_combinations` (AIG019/AIG020/AIG021), under
its MIT license. The source's `NotAction`-complement modeling (treating an `Allow`+`NotAction`
statement's complement as contributing to each category) is deliberately NOT ported -- a
disclosed scope narrowing, not a silent one.

Scans Terraform `.tf` files and bare IAM policy `.json` documents via the shared
`iter_policy_statement_blocks` walker. Unlike every other guard in this family, the unit of
analysis is ONE POLICY DOCUMENT (every `Allow` statement's actions inside the innermost object
that declares `Statement`), not one statement and not the whole file: two unrelated roles'
policies in one `main.tf` are never pooled (PR #1051 review, H3). The location is the line that
opens that document. A statement carrying `Principal`/`NotPrincipal` is a trust or resource policy,
not a grant to the identity under review, so it is skipped: otherwise every role's own
`sts:AssumeRole` trust statement counts as "lateral movement". A bare `*` action is left to
`iam-wildcard`. Suppress an audited file with a
`# security: allow-agent-iam-killchain-combination` comment in a `.tf` file, or the literal string
anywhere in a `.json` file (JSON has no comment syntax, #424).
"""
from __future__ import annotations

import re
from bisect import bisect_left
from fnmatch import fnmatchcase
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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
_ACTION_HEAD = re.compile(r'"?(?<!Not)Action"?\s*[:=]\s*', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')
_PRINCIPAL_KEY = re.compile(r'"?(?:Not)?Principal"?\s*[:=]', re.IGNORECASE)
_STATEMENT_KEY = re.compile(r'"?Statement"?\s*[:=]', re.IGNORECASE)
_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-agent-iam-killchain-combination")

# Ported from aws-agent-identity-guard's _CREDENTIAL_HARVEST_ACTIONS/_LATERAL_MOVEMENT_ACTIONS/
# _METADATA_REACH_ACTIONS. fnmatch-compared (lowercased) against every granted action, so a
# wildcard pattern among the granted actions (e.g. "secretsmanager:*") still matches.
_CREDENTIAL_HARVEST_ACTIONS = tuple(a.lower() for a in (
    "secretsmanager:GetSecretValue", "ssm:GetParameter", "ssm:GetParameters",
    "ssm:GetParametersByPath", "sts:GetSessionToken", "sts:GetFederationToken",
    "iam:CreateAccessKey", "iam:UpdateAccessKey", "ecr:GetAuthorizationToken",
    "eks:DescribeCluster",
))
_LATERAL_MOVEMENT_ACTIONS = tuple(a.lower() for a in (
    "sts:AssumeRole", "iam:PassRole", "ssm:SendCommand", "ssm:StartSession",
    "eks:AccessKubernetesApi",
))
_METADATA_REACH_ACTIONS = tuple(a.lower() for a in (
    "ec2:DescribeInstances", "ec2:DescribeIamInstanceProfileAssociations",
    "iam:ListInstanceProfiles", "iam:GetInstanceProfile",
))

_STANDARDS = ["OWASP:A01", "CWE-269"]


def _policy_roots(src: str) -> list[tuple[int, int]]:
    """`(start, end)` of every `{...}` object in `src` that declares a `Statement` key (a policy
    document root), sorted by start. `src` is the comment/heredoc-blanked view, so a brace or
    quote in a comment or a non-policy heredoc cannot unbalance the walk; offsets match the
    original text.

    Linear (#1051 re-review L1): the `Statement` keys are found in ONE pass, and each closing
    brace asks by bisection whether a key lies inside its object, instead of re-searching the
    object's whole span (O(size x depth) on a deeply nested file with no policy in it)."""
    keys = [(m.start(), m.end()) for m in _STATEMENT_KEY.finditer(src)]
    key_starts = [k[0] for k in keys]
    roots: list[tuple[int, int]] = []
    stack: list[int] = []
    in_str = False
    i, n = 0, len(src)
    while i < n:
        ch = src[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            stack.append(i)
        elif ch == "}" and stack:
            s = stack.pop()
            k = bisect_left(key_starts, s)
            if k < len(keys) and keys[k][1] <= i + 1:  # first key at/after `{` ends inside `}`
                roots.append((s, i + 1))
        i += 1
    roots.sort()
    return roots


def _allowed_actions_by_document(text: str) -> dict[int, list[str]]:
    """Granted `Action` values from each policy document's `Effect: Allow` statements, keyed by the
    offset that opens the document (the innermost enclosing `Statement`-bearing object; a
    statement with no such parent is its own document). Statements with a `Principal` (trust and
    resource policies) and a bare `*` action are not counted.

    Statements are assigned to their innermost root in one ordered sweep (#1051 re-review L1):
    roots never partially overlap, so the open roots at any offset form a chain whose top is the
    innermost. Scanning every root per statement was O(documents x statements)."""
    roots = _policy_roots(blank_policy_noise(text))
    docs: dict[int, list[str]] = {}
    open_roots: list[tuple[int, int]] = []
    ri = 0
    for start, _end, block in sorted(iter_policy_statement_blocks(text)):
        while ri < len(roots) and roots[ri][0] < start:
            while open_roots and open_roots[-1][1] <= roots[ri][0]:
                open_roots.pop()
            open_roots.append(roots[ri])
            ri += 1
        while open_roots and open_roots[-1][1] <= start:
            open_roots.pop()
        if not _EFFECT_ALLOW.search(block) or _PRINCIPAL_KEY.search(block):
            continue
        key = open_roots[-1][0] if open_roots else start
        for _m, val in iter_policy_key_values(block, _ACTION_HEAD):
            for qm in _QUOTED.finditer(val or ""):
                action = qm.group(1).strip().lower()
                if action and action != "*":
                    docs.setdefault(key, []).append(action)
    return docs


def _matches_category(actions: list[str], category: tuple[str, ...]) -> list[str]:
    """Granted actions that cover at least one literal action in `category`.

    `fnmatchcase(p, a)` -- the category action `p` (always a literal, no wildcard) is checked
    as a NAME against the granted action `a` as the PATTERN, so a granted wildcard like
    `secretsmanager:*` correctly matches the literal `secretsmanager:getsecretvalue` category
    entry. Argument order matters: fnmatch only expands wildcards in the second argument."""
    hits: list[str] = []
    for a in actions:
        if any(fnmatchcase(p, a) for p in category):
            hits.append(a)
    return hits


class AgentIamKillchainCombinationGuard(Guard):
    id = "agent-iam-killchain-combination"
    title = "Agent IAM policy combines action categories that chain into a multi-step breach"
    area = "AI agent"
    # A heuristic combination of grants, not a proven bug: rank below a proven finding.
    surfacing = True

    # canary-killchain.json: one policy granting a credential-harvest action, a lateral-movement
    # action, AND a metadata-reach action -> fires all three combination rules.
    canary_plant = CanaryPlant(
        files={
            "canary-killchain.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "Action": [\n'
                '      "secretsmanager:GetSecretValue",\n'
                '      "sts:AssumeRole",\n'
                '      "ec2:DescribeInstances"\n'
                "    ],\n"
                '    "Resource": "*"\n'
                "  }]\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "agent-iam-killchain-combination/harvest-plus-lateral",
            "agent-iam-killchain-combination/harvest-plus-metadata",
            "agent-iam-killchain-combination/full-chain",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        # Cheap raw precheck before the blanking pass (#1051 review M4). Blanking only turns
        # characters into spaces, so a file whose RAW text has no `"Statement"` (JSON) or no
        # `Effect` key word (HCL) cannot hold a policy statement once blanked either.
        if not (_IS_POLICY if f.suffix == ".json" else _EFFECT_WORD).search(text):
            return []
        if f.suffix == ".json" and not _IS_POLICY.search(blank_policy_noise(text)):
            return []
        out: list[Finding] = []
        for doc_start, actions in sorted(_allowed_actions_by_document(text).items()):
            harvest = _matches_category(actions, _CREDENTIAL_HARVEST_ACTIONS)
            lateral = _matches_category(actions, _LATERAL_MOVEMENT_ACTIONS)
            metadata = _matches_category(actions, _METADATA_REACH_ACTIONS)
            line = text.count("\n", 0, doc_start) + 1
            location = f"{rel(root, f)}:{line}"
            if harvest and lateral:
                out.append(self._finding(location, "harvest-plus-lateral", "high", harvest, lateral))
            if harvest and metadata:
                out.append(self._finding(location, "harvest-plus-metadata", "high", harvest, metadata))
            if harvest and lateral and metadata:
                out.append(self._finding(location, "full-chain", "high", harvest, lateral + metadata))
        return out

    def _finding(
        self, location: str, kind: str, severity: Severity, first: list[str], second: list[str]
    ) -> Finding:
        first_sample = ", ".join(sorted(set(first))[:3])
        second_sample = ", ".join(sorted(set(second))[:3])
        descriptions = {
            "harvest-plus-lateral": (
                f"This policy's Allow statements combine credential-access ({first_sample}) AND "
                f"lateral-movement ({second_sample}) actions. A principal holding both can use "
                "the first to obtain a credential and the second to move laterally with it.",
                "Split credential-read and role-assumption into separate roles that cannot be "
                "held by the same session. If an agent must do both, gate the assume-role "
                "behind a distinct short-lived role with session tagging and CloudTrail alerting.",
            ),
            "harvest-plus-metadata": (
                f"This policy's Allow statements combine credential-access ({first_sample}) with "
                f"instance-identity-discovery ({second_sample}) actions. This is a review signal, "
                "not proof of IMDS access or an SSRF path.",
                "Review whether the role needs instance/profile enumeration at all. Evaluate "
                "instance metadata protection separately -- these IAM actions alone do not "
                "establish metadata reachability.",
            ),
            "full-chain": (
                f"This policy's Allow statements contain credential-access, lateral-movement, "
                f"AND identity-discovery actions together ({first_sample}, {second_sample}). "
                "This static match does not prove an executable chain, but the role is "
                "over-scoped for any single agent to hold all three at once.",
                "Decompose this role by capability. Apply a permission boundary denying "
                "`sts:AssumeRole` and `secretsmanager:*` together, and require human approval "
                "for role chaining.",
            ),
        }
        message, remediation = descriptions[kind]
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=location,
            message=message,
            remediation=(
                f"{remediation} Suppress an audited exception with "
                "`# security: allow-agent-iam-killchain-combination`."
            ),
            rule=f"agent-iam-killchain-combination/{kind}",
            standards=list(_STANDARDS),
        )
