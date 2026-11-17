"""Guard: CloudFormation classic WAF WebACL with a DefaultAction of ALLOW (checklist §6a).

`AWS::WAF::WebACL` (classic WAF — `AWS::WAFv2::WebACL` is the newer resource type and not covered
here) carries a `DefaultAction` that governs any request that doesn't match one of the WebACL's own
configured rules. When that default is `ALLOW`, the WebACL's protection is opt-in per rule rather
than a real default-deny posture: unmatched traffic — which, in practice, is most traffic a WAF
never got a specific rule written for — sails straight through. This is not itself a direct exploit
(the WAF still blocks whatever rules ARE configured), so it fires MEDIUM: a real posture weakness,
not a proven bypass of an active control.

This is a **new** checklist item — no existing agentsec item covers WAF WebACL default-action
configuration — added alongside this guard rather than reusing an unrelated one.

Pattern verified against cfn_nag's real source (`WafWebAclDefaultActionRule.rb`, rule `F665`,
`stelligent/cfn_nag`), cited for provenance only; detection logic and test fixtures here are
original, developed independently against the pattern description.

Fires MEDIUM when an `AWS::WAF::WebACL` resource's block contains a `DefaultAction` context whose
`Type` is `ALLOW`. Detection scope (documented, not accidental): rather than a strict nested-block
parse (this codebase's text-block guards don't do real YAML/JSON structural parsing — see
`agentsec/cfn.py`), the check anchors `Type: ALLOW` / `"Type": "ALLOW"` immediately after a
`DefaultAction` key — only whitespace, an optional opening `{`, and optional line breaks are
allowed in between, which matches the real `AWS::WAF::WebACL DefaultAction` shape (a `WafAction`
object whose only key is `Type`). That tight adjacency (not a wide bounded span) is deliberate: a
`Rules` list entry has its own per-rule `Action`/`OverrideAction` block, each of which can
legitimately have `Type: ALLOW` without it being the WebACL's *default* — a wider "within N
characters" span was tried and produces exactly that false positive (a `DefaultAction: BLOCK`
WebACL whose `Rules` list separately contains an `Action: {Type: ALLOW}` entry); the immediate-
adjacency anchor does not, without requiring a real nested-object parse this codebase doesn't do
for CFN blocks.

Suppress an audited case (e.g. a WebACL that is intentionally monitor-only, backed by rules doing
the real enforcement elsewhere) with a comment containing `security: allow-waf-default-allow`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, the same known, documented limitation
shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

# `DefaultAction` immediately followed by its own (and only) `Type` key — whitespace, line
# breaks, and an optional opening `{` (the JSON-reconstruction shape) are the only characters
# allowed in between, so this does not spill into an unrelated `Rules` list entry's own
# `Action`/`OverrideAction` block later in the same resource (see module docstring).
_DEFAULT_ACTION_ALLOW = re.compile(
    r'"?DefaultAction"?\s*[:=]\s*\{?\s*"?Type"?\s*[:=]\s*["\']?ALLOW["\']?',
    re.IGNORECASE,
)
_PRAGMA = "security: allow-waf-default-allow"

_STANDARDS = ["OWASP:A05"]


class CfnWafDefaultAllowGuard(Guard):
    id = "cfn-waf-default-allow"
    title = "WAF WebACL DefaultAction is not ALLOW"
    area = "Cloud & IaC"

    # cfn_waf_webacl.yaml: AWS::WAF::WebACL with DefaultAction Type: ALLOW -> fires
    # cfn-waf-default-allow/default-action-allow.
    canary_plant = CanaryPlant(
        files={
            "cfn_waf_webacl.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryWebAcl:\n"
                "    Type: AWS::WAF::WebACL\n"
                "    Properties:\n"
                "      Name: canary-web-acl\n"
                "      MetricName: canaryWebAcl\n"
                "      DefaultAction:\n"
                "        Type: ALLOW\n"
            ),
        },
        expects=frozenset({
            "cfn-waf-default-allow/default-action-allow",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "cloudformation" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml", ".json")):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource in cfn_resources(text):
            if resource.resource_type != "AWS::WAF::WebACL":
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not _DEFAULT_ACTION_ALLOW.search(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::WAF::WebACL) sets `DefaultAction.Type: "
                        "ALLOW`. Any request that doesn't match one of this WebACL's configured "
                        "rules is allowed through by default, making the WAF's protection "
                        "opt-in per rule rather than a real default-deny posture."
                    ),
                    remediation=(
                        "Set `DefaultAction.Type: BLOCK` and use explicit rules to allow the "
                        "traffic you intend to pass. Suppress an audited exception with a "
                        "`security: allow-waf-default-allow` comment anywhere in the resource "
                        "(YAML templates only)."
                    ),
                    rule="cfn-waf-default-allow/default-action-allow",
                    standards=list(_STANDARDS),
                )
            )
        return out
