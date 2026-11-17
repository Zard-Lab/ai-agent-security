"""Guard: CloudFormation NetworkAclEntry `deny` rule whose CIDR is not the full-range block
(checklist §7, new item `7-cfn-nacl-ineffective-deny`).

Detection target is cfn_nag's real rule `W71` (`EC2NetworkAclEntryIneffectiveDenyRule.rb`,
`stelligent/cfn_nag`): an `AWS::EC2::NetworkAclEntry` with `RuleAction: deny` whose `CidrBlock` (or
`Ipv6CidrBlock`) is not the "deny everything" range. cfn_nag's real Ruby implementation reasons
about this as part of a broader NACL-effectiveness analysis (rule numbers, evaluation order, whether
a narrower `allow` rule elsewhere in the ACL already makes the deny moot). **This guard does NOT
attempt that** — no CIDR-containment math, no subnet-overlap reasoning, no cross-rule NACL priority
ordering, all of which this codebase's regex/text-block philosophy is not suited for (see
`agentsec/cfn.py`'s module docstring on why: no PyYAML at runtime, so no real structural model).

The PRACTICAL v1 scope: fire when a `deny` NetworkAclEntry's `CidrBlock`/`Ipv6CidrBlock` is present
but is textually NOT exactly `0.0.0.0/0` (IPv4) or `::/0` (IPv6) — the full-range values. A narrow
CIDR on a deny rule is not itself a bug (a deliberate "block this one bad range" rule is a legitimate
NACL pattern), which is why this guard is `surfacing = True`: it surfaces "go check whether this
narrow deny does what the author intended," not a proven vulnerability.

Detection logic and test fixtures here are original, developed independently against the pattern
description; `EC2NetworkAclEntryIneffectiveDenyRule.rb` is cited for provenance only, not copied.

Suppress an audited/intentional narrow deny with a comment containing
`security: allow-nacl-ineffective-deny` anywhere in the resource's block (YAML `#` comment; not
meaningful in JSON, which has no comment syntax — a JSON template can't carry this pragma at all,
the same known, documented limitation shared by every CFN guard in this batch).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_RULE_ACTION_DENY = re.compile(r'"?RuleAction"?\s*:\s*["\']?deny["\']?', re.IGNORECASE)
# The `(?<!Ipv6)` lookbehind keeps this from matching the `CidrBlock` substring inside
# `Ipv6CidrBlock` itself (`Ipv6CidrBlock` literally contains `CidrBlock`).
_CIDR_BLOCK = re.compile(r'(?<!Ipv6)"?CidrBlock"?\s*:\s*["\']?([0-9A-Za-z./:]+)["\']?')
_IPV6_CIDR_BLOCK = re.compile(r'"?Ipv6CidrBlock"?\s*:\s*["\']?([0-9A-Za-z./:]+)["\']?')
_PRAGMA = "security: allow-nacl-ineffective-deny"

_FULL_RANGE_IPV4 = "0.0.0.0/0"
_FULL_RANGE_IPV6 = "::/0"

_STANDARDS = ["OWASP:A05"]


class CfnNaclIneffectiveDenyGuard(Guard):
    id = "cfn-nacl-ineffective-deny"
    title = "Network ACL deny entry's CIDR block is not the full-range 0.0.0.0/0 or ::/0"
    area = "Cloud & IaC"
    # Per-RULE surfacing (matches `compose_no_network_segmentation.py`'s established pattern for a
    # guard added after the #617/BB4 migration), not a flat `surfacing = True`: this guard has
    # exactly one rule, and pinning the prefix to that rule's own full string keeps it inert
    # against `tests/test_checkmeta.py`'s frozen pre-migration equivalence snapshot (which only
    # knows about the 5 guards that existed at migration time) while still classifying every REAL
    # finding this guard ever emits as a review signal, since it never emits any other rule.
    surfacing_rule_prefixes = ("cfn-nacl-ineffective-deny/narrow-cidr-deny",)

    # cfn_nacl_deny.yaml: AWS::EC2::NetworkAclEntry with RuleAction: deny and a narrow CIDR
    # (10.0.0.0/24, not the full-range 0.0.0.0/0) -> fires cfn-nacl-ineffective-deny/narrow-cidr-deny.
    canary_plant = CanaryPlant(
        files={
            "cfn_nacl_deny.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryDenyEntry:\n"
                "    Type: AWS::EC2::NetworkAclEntry\n"
                "    Properties:\n"
                "      NetworkAclId: !Ref CanaryAcl\n"
                "      RuleNumber: 100\n"
                "      Protocol: -1\n"
                "      RuleAction: deny\n"
                "      CidrBlock: 10.0.0.0/24\n"
                "      Egress: false\n"
            ),
        },
        expects=frozenset({
            "cfn-nacl-ineffective-deny/narrow-cidr-deny",
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
            if resource.resource_type != "AWS::EC2::NetworkAclEntry":
                continue
            if not _RULE_ACTION_DENY.search(resource.block):
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue

            cidr_match = _CIDR_BLOCK.search(resource.block)
            ipv6_match = _IPV6_CIDR_BLOCK.search(resource.block)

            narrow_cidr: str | None = None
            if cidr_match and cidr_match.group(1).strip() != _FULL_RANGE_IPV4:
                narrow_cidr = cidr_match.group(1).strip()
            elif ipv6_match and ipv6_match.group(1).strip() != _FULL_RANGE_IPV6:
                narrow_cidr = ipv6_match.group(1).strip()

            if narrow_cidr is None:
                continue

            out.append(
                Finding(
                    check_id=self.id,
                    severity="low",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::EC2::NetworkAclEntry) has "
                        f"`RuleAction: deny` with CIDR `{narrow_cidr}` — not the full-range "
                        f"`{_FULL_RANGE_IPV4}` / `{_FULL_RANGE_IPV6}`. A deny rule scoped to a "
                        "narrow range only blocks traffic from that specific range; confirm this "
                        "is intentional (a deliberate block of a known-bad range) rather than a "
                        "mistaken assumption that this rule denies everything."
                    ),
                    remediation=(
                        "Confirm by hand whether this narrow-CIDR deny is intentional. If the "
                        "intent was to deny all traffic, use `CidrBlock: 0.0.0.0/0` or "
                        "`Ipv6CidrBlock: ::/0`. Suppress an audited, intentional narrow deny with "
                        "a `security: allow-nacl-ineffective-deny` comment anywhere in the "
                        "resource (YAML templates only)."
                    ),
                    rule="cfn-nacl-ineffective-deny/narrow-cidr-deny",
                    standards=list(_STANDARDS),
                )
            )
        return out
