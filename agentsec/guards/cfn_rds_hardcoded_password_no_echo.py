"""Guard: CloudFormation RDS instance/cluster with a hardcoded or unmasked MasterUserPassword
(checklist §7, new item `7-cfn-rds-hardcoded-password`).

A database master password is the single credential that unlocks everything the database holds.
Two CloudFormation authoring mistakes both defeat the point of parameterizing it at all:

- **A literal value.** `MasterUserPassword: 'hunter2'` (or the JSON equivalent) puts the plaintext
  password directly in source control — every commit history, every fork, every CI log that prints
  the template body has it forever, and rotating the real database password does nothing to un-leak
  the one sitting in git.
- **A parameter without `NoEcho: true`.** `MasterUserPassword: !Ref DBPassword` looks safer (the
  value isn't literally in the template), but if the `DBPassword` Parameter's own declaration in
  the same template's `Parameters:` section omits `NoEcho: true`, CloudFormation does not mask the
  value in the console, the CLI/API describe-stack responses, or CloudTrail events — so the
  password is still disclosed, just one indirection later, to anyone who can read stack
  events/parameters instead of the template.

This guard's v1 scope implements BOTH cases: a literal `MasterUserPassword` value always fires, and
a `!Ref`/`{"Ref": ...}` to a Parameter is traced to that parameter's own declaration in the SAME
FILE's `Parameters:` section to check for `NoEcho: true`. This is a genuinely new checklist item —
no existing agentsec item (Terraform or CloudFormation) covers this pattern for any IaC format.

Pattern verified against cfripper's real source (`hardcoded_RDS_password.py`, `Skyscanner/cfripper`,
our research batch) — cited for provenance; detection logic and test fixtures here are original, developed
independently against the pattern description (including this guard's own take on the cluster/
instance relationship: unlike cfripper's real structural cross-check, this guard does not suppress
an instance's own literal/unmasked `MasterUserPassword` just because it also has a
`DBClusterIdentifier` pointing at a cluster — see the wiki doc's Known bypasses section for why that
is an intentional, documented scope decision rather than an oversight).

A CFN intrinsic function other than a bare `!Ref`/`{"Ref": ...}` (`!Sub`, `!GetAtt`,
`!ImportValue`, ...) is not resolved — no dataflow tracing beyond the one hop this guard performs —
and is treated as "unknown, stay silent" rather than flagged, to avoid a false positive on a pattern
this guard cannot actually evaluate. A Secrets Manager / SSM Parameter Store dynamic reference
embedded in a string value (`'{{resolve:secretsmanager:...}}'`) is recognized explicitly and never
flagged — it is the AWS-recommended safe pattern, the opposite of a hardcoded password.

Suppress an audited case with a comment containing `security: allow-rds-hardcoded-password`
anywhere in the resource's block (YAML `#` comment; not meaningful in JSON, which has no comment
syntax — a JSON template can't carry this pragma at all, the same known, documented limitation
shared by every CFN guard in this batch).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec.cfn import CfnResource, cfn_resources, iter_yaml_section_blocks
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_RDS_RESOURCE_TYPES = frozenset({"AWS::RDS::DBInstance", "AWS::RDS::DBCluster"})

_PRAGMA = "security: allow-rds-hardcoded-password"

_STANDARDS = ["OWASP:A02", "CWE-798"]

# `MasterUserPassword` sourced from a Parameter: YAML short form (`!Ref Name`) or the JSON
# structural form (`{"Ref": "Name"}`, which `json.dumps(indent=2)` always spreads onto three lines
# for a nested object — `\s` matches newlines, so this matches across that reconstruction too).
_REF_PATTERN = re.compile(
    r'"?MasterUserPassword"?\s*:\s*'
    r'(?:!Ref\s+([A-Za-z0-9]+)\b|\{\s*"Ref"\s*:\s*"([A-Za-z0-9]+)"\s*\})'
)

_MASTER_PASSWORD_KEY = re.compile(r'"?MasterUserPassword"?\s*:\s*')

_DYNAMIC_INTRINSIC_PREFIXES = (
    "!Sub",
    "!GetAtt",
    "!ImportValue",
    "!Join",
    "!Select",
    "!FindInMap",
    "!If",
    '"Fn::',
)

_NOECHO_TRUE = re.compile(r'"?NoEcho"?\s*:\s*(?:true|"true")\b', re.IGNORECASE)


def _find_master_password(block: str) -> tuple[str, str] | None:
    """Classify a resource block's `MasterUserPassword` property, if present.

    Returns `(kind, value)`:
    - `("ref", param_name)` — sourced from a Parameter via `!Ref`/`{"Ref": ...}`.
    - `("literal", value)` — a literal string/bare value directly in the template.
    - `("dynamic", value)` — an unresolvable CFN intrinsic, or a Secrets Manager/SSM dynamic
      reference (`{{resolve:...}}`) embedded in the value — never flagged either way.

    Returns `None` if the property is absent, or its value could not be confidently classified
    (e.g. a nested JSON intrinsic other than `Ref`, which spans multiple lines this function does
    not attempt to reassemble) — staying silent rather than risking a false positive.
    """
    ref = _REF_PATTERN.search(block)
    if ref:
        name = ref.group(1) or ref.group(2)
        assert name is not None  # nosec B101 (type-narrowing only: one of the two capture groups matched)
        return ("ref", name)

    m = _MASTER_PASSWORD_KEY.search(block)
    if not m:
        return None
    rest = block[m.end() :]
    line_end = rest.find("\n")
    raw_value = rest if line_end == -1 else rest[:line_end]
    value = raw_value.strip().rstrip(",").strip()
    if not value or value == "{":
        # Either genuinely empty, or a nested JSON object this function doesn't resolve (the
        # `Ref` shape is handled above; anything else nested — e.g. `{"Fn::Sub": ...}` — is left
        # unclassified rather than guessed at).
        return None
    if value.startswith(_DYNAMIC_INTRINSIC_PREFIXES):
        return ("dynamic", value)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    if "{{resolve:" in value:
        return ("dynamic", value)
    return ("literal", value)


def _yaml_parameter_block(text: str, param_name: str) -> str | None:
    """The text block for `param_name` under a YAML template's top-level `Parameters:` section,
    or `None` if there is no `Parameters:` section or no parameter by that name. Delegates to
    `agentsec.cfn.iter_yaml_section_blocks` — the shared indentation-scoped section splitter — so
    a header-comment tolerance fix lands once in that one walker rather than in a drifting copy
    here (this was a duplicate that missed #856's `Resources:` fix on its `Parameters:` header;
    #857)."""
    for name, block in iter_yaml_section_blocks(text, "Parameters"):
        if name == param_name:
            return block
    return None


def _json_parameter_no_echo(text: str, param_name: str) -> bool | None:
    """`True`/`False` for the named Parameter's `NoEcho` in a JSON template, or `None` if the
    text isn't valid JSON, has no `Parameters` section, or no parameter by that name."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    params = data.get("Parameters")
    if not isinstance(params, dict):
        return None
    param = params.get(param_name)
    if not isinstance(param, dict):
        return None
    return param.get("NoEcho") is True or str(param.get("NoEcho")).strip().lower() == "true"


def _param_has_no_echo(text: str, is_json: bool, param_name: str) -> bool | None:
    """`True`/`False` for whether `param_name`'s declaration in this same template file has
    `NoEcho: true` set. `None` when the parameter's declaration can't be found in this file at
    all (e.g. a cross-file/nested-stack parameter, or a malformed template) — the caller treats
    that as "nothing to safely assert" and stays silent rather than guess."""
    if is_json:
        return _json_parameter_no_echo(text, param_name)
    block = _yaml_parameter_block(text, param_name)
    if block is None:
        return None
    return bool(_NOECHO_TRUE.search(block))


class CfnRdsHardcodedPasswordNoEchoGuard(Guard):
    id = "cfn-rds-hardcoded-password-no-echo"
    title = "RDS instance/cluster MasterUserPassword is not a literal value / lacks NoEcho on its parameter"
    area = "Secrets"

    # cfn_rds_password.yaml: AWS::RDS::DBInstance with a literal MasterUserPassword -> fires
    # cfn-rds-hardcoded-password-no-echo/literal-password.
    canary_plant = CanaryPlant(
        files={
            "cfn_rds_password.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryDb:\n"
                "    Type: AWS::RDS::DBInstance\n"
                "    Properties:\n"
                "      Engine: postgres\n"
                "      MasterUsername: canary_admin\n"
                "      MasterUserPassword: hunter2canary\n"
            ),
        },
        expects=frozenset({
            "cfn-rds-hardcoded-password-no-echo/literal-password",
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
        is_json = text.lstrip().startswith("{")
        for resource in cfn_resources(text):
            if resource.resource_type not in _RDS_RESOURCE_TYPES:
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            found = _find_master_password(resource.block)
            if found is None:
                continue
            kind, value = found
            if kind == "dynamic":
                continue
            if kind == "literal":
                out.append(self._literal_finding(root, f, resource))
                continue
            # kind == "ref": traced to the same file's Parameters: section.
            no_echo = _param_has_no_echo(text, is_json, value)
            if no_echo is None or no_echo:
                continue
            out.append(self._param_finding(root, f, resource, value))
        return out

    def _literal_finding(self, root: Path, f: Path, resource: CfnResource) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}",
            message=(
                f"`{resource.logical_id}` ({resource.resource_type}) sets `MasterUserPassword` "
                "to a literal value directly in the template. This is a plaintext database "
                "password committed to source control — anyone with read access to the "
                "repository (or its history) has the credential, and rotating the real database "
                "password does not un-leak the copy already in git."
            ),
            remediation=(
                "Replace the literal value with a `!Ref` to a Parameter (`NoEcho: true`) or a "
                "Secrets Manager/SSM dynamic reference (`{{resolve:secretsmanager:...}}`). "
                "Suppress an audited exception with a `security: allow-rds-hardcoded-password` "
                "comment anywhere in the resource (YAML templates only)."
            ),
            rule="cfn-rds-hardcoded-password-no-echo/literal-password",
            standards=list(_STANDARDS),
        )

    def _param_finding(
        self, root: Path, f: Path, resource: CfnResource, param_name: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}",
            message=(
                f"`{resource.logical_id}` ({resource.resource_type}) sources `MasterUserPassword` "
                f"from Parameter `{param_name}`, which does not declare `NoEcho: true`. "
                "CloudFormation will not mask this value in the console, the CLI/API "
                "describe-stack responses, or CloudTrail events — the password is disclosed to "
                "anyone who can read stack events/parameters, even though it is not literally in "
                "the template."
            ),
            remediation=(
                f"Add `NoEcho: true` to Parameter `{param_name}`'s declaration in the template's "
                "`Parameters:` section. Suppress an audited exception with a "
                "`security: allow-rds-hardcoded-password` comment anywhere in the resource "
                "(YAML templates only)."
            ),
            rule="cfn-rds-hardcoded-password-no-echo/param-missing-noecho",
            standards=list(_STANDARDS),
        )
