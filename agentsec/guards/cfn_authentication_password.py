"""Guard: `AWS::CloudFormation::Authentication` resource carrying a literal password (checklist §8,
new item — CFN-only, no Terraform equivalent, since this resource type is unique to CloudFormation).

`AWS::CloudFormation::Authentication` is a deprecated resource type used to supply credentials that
`AWS::CloudFormation::Init` (`cfn-init`) needs to fetch private content (an S3 object behind an
IAM/role-based auth block, or a basic-auth-protected URI) during instance bootstrap. Its properties
are a map of named authentication blocks, each of which can carry a `password` key — nested under
whatever the template author named the block (`Properties.<AuthName>.password`, or deeper still,
e.g. under an `S3`-typed sub-block) — the exact nesting depth varies by auth type, so this guard
does not assume one; it treats ANY `Password`/`password` key found anywhere inside the resource's
own block as the target, since the nesting doesn't change the vulnerability.

The vulnerability: unlike almost every other CFN credential-shaped property, `AWS::CloudFormation::
Authentication`'s properties are NOT accepted as `NoEcho` — AWS's own docs note the resource predates
that protection — so a literal (hardcoded) password value is stored, and displayed, in PLAINTEXT in
the CloudFormation console (Resources tab, and in the template body itself) to anyone with read
access to the stack. That is a materially larger exposure surface than "only whoever can read the
repo": every IAM principal with `cloudformation:GetTemplate`/console read on the stack, not just repo
contributors, can read the password. CWE-798 (Use of Hard-coded Credentials), OWASP:A02.

Pattern verified against cfripper's real source (`cloudformation_authentication.py`, `Skyscanner/
cfripper` in the research batch), cited for provenance; the detection logic and test
fixtures here are original, developed independently against the pattern description.

Fires HIGH when a resource's `Type` is `AWS::CloudFormation::Authentication` and its block contains
a `Password`/`password` key whose value is a LITERAL string or bare scalar — not a reference to a
parameter or another resource. The following value forms are treated as references (never literal,
so they never fire), because a `NoEcho` parameter reference or a Secrets Manager/SSM dynamic
reference means no plaintext credential is embedded in the template body at all:

- A YAML short-form intrinsic tag: `!Ref`, `!Sub`, `!GetAtt`, `!If`, `!FindInMap`, `!ImportValue`,
  `!Join`, `!Select` (any `!Tag` form — the tag alone is enough to treat the whole value as
  non-literal, since none of these produce a static credential).
- A `Ref`/`Fn::*` flow-mapping object, in either JSON or YAML flow-mapping syntax: `{"Ref": "..."}`,
  `{Ref: ...}`, `{"Fn::Sub": "..."}`, `{Fn::GetAtt: [...]}`.
- A Secrets Manager/SSM **dynamic reference** embedded as a literal-looking string:
  `{{resolve:secretsmanager:...}}` / `{{resolve:ssm:...}}` / `{{resolve:ssm-secure:...}}` — this
  *looks* like a plain string to the parser, but CloudFormation resolves it at deploy time from the
  named secret, so no credential material is actually present in the template.

Everything else — a bare quoted or unquoted scalar (`"hunter2"`, `hunter2`) — is treated as a
literal and fires.

Suppress an audited/intentional case (e.g. a deliberately decoy fixture) with a comment containing
`security: allow-cfn-authentication-password` anywhere in the resource's block (YAML `#` comment;
not meaningful in JSON, which has no comment syntax — a JSON template can't carry this pragma at
all, a known, documented limitation shared by every CFN guard in this batch — see `agentsec.cfn`'s
module docstring).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.cfn import cfn_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_RESOURCE_TYPE = "AWS::CloudFormation::Authentication"

# Any "password"/"Password" key, in either bare-YAML or quoted-JSON key form. `\b...\b` keeps this
# from matching inside a longer identifier like "PasswordHash" (no word boundary between two letter
# characters), while still matching at any nesting depth inside the resource's block text.
_PASSWORD_KEY = re.compile(r'["\']?\bpassword\b["\']?\s*:\s*', re.IGNORECASE)

# A Secrets Manager / SSM dynamic reference embedded as a literal-looking string value.
_DYNAMIC_REF = re.compile(r"\{\{\s*resolve:", re.IGNORECASE)

_PRAGMA = "security: allow-cfn-authentication-password"

_STANDARDS = ["OWASP:A02", "CWE-798"]


def _value_is_literal(after_colon: str) -> bool:
    """`after_colon` is the block text immediately following a matched `password:` key's colon.
    Returns True only when the value is a plain literal scalar (not a reference form)."""
    text = after_colon.lstrip()
    if not text:
        return False
    if text[0] == "!":
        # YAML short-form intrinsic tag, e.g. `!Ref SomeParam` / `!Sub "${x}"` — YAML reserves a
        # leading unquoted `!` for tags, so this is never a literal scalar value.
        return False
    if text[0] == "{":
        # A flow-mapping/JSON object value (`{"Ref": "..."}`, `{Fn::Sub: "..."}`, or any other
        # object shape) — never treated as a plain literal scalar here. This guard only fires on
        # an unambiguous bare/quoted string value, so an object of any kind is conservatively
        # skipped rather than risk a false positive on a reference form we don't recognize.
        return False
    # A scalar: quoted string or bare word/number, up to the next structural delimiter.
    if text[0] in ("'", '"'):
        quote = text[0]
        m = re.match(re.escape(quote) + r"(.*?)" + re.escape(quote), text, re.DOTALL)
        literal = m.group(1) if m else text[1:]
    else:
        m = re.match(r"[^,\n}]+", text)
        literal = m.group(0).strip() if m else text.strip()
    if not literal:
        return False
    return not _DYNAMIC_REF.search(literal)


class CfnAuthenticationPasswordGuard(Guard):
    id = "cfn-authentication-password"
    title = "AWS::CloudFormation::Authentication resource carries a literal password"
    area = "Secrets"

    # cfn_authentication.yaml: AWS::CloudFormation::Authentication with a literal `password` value
    # -> fires cfn-authentication-password/literal-password.
    canary_plant = CanaryPlant(
        files={
            "cfn_authentication.yaml": (
                "AWSTemplateFormatVersion: '2010-09-09'\n"
                "Resources:\n"
                "  CanaryAuth:\n"
                "    Type: AWS::CloudFormation::Authentication\n"
                "    Properties:\n"
                "      testBasicAuth:\n"
                "        type: basic\n"
                "        username: canary-user\n"
                "        password: canary-literal-secret\n"
                "        uris: [http://example.invalid/private]\n"
            ),
        },
        expects=frozenset({
            "cfn-authentication-password/literal-password",
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
            if resource.resource_type != _RESOURCE_TYPE:
                continue
            if pragma_present(_PRAGMA, resource.block, dialect=resource.pragma_dialect):
                continue
            if not self._has_literal_password(resource.block):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.logical_id}` (AWS::CloudFormation::Authentication) carries a "
                        "literal `password` value rather than a reference. This deprecated resource "
                        "type is not NoEcho-protected — a hardcoded password here is displayed in "
                        "PLAINTEXT in the CloudFormation console to anyone with console read access "
                        "to the stack, not just repo contributors."
                    ),
                    remediation=(
                        "Reference a NoEcho CloudFormation parameter (`!Ref DBPassword`) or a "
                        "Secrets Manager/SSM dynamic reference (`{{resolve:secretsmanager:...}}`) "
                        "instead of a literal password value. Suppress an audited/intentional case "
                        "with a `security: allow-cfn-authentication-password` comment anywhere in "
                        "the resource (YAML templates only)."
                    ),
                    rule="cfn-authentication-password/literal-password",
                    standards=list(_STANDARDS),
                )
            )
        return out

    @staticmethod
    def _has_literal_password(block: str) -> bool:
        return any(_value_is_literal(block[m.end():]) for m in _PASSWORD_KEY.finditer(block))
