"""Guard: an AWS IAM role trust policy allows any AWS account to assume it, or trusts a
principal without the documented confused-deputy mitigation (checklist §6c).

    resource "aws_iam_role" "app" {
      assume_role_policy = jsonencode({
        Statement = [{
          Effect    = "Allow"
          Principal = { AWS = "*" }
          Action    = "sts:AssumeRole"
        }]
      })
    }

An IAM role's `assume_role_policy` (its trust policy) with `"Effect": "Allow"` and
`"Principal": {"AWS": "*"}` lets literally any AWS account in existence assume the
role — anyone who can call `sts:AssumeRole` with this role's ARN gets whatever
permissions the role carries, no membership in the same account required. This is a
different attribute and JSON shape from `iam-wildcard` (which flags `Action`/
`Resource` wildcards on a policy's own permissions, not who may assume a role) and
from `s3-bucket-policy-wildcard-principal` (a different resource type entirely).
CWE-284 (Improper Access Control), OWASP:A01.

A second rule, MEDIUM and a review signal (2026-10-08, aws-agent-identity-guard research-cycle;
narrowed and downgraded in the PR #1051 reviews): an AWS-SERVICE principal from the short list
of services that act on behalf of ANOTHER resource (SNS, S3, EventBridge and EventBridge
Scheduler, CloudTrail, Config, CloudWatch Logs),
trusted with no `aws:SourceArn`/`SourceAccount`/`SourceOrgID`/`SourceOrgPaths` condition anywhere
in the statement. That is the cross-service confused-deputy shape AWS's IAM guide documents those
keys for: without one, a resource of that service type in ANY account can make the service assume
this role. AWS recommends rather than requires the condition, and its own canonical EventBridge
and Config service-role trust policies omit it, so the rule never fails a `--fail-on high` gate.
A compute/runtime service assuming its own execution role (`lambda`, `ecs-tasks`, `ec2`,
`bedrock`, ...) is the ordinary service-role shape and does not fire; flagging every service role
made the rule fire on nearly all IAM. An explicit `arn:aws:iam::...` principal without
`sts:ExternalId` is NOT flagged: ExternalId matters only for third-party delegation, and a static
scan cannot tell a third party's account from the role's own (the review measured it firing HIGH
on the same-account `:root` trust and the KMS default key policy).

Fires HIGH when an `aws_iam_role` resource's (Terraform) or a bare trust-policy
`.json` document's `assume_role_policy`/top-level body contains an `"Effect": "Allow"`
statement whose `Principal` carries a wildcard: `"AWS": "*"`, `"AWS": [..., "*", ...]`
(the wildcard anywhere in the array, not just first), or the bare `"Principal": "*"`
string form. A wildcard narrowed by a positive `aws:PrincipalOrgID`/`aws:PrincipalOrgPaths`
condition with a specific value (the documented org-wide trust shape) does not fire (PR #1051 re-review; this also
narrowed the pre-existing `.tf` path). A `Deny` statement, a principal scoped to a specific
account ID/ARN, or a `Principal` using `Service` (not `AWS`) does not fire that rule (but may fire the
confused-deputy rule above instead). The `.tf` scan isolates each
**brace-bounded statement object** (the `{...}` that directly contains the `Effect`)
and looks for the wildcard principal only within that object's own span, so: (a) a
`Deny` statement's wildcard principal elsewhere in the same trust policy cannot be
misattributed to a sibling `Allow` statement, and (b) `Principal` and `Effect` may
appear in either order and any distance apart within the statement. The bare-JSON
scan uses the shared `iter_policy_statement_blocks` walker for the same per-statement
isolation, and treats a statement as a trust statement only when its `Action` names
`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity` or `sts:AssumeRoleWithSAML`, or a pattern
covering one (`sts:*`, `sts:Assume*`; a bare `*` does not count): an S3/SNS/
SQS/KMS resource policy also carries `Principal`, but nothing in it can be "assumed", so it
is left to the guards that own those resource types.

Suppress an audited case with `# security: allow-iam-role-public-assume` anywhere in
the resource block (a `.tf` comment) or anywhere in the file (a `.json` document has
no comment syntax; the same fallback the other widened IAM guards use, #424).
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
    is_nonproduct_path,
    iter_files,
    iter_policy_key_values,
    iter_policy_statement_blocks,
    iter_terraform_resources,
    neutralize_interpolations,
    pragma_present,
    read,
    rel,
)

_ASSUME_ROLE_ATTR = re.compile(r"\bassume_role_policy\b")
_EFFECT_ALLOW = re.compile(r'"?Effect"?\s*[:=]\s*"Allow"')
_IS_TRUST_POLICY = re.compile(r'"Statement"', re.IGNORECASE)
_HAS_PRINCIPAL_KEY = re.compile(r'"?Principal"?\s*[:=]', re.IGNORECASE)
# A wildcard principal, in any of the forms that grant "any AWS account":
#   Principal = "*"            (bare string form, no AWS key)
#   AWS = "*"                  (string)
#   AWS = [ ..., "*", ... ]    (the wildcard ANYWHERE in the array, not just first element)
_WILDCARD_PRINCIPAL_STRING = re.compile(r'"?(?:Principal|AWS)"?\s*[:=]\s*"\*"')
# Key heads whose list/string VALUE is read by base.iter_policy_key_values: uncapped and linear.
# (Round 3 bounded `\[[^\]]*\]` value regexes with length caps; round 4 showed a cap is a silent
# bypass, e.g. 4200 spaces before the `"*"` of an AWS list hid it, so no list body is capped.)
_AWS_HEAD = re.compile(r'"?AWS"?\s*[:=]\s*')
# The Action key; NotAction is excluded by the lookbehind.
_ACTION_HEAD = re.compile(r'"?(?<!Not)Action"?\s*[:=]\s*', re.IGNORECASE)
_ASSUME_ACTIONS = ("sts:assumerole", "sts:assumerolewithwebidentity", "sts:assumerolewithsaml")
_SERVICE_HEAD = re.compile(r'"?Service"?\s*[:=]\s*', re.IGNORECASE)
_QUOTED = re.compile(r'"([^"]*)"')
_SERVICE_HOST = re.compile(r"(?P<name>[a-z0-9.-]+)\.amazonaws\.com(?:\.cn)?", re.IGNORECASE)
# Services that assume a customer role ON BEHALF OF another resource, where AWS documents
# aws:SourceArn/SourceAccount as the cross-service confused-deputy mitigation (IAM user guide,
# "The confused deputy problem"; each service's own "cross-service confused deputy prevention"
# page). Matched on the full name or, for the regional `logs.<region>` form, the first label.
_SOURCE_SCOPED_SERVICES = frozenset({
    "sns", "s3", "events", "scheduler", "cloudtrail", "config", "logs", "delivery.logs",
})
_SOURCE_SCOPE = re.compile(
    r'"?aws:(?:SourceArn|SourceAccount|SourceOrgID|SourceOrgPaths)"?', re.IGNORECASE
)
# `AWS: "*"` narrowed to one AWS Organization (or OU path) is the documented org-wide trust shape,
# not "any AWS account" (#1051 re-review L4). DESIGN RULE (round 3, applied at every level in
# round 4): fire only on what is PROVABLY unscoped. A Condition is read only when it is a literal;
# anything not statically readable counts as scoped, at each of three levels:
#   1. the `Condition` value itself (`var.cond`, `local.x`, `merge(...)`),
#   2. a positive operator's value (`StringEquals = var.org_cond`),
#   3. the org key's value (a reference, a `${...}` interpolation, a list holding one).
# - Positive operators: StringEquals/StringLike/ArnEquals/ArnLike, optionally `ForAnyValue:`.
#   Never scoping, readable or not: StringNotEquals (everyone OUTSIDE the org), Null, Bool, and the
#   `IfExists` suffix / `ForAllValues:` prefix, both TRUE when the key is absent (an account in no
#   organization).
# - Provably unscoped org value: a `*`/`?` in the org id (`*`, `o-*`, `o-a*`; for
#   PrincipalOrgPaths, in the first path segment), a list (an OR) with any such element, or the
#   self-referential IAM variable `${aws:PrincipalOrgID}` (also as HCL's escaped `$${...}`).
# Cost: `${...}` is neutralised by base.neutralize_interpolations (one brace-depth scan, nested and
# multi-line safe), and every value is read by base.iter_policy_key_values or one `str.find` per
# operator map: uncapped and linear, no length caps anywhere (a cap is a silent bypass, round 4).
_CONDITION_HEAD = re.compile(r'"?Condition"?\s*[:=]\s*', re.IGNORECASE)
_OPERATOR_HEAD = re.compile(
    r'"?(?P<op>(?:ForAnyValue:|ForAllValues:)?(?:StringEquals|StringLike|ArnEquals|ArnLike)'
    r'(?:IfExists)?)"?\s*[:=]\s*',
    re.IGNORECASE,
)
_ORG_KEY_HEAD = re.compile(r'"?aws:PrincipalOrg(?P<kind>ID|Paths)"?\s*[:=]\s*', re.IGNORECASE)
_ORG_VALUE_TOKEN = re.compile(r'"([^"]*)"|([A-Za-z_][\w.\[\]-]*)')
# `$(`...`)` is a neutralised `${...}`; the optional extra `$` is HCL's `$${...}` escape, which
# renders the literal IAM policy variable, so it is the self-reference too.
_SELF_REFERENCE = re.compile(r"\$?\$\(aws:PrincipalOrg(?:ID|Paths)\)", re.IGNORECASE)


def _org_value_unscoped(kind: str, val: str) -> bool:
    """Is this (neutralised) org-key value PROVABLY a wildcard? Unevaluable values are not."""
    for m in _ORG_VALUE_TOKEN.finditer(val):
        literal = m.group(1)
        if literal is None:
            continue  # a bare Terraform reference (var.x, data.y.id): not evaluable, scoped
        literal = literal.strip()
        if _SELF_REFERENCE.fullmatch(literal):
            return True  # aws:PrincipalOrgID == ${aws:PrincipalOrgID}: any organization at all
        if "$(" in literal:
            continue  # contains a `${...}` interpolation (`"${var.prefix}*"`): not evaluable, scoped
        org_part = literal.split("/", 1)[0] if kind.lower() == "paths" else literal
        if "*" in org_part or "?" in org_part:
            return True
    return False


def _org_scoped(statement: str) -> bool:
    """True when the statement restricts principals TO an organization or OU path, or has a
    Condition that cannot be read statically (the design rule above)."""
    neutral = neutralize_interpolations(statement)
    for cm in _CONDITION_HEAD.finditer(neutral):
        if not neutral.startswith("{", cm.end()):
            return True  # level 1: `Condition = var.cond` / `merge(...)`: not readable
    prev_end = -1
    for om in _OPERATOR_HEAD.finditer(neutral):
        if om.start() < prev_end:
            continue
        op = om.group("op").lower()
        if op.startswith("forallvalues:") or op.endswith("ifexists"):
            continue
        i = om.end()
        if not neutral.startswith("{", i):
            return True  # level 2: `StringEquals = var.org_cond`: not readable
        j = neutral.find("}", i + 1)
        if j < 0:
            return True  # an unclosed operator map is not readable either
        prev_end = j + 1
        for km, val in iter_policy_key_values(neutral[i + 1 : j], _ORG_KEY_HEAD):
            if val is None or not _org_value_unscoped(km.group("kind"), val):
                return True  # level 3: a reference/unreadable or specific org value: scoped
    return False


_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-iam-role-public-assume")

_STANDARDS = ["OWASP:A01", "CWE-284"]
_STANDARDS_CONFUSED_DEPUTY = ["OWASP:A01", "CWE-441"]


def _wildcard_principal_offset(statement: str) -> int | None:
    """Offset of the first wildcard principal in one statement (`Principal: "*"`, `AWS: "*"`, or
    `"*"` anywhere in an `AWS` list), or None. The list is read uncapped and linearly."""
    hits: list[int] = []
    sm = _WILDCARD_PRINCIPAL_STRING.search(statement)
    if sm is not None:
        hits.append(sm.start())
    for hm, val in iter_policy_key_values(statement, _AWS_HEAD):
        if val is not None and val.startswith("[") and any(q.strip() == "*" for q in _QUOTED.findall(val)):
            hits.append(hm.start())
            break
    return min(hits) if hits else None


def _grants_assume_role(block: str) -> bool:
    """Does this statement's `Action` name, or a pattern of it cover, `sts:AssumeRole` or its
    WithWebIdentity/WithSAML variants? A pattern such as `sts:*` or `sts:Assume*` counts (it is
    what IAM itself would evaluate); a bare `*` does not, since that is a resource policy's
    catch-all far more often than a trust policy and `iam-wildcard` already owns it."""
    for _m, val in iter_policy_key_values(block, _ACTION_HEAD):
        for qm in _QUOTED.finditer(val or ""):
            action = qm.group(1).strip().lower()
            if action != "*" and any(fnmatchcase(a, action) for a in _ASSUME_ACTIONS):
                return True
    return False


def _source_scoped_services(block: str) -> list[str]:
    """The `Service` principals in one statement that are on the source-scoping list."""
    out: list[str] = []
    for _m, val in iter_policy_key_values(block, _SERVICE_HEAD):
        for qm in _QUOTED.finditer(val or ""):
            host = _SERVICE_HOST.fullmatch(qm.group(1).strip())
            if host is None:
                continue
            name = host.group("name").lower()
            if name in _SOURCE_SCOPED_SERVICES or name.split(".", 1)[0] in _SOURCE_SCOPED_SERVICES:
                out.append(qm.group(1).strip())
    return out


def _confused_deputy_findings(block: str) -> list[tuple[str, str]]:
    """`(rule_suffix, message)` pairs for confused-deputy gaps in one Allow statement's text.

    Pure text check, same conservative "any occurrence anywhere in the block" posture the rest
    of this module and its siblings use -- never claims a Condition is correctly SCOPED, only
    that the documented mitigation key is present or absent."""
    out: list[tuple[str, str]] = []
    services = _source_scoped_services(block)
    if services and not _SOURCE_SCOPE.search(block):
        out.append((
            "service-principal-no-source-scope",
            f"This trust statement lets `{services[0]}` assume the role with no `aws:SourceArn`/"
            "`SourceAccount`/`SourceOrgID`/`SourceOrgPaths` condition. That service acts on behalf "
            "of another resource, so without source scoping a resource of that type in ANY account "
            "can make it assume this role (the cross-service confused deputy).",
        ))
    return out


def _skeletonize(text: str) -> tuple[str, str]:
    """Return `(brace_text, code_text)`, each exactly as long as `text` (offsets aligned).

    - **brace_text** keeps only structural `{`/`}` that are OUTSIDE string literals and comments;
      every other char (string CONTENTS included) becomes a space — so brace-depth object bounding
      is not fooled by a `{`/`}` inside a `Condition` string value.
    - **code_text** blanks `#`/`//` comment bodies (string-aware: a `//` inside a string, e.g. an
      `https://` URL, is NOT treated as a comment) but keeps string literals intact — so the
      Effect/Principal patterns still match, while a commented-out statement does not.

    Both preserve newlines and every char offset, so a match position maps back to its line. This
    is the string/comment-aware counterpart of `base.py::_tf_line_scan` for char-level extraction."""
    brace: list[str] = []
    code: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\" and i + 1 < n:  # escape: keep both chars in code, blank both in brace
                brace.append("  ")
                code.append(text[i : i + 2])
                i += 2
                continue
            brace.append(" ")
            code.append(c)
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            brace.append(" ")
            code.append('"')
            i += 1
            continue
        if c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):  # comment to end of line
            while i < n and text[i] != "\n":
                brace.append(" ")
                code.append(" ")
                i += 1
            continue
        if c in "{}":
            brace.append(c)
        else:
            brace.append(" ")
        code.append(c)
        i += 1
    return "".join(brace), "".join(code)


def _enclosing_object(text: str, pos: int) -> tuple[int, int] | None:
    """Return `(open, close)` char offsets of the `{...}` object that directly encloses `pos`
    (the statement object around an `Effect` key), or None if `pos` is not inside any braces.
    Operates on the `brace_text` skeleton from `_skeletonize`, where string/comment braces are
    already blanked, so only structural braces are counted."""
    depth = 0
    start = -1
    i = pos
    while i >= 0:
        c = text[i]
        if c == "}":
            depth += 1
        elif c == "{":
            if depth == 0:
                start = i
                break
            depth -= 1
        i -= 1
    if start < 0:
        return None
    depth = 0
    for j in range(start, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return (start, j + 1)
    return (start, len(text))


class IamRolePublicAssumeGuard(Guard):
    id = "iam-role-public-assume"
    title = "IAM role trust policy allows any AWS account to assume it"
    area = "Cloud & IaC"
    # The source-scoping rule is a review signal: AWS recommends aws:SourceArn/SourceAccount for
    # these services, but its own canonical EventBridge/Config service-role trust omits it. The
    # wildcard-principal rule stays a proven, gating finding.
    surfacing_rule_prefixes = ("iam-role-public-assume/service-principal-no-source-scope",)

    # iam_role_trust.tf: aws_iam_role assume_role_policy Allow + Principal AWS:* ->
    # fires wildcard-principal. Must NOT contain: allow-iam-role-public-assume pragma.
    # trust_policy.json: the same wildcard-principal shape in a bare JSON trust-policy document ->
    # also fires wildcard-principal, proving the 2026-10-08 format-widening works.
    # trust_policy_no_source_scope.json: an SNS service principal (a service that assumes the role
    # on behalf of another resource) with no source-scoping condition -> fires
    # service-principal-no-source-scope.
    canary_plant = CanaryPlant(
        files={
            "iam_role_trust.tf": (
                'resource "aws_iam_role" "canary" {\n'
                "  assume_role_policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      Principal = { AWS = "*" }\n'
                '      Action    = "sts:AssumeRole"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
            "trust_policy.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "Principal": {"AWS": "*"},\n'
                '    "Action": "sts:AssumeRole"\n'
                "  }]\n"
                "}\n"
            ),
            "trust_policy_no_source_scope.json": (
                "{\n"
                '  "Version": "2012-10-17",\n'
                '  "Statement": [{\n'
                '    "Effect": "Allow",\n'
                '    "Principal": {"Service": "sns.amazonaws.com"},\n'
                '    "Action": "sts:AssumeRole"\n'
                "  }]\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "iam-role-public-assume/wildcard-principal",
            "iam-role-public-assume/service-principal-no-source-scope",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # a trust policy (bare JSON or Terraform) can live in any repo

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        for f in iter_files(root, (".json",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan_json(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            if resource_type != "aws_iam_role":
                continue
            raw_body = "\n".join(line for _, line in body)
            if not _ASSUME_ROLE_ATTR.search(raw_body) or pragma_present(_PRAGMA, raw_body, dialect="hcl"):
                continue
            brace_text, code = _skeletonize(raw_body)
            linenos = [ln for ln, _ in body]  # index k -> original line number of body line k
            seen: set[int] = set()
            seen_cd: set[tuple[int, str]] = set()
            # Each Effect:Allow marks a statement; isolate its own brace-bounded object and look
            # for a wildcard principal ONLY within that object, so a sibling Deny's wildcard can't
            # be misattributed and Principal/Effect order + distance no longer matter. Brace bounds
            # come from the string/comment-blanked skeleton; the principal search uses code (strings
            # intact, comments blanked) — both offset-aligned with each other and raw_body.
            for m in _EFFECT_ALLOW.finditer(code):
                span = _enclosing_object(brace_text, m.start())
                if span is None:
                    continue
                statement = code[span[0] : span[1]]
                pm = None if _org_scoped(statement) else _wildcard_principal_offset(statement)
                if pm is not None:
                    abs_pos = span[0] + pm
                    line_idx = code.count("\n", 0, abs_pos)
                    lineno = linenos[line_idx] if line_idx < len(linenos) else linenos[-1]
                    if lineno not in seen:
                        seen.add(lineno)
                        out.append(self._finding(root, f, resource_type, resource_name, lineno))
                    continue  # the statement is already maximally open; a confused-deputy
                    # gap on a co-listed scoped principal in the same array is moot
                for suffix, message in _confused_deputy_findings(statement):
                    line_idx = code.count("\n", 0, span[0])
                    lineno = linenos[line_idx] if line_idx < len(linenos) else linenos[-1]
                    if (lineno, suffix) not in seen_cd:
                        seen_cd.add((lineno, suffix))
                        out.append(
                            self._confused_deputy_finding(
                                root, f, resource_type, resource_name, lineno, suffix, message
                            )
                        )
        return out

    def _scan_json(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        # Cheap raw precheck before the blanking pass (#1051 review M4): blanking only turns
        # characters into spaces, so no raw `"Statement"` means none after blanking either.
        if not _IS_TRUST_POLICY.search(text):
            return out
        src = blank_policy_noise(text)
        if not _IS_TRUST_POLICY.search(src) or not _HAS_PRINCIPAL_KEY.search(src):
            return out  # no Principal key at all -- an identity/permission policy, not a trust policy
        for start, _end, block in iter_policy_statement_blocks(text):
            # Only a statement that grants sts:AssumeRole* is a trust statement; an S3/SNS/SQS/KMS
            # resource policy also has a Principal, but nothing in it can be assumed (H1, #1051).
            if not _EFFECT_ALLOW.search(block) or not _grants_assume_role(block):
                continue
            pm = None if _org_scoped(block) else _wildcard_principal_offset(block)
            if pm is not None:
                lineno = text.count("\n", 0, start + pm) + 1
                out.append(self._finding(root, f, "trust-policy", f.stem, lineno))
                continue  # already maximally open; skip the confused-deputy checks
            for suffix, message in _confused_deputy_findings(block):
                lineno = text.count("\n", 0, start) + 1
                out.append(
                    self._confused_deputy_finding(root, f, "trust-policy", f.stem, lineno, suffix, message)
                )
        return out

    def _finding(self, root: Path, f: Path, resource_type: str, resource_name: str, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"`{resource_type}.{resource_name}`'s trust policy allows `Principal: "
                '{"AWS": "*"}` under `Effect: Allow` — any AWS account in existence can '
                "call `sts:AssumeRole` and take on this role's permissions."
            ),
            remediation=(
                "Scope `Principal.AWS` to the specific account ID(s) or role ARN(s) that "
                "should be able to assume this role, or use `Service` for an AWS-service "
                "trust relationship. Suppress an audited exception with "
                "`# security: allow-iam-role-public-assume` anywhere in the resource block."
            ),
            rule="iam-role-public-assume/wildcard-principal",
            standards=list(_STANDARDS),
        )

    def _confused_deputy_finding(
        self,
        root: Path,
        f: Path,
        resource_type: str,
        resource_name: str,
        lineno: int,
        suffix: str,
        message: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="IAM trust policy missing a confused-deputy mitigation",
            location=f"{rel(root, f)}:{lineno}",
            message=f"`{resource_type}.{resource_name}`: {message}",
            remediation=(
                "Add an `aws:SourceArn` (or `aws:SourceAccount`/`aws:SourceOrgID`) condition naming "
                "the resource or account the service acts for. Suppress an audited exception with "
                "`# security: allow-iam-role-public-assume` anywhere in the resource block."
            ),
            rule=f"iam-role-public-assume/{suffix}",
            standards=list(_STANDARDS_CONFUSED_DEPUTY),
        )
