"""Guard: Terraform S3 bucket policy does not deny insecure (non-TLS) transport (checklist §6a).

    resource "aws_s3_bucket_policy" "app" {
      bucket = aws_s3_bucket.app.id
      policy = jsonencode({
        Statement = [{
          Effect    = "Allow"
          Principal = "*"
          Action    = "s3:GetObject"
          Resource  = "${aws_s3_bucket.app.arn}/*"
        }]
        # no statement anywhere denies non-TLS requests
      })
    }

S3 does not encrypt requests in transit by default — a client that reaches the bucket over plain
HTTP (or TLS downgraded below the account's minimum) sends and receives object data and
credentials unencrypted. The standard mitigation is an explicit bucket-policy statement that
denies every request where `aws:SecureTransport` is false. Without one, nothing in the bucket's
own policy stops an insecure request from a client, proxy, or script that doesn't already enforce
TLS itself. CWE-319 (Cleartext Transmission of Sensitive Information), OWASP:A02.

Scope deliberately narrower than the real-world rule this is inspired by, to keep false positives
low (the same disclosed trade-off `s3_bucket_policy_wildcard_principal.py` makes with its
`Condition`-presence heuristic): **only buckets that already have an explicit
`aws_s3_bucket_policy` resource are evaluated.** A bucket with no policy resource at all is not
flagged — that would fire on nearly every ordinary bucket in a typical app (plenty of buckets are
intentionally left to the account's default TLS behavior with no custom policy at all) and swamp
the signal with findings nobody would act on. This guard only has an opinion once a team has
already decided to hand-write a bucket policy.

For each `aws_s3_bucket_policy` resource, its `policy = jsonencode({ ... })` (or raw JSON heredoc)
body is walked statement-by-statement via the shared `iter_policy_statement_blocks` helper
(`agentsec/guards/base.py`) — the same walker `s3_bucket_policy_wildcard_principal.py` uses, so a
statement spanning multiple lines, or a string/comment/heredoc with a stray quote or brace, can't
desync the scan. A statement satisfies the mitigation when it has BOTH:

- `Effect` equal to the literal string `"Deny"` (case-sensitive — Terraform/IAM's own enum value
  is capitalized exactly this way; a policy author who got the case wrong wrote a statement AWS
  itself would reject or ignore, so no such statement counts), AND
- a `Condition` key present, whose text mentions `SecureTransport` anywhere.

This guard does not parse the condition's actual boolean operator or value (`Bool` /
`"aws:SecureTransport": "false"` vs `"true"`, `StringEquals` vs `Bool`, …) — it only confirms the
policy's text references `SecureTransport` at all inside a `Deny` statement's `Condition`. That is
the limit of what a text-only scan can reliably assert; a `Deny` + `Condition` + `SecureTransport`
combination that is subtly miswritten (e.g. accidentally requiring secure transport rather than
denying its absence) is an accepted false negative here, not a bug — a known, documented
simplification.

`policy` is not always an inline `jsonencode({ ... })` literal, and the other common shapes need
different handling (review H8):

- **`policy = data.aws_iam_policy_document.<label>.json`** — the most common real-world shape.
  The referenced `data "aws_iam_policy_document" "<label>" { ... }` is resolved only within the
  referencing `aws_s3_bucket_policy` resource's own directory (every `.tf` file in that same
  directory, not the whole repo — a repo-global lookup by label alone let one module's
  same-labelled data source silence a different module's policy of the same name, review H-4),
  and its own `statement { effect = "Deny" ... condition { ... } }` HCL blocks are scanned the
  same way, via `_denies_insecure_transport_hcl`. If the referenced data source cannot be found
  in that directory, this guard stays silent for that policy — it has no way to prove the
  policy is missing the mitigation, and firing on "couldn't resolve it" would be a guess, not a
  finding.
  The reference may carry a `count`/`for_each` index (`data.aws_iam_policy_document.tls[0].json`)
  or the legacy interpolation wrapper (`"${data.aws_iam_policy_document.tls.json}"`).
- **A literal policy** -- `policy = jsonencode({ ... })`, a `<<EOF` heredoc, or a quoted JSON
  string (`policy = "{...}"`) -- is scanned statement by statement, as described above.
- **Anything else** -- `policy = file(...)`, `templatefile(...)`, `var.*`, `local.*`, a module
  output, another resource's attribute -- holds policy content that lives outside what this
  guard can read. These stay silent for the same reason: absence of proof is not proof of
  absence. The guard fires only on a policy it could actually read (PR #1162 round-2 M-4: it
  used to treat every non-`data`, non-`file`/`var` right-hand side as an empty literal policy, so
  `policy = local.bucket_policy` fired even when the local held a correct Deny).

If NONE of a policy's statements satisfy both conditions, this guard fires once for that
`aws_s3_bucket_policy` resource; if at least one does, it stays silent for that resource.

Fires MEDIUM. Rule id: `s3-bucket-insecure-transport-allowed/no-deny-insecure-transport`.

Suppress an audited case (e.g. TLS is enforced upstream by a CloudFront/ALB listener policy
instead) with `# security: allow-s3-insecure-transport` anywhere in the `aws_s3_bucket_policy`
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
    blank_policy_noise,
    is_nonproduct_path,
    iter_files,
    iter_policy_statement_blocks,
    iter_terraform_resources,
    pragma_present,
    read,
    rel,
    terraform_code_view,
)

# Case-sensitive on purpose — see module docstring: IAM's own enum value is capitalized exactly
# "Deny", and a statement that got the case wrong is not a statement AWS would honor as a deny.
_EFFECT_DENY = re.compile(r'"?Effect"?\s*[:=]\s*"Deny"')
_CONDITION_KEY = re.compile(r'"?Condition"?\s*[:=]')
_SECURE_TRANSPORT = re.compile(r"SecureTransport", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-s3-insecure-transport")

_STANDARDS = ["OWASP:A02", "CWE-319"]

# `policy = data.aws_iam_policy_document.<label>.json` -- resolved within the resource's own
# directory, see module docstring. An optional `[index]` (count / for_each) and the legacy
# `"${...}"` wrapper are accepted around the same reference.
_POLICY_DATA_SOURCE_REF = re.compile(
    r'\bpolicy\s*=\s*(?:"\$\{\s*)?data\.aws_iam_policy_document\.(?P<label>[A-Za-z0-9_-]+)'
    r"(?:\[[^\]\n]*\])?\.json\b"
)
# A policy whose content is written right here: `jsonencode({`, a heredoc, or a quoted JSON
# string. Only these are scanned statement by statement; any other right-hand side (`file()`,
# `var.*`, `local.*`, a module output, ...) is content this guard cannot read, and stays silent.
# Matched against `terraform_code_view`, so a commented-out `# policy = jsonencode({` is not one.
_POLICY_LITERAL = re.compile(r'\bpolicy\s*=\s*(?:jsonencode\s*\(\s*\{|<<-?\s*\w+|"\s*\{)')

_IAM_POLICY_DOCUMENT_DATA = re.compile(
    r'\bdata\s+"aws_iam_policy_document"\s+"(?P<label>[^"]+)"\s*'
    r"\{(?P<inner>(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}",
    re.DOTALL,
)
_HCL_STATEMENT_BLOCK = re.compile(r"\bstatement\s*\{(?P<inner>(?:[^{}]|\{[^{}]*\})*)\}", re.DOTALL)
_HCL_EFFECT_DENY = re.compile(r'\beffect\s*=\s*"Deny"')
_HCL_CONDITION_BLOCK = re.compile(r"\bcondition\s*\{[^{}]*\}", re.DOTALL)


def _denies_insecure_transport(block: str) -> bool:
    return bool(
        _EFFECT_DENY.search(block)
        and _CONDITION_KEY.search(block)
        and _SECURE_TRANSPORT.search(block)
    )


def _denies_insecure_transport_hcl(statement_inner: str) -> bool:
    """Same check as `_denies_insecure_transport`, for an `aws_iam_policy_document` data
    source's HCL `statement { ... }` block shape rather than a JSON `Statement` object."""
    if not _HCL_EFFECT_DENY.search(statement_inner):
        return False
    return any(
        _SECURE_TRANSPORT.search(cond.group(0))
        for cond in _HCL_CONDITION_BLOCK.finditer(statement_inner)
    )


class S3BucketInsecureTransportAllowedGuard(Guard):
    id = "s3-bucket-insecure-transport-allowed"
    title = "S3 bucket policy does not deny insecure (non-TLS) transport"
    area = "Cloud & IaC"

    # s3_insecure_transport.tf: aws_s3_bucket_policy with one Allow/s3:GetObject statement and no
    # Deny/SecureTransport statement anywhere -> fires
    # s3-bucket-insecure-transport-allowed/no-deny-insecure-transport.
    canary_plant = CanaryPlant(
        files={
            "s3_insecure_transport.tf": (
                # Resource label deliberately NOT "canary" — aws_observability_hygiene's own
                # canary cross-matches ANY aws_s3_bucket resource named "canary" across the
                # whole merged canary repo; a unique label avoids that cross-guard collision
                # (see s3_mfa_delete_disabled.py's canary_plant for the concrete incident).
                'resource "aws_s3_bucket" "insecure_transport_canary" {\n'
                '  bucket = "canary-insecure-transport-bucket"\n'
                "}\n"
                "\n"
                'resource "aws_s3_bucket_policy" "insecure_transport_canary" {\n'
                "  bucket = aws_s3_bucket.insecure_transport_canary.id\n"
                "  policy = jsonencode({\n"
                "    Statement = [{\n"
                '      Effect    = "Allow"\n'
                '      Principal = "*"\n'
                '      Action    = "s3:GetObject"\n'
                '      Resource  = "${aws_s3_bucket.insecure_transport_canary.arn}/*"\n'
                "    }]\n"
                "  })\n"
                "}\n"
            ),
        },
        expects=frozenset({"s3-bucket-insecure-transport-allowed/no-deny-insecure-transport"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = [
            f for f in iter_files(root, (".tf",))
            if not is_nonproduct_path(rel(root, f), profile.archive_segments)
        ]

        # Resolve every `data "aws_iam_policy_document" "<label>"` in the scanned files first,
        # so a
        # `policy = data.aws_iam_policy_document.<label>.json` reference can be checked for its
        # own Deny/SecureTransport statement rather than treated as having none at all. Keyed
        # by (directory, label) rather than by label alone (round-2 review, H-4): a repo-global
        # label map let one module's same-labelled, Deny-bearing data source silence a
        # different module's Allow-only policy of the same name — `policy` is a very common
        # label. A `data.aws_iam_policy_document.*.json` reference is only ever resolved
        # within the referencing resource's own directory, matching how Terraform itself scopes
        # a data source to its module.
        policy_documents: dict[tuple[Path, str], list[str]] = {}
        for f in files:
            # The code view: an interpolation inside a statement (`resources = ["${...}/*"]`,
            # `values = ["${var.v}"]`) adds a brace level the nested-block regexes cannot absorb.
            text = terraform_code_view(read(f))
            for doc_match in _IAM_POLICY_DOCUMENT_DATA.finditer(text):
                label = doc_match.group("label")
                stmt_inners = [
                    sm.group("inner")
                    for sm in _HCL_STATEMENT_BLOCK.finditer(doc_match.group("inner"))
                ]
                policy_documents.setdefault((f.parent, label), []).extend(stmt_inners)

        out: list[Finding] = []
        for f in files:
            out.extend(self._scan(root, f, policy_documents))
        return out

    def _scan(
        self, root: Path, f: Path, policy_documents: dict[tuple[Path, str], list[str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        for resource_type, resource_name, start, body in iter_terraform_resources(text):
            if resource_type != "aws_s3_bucket_policy":
                continue
            body_text = "\n".join(line for _, line in body)
            if pragma_present(_PRAGMA, body_text, dialect="hcl"):
                continue
            # Comments blanked: a commented-out `# policy = data....json` is not the policy
            # (PR #1162 round-4 L1). Not the full code view: the reference's own `"${...}"` and
            # `[index]` must stay readable for `_POLICY_DATA_SOURCE_REF`.
            data_ref = _POLICY_DATA_SOURCE_REF.search(blank_policy_noise(body_text))
            if data_ref is not None:
                stmt_inners = policy_documents.get((f.parent, data_ref.group("label")))
                if not stmt_inners:
                    # Referenced data source not found in this resource's own directory --
                    # can't prove the mitigation is missing, so don't guess.
                    continue
                if any(_denies_insecure_transport_hcl(s) for s in stmt_inners):
                    continue
            elif _POLICY_LITERAL.search(terraform_code_view(body_text)):
                statements = iter_policy_statement_blocks(body_text)
                if any(_denies_insecure_transport(block) for _s, _e, block in statements):
                    continue
            else:
                # file()/templatefile()/var.*/local.*/a module output -- content this guard
                # cannot read at all.
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{start}",
                    message=(
                        f"`aws_s3_bucket_policy.{resource_name}` has no statement denying "
                        "insecure (non-TLS) transport — no statement with `Effect: \"Deny\"` and "
                        "a `Condition` referencing `aws:SecureTransport` was found anywhere in "
                        "this policy. A client that reaches this bucket over plain HTTP sends "
                        "and receives object data and credentials unencrypted."
                    ),
                    remediation=(
                        "Add a statement denying insecure transport, e.g.: "
                        '`{ Effect = "Deny", Principal = "*", Action = "s3:*", '
                        'Resource = [aws_s3_bucket.<name>.arn, "${aws_s3_bucket.<name>.arn}/*"], '
                        'Condition = { Bool = { "aws:SecureTransport" = "false" } } }`. '
                        "Suppress an audited exception (e.g. TLS enforced upstream by a "
                        "CloudFront/ALB listener policy instead) with "
                        "`# security: allow-s3-insecure-transport` anywhere in the resource "
                        "block."
                    ),
                    rule="s3-bucket-insecure-transport-allowed/no-deny-insecure-transport",
                    standards=list(_STANDARDS),
                )
            )
        return out
