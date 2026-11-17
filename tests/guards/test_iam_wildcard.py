from __future__ import annotations

import pytest

from agentsec.guards.base import iter_policy_statement_blocks
from agentsec.guards.iam_wildcard import IamWildcardGuard
from tests.guards._common import *  # noqa: F401,F403


def test_iam_wildcard_flags_action_star(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:x"}]}\n', encoding="utf-8"
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1
    assert findings[0].rule == "iam-wildcard/action-star" and findings[0].severity == "high"

def test_iam_wildcard_flags_resource_star(tmp_path: Path) -> None:
    (tmp_path / "p.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}\n', encoding="utf-8"
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1 and findings[0].rule == "iam-wildcard/resource-star"

def test_iam_wildcard_passes_scoped_policy(tmp_path: Path) -> None:
    (tmp_path / "p.json").write_text(
        '{"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}\n', encoding="utf-8"
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []

def test_iam_wildcard_ignores_non_policy_json(tmp_path: Path) -> None:
    # a plain config json with a "*" but no IAM Statement -> not a policy, silent
    (tmp_path / "tsconfig.json").write_text('{"include": ["*"], "compilerOptions": {}}\n', encoding="utf-8")
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []

def test_iam_wildcard_pragma(tmp_path: Path) -> None:
    (tmp_path / "p.json").write_text(
        '// security: allow-iam-wildcard\n{"Statement": [{"Effect": "Allow", "Action": "*"}]}\n', encoding="utf-8"
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []

def test_iam_wildcard_silent_wildcard_in_deny_statement(tmp_path: Path) -> None:
    # #423 FP-bait: a wildcard inside an explicit-DENY statement is a lockdown, not a grant.
    # Only the (scoped) Allow statement should be evaluated -> no finding.
    (tmp_path / "p.json").write_text(
        '{"Statement": [\n'
        '  {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"},\n'
        '  {"Effect": "Deny", "Action": "*", "Resource": "*"}\n'
        ']}\n', encoding="utf-8"
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []

def test_iam_wildcard_flags_allow_star_alongside_deny(tmp_path: Path) -> None:
    # regression: an Allow wildcard is still caught even when a Deny statement is also present.
    (tmp_path / "p.json").write_text(
        '{"Statement": [\n'
        '  {"Effect": "Deny", "Action": "iam:*", "Resource": "*"},\n'
        '  {"Effect": "Allow", "Action": "*", "Resource": "arn:x"}\n'
        ']}\n', encoding="utf-8"
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1 and findings[0].rule == "iam-wildcard/action-star"

def test_iam_wildcard_string_brace_does_not_hide_grant(tmp_path: Path) -> None:
    # PR #446 review: an unbalanced `}` inside a string value (a Sid) must not unbalance the
    # brace walk and hide a real Allow wildcard grant that follows it.
    (tmp_path / "p.json").write_text(
        '{"Statement": [{"Sid": "weird}sid", "Effect": "Allow", "Action": "*", "Resource": "arn:x"}]}\n', encoding="utf-8"
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1 and findings[0].rule == "iam-wildcard/action-star"

def test_iam_wildcard_heredoc_odd_quote_does_not_hide_grant(tmp_path: Path) -> None:
    # PR #446 re-review: an unrelated local-exec heredoc with an ODD number of `"` must not
    # desync the brace walk and hide a real Allow wildcard grant elsewhere in the file.
    (tmp_path / "main.tf").write_text(
        'resource "null_resource" "x" {\n'
        '  provisioner "local-exec" {\n'
        "    command = <<EOF\n"
        'echo "starting the service\n'
        "EOF\n"
        "  }\n"
        "}\n"
        'policy = {\n'
        '  "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:x"}]\n'
        "}\n",
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) == 1 and findings[0].rule == "iam-wildcard/action-star"

def test_iam_wildcard_is_universal() -> None:
    assert IamWildcardGuard().applies(_ANY) is True



def test_iam_wildcard_falls_back_when_no_statement_block_parses(tmp_path: Path) -> None:
    # Regression (#446 review): `blank_policy_noise` kept a heredoc body only when the OPENING
    # line contained the literal substring `policy`, so a wildcard policy in an `admin_doc = <<EOT`
    # was blanked away and `iter_policy_statement_blocks` returned [] — the guard emitted nothing
    # even though the file had ALREADY passed both gates (a "Statement" and an "Effect": "Allow"
    # are present).
    #
    # The #446 RE-review fixed that at the ROOT: the heredoc keep decision now reads the BODY, so
    # this document parses into a real statement block and never reaches the fallback. The wildcard
    # must still be reported either way — that is what this test pins.
    (tmp_path / "main.tf").write_text(
        "locals {\n"
        "  admin_doc = <<EOT\n"
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert len(findings) >= 1
    assert any(f.rule == "iam-wildcard/action-star" for f in findings)


def test_iam_wildcard_deny_statement_bait_survives_the_fallback(tmp_path: Path) -> None:
    # FP-bait: the per-statement walk exists so a wildcard inside a DENY (a hardening pattern)
    # does not inherit the file-level Allow gate. This file PARSES, so the fallback never runs
    # and that protection is unchanged.
    (tmp_path / "p.json").write_text(
        '{"Version":"2012-10-17","Statement":[\n'
        '  {"Effect":"Deny","Action":"*","Resource":"*"},\n'
        '  {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}\n'
        "]}\n",
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_heredoc_policy_body_parses_into_a_statement_block(tmp_path: Path) -> None:
    # The ROOT-CAUSE half of the #446 re-review: the heredoc keep decision is made on the BODY
    # (does it declare an Effect/Statement?), never on the attribute name. So the `admin_doc`
    # document above is now recovered by the WALKER — proven here directly, since the guard
    # assertion alone can't distinguish "parsed" from "caught by the fallback".
    text = (
        "locals {\n"
        "  admin_doc = <<EOT\n"
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\n'
        "EOT\n"
        "}\n"
    )
    blocks = iter_policy_statement_blocks(text)
    assert len(blocks) == 1
    assert '"Action":"*"' in blocks[0][2]


def test_iam_wildcard_commented_out_policy_example_is_not_a_grant(tmp_path: Path) -> None:
    # FP-bait (#446 re-review): a documentation header showing a policy in a `#` comment is
    # prose. The file holds no IAM resource at all, so nothing may fire — including via the
    # unparseable-document fallback, which is why that fallback scans the BLANKED text.
    (tmp_path / "main.tf").write_text(
        "# Example policy (do NOT copy verbatim, illustrative documentation only):\n"
        '# {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\n'
        'resource "aws_s3_bucket" "b" {\n'
        '  bucket = "my-bucket"\n'
        "}\n",
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_commented_example_does_not_mask_a_real_grant(tmp_path: Path) -> None:
    # The other direction of the same file shape: blanking the comment must not blind the guard
    # to a REAL wildcard policy living below it (exactly one finding, on the real line).
    (tmp_path / "main.tf").write_text(
        '# {"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}  <- example only\n'
        'resource "aws_iam_role_policy" "p" {\n'
        "  admin_doc = <<EOT\n"
        '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:x"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.location) for f in findings] == [("iam-wildcard/action-star", "main.tf:4")]


def test_iam_wildcard_unparseable_document_still_falls_back(tmp_path: Path) -> None:
    # The fallback's own net, now that the heredoc case is fixed at the root: a TRUNCATED policy
    # (unbalanced braces) recovers no statement block, so the coarse file-level scan must still
    # report the wildcard rather than the guard failing open.
    (tmp_path / "p.json").write_text(
        '{"Version":"2012-10-17","Statement":[\n'
        '  {"Effect":"Allow","Action":"*","Resource":"*"\n',
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "iam-wildcard/action-star" for f in findings)


def test_iam_wildcard_tf_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: a `.tf` file is read under the HCL comment-only view, so a string attribute quoting
    # the pragma is content, not an opt-out (the heredoc policy body is content too).
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_policy" "admin" {\n'
        '  description = "opt out with # security: allow-iam-wildcard"\n'
        "  policy = <<EOT\n"
        '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:x"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-wildcard/action-star"]


def test_iam_wildcard_tf_comment_pragma_still_suppresses(tmp_path: Path) -> None:
    # The rule-4 direction of the same change: a real `#` comment in the `.tf` file (outside the
    # heredoc body, which the HCL view treats as content) still opts out.
    (tmp_path / "main.tf").write_text(
        "# security: allow-iam-wildcard\n"
        'resource "aws_iam_policy" "admin" {\n'
        "  policy = <<EOT\n"
        '{"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:x"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_partial_pattern_expands_to_passrole(tmp_path: Path) -> None:
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": "iam:*Role*", "Resource": "*"}\n]}\n',
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "iam-wildcard/partial-wildcard-dangerous" for f in findings)
    assert any("iam:PassRole" in f.message for f in findings)


def test_iam_wildcard_partial_read_pattern_is_not_partial_wildcard_dangerous(tmp_path: Path) -> None:
    # PR #1051 review H2: `s3:Get*` is a data read, not a privilege-escalation action, so the
    # partial-wildcard rule stays out of it. The pre-existing resource-star rule still owns the
    # `Resource: "*"` half of this statement.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}\n]}\n',
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-wildcard/resource-star"]


@pytest.mark.parametrize(
    "actions,resource",
    [
        ('["s3:Get*", "s3:List*"]', '["arn:aws:s3:::my-app-bucket", "arn:aws:s3:::my-app-bucket/*"]'),
        ('["ssm:Get*"]', '"arn:aws:ssm:us-east-1:111:parameter/app/*"'),
        ('["kms:Decrypt*", "kms:Describe*"]', '"arn:aws:kms:us-east-1:111:key/abc"'),
        ('"lambda:Invoke*"', '"arn:aws:lambda:us-east-1:111:function:tool-*"'),
        ('"secretsmanager:Get*"', '"arn:aws:secretsmanager:us-east-1:111:secret:app-*"'),
        ('"bedrock:Invoke*"', '"arn:aws:bedrock:us-east-1::foundation-model/anthropic.*"'),
    ],
)
def test_iam_wildcard_scoped_data_read_partial_wildcards_stay_silent(
    tmp_path: Path, actions: str, resource: str
) -> None:
    # H2: least-privilege read grants scoped to one bucket / parameter path / key / function.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        f'  {{"Effect": "Allow", "Action": {actions}, "Resource": {resource}}}\n]}}\n',
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_notaction_partial_pattern_is_not_an_expansion(tmp_path: Path) -> None:
    # H2: under NotAction the pattern is an EXCLUSION; reporting it as "expands to a dangerous
    # action" inverts the semantics. iam-notaction-with-allow owns the Allow+NotAction shape.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "NotAction": ["iam:*Role*"], "Resource": "arn:aws:s3:::b/*"}\n]}\n',
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


@pytest.mark.parametrize(
    "pattern,expanded",
    [
        ("iam:Put*", "iam:putrolepolicy"),
        ("iam:*Role*", "iam:passrole"),
        ("sts:Assume*", "sts:assumerole"),
        ("cloudtrail:Stop*", "cloudtrail:stoplogging"),
    ],
)
def test_iam_wildcard_partial_escalation_pattern_still_fires_on_scoped_resource(
    tmp_path: Path, pattern: str, expanded: str
) -> None:
    # Still-fires for the H2 narrowing: a partial wildcard over privilege-escalation actions is
    # flagged even when the Resource is scoped (so resource-star cannot be what fires).
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        f'  {{"Effect": "Allow", "Action": ["s3:GetObject", "{pattern}"], '
        '"Resource": "arn:aws:iam::111:role/app-*"}\n]}\n',
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-wildcard/partial-wildcard-dangerous"]
    assert expanded in findings[0].message.lower()
    assert findings[0].location.endswith("policy.json:2")


def test_iam_wildcard_scoped_service_wildcard_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a plain service-wide wildcard ("iam:*") is a deliberate design choice this guard
    # has always declined to flag (common, not inherently dangerous on its own) -- the new
    # partial-wildcard rule must not reach it from the back door via fnmatch.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": "iam:*", "Resource": "arn:aws:iam::123:role/app"}\n]}\n',
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_harmless_readonly_wildcard_stays_silent(tmp_path: Path) -> None:
    # FP-bait: a read-only-looking wildcard that does NOT expand to anything in the dangerous set.
    # Resource is scoped (not "*") so the unrelated, pre-existing resource-star rule can't fire.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": "ec2:Describe*", "Resource": "arn:aws:ec2:*:*:instance/*"}\n]}\n',
        encoding="utf-8",
    )
    assert IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_wildcard_bare_star_not_double_counted_as_partial(tmp_path: Path) -> None:
    # The bare "*" case is already caught by action-star; it must not ALSO fire the
    # partial-wildcard rule for the same statement.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [\n'
        '  {"Effect": "Allow", "Action": "*", "Resource": "*"}\n]}\n',
        encoding="utf-8",
    )
    findings = IamWildcardGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-wildcard/action-star"]
