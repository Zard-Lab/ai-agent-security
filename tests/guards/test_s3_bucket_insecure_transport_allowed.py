from __future__ import annotations

from agentsec.guards.s3_bucket_insecure_transport_allowed import (
    S3BucketInsecureTransportAllowedGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_RULE = "s3-bucket-insecure-transport-allowed/no-deny-insecure-transport"


def test_policy_with_no_deny_statement_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_policy_with_deny_but_no_condition_fires(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Deny"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _RULE for f in findings)


def test_policy_with_deny_secure_transport_condition_silent(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [\n"
        "      {\n"
        '        Effect    = "Allow"\n'
        '        Principal = "*"\n'
        '        Action    = "s3:GetObject"\n'
        "      },\n"
        "      {\n"
        '        Effect    = "Deny"\n'
        '        Principal = "*"\n'
        '        Action    = "s3:*"\n'
        "        Condition = {\n"
        '          Bool = { "aws:SecureTransport" = "false" }\n'
        "        }\n"
        "      }\n"
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_policy_from_data_source_with_deny_silent(tmp_path: Path) -> None:
    # Review H8: the most common real-world shape -- policy built from a separate
    # aws_iam_policy_document data source rather than an inline jsonencode(). This one
    # correctly denies insecure transport, so it must stay silent.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = data.aws_iam_policy_document.tls.json\n"
        "}\n"
        'data "aws_iam_policy_document" "tls" {\n'
        "  statement {\n"
        '    effect    = "Allow"\n'
        '    actions   = ["s3:GetObject"]\n'
        '    resources = ["${aws_s3_bucket.app.arn}/*"]\n'
        "  }\n"
        "  statement {\n"
        '    effect    = "Deny"\n'
        '    actions   = ["s3:*"]\n'
        '    resources = [aws_s3_bucket.app.arn, "${aws_s3_bucket.app.arn}/*"]\n'
        "    condition {\n"
        '      test     = "Bool"\n'
        '      variable = "aws:SecureTransport"\n'
        '      values   = ["false"]\n'
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_policy_from_data_source_without_deny_fires(tmp_path: Path) -> None:
    # Same data-source shape, but the real vulnerable case: no Deny/SecureTransport statement.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = data.aws_iam_policy_document.tls.json\n"
        "}\n"
        'data "aws_iam_policy_document" "tls" {\n'
        "  statement {\n"
        '    effect    = "Allow"\n'
        '    actions   = ["s3:GetObject"]\n'
        '    resources = ["${aws_s3_bucket.app.arn}/*"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _RULE for f in findings)


def test_data_source_label_resolved_only_within_its_own_directory(tmp_path: Path) -> None:
    # round-2 review H-4: the label map used to be repo-global, so modB's same-labelled,
    # Deny-bearing data source silenced modA's own Allow-only policy of the same name --
    # "policy" is a very common label. modA's reference must resolve against modA's own
    # directory only and fire, even though an unrelated modB elsewhere in the repo declares a
    # data source with the identical label that DOES deny insecure transport.
    moda = tmp_path / "modA"
    modb = tmp_path / "modB"
    moda.mkdir()
    modb.mkdir()
    (moda / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = data.aws_iam_policy_document.policy.json\n"
        "}\n"
        'data "aws_iam_policy_document" "policy" {\n'
        "  statement {\n"
        '    effect    = "Allow"\n'
        '    actions   = ["s3:GetObject"]\n'
        '    resources = ["${aws_s3_bucket.app.arn}/*"]\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (modb / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "other" {\n'
        "  bucket = aws_s3_bucket.other.id\n"
        "  policy = data.aws_iam_policy_document.policy.json\n"
        "}\n"
        'data "aws_iam_policy_document" "policy" {\n'
        "  statement {\n"
        '    effect    = "Deny"\n'
        '    actions   = ["s3:*"]\n'
        '    resources = [aws_s3_bucket.other.arn, "${aws_s3_bucket.other.arn}/*"]\n'
        "    condition {\n"
        '      test     = "Bool"\n'
        '      variable = "aws:SecureTransport"\n'
        '      values   = ["false"]\n'
        "    }\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    by_resource = {f.message for f in findings if f.rule == _RULE}
    assert any("app" in m for m in by_resource), "modA's own Allow-only policy must fire"
    assert not any("other" in m for m in by_resource), "modB's own Deny policy must stay silent"


def test_policy_from_unresolved_data_source_stays_silent(tmp_path: Path) -> None:
    # The referenced data source isn't declared anywhere in the repo (e.g. it lives in a
    # module this scan didn't see) -- can't prove the mitigation is missing, so stay silent
    # rather than guess.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = data.aws_iam_policy_document.missing.json\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_policy_from_file_function_stays_silent(tmp_path: Path) -> None:
    # policy = file(...) -- content lives outside what this guard can read.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        '  policy = file("${path.module}/policy.json")\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_policy_from_variable_stays_silent(tmp_path: Path) -> None:
    # policy = var.* -- same reasoning as file()/templatefile().
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = var.bucket_policy\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_bucket_with_no_policy_resource_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the deliberately narrowed scope -- a bucket with NO aws_s3_bucket_policy at all
    # must never be flagged, or nearly every ordinary bucket would fire.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id  # security: allow-s3-insecure-transport\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert S3BucketInsecureTransportAllowedGuard().applies(profile) is False


def test_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert S3BucketInsecureTransportAllowedGuard().applies(profile) is True


# --- PR #1162 round-2 M-4: non-inline policy shapes -------------------------------------------


def _tls_data_source(effect: str) -> str:
    return (
        'data "aws_iam_policy_document" "tls" {\n'
        "  statement {\n"
        f'    effect    = "{effect}"\n'
        '    actions   = ["s3:*"]\n'
        '    resources = ["${aws_s3_bucket.app.arn}/*"]\n'
        "    principals {\n"
        '      type        = "*"\n'
        '      identifiers = ["*"]\n'
        "    }\n"
        "    condition {\n"
        '      test     = "Bool"\n'
        '      variable = "aws:SecureTransport"\n'
        '      values   = ["false"]\n'
        "    }\n"
        "  }\n"
        "}\n"
    )


def _bucket_policy(policy_rhs: str) -> str:
    return (
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        f"  policy = {policy_rhs}\n"
        "}\n"
    )


def _findings(tmp_path: Path, content: str) -> list[Finding]:
    (tmp_path / "policy.tf").write_text(content, encoding="utf-8")
    return S3BucketInsecureTransportAllowedGuard().run(tmp_path, _tf_prof(tmp_path))


def test_non_inline_policy_shapes_with_a_deny_stay_silent(tmp_path: Path) -> None:
    # Each of these used to fire although the policy carries a correct Deny: the guard treated
    # every right-hand side it did not recognise as an empty literal policy.
    for rhs in (
        "local.bucket_policy",
        "data.aws_iam_policy_document.tls[0].json",
        '"${data.aws_iam_policy_document.tls.json}"',
        "module.policies.bucket_policy_json",
    ):
        content = (
            _tls_data_source("Deny")
            + "locals {\n  bucket_policy = data.aws_iam_policy_document.tls.json\n}\n"
            + _bucket_policy(rhs)
        )
        assert _findings(tmp_path, content) == [], rhs


def test_indexed_and_legacy_data_references_still_resolve_and_fire(tmp_path: Path) -> None:
    # The direction the M-4 narrowing trades against: the `[0]` and `"${...}"` forms are
    # RESOLVED to their data source (not waved through as unreadable), so an Allow-only data
    # source still fires through them.
    for rhs in (
        "data.aws_iam_policy_document.tls[0].json",
        '"${data.aws_iam_policy_document.tls.json}"',
    ):
        findings = _findings(tmp_path, _tls_data_source("Allow") + _bucket_policy(rhs))
        assert [f.rule for f in findings] == [_RULE], rhs


def test_literal_heredoc_policy_without_deny_still_fires(tmp_path: Path) -> None:
    # A heredoc is a literal policy and is still read statement by statement.
    content = _bucket_policy(
        "<<POLICY\n"
        "{\n"
        '  "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]\n'
        "}\n"
        "POLICY"
    )
    assert [f.rule for f in _findings(tmp_path, content)] == [_RULE]


def test_commented_out_inline_policy_is_not_read_as_the_policy(tmp_path: Path) -> None:
    # A `# policy = jsonencode({` comment above the real (unreadable) policy is not a literal
    # policy to scan.
    content = (
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  # policy = jsonencode({ Statement = [] })\n"
        "  policy = local.bucket_policy\n"
        "}\n"
    )
    assert _findings(tmp_path, content) == []


def test_allow_statement_with_secure_transport_condition_is_not_a_deny(tmp_path: Path) -> None:
    # PR #1162 round-2 Low (a surviving mutant): an `Allow` that merely mentions
    # aws:SecureTransport in its condition does not deny insecure transport, so the policy
    # still fires. Without this test, dropping the `effect = "Deny"` requirement went unnoticed.
    content = _tls_data_source("Allow") + _bucket_policy("data.aws_iam_policy_document.tls.json")
    assert [f.rule for f in _findings(tmp_path, content)] == [_RULE]


def test_commented_out_data_reference_is_not_the_policy(tmp_path: Path) -> None:
    # PR #1162 round-4 L1: a commented `# policy = data....json` above the real Allow-only
    # literal policy used to win, fail to resolve, and silence the guard.
    content = (
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  # policy = data.aws_iam_policy_document.old.json\n"
        "  policy = jsonencode({\n"
        '    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject" }]\n'
        "  })\n"
        "}\n"
    )
    assert [f.rule for f in _findings(tmp_path, content)] == [_RULE]
    # FP-bait: the real data reference (with a Deny) is still resolved and stays silent.
    real = _tls_data_source("Deny") + _bucket_policy("data.aws_iam_policy_document.tls.json  # TLS-only")
    assert _findings(tmp_path, real) == []
