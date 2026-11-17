from __future__ import annotations

from agentsec.guards.s3_bucket_canned_acl import S3BucketCannedAclGuard
from tests.guards._common import *  # noqa: F401,F403

_INLINE_RULE = "s3-bucket-canned-acl/inline-acl-attribute"
_RESOURCE_RULE = "s3-bucket-canned-acl/acl-resource"


# --- Rule A: legacy inline `acl` attribute ------------------------------------------------------

def test_inline_acl_public_read_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _INLINE_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_inline_acl_public_read_write_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        '  acl    = "public-read-write"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _INLINE_RULE for f in findings)


def test_inline_acl_authenticated_read_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        '  acl    = "authenticated-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _INLINE_RULE for f in findings)


def test_inline_acl_private_silent(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        '  acl    = "private"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_inline_acl_log_delivery_write_silent(tmp_path: Path) -> None:
    # FP-bait: another valid, non-public canned ACL must not fire.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        '  acl    = "log-delivery-write"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_inline_acl_no_attribute_silent(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_inline_acl_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"  # security: allow-s3-canned-acl\n'
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


# --- Rule B: split-resource `aws_s3_bucket_acl` --------------------------------------------------

def test_split_resource_acl_public_read_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "acl.tf").write_text(
        'resource "aws_s3_bucket_acl" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _RESOURCE_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert "aws_s3_bucket.data" in matches[0].message


def test_split_resource_acl_public_read_write_fires(tmp_path: Path) -> None:
    (tmp_path / "acl.tf").write_text(
        'resource "aws_s3_bucket_acl" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        '  acl    = "public-read-write"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _RESOURCE_RULE for f in findings)


def test_split_resource_acl_private_silent(tmp_path: Path) -> None:
    (tmp_path / "acl.tf").write_text(
        'resource "aws_s3_bucket_acl" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        '  acl    = "private"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_split_resource_acl_does_not_need_bucket_resource_to_exist(tmp_path: Path) -> None:
    # The acl-resource rule fires on the aws_s3_bucket_acl resource's own value alone -- the
    # referenced bucket resource itself need not be found in the scanned files.
    (tmp_path / "acl.tf").write_text(
        'resource "aws_s3_bucket_acl" "orphan" {\n'
        "  bucket = aws_s3_bucket.missing.id\n"
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _RESOURCE_RULE]
    assert len(matches) == 1


def test_split_resource_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "acl.tf").write_text(
        'resource "aws_s3_bucket_acl" "data" {\n'
        "  bucket = aws_s3_bucket.data.id  # security: allow-s3-canned-acl\n"
        '  acl    = "public-read"\n'
        "}\n",
        encoding="utf-8",
    )
    findings = S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


# --- where `acl` is read from (PR #1162 round 6) -------------------------------------------------
# The whole resource body is read, plus a one-line resource's own attribute. Round 5 moved the read
# onto `top_level_attribute_text` alone, and its brace scanner does not understand `/* */`, so a
# `{` inside a block comment hid every later attribute (F1); a nested-block key also stopped
# counting with no test either way (F2). The guard fails closed: it fires when any `acl` line in the
# body is public, not only the first one (round 7 M1).

def _rules(tmp_path: Path, hcl: str) -> list[str]:
    (tmp_path / "s3.tf").write_text(hcl, encoding="utf-8")
    return [f.rule for f in S3BucketCannedAclGuard().run(tmp_path, _tf_prof(tmp_path))]


def test_acl_below_a_block_comment_holding_a_brace_still_fires(tmp_path: Path) -> None:
    hcl = 'resource "aws_s3_bucket" "b" {\n  /* {\n  */\n  acl = "public-read"\n}\n'
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_acl_after_a_nested_block_still_fires(tmp_path: Path) -> None:
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  versioning {\n    enabled = true\n  }\n'
        '  acl = "public-read"\n}\n'
    )
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_acl_after_a_tags_map_with_a_brace_in_a_value_still_fires(tmp_path: Path) -> None:
    hcl = 'resource "aws_s3_bucket" "b" {\n  tags = { a = "}" }\n  acl = "public-read"\n}\n'
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_acl_key_inside_a_nested_block_counts(tmp_path: Path) -> None:
    # No real aws_s3_bucket nested block has an `acl` attribute; the read fails closed rather
    # than depend on the brace scanner to rule one out.
    hcl = 'resource "aws_s3_bucket" "b" {\n  grant {\n    acl = "public-read"\n  }\n}\n'
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_public_acl_after_a_nested_private_acl_still_fires(tmp_path: Path) -> None:
    # Round 7 M1: only the first `acl` line was evaluated, so a private one ahead of the public
    # one silenced the guard. Every `acl` line is evaluated.
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  grant {\n    acl = "private"\n  }\n'
        '  acl = "public-read"\n}\n'
    )
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_public_acl_before_a_nested_private_acl_still_fires(tmp_path: Path) -> None:
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n  grant {\n'
        '    acl = "private"\n  }\n}\n'
    )
    assert _rules(tmp_path, hcl) == [_INLINE_RULE]


def test_several_non_public_acls_stay_silent(tmp_path: Path) -> None:
    # FP-bait for evaluating every `acl` line: none of them is public.
    hcl = (
        'resource "aws_s3_bucket" "b" {\n  grant {\n    acl = "private"\n  }\n'
        '  acl = "log-delivery-write"\n}\n'
    )
    assert _rules(tmp_path, hcl) == []


def test_commented_out_acl_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the body-wide read: a `#`/`//` comment line is not the attribute.
    hcl = 'resource "aws_s3_bucket" "b" {\n  # acl = "public-read"\n  // acl = "public-read"\n}\n'
    assert _rules(tmp_path, hcl) == []


def test_one_line_acl_resource_fires(tmp_path: Path) -> None:
    assert _rules(tmp_path, 'resource "aws_s3_bucket_acl" "a" { acl = "public-read" }\n') == [_RESOURCE_RULE]


def test_one_line_private_acl_resource_stays_silent(tmp_path: Path) -> None:
    assert _rules(tmp_path, 'resource "aws_s3_bucket_acl" "a" { acl = "private" }\n') == []


# --- applies() gate -----------------------------------------------------------------------------

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert S3BucketCannedAclGuard().applies(profile) is False


def test_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert S3BucketCannedAclGuard().applies(profile) is True
