from __future__ import annotations

from agentsec.guards.s3_mfa_delete_disabled import S3MfaDeleteDisabledGuard
from tests.guards._common import *  # noqa: F401,F403

_INLINE_RULE = "s3-mfa-delete-disabled/inline-versioning-block"
_SPLIT_RULE = "s3-mfa-delete-disabled/versioning-configuration-resource"


# --- Rule A: legacy inline `versioning` block -----------------------------------------------

def test_inline_versioning_missing_mfa_delete_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"})
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, profile)
    matches = [f for f in findings if f.rule == _INLINE_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_inline_versioning_explicit_mfa_delete_false_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        "    enabled    = true\n"
        "    mfa_delete = false\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"})
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, profile)
    assert any(f.rule == _INLINE_RULE for f in findings)


def test_inline_versioning_mfa_delete_true_silent(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        "    enabled    = true\n"
        "    mfa_delete = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"})
    assert S3MfaDeleteDisabledGuard().run(tmp_path, profile) == []


def test_bucket_with_no_versioning_at_all_stays_silent(tmp_path: Path) -> None:
    # FP-bait: no versioning configured anywhere is aws-observability-hygiene's finding, not
    # this guard's -- this guard only has an opinion once versioning is already on.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"})
    assert S3MfaDeleteDisabledGuard().run(tmp_path, profile) == []


def test_inline_versioning_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"  # security: allow-s3-mfa-delete\n'
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"})
    assert S3MfaDeleteDisabledGuard().run(tmp_path, profile) == []


# --- Rule B: split-resource `aws_s3_bucket_versioning` ---------------------------------------

def test_split_resource_missing_mfa_delete_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _SPLIT_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_split_resource_mfa_delete_disabled_string_fires(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Disabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert any(f.rule == _SPLIT_RULE for f in findings)


def test_split_resource_mfa_delete_enabled_string_silent(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_split_resource_wins_over_legacy_inline_no_double_report(tmp_path: Path) -> None:
    # A bucket with BOTH a legacy inline block (bad) and a linked split resource (good) must be
    # judged once, by the split resource -- never double-reported.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


def test_split_resource_for_different_bucket_does_not_silence(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n"
        'resource "aws_s3_bucket" "other" {\n'
        '  bucket = "other-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "other" {\n'
        "  bucket = aws_s3_bucket.other.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _INLINE_RULE]
    assert len(matches) == 1
    assert "aws_s3_bucket.data" in matches[0].message


def test_two_modules_same_bare_label_both_judged(tmp_path: Path) -> None:
    # Review H7: two unrelated buckets in two different directories both happen to use the
    # bare label "logs". The matching here has no module scoping, so it must not let modA's
    # enabled versioning (sorted/read first) silence modB's disabled one.
    (tmp_path / "modA").mkdir()
    (tmp_path / "modA" / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "modA-logs"\n'
        "}\n"
        'resource "aws_s3_bucket_versioning" "logs" {\n'
        "  bucket = aws_s3_bucket.logs.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "modB").mkdir()
    (tmp_path / "modB" / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "modB-logs"\n'
        "}\n"
        'resource "aws_s3_bucket_versioning" "logs" {\n'
        "  bucket = aws_s3_bucket.logs.id\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    matches = [f for f in findings if f.rule == _SPLIT_RULE]
    assert len(matches) == 1
    assert "modB" in matches[0].location


def test_split_resource_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id  # security: allow-s3-mfa-delete\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert findings == []


# --- applies() gate ----------------------------------------------------------------------------

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert S3MfaDeleteDisabledGuard().applies(profile) is False


def test_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert S3MfaDeleteDisabledGuard().applies(profile) is True


# --- PR #1162 round-1 M6: versioning must be provably ON; comments are not config ------------


def _mfa_findings(tmp_path: Path, content: str) -> list[str]:
    (tmp_path / "s3.tf").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"terraform"})
    return [f.rule for f in S3MfaDeleteDisabledGuard().run(tmp_path, profile)]


def _inline(versioning_lines: str) -> str:
    return (
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "  versioning {\n"
        f"{versioning_lines}"
        "  }\n"
        "}\n"
    )


def _split(config_lines: str) -> str:
    return (
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "app-data"\n'
        "}\n"
        'resource "aws_s3_bucket_versioning" "data" {\n'
        "  bucket = aws_s3_bucket.data.id\n"
        "  versioning_configuration {\n"
        f"{config_lines}"
        "  }\n"
        "}\n"
    )


def test_versioning_not_on_is_out_of_scope(tmp_path: Path) -> None:
    # Suspended / disabled / defaulted-off / variable versioning used to fire: MFA Delete is only
    # meaningful once versioning is on, and the docstring scopes the guard to exactly that.
    for content in (
        _inline("    enabled = false\n"),
        _inline("    mfa_delete = false\n"),  # `enabled` omitted -> defaults to false
        _inline("    enabled = var.versioning\n"),
        _split('    status = "Suspended"\n'),
        _split('    status = "Disabled"\n'),
        _split("    status = var.versioning_status\n"),
    ):
        assert _mfa_findings(tmp_path, content) == [], content


def test_versioning_on_without_mfa_still_fires_in_both_forms(tmp_path: Path) -> None:
    # The direction the scope narrowing trades against.
    assert _mfa_findings(tmp_path, _inline("    enabled = true\n")) == [_INLINE_RULE]
    assert _mfa_findings(tmp_path, _inline('    enabled = "true"\n')) == [_INLINE_RULE]
    assert _mfa_findings(tmp_path, _split('    status = "Enabled"\n')) == [_SPLIT_RULE]


def test_commented_out_mfa_delete_does_not_suppress(tmp_path: Path) -> None:
    # A `# mfa_delete = ...` comment used to satisfy the check on a bucket that never sets it.
    assert _mfa_findings(tmp_path, _inline("    enabled = true\n    # mfa_delete = true\n")) == [
        _INLINE_RULE
    ]
    assert _mfa_findings(
        tmp_path, _split('    status = "Enabled"\n    # mfa_delete = "Enabled"\n')
    ) == [_SPLIT_RULE]
    # FP-bait: the real attribute with a trailing comment still satisfies it.
    assert _mfa_findings(tmp_path, _split('    status = "Enabled"\n    mfa_delete = "Enabled"  # root-applied\n')) == []


def test_commented_out_enabled_status_is_not_versioning_on(tmp_path: Path) -> None:
    # `# status = "Enabled"` above a suspended configuration is not versioning on.
    assert _mfa_findings(tmp_path, _split('    # status = "Enabled"\n    status = "Suspended"\n')) == []


def test_inline_bucket_is_not_judged_by_a_split_resource_in_another_directory(tmp_path: Path) -> None:
    # PR #1162 round-2 Low (H7's inline form): modA's inline-versioning bucket with no MFA used
    # to link to modB's same-labelled split resource (which requires MFA) and stay silent.
    # Terraform scopes a resource reference to its own module directory, so modB's split
    # resource cannot be modA's bucket.
    (tmp_path / "modA").mkdir()
    (tmp_path / "modA" / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "modA-logs"\n'
        "  versioning {\n"
        "    enabled = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "modB").mkdir()
    (tmp_path / "modB" / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "modB-logs"\n'
        "}\n"
        'resource "aws_s3_bucket_versioning" "logs" {\n'
        "  bucket = aws_s3_bucket.logs.id\n"
        "  versioning_configuration {\n"
        '    status     = "Enabled"\n'
        '    mfa_delete = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert [(f.rule, "modA" in f.location) for f in findings] == [(_INLINE_RULE, True)]


def test_split_resource_in_another_file_of_the_same_directory_still_links(tmp_path: Path) -> None:
    # The direction the directory scoping trades against: the split resource routinely lives in
    # a separate file (versioning.tf) of the SAME module, and must still decide the bucket.
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "app-logs"\n'
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "versioning.tf").write_text(
        'resource "aws_s3_bucket_versioning" "logs" {\n'
        "  bucket = aws_s3_bucket.logs.id\n"
        "  versioning_configuration {\n"
        '    status = "Enabled"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    findings = S3MfaDeleteDisabledGuard().run(tmp_path, _tf_prof(tmp_path))
    assert [f.rule for f in findings] == [_SPLIT_RULE]
