from __future__ import annotations

from agentsec.guards.ecr_repository_hygiene import EcrRepositoryHygieneGuard
from tests.guards._common import *  # noqa: F401,F403


def test_ecr_repository_hygiene_flags_all_three_gaps(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app-image"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    assert len(findings) == 3
    rules = {f.rule for f in findings}
    assert rules == {
        "ecr-repository-hygiene/scan-on-push-disabled",
        "ecr-repository-hygiene/mutable-tags",
        "ecr-repository-hygiene/no-lifecycle-policy",
    }
    for f in findings:
        assert f.severity == "medium"
        assert f.location.endswith(":1")


def test_ecr_repository_hygiene_flags_scan_on_push_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app-image"\n'
        '  image_tag_mutability = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = false\n"
        "  }\n"
        "}\n"
        'resource "aws_ecr_lifecycle_policy" "app" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        '  policy     = "{}"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ecr-repository-hygiene/scan-on-push-disabled"


def test_ecr_repository_hygiene_flags_mutable_tags(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name                  = "app-image"\n'
        '  image_tag_mutability  = "MUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n"
        'resource "aws_ecr_lifecycle_policy" "app" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        '  policy     = "{}"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ecr-repository-hygiene/mutable-tags"


def test_ecr_repository_hygiene_flags_no_lifecycle_policy(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name                  = "app-image"\n'
        '  image_tag_mutability  = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ecr-repository-hygiene/no-lifecycle-policy"


def test_ecr_repository_hygiene_lifecycle_policy_found_in_other_file(tmp_path: Path) -> None:
    # cross-file: the repository and its lifecycle policy commonly live in different .tf files.
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name                  = "app-image"\n'
        '  image_tag_mutability  = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "lifecycle.tf").write_text(
        'resource "aws_ecr_lifecycle_policy" "app" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        '  policy     = "{}"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryHygieneGuard().run(tmp_path, profile) == []


def test_ecr_repository_hygiene_lifecycle_policy_for_different_repo_still_fires(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name                  = "app-image"\n'
        '  image_tag_mutability  = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n"
        'resource "aws_ecr_repository" "other" {\n'
        '  name                  = "other-image"\n'
        '  image_tag_mutability  = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n"
        'resource "aws_ecr_lifecycle_policy" "other" {\n'
        "  repository = aws_ecr_repository.other.name\n"
        '  policy     = "{}"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "ecr-repository-hygiene/no-lifecycle-policy"
    assert "app" in findings[0].message


def test_ecr_repository_hygiene_silent_when_fully_configured(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name                  = "app-image"\n'
        '  image_tag_mutability  = "IMMUTABLE"\n'
        "  image_scanning_configuration {\n"
        "    scan_on_push = true\n"
        "  }\n"
        "}\n"
        'resource "aws_ecr_lifecycle_policy" "app" {\n'
        "  repository = aws_ecr_repository.app.name\n"
        '  policy     = "{}"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryHygieneGuard().run(tmp_path, profile) == []


def test_ecr_repository_hygiene_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        "  scan_on_push = false\n"  # not a real S3 attribute, confirms resource-type scoping
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryHygieneGuard().run(tmp_path, profile) == []


def test_ecr_repository_hygiene_pragmas_silence_each_rule(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        "  # security: allow-ecr-scan-on-push\n"
        "  # security: allow-ecr-tag-mutability\n"
        "  # security: allow-ecr-lifecycle-policy\n"
        '  name = "app-image"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert EcrRepositoryHygieneGuard().run(tmp_path, profile) == []


def test_ecr_repository_hygiene_comment_does_not_suppress_finding(tmp_path: Path) -> None:
    (tmp_path / "ecr.tf").write_text(
        'resource "aws_ecr_repository" "app" {\n'
        '  name = "app-image"\n'
        "  # scan_on_push = true\n"
        '  # image_tag_mutability = "IMMUTABLE"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = EcrRepositoryHygieneGuard().run(tmp_path, profile)
    rules = {f.rule for f in findings}
    assert "ecr-repository-hygiene/scan-on-push-disabled" in rules
    assert "ecr-repository-hygiene/mutable-tags" in rules


def test_ecr_repository_hygiene_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert EcrRepositoryHygieneGuard().applies(profile) is False


def test_ecr_repository_hygiene_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert EcrRepositoryHygieneGuard().applies(profile) is True
